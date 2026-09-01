// Package instance writes the configuration that makes a machine somebody's
// own instance, and refuses to write it in the ways that have gone wrong before.
//
// Three rules shape everything here.
//
// It edits, never replaces. /etc/corex/config.json holds a dozen settings this
// package has no opinion about — the data directory, the AI engines, the file
// quota, whatever an operator has tuned. Marshalling a Go struct over the top
// of it would silently drop every key the struct does not know, which is a
// spectacular way to lose somebody's configuration while reporting success. So
// the file is read as a tree, the handful of paths this package owns are set,
// and everything else is carried through untouched.
//
// It shows what it is about to change, key by key. A diff nobody can read is a
// confirmation nobody gives.
//
// And it checks that what it wrote will actually be read. coreX applies
// environment variables AFTER unmarshalling the JSON, so a stale COREX_* line
// in an env file beats the file this package just wrote — which is not a
// hypothetical: it is the defect that had both services running entirely on
// example.org while their JSON said otherwise. A write that will be overridden
// is worse than a write that fails, because it looks like it worked.
package instance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Change is one setting this package would alter.
type Change struct {
	Path string // dotted path into the file, e.g. instance.cookieDomain
	From string
	To   string
}

func (c Change) String() string {
	if c.From == "" {
		return fmt.Sprintf("%s: (unset) -> %s", c.Path, c.To)
	}
	return fmt.Sprintf("%s: %s -> %s", c.Path, c.From, c.To)
}

// File is a JSON configuration file being edited in place.
type File struct {
	Path string
	tree map[string]any
	orig map[string]any
}

// Open reads a configuration file. A file that does not exist yet is an empty
// tree, not an error: on a fresh instance most of these have never been written.
// A file that exists and cannot be parsed IS an error — treating unreadable as
// absent is how an installer ends up writing over live configuration.
func Open(path string) (*File, error) {
	f := &File{Path: path, tree: map[string]any{}, orig: map[string]any{}}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return f, nil
	}
	if err := json.Unmarshal(b, &f.tree); err != nil {
		return nil, fmt.Errorf("%s exists but is not readable as JSON (%w) — fix or move it aside deliberately", path, err)
	}
	// A second parse, so the diff compares against what was really there
	// rather than against a tree this package may already have edited.
	_ = json.Unmarshal(b, &f.orig)
	return f, nil
}

// Set records an intended value at a dotted path.
func (f *File) Set(path string, value any) {
	parts := strings.Split(path, ".")
	node := f.tree
	for _, p := range parts[:len(parts)-1] {
		next, ok := node[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			node[p] = next
		}
		node = next
	}
	node[parts[len(parts)-1]] = value
}

// Changes lists what would differ from what is on disk.
func (f *File) Changes() []Change {
	var out []Change
	walk(f.tree, nil, func(path string, v any) {
		was, had := lookup(f.orig, path)
		to := render(v)
		if had && render(was) == to {
			return
		}
		from := ""
		if had {
			from = render(was)
		}
		out = append(out, Change{Path: path, From: from, To: to})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func walk(node map[string]any, prefix []string, fn func(string, any)) {
	keys := make([]string, 0, len(node))
	for k := range node {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := append(append([]string{}, prefix...), k)
		if sub, ok := node[k].(map[string]any); ok {
			walk(sub, p, fn)
			continue
		}
		fn(strings.Join(p, "."), node[k])
	}
}

func lookup(node map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	var cur any = node
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func render(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
}

// Save writes the file, keeping the previous version beside it.
//
// The write is atomic. A half-written configuration is worse than none: it is
// the file a service reads at its next start, and the next start is exactly
// what a configuration change is followed by.
// chown is a variable so a test can watch what Save asks for. The real one
// needs root and would be a no-op in a test that runs as anybody else.
var chown = os.Chown

func (f *File) Save(mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o750); err != nil {
		return err
	}
	// Who owns the file today. Save writes a NEW file and renames it over the
	// old one, and a new file belongs to the process that created it — root.
	// /etc/corex/config.json is root:corex 0640 and corex-api runs as corex;
	// /etc/solisuite/config.json is root:solisuite and solisuite runs as
	// solisuite. Losing the group takes both services off the air at their
	// next restart, with "permission denied" on a file that is plainly there.
	//
	// It did, on 2026-08-30. The wizard rewrote both files, nothing looked
	// wrong for two hours because each service had already read its config,
	// and then the wizard's own restart step killed them.
	uid, gid := -1, -1
	if fi, err := os.Stat(f.Path); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	}

	if old, err := os.ReadFile(f.Path); err == nil {
		bak := fmt.Sprintf("%s.before-%s", f.Path, time.Now().UTC().Format("20060102T150405Z"))
		if err := os.WriteFile(bak, old, mode); err != nil {
			return fmt.Errorf("could not keep a copy of the previous %s: %w", f.Path, err)
		}
		// The copy carries the same ownership. A backup somebody has to become
		// root to read is a backup that will not be read in the hour it is for.
		if uid >= 0 {
			if err := chown(bak, uid, gid); err != nil {
				return fmt.Errorf("could not set the owner of %s: %w", bak, err)
			}
		}
	}
	b, err := json.MarshalIndent(f.tree, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.Path + ".incoming"
	if err := os.WriteFile(tmp, append(b, '\n'), mode); err != nil {
		return err
	}
	// Before the rename, so the file is never visible at its final path with
	// the wrong owner.
	if uid >= 0 {
		if err := chown(tmp, uid, gid); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("could not give %s back the owner it had: %w", f.Path, err)
		}
	}
	return os.Rename(tmp, f.Path)
}

// --- the override trap -----------------------------------------------------

// Override is an environment setting that would beat the file.
type Override struct {
	File     string
	Variable string
	Value    string
	Beats    string // the JSON path it overrides
}

func (o Override) String() string {
	return fmt.Sprintf("%s sets %s=%s, which overrides %s", o.File, o.Variable, o.Value, o.Beats)
}

// CheckOverrides reads a systemd EnvironmentFile and reports any variable that
// would take precedence over the paths just written.
//
// This exists because of a real failure rather than a theoretical one. coreX
// runs applyEnv AFTER unmarshalling its JSON, and Solisuite does the same with
// SOLISUITE_APP_HOST_*, so a line left in an env file wins over the file the
// wizard wrote. The observed result was both services running entirely on
// example.org while their configuration said otherwise — and every check that
// looked at the JSON reported everything as correct.
func CheckOverrides(envPath string, watched map[string]string) ([]Override, error) {
	b, err := os.ReadFile(envPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Override
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		beats, ok := watched[name]
		if !ok {
			beats, ok = prefixWatched(watched, name)
		}
		if ok {
			out = append(out, Override{File: envPath, Variable: name, Value: value, Beats: beats})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Variable < out[j].Variable })
	return out, nil
}

// prefixWatched covers families like SOLISUITE_APP_HOST_<ID>, where the
// variable name is not known in advance but the prefix is.
func prefixWatched(watched map[string]string, name string) (string, bool) {
	for k, v := range watched {
		if strings.HasSuffix(k, "*") && strings.HasPrefix(name, strings.TrimSuffix(k, "*")) {
			return v, true
		}
	}
	return "", false
}

// CoreXOverrides are the variables that would beat what this package writes
// into coreX's configuration.
var CoreXOverrides = map[string]string{
	"COREX_PUBLIC_BASE_URL":  "instance.publicBaseUrl",
	"COREX_COOKIE_DOMAIN":    "instance.cookieDomain",
	"COREX_DISPLAY_NAME":     "instance.displayName",
	"COREX_TENANT_ID":        "instance.tenantId",
	"COREX_MAIL_DOMAIN":      "mail.domain",
	"COREX_INSECURE_COOKIES": "auth.insecureCookies",
}

// SolisuiteOverrides likewise. The wildcard covers the per-app family, which is
// the half nobody remembers exists.
var SolisuiteOverrides = map[string]string{
	"SOLISUITE_APP_HOST_*": "apps[].host",
	"SOLISUITE_COREX_URL":  "corexUrl",
	"SOLISUITE_LISTEN":     "listen",
	// The one that was missing, found on 2026-09-01. A line reading
	// SOLISUITE_WEB_ROOT=/opt/solisuite/web sat in the environment file from
	// an install in August. The wizard wrote webRoot into the JSON, read it
	// back, reported the new directory — and Solisuite went on serving a front
	// end from three weeks earlier, because the environment is applied after
	// the file. Every check agreed and a message would not open.
	"SOLISUITE_WEB_ROOT": "webRoot",
}
