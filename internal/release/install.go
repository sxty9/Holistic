package release

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Installed is what this machine believes it is running. Written by the
// installer and by every upgrade, read by every upgrade.
//
// The installer did not write this at first, which meant `upgrade` had nothing
// to compare against and could only ever reinstall. A version you cannot read
// back is not a version.
type Installed struct {
	Version     string    `json:"version"`
	Platform    string    `json:"platform"`
	Archive     string    `json:"archive"`
	SHA256      string    `json:"sha256"`
	InstalledAt time.Time `json:"installedAt"`
	// Binaries is what was laid down, so an upgrade knows what it may replace
	// and — more to the point — what it may not. A binary this machine did not
	// install is not ours to overwrite.
	Binaries []string `json:"binaries"`
}

const stateFile = "installed.json"

func ReadInstalled(stateDir string) (*Installed, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, stateFile))
	if err != nil {
		return nil, err
	}
	var in Installed
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("%s is not readable as a version record: %w", stateFile, err)
	}
	return &in, nil
}

func WriteInstalled(stateDir string, in *Installed) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	// Written to a sibling and renamed, so a crash mid-write leaves the previous
	// record intact rather than a truncated one. A half-written version record
	// reads as "no version", which would make the next upgrade reinstall
	// silently.
	tmp := filepath.Join(stateDir, "."+stateFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(stateDir, stateFile))
}

// Swap replaces the binaries in binDir with the ones in the unpacked release,
// keeping the displaced ones so a failure can be undone.
//
// It returns the names it replaced, and a function that puts the old ones back.
// Nothing here restarts anything: swapping files and restarting services are
// separate failures with separate recoveries, and running them as one step is
// how you end up with new binaries and dead units.
func Swap(rel *Release, binDir string) (replaced []string, undo func() error, err error) {
	srcDir := filepath.Join(rel.Dir, "holistic", "bin")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, nil, err
	}

	backupDir, err := os.MkdirTemp(filepath.Dir(binDir), ".holistic-previous-")
	if err != nil {
		return nil, nil, err
	}

	undo = func() error {
		var firstErr error
		for _, name := range replaced {
			from := filepath.Join(backupDir, name)
			if _, statErr := os.Stat(from); statErr != nil {
				continue // it was new; there is nothing to put back
			}
			if e := os.Rename(from, filepath.Join(binDir, name)); e != nil && firstErr == nil {
				firstErr = e
			}
		}
		return firstErr
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		dst := filepath.Join(binDir, name)

		// Keep the outgoing one. Rename rather than copy: on Linux a running
		// process holds its inode open, so renaming the file out from under it
		// is safe and instant, and the process keeps running the old code until
		// it is restarted — which is exactly the window we want.
		if _, statErr := os.Stat(dst); statErr == nil {
			if e := os.Rename(dst, filepath.Join(backupDir, name)); e != nil {
				_ = undo()
				return replaced, undo, fmt.Errorf("could not set aside the current %s: %w", name, e)
			}
		}

		if e := copyExecutable(filepath.Join(srcDir, name), dst); e != nil {
			_ = undo()
			return replaced, undo, fmt.Errorf("could not install %s: %w", name, e)
		}
		replaced = append(replaced, name)
	}

	sort.Strings(replaced)
	return replaced, undo, nil
}

func copyExecutable(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// Into a sibling then renamed, so a reader never sees a partial binary.
	tmp := dst + ".incoming"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// RestartUnits restarts the units that are currently active, and only those.
//
// A unit that is stopped is stopped on purpose. Starting it because an upgrade
// happened to run would turn `upgrade` into a thing that changes what is
// running on the machine, and the one unit where that would matter most is the
// setup listener: it disables itself when the instance is claimed, and bringing
// it back would reopen a root-privileged HTTP server on the local network.
func RestartUnits(units []string) ([]string, error) {
	var restarted []string
	for _, u := range units {
		if !unitIsActive(u) {
			continue
		}
		out, err := exec.Command("systemctl", "restart", u).CombinedOutput()
		if err != nil {
			return restarted, fmt.Errorf("%s did not come back: %v\n%s", u, err, strings.TrimSpace(string(out)))
		}
		restarted = append(restarted, u)
	}
	return restarted, nil
}

func unitIsActive(unit string) bool { return isActive(unit) }

// isActive is a variable for the same reason unitExec is: the checks that read
// the service manager have to be exercisable without one.
var isActive = func(unit string) bool {
	// `is-active` exits non-zero for anything that is not active, which is the
	// question being asked, so the exit code is the answer.
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

// Claimed reports whether this instance has been set up. An upgrade must never
// change this: the same transaction that writes it destroys the setup code and
// disables the listener, and undoing any of that reopens the takeover window
// that the claim closed.
func Claimed(confDir string) bool {
	_, err := os.Stat(filepath.Join(confDir, "claimed"))
	return err == nil
}

// Whether the units that get restarted actually run the binaries that were just
// replaced.
//
// This exists because they did not, and nothing said so. On 2026-09-01 an
// instance had been upgraded five times: /opt/holistic/bin held v0.2.5 and
// corex-api.service ran /opt/corex/bin/corex-api, dated 16 August. Every
// upgrade replaced files nothing executed, restarted the old processes, printed
// the list of units it had restarted, and ended with "Now running v0.2.5." The
// machine was serving August code and every check agreed it was current.
//
// It is the failure this whole project began with, in the tool built to prevent
// it: each step succeeded and the outcome did not happen.

// unitExec reads a unit's ExecStart path. It is a variable so a test can drive
// every branch of the check without a service manager.
var unitExec = func(unit string) (string, error) {
	out, err := exec.Command("systemctl", "show", unit, "-p", "ExecStart", "--value").Output()
	if err != nil {
		return "", err
	}
	// The value is a structured record, not a command line:
	//   { path=/opt/corex/bin/corex-api ; argv[]=... ; ignore_errors=no ; ... }
	// The path field is the binary that will actually be executed, and it is
	// the only field this check is about.
	for _, f := range strings.Fields(string(out)) {
		if p, ok := strings.CutPrefix(f, "path="); ok {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s has no ExecStart path", unit)
}

// Stray is a unit that runs a binary from somewhere this release does not
// manage.
type Stray struct {
	Unit string
	// Runs is the binary the service manager will actually execute.
	Runs string
}

// StrayUnits reports the active units among these whose ExecStart points
// outside binDir.
//
// Only active ones: a unit that is not running was not restarted either, so it
// is not making a false claim about anything. And only ExecStart — not the
// unit file's own path, not its name — because the question is what runs, and a
// unit can be edited, dropped-in over, or aliased.
func StrayUnits(units []string, binDir string) ([]Stray, error) {
	want, err := filepath.Abs(binDir)
	if err != nil {
		return nil, err
	}
	var out []Stray
	for _, u := range units {
		if !unitIsActive(u) {
			continue
		}
		path, err := unitExec(u)
		if err != nil {
			// Unreadable is not the same as fine. A check that can return "all
			// clear" because it could not read is not a check.
			out = append(out, Stray{Unit: u, Runs: "could not be read: " + err.Error()})
			continue
		}
		if filepath.Dir(path) != want {
			out = append(out, Stray{Unit: u, Runs: path})
		}
	}
	return out, nil
}

// StrayMessage is what the operator is told. It names each unit, what it runs
// instead, and what to do — and it says plainly that the upgrade did not reach
// them, because the one thing this must never do is read like a warning beside
// a success.
func StrayMessage(strays []Stray, binDir, version string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "the binaries under %s are now %s, and these services do NOT run them:\n\n", binDir, version)
	for _, s := range strays {
		fmt.Fprintf(&b, "    %-28s runs %s\n", s.Unit, s.Runs)
	}
	fmt.Fprintf(&b, "\nSo they were restarted and came back on the software they were already running.\n"+
		"Nothing about this instance changed.\n\n"+
		"Point each unit's ExecStart at %s and reload systemd, then upgrade again:\n\n"+
		"    sudo systemctl edit --full <unit>\n"+
		"    sudo systemctl daemon-reload\n", binDir)
	return b.String()
}

// SwapAssets replaces a directory of static files with the release's copy.
//
// It exists because upgrade replaced binaries and nothing else, while install
// laid down the web directories — so an instance that was upgraded rather than
// reinstalled kept whatever front end it had when it was first installed. That
// is the same defect as the units running binaries from elsewhere, one layer
// up: the release said one thing, the machine served another, and nothing
// reported a difference.
//
// The old directory is moved aside and only removed once the new one is in
// place, so a failure halfway leaves the previous front end serving rather than
// an empty directory.
func SwapAssets(rel *Release, dest, name string) (bool, error) {
	src := filepath.Join(rel.Dir, "holistic", name)
	if fi, err := os.Stat(src); err != nil || !fi.IsDir() {
		// A release that predates this directory simply does not carry it.
		// Leaving what is there is right; removing it would break an instance
		// that is downgrading.
		return false, nil
	}
	staged := dest + ".incoming"
	if err := os.RemoveAll(staged); err != nil {
		return false, err
	}
	if err := copyTree(src, staged); err != nil {
		return false, err
	}
	previous := dest + ".previous"
	_ = os.RemoveAll(previous)
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, previous); err != nil {
			return false, err
		}
	}
	if err := os.Rename(staged, dest); err != nil {
		// Put the old one back rather than leave nothing being served.
		_ = os.Rename(previous, dest)
		return false, err
	}
	_ = os.RemoveAll(previous)
	return true, nil
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
			// Not copied, and not silently skipped either: a symlink or a
			// device node in a release archive is something nobody intended.
			return fmt.Errorf("%s is not a regular file", path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}
