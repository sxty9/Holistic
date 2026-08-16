package instance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

// The rule that matters most. A config file holds a dozen settings this package
// has no opinion about; marshalling a struct over the top would drop every key
// the struct does not know while reporting success.
func TestEverythingWeDoNotOwnIsCarriedThrough(t *testing.T) {
	p := write(t, "config.json", `{
	  "dataDir": "/var/lib/corex",
	  "logLevel": "debug",
	  "instance": { "tenantId": "t-1", "displayName": "old name" },
	  "files": { "quotaBytes": 12345, "hostShared": true },
	  "ai": { "engines": ["claude"], "ollamaModel": "llama3" }
	}`)

	f, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Set("instance.displayName", "Henry's box")
	f.Set("instance.publicBaseUrl", "https://example.org")
	if err := f.Save(0o640); err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["dataDir"] != "/var/lib/corex" || got["logLevel"] != "debug" {
		t.Errorf("top-level settings were lost: %v", got)
	}
	files := got["files"].(map[string]any)
	if files["quotaBytes"].(float64) != 12345 || files["hostShared"] != true {
		t.Errorf("an untouched section was rewritten: %v", files)
	}
	ai := got["ai"].(map[string]any)
	if ai["ollamaModel"] != "llama3" {
		t.Error("a tuned setting was dropped")
	}
	inst := got["instance"].(map[string]any)
	if inst["tenantId"] != "t-1" {
		t.Error("the tenant id was lost, which would re-arm the first-admin land grab")
	}
	if inst["displayName"] != "Henry's box" || inst["publicBaseUrl"] != "https://example.org" {
		t.Errorf("the intended change did not land: %v", inst)
	}
}

func TestTheDiffIsReadableAndComplete(t *testing.T) {
	p := write(t, "config.json", `{"instance":{"displayName":"old","cookieDomain":""}}`)
	f, _ := Open(p)
	f.Set("instance.displayName", "new")
	f.Set("instance.cookieDomain", "example.org")
	f.Set("auth.insecureCookies", false)

	changes := f.Changes()
	byPath := map[string]Change{}
	for _, c := range changes {
		byPath[c.Path] = c
	}
	if c := byPath["instance.displayName"]; c.From != "old" || c.To != "new" {
		t.Errorf("displayName change reads %q", c)
	}
	if c := byPath["auth.insecureCookies"]; c.From != "" || c.To != "false" {
		t.Errorf("a new setting should read as unset -> value, got %q", c)
	}
	if s := byPath["instance.cookieDomain"].String(); !strings.Contains(s, "example.org") {
		t.Errorf("cookieDomain change reads %q", s)
	}
	// Settings that did not change must not appear; a diff full of noise is a
	// diff nobody reads.
	f2, _ := Open(p)
	f2.Set("instance.displayName", "old")
	if got := f2.Changes(); len(got) != 0 {
		t.Errorf("unchanged settings appeared in the diff: %v", got)
	}
}

// The previous version is kept. A configuration change is followed by a service
// restart, which is exactly when you find out you wanted the old one.
func TestThePreviousVersionIsKept(t *testing.T) {
	p := write(t, "config.json", `{"instance":{"displayName":"old"}}`)
	f, _ := Open(p)
	f.Set("instance.displayName", "new")
	if err := f.Save(0o640); err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(filepath.Dir(p))
	var backup string
	for _, e := range entries {
		if strings.Contains(e.Name(), ".before-") {
			backup = filepath.Join(filepath.Dir(p), e.Name())
		}
	}
	if backup == "" {
		t.Fatal("no copy of the previous configuration was kept")
	}
	b, _ := os.ReadFile(backup)
	if !strings.Contains(string(b), "old") {
		t.Error("the copy does not hold the previous content")
	}
	if _, err := os.Stat(p + ".incoming"); !os.IsNotExist(err) {
		t.Error("a temporary file was left behind")
	}
}

// Treating unreadable as absent is how an installer writes over live
// configuration. Nextcloud wrote a fresh config.php whenever it could not read
// the existing one, concluded it was not installed, and offered the installer.
func TestAnUnreadableFileIsNotAnEmptyOne(t *testing.T) {
	p := write(t, "config.json", `{"instance": { truncated`)
	if _, err := Open(p); err == nil {
		t.Fatal("a corrupt configuration file was treated as empty")
	}
	// But a genuinely absent file is fine — on a fresh instance most of these
	// have never been written.
	if _, err := Open(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Errorf("a missing file should be an empty tree, got %v", err)
	}
}

// The defect that had both services running entirely on example.org while their
// JSON said otherwise. coreX applies environment variables after unmarshalling
// the file, so a stale line beats whatever was just written — and every check
// that reads the JSON reports success.
func TestAnEnvironmentFileThatWouldWinIsReported(t *testing.T) {
	p := write(t, "corex-api.env", `
# left over from an earlier install
COREX_PUBLIC_BASE_URL=https://example.org
COREX_COOKIE_DOMAIN=example.org
# this one is commented out and must not count
#COREX_DISPLAY_NAME=whatever
COREX_LOG_LEVEL=debug
`)
	got, err := CheckOverrides(p, CoreXOverrides)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 overrides, got %d: %v", len(got), got)
	}
	if got[0].Variable != "COREX_COOKIE_DOMAIN" || got[0].Beats != "instance.cookieDomain" {
		t.Errorf("first override reads %q", got[0])
	}
	if !strings.Contains(got[1].String(), "instance.publicBaseUrl") {
		t.Errorf("the report does not name the setting being overridden: %q", got[1])
	}
}

// The per-app family is the half nobody remembers exists, and its names are not
// known in advance.
func TestTheWildcardFamilyIsCaught(t *testing.T) {
	p := write(t, "solisuite.env", "SOLISUITE_APP_HOST_MAIL=mail.old.example\nSOLISUITE_LISTEN=:8795\n")
	got, err := CheckOverrides(p, SolisuiteOverrides)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected both to be caught, got %v", got)
	}
	var found bool
	for _, o := range got {
		if o.Variable == "SOLISUITE_APP_HOST_MAIL" {
			found = true
		}
	}
	if !found {
		t.Error("a per-app host override was not recognised")
	}
}

func TestNoEnvironmentFileIsNotAProblem(t *testing.T) {
	got, err := CheckOverrides(filepath.Join(t.TempDir(), "absent.env"), CoreXOverrides)
	if err != nil {
		t.Fatalf("a missing env file should be silence, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestWrittenFilesAreNotWorldReadable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	f, _ := Open(p)
	f.Set("instance.displayName", "x")
	if err := f.Save(0o640); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm()&0o007 != 0 {
		t.Errorf("configuration is world readable: %o", st.Mode().Perm())
	}
}
