package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A release, built in memory, so the tests exercise the real verification chain
// rather than a description of it.
type fakeRelease struct {
	pub     ed25519.PublicKey
	archive []byte
	sums    []byte
	sig     []byte
	server  *httptest.Server
}

func buildRelease(t *testing.T, entries map[string]string) *fakeRelease {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	zw.Close()

	archive := buf.Bytes()
	sum := sha256.Sum256(archive)
	sums := []byte(hex.EncodeToString(sum[:]) + "  holistic-linux-amd64.tar.gz\n")

	return &fakeRelease{pub: pub, archive: archive, sums: sums, sig: ed25519.Sign(priv, sums)}
}

func (f *fakeRelease) serve(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/download/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) { w.Write(f.sums) })
	mux.HandleFunc("/latest/download/SHA256SUMS.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(f.sig) })
	mux.HandleFunc("/latest/download/holistic-linux-amd64.tar.gz", func(w http.ResponseWriter, r *http.Request) { w.Write(f.archive) })
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)
	return f.server.URL
}

func (f *fakeRelease) client(url string) *Client {
	return &Client{BaseURL: url, PublicKey: f.pub, HTTP: f.server.Client()}
}

func goodRelease() map[string]string {
	return map[string]string{
		"holistic/bin/holistic":       "#!/bin/true\n",
		"holistic/bin/holistic-setup": "#!/bin/true\n",
		"holistic/deploy/x.service":   "[Unit]\n",
		"holistic/VERSION":            "v9.9.9\n",
	}
}

func TestAVerifiedReleaseUnpacks(t *testing.T) {
	f := buildRelease(t, goodRelease())
	url := f.serve(t)
	dir := t.TempDir()

	rel, err := f.client(url).Fetch(dir, "linux-amd64", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "holistic", "bin", "holistic")); err != nil {
		t.Errorf("the binary did not land: %v", err)
	}
	if len(rel.SHA256) != 64 {
		t.Errorf("checksum looks wrong: %q", rel.SHA256)
	}
}

// The signature is checked before the archive is fetched. A tampered manifest
// must not get as far as talking us into downloading anything.
func TestATamperedManifestStopsBeforeTheDownload(t *testing.T) {
	f := buildRelease(t, goodRelease())
	f.sums = append(f.sums, byte(' ')) // signature no longer covers this
	url := f.serve(t)

	fetched := false
	f.server.Config.Handler.(*http.ServeMux).HandleFunc("/x", func(http.ResponseWriter, *http.Request) { fetched = true })

	dir := t.TempDir()
	_, err := f.client(url).Fetch(dir, "linux-amd64", "latest")
	if err == nil {
		t.Fatal("a manifest that fails its signature was accepted")
	}
	if !strings.Contains(err.Error(), "not signed by the key") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
	if fetched {
		t.Error("the archive was fetched despite the manifest failing")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("something was written despite the failure: %v", entries)
	}
}

func TestAFlippedByteInTheArchiveIsCaught(t *testing.T) {
	f := buildRelease(t, goodRelease())
	f.archive[len(f.archive)/2] ^= 0x01
	url := f.serve(t)

	dir := t.TempDir()
	_, err := f.client(url).Fetch(dir, "linux-amd64", "latest")
	if err == nil {
		t.Fatal("a corrupted archive was accepted")
	}
	if !strings.Contains(err.Error(), "does not match the signed manifest") {
		t.Errorf("unhelpful error: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Error("the corrupted archive was unpacked anyway")
	}
}

// This code runs as root by necessity, so an archive entry naming its way out of
// the unpack directory is the one that would matter most.
func TestAnEntryCannotEscapeTheUnpackDirectory(t *testing.T) {
	for _, name := range []string{
		"../escaped",
		"holistic/../../escaped",
		"/etc/escaped",
		"holistic/bin/../../../escaped",
	} {
		f := buildRelease(t, map[string]string{
			"holistic/bin/holistic": "ok\n",
			name:                    "owned\n",
		})
		url := f.serve(t)
		dir := t.TempDir()

		_, err := f.client(url).Fetch(dir, "linux-amd64", "latest")
		outside := filepath.Join(filepath.Dir(dir), "escaped")
		if _, statErr := os.Stat(outside); statErr == nil {
			t.Fatalf("%s: the entry landed outside the unpack directory", name)
		}
		if _, statErr := os.Stat("/etc/escaped"); statErr == nil {
			t.Fatalf("%s: the entry landed in /etc", name)
		}
		// Escaping must fail loudly rather than be quietly relocated: an archive
		// that tries this is not one to half-install.
		if err == nil {
			t.Errorf("%s: escaping was silently tolerated", name)
		}
	}
}

// A symlink in the archive is a second way out of the directory, and a release
// is binaries, units and example configuration — none of which needs one.
func TestNonRegularEntriesAreRefused(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "holistic/bin/holistic", Mode: 0o755, Size: 3, Typeflag: tar.TypeReg})
	tw.Write([]byte("ok\n"))
	tw.WriteHeader(&tar.Header{Name: "holistic/bin/evil", Linkname: "/etc/shadow", Typeflag: tar.TypeSymlink})
	tw.Close()
	zw.Close()

	if err := untar(buf.Bytes(), t.TempDir()); err == nil {
		t.Fatal("a symlink entry was accepted")
	} else if !strings.Contains(err.Error(), "unexpected entry type") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// Verifying nothing and reporting success is the failure this package exists to
// prevent, so a build with no key must refuse rather than skip the check.
func TestAKeylessBuildRefusesToVerify(t *testing.T) {
	f := buildRelease(t, goodRelease())
	url := f.serve(t)
	c := &Client{BaseURL: url, HTTP: f.server.Client()} // no PublicKey
	if _, err := c.Fetch(t.TempDir(), "linux-amd64", "latest"); err == nil {
		t.Fatal("a keyless client verified a release")
	}

	if _, err := ParsePublicKey("REPLACE_ME"); err == nil {
		t.Error("the placeholder key was accepted as a key")
	}
	if _, err := ParsePublicKey(""); err == nil {
		t.Error("an empty key was accepted as a key")
	}
}

func TestPublicKeyRoundTrips(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	got, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pemBytes))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Error("the key did not survive the round trip")
	}
}

// A redirect to plain HTTP would put the manifest on the wire for anyone to
// rewrite, and the signature check would then be verifying the attacker's file
// against the attacker's signature.
func TestPlainHTTPIsRefused(t *testing.T) {
	c := &Client{BaseURL: "http://example.invalid", PublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize)}
	_, err := c.Fetch(t.TempDir(), "linux-amd64", "latest")
	if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("plain HTTP was not refused: %v", err)
	}
}

func TestChecksumOfAcceptsBothManifestForms(t *testing.T) {
	m := []byte("aaa  plain.tar.gz\nbbb *binary.tar.gz\n")
	if got, _ := checksumOf(m, "plain.tar.gz"); got != "aaa" {
		t.Errorf("plain form: got %q", got)
	}
	if got, _ := checksumOf(m, "binary.tar.gz"); got != "bbb" {
		t.Errorf("binary form: got %q", got)
	}
	if _, err := checksumOf(m, "absent.tar.gz"); err == nil {
		t.Error("a file absent from the manifest was accepted")
	}
}

// "latest" is a request, not an answer. An upgrade that records it as the
// installed version leaves a machine that cannot say which release it runs, and
// so cannot be told whether it has a given fix.
func TestTheVersionRecordedIsTheOneThatArrived(t *testing.T) {
	f := buildRelease(t, goodRelease())
	url := f.serve(t)

	rel, err := f.client(url).Fetch(t.TempDir(), "linux-amd64", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "v9.9.9" {
		t.Errorf("Version = %q, want v9.9.9 — the tag asked for was recorded instead of the one in the archive", rel.Version)
	}
}

// The first two releases predate the VERSION file. Saying "latest" is worse
// than saying the tag, and inventing one would be worse than both.
func TestAReleaseWithoutAVersionFileFallsBackToTheRefAsked(t *testing.T) {
	e := goodRelease()
	delete(e, "holistic/VERSION")
	f := buildRelease(t, e)
	url := f.serve(t)

	rel, err := f.client(url).Fetch(t.TempDir(), "linux-amd64", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "latest" {
		t.Errorf("Version = %q, want the requested ref back", rel.Version)
	}
}

// The check that would have caught five upgrades that changed nothing.
func TestStrayUnitsNamesWhatActuallyRuns(t *testing.T) {
	active := map[string]bool{"a.service": true, "b.service": true, "off.service": false}
	exec := map[string]string{
		"a.service":   "/opt/holistic/bin/a",
		"b.service":   "/opt/corex/bin/b",
		"off.service": "/opt/corex/bin/off",
	}
	restore := stubUnits(active, exec)
	defer restore()

	got, err := StrayUnits([]string{"a.service", "b.service", "off.service"}, "/opt/holistic/bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("wanted one stray, got %d: %+v", len(got), got)
	}
	if got[0].Unit != "b.service" || got[0].Runs != "/opt/corex/bin/b" {
		t.Errorf("the stray is reported as %+v", got[0])
	}
	// An inactive unit was not restarted either, so it is making no false
	// claim and must not be reported as one.
	for _, s := range got {
		if s.Unit == "off.service" {
			t.Error("a unit that is not running was reported as a stray")
		}
	}
}

// A unit whose ExecStart cannot be read is reported, not passed over. A check
// that can answer "all clear" because it could not read is not a check.
func TestAnUnreadableUnitIsNotAPass(t *testing.T) {
	restore := stubUnits(map[string]bool{"a.service": true}, map[string]string{})
	defer restore()
	got, err := StrayUnits([]string{"a.service"}, "/opt/holistic/bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("an unreadable unit produced %d strays", len(got))
	}
	if !strings.Contains(got[0].Runs, "could not be read") {
		t.Errorf("it does not say the unit could not be read: %q", got[0].Runs)
	}
}

// A trailing separator or a relative form of the same directory is the same
// directory, and reporting it as a stray would make the check cry wolf until
// somebody switches it off.
func TestTheSameDirectoryWrittenDifferentlyIsNotAStray(t *testing.T) {
	restore := stubUnits(
		map[string]bool{"a.service": true},
		map[string]string{"a.service": "/opt/holistic/bin/a"})
	defer restore()
	for _, dir := range []string{"/opt/holistic/bin", "/opt/holistic/bin/", "/opt/holistic/./bin"} {
		got, err := StrayUnits([]string{"a.service"}, dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("%q was read as a different directory", dir)
		}
	}
}

// The message has to read as a failure, not as a note beside a success.
func TestTheStrayMessageSaysNothingChanged(t *testing.T) {
	msg := StrayMessage([]Stray{{Unit: "corex-api.service", Runs: "/opt/corex/bin/corex-api"}},
		"/opt/holistic/bin", "v0.2.5")
	for _, want := range []string{"corex-api.service", "/opt/corex/bin/corex-api", "Nothing about this instance changed"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not contain %q:\n%s", want, msg)
		}
	}
}

// stubUnits replaces the two calls to the service manager, so every branch of
// the check runs without one.
func stubUnits(active map[string]bool, execs map[string]string) func() {
	oldExec, oldActive := unitExec, isActive
	unitExec = func(u string) (string, error) {
		p, ok := execs[u]
		if !ok {
			return "", errors.New("no such unit")
		}
		return p, nil
	}
	isActive = func(u string) bool { return active[u] }
	return func() { unitExec, isActive = oldExec, oldActive }
}

// Upgrade replaced binaries and left the static files, so an instance that was
// upgraded rather than reinstalled served the front end it had on the day it
// was installed. Same defect as a unit running a binary from elsewhere, one
// layer up.
func TestSwapAssetsReplacesTheWholeDirectory(t *testing.T) {
	dir := t.TempDir()
	relDir := filepath.Join(dir, "rel")
	if err := os.MkdirAll(filepath.Join(relDir, "holistic", "web", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(relDir, "holistic", "web", "index.html"), "new")
	write(filepath.Join(relDir, "holistic", "web", "assets", "app-new.js"), "new js")

	dest := filepath.Join(dir, "opt", "web")
	write(filepath.Join(dest, "index.html"), "old")
	write(filepath.Join(dest, "assets", "app-old.js"), "old js")

	swapped, err := SwapAssets(&Release{Dir: relDir}, dest, "web")
	if err != nil {
		t.Fatal(err)
	}
	if !swapped {
		t.Fatal("it reported that nothing was replaced")
	}
	got, err := os.ReadFile(filepath.Join(dest, "index.html"))
	if err != nil || string(got) != "new" {
		t.Errorf("index.html is %q (%v)", got, err)
	}
	// The whole directory, not a merge. A hashed asset left behind from an
	// older build is a file nothing references and a mystery to whoever finds
	// it next; worse, an index that still points at one is a page that half
	// loads.
	if _, err := os.Stat(filepath.Join(dest, "assets", "app-old.js")); err == nil {
		t.Error("a file from the previous build survived the replacement")
	}
	if _, err := os.Stat(filepath.Join(dest, "assets", "app-new.js")); err != nil {
		t.Errorf("the new build's asset is not there: %v", err)
	}
	// Nothing is left lying beside it.
	for _, leftover := range []string{dest + ".incoming", dest + ".previous"} {
		if _, err := os.Stat(leftover); err == nil {
			t.Errorf("%s was left behind", leftover)
		}
	}
}

// A release that does not carry the directory leaves what is there. Removing
// it would empty the front end of an instance that is downgrading.
func TestSwapAssetsLeavesWhatAReleaseDoesNotCarry(t *testing.T) {
	dir := t.TempDir()
	relDir := filepath.Join(dir, "rel")
	if err := os.MkdirAll(filepath.Join(relDir, "holistic"), 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "opt", "web")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "index.html"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	swapped, err := SwapAssets(&Release{Dir: relDir}, dest, "web")
	if err != nil {
		t.Fatal(err)
	}
	if swapped {
		t.Error("it reported replacing a directory the release does not carry")
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "index.html")); string(got) != "old" {
		t.Errorf("it changed what was there: %q", got)
	}
}
