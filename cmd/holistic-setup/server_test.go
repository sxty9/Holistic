package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sxty9/Holistic/internal/claim"
	"github.com/sxty9/Holistic/internal/lan"
)

type paths struct{ claim, ledger, seal string }

func tmp(t *testing.T) paths {
	t.Helper()
	d := t.TempDir()
	return paths{
		claim:  filepath.Join(d, "setup.claim"),
		ledger: filepath.Join(d, "provisioned.json"),
		seal:   filepath.Join(d, "claimed"),
	}
}

func req(method, path string, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, "http://"+lan.SetupName+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, "http://"+lan.SetupName+path, nil)
	}
	r.RemoteAddr = "192.168.178.42:50000"
	return r
}

// The Immich failure, guarded directly. Immich re-offered administrator
// registration to the whole network whenever its data directory looked empty,
// which happened every time an encrypted disk was not mounted before the
// service started. "I cannot see what has been set up" was read as "nothing has
// been set up yet".
func TestAClaimedInstanceWithAnUnreadableLedgerRefusesToServe(t *testing.T) {
	p := tmp(t)
	if err := os.WriteFile(p.seal, []byte("claimed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.ledger, []byte("{ truncated"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := newServer(p.claim, p.ledger, p.seal)
	if err == nil {
		t.Fatal("a claimed instance with an unreadable ledger started serving anyway")
	}
	if !strings.Contains(err.Error(), "Refusing to serve") {
		t.Errorf("the refusal does not say what it is refusing: %v", err)
	}
	if !strings.Contains(err.Error(), "mount") {
		t.Errorf("the refusal does not name the likely cause, so nobody can fix it: %v", err)
	}
}

// An instance with no setup code cannot prove anybody installed it, so it must
// not fall back to serving the wizard openly.
func TestNoSetupCodeMeansNoSetup(t *testing.T) {
	// This asserted that newServer returned an error — the mechanism, not the
	// guarantee. The guarantee is that the wizard is not reachable without a
	// code, and it still holds; what changed is that the daemon now stays up
	// and says so instead of exiting.
	//
	// Exiting was doing real harm. Redeeming a code destroys it, and the seal
	// is only written when setup finishes, so an instance mid-setup has neither
	// — for as long as setup takes, and two of its steps wait on a registrar.
	// Any restart in that window put the daemon in a loop: 398 restarts on the
	// machine this was found on, with the LAN listener gone.
	p := tmp(t)
	srv, err := newServer(p.claim, p.ledger, p.seal)
	if err != nil {
		t.Fatalf("the daemon refused to start with no code: %v", err)
	}
	if !srv.needsCode {
		t.Fatal("it started without knowing it has no code")
	}

	h := srv.routes()
	for _, probe := range []struct{ method, path string }{
		{"POST", "/claim/"},
		{"GET", "/api/state/"},
		{"POST", "/api/step/domain/run"},
	} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(probe.method, probe.path, nil)
		r.Host = "192.168.178.98"
		r.RemoteAddr = "192.168.178.42:50000"
		h.ServeHTTP(rec, r)
		if rec.Code != 404 {
			t.Errorf("%s %s answered %d with no setup code present, want 404",
				probe.method, probe.path, rec.Code)
		}
	}
}

func claimable(t *testing.T) (*server, paths, string) {
	t.Helper()
	p := tmp(t)
	code, err := claim.Mint(p.claim)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(p.claim, p.ledger, p.seal)
	if err != nil {
		t.Fatal(err)
	}
	return s, p, code
}

// The gate is the page, not a check bolted onto the last step. Jellyfin guards
// only its final action, so an unauthenticated visitor can walk the wizard from
// the beginning and reset the administrator's password.
func TestTheWizardIsNotServedBeforeTheCode(t *testing.T) {
	s, _, _ := claimable(t)
	h := s.routes()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", "/", ""))
	body := w.Body.String()
	if !strings.Contains(body, "not claimed yet") {
		t.Errorf("the first page is not the gate: %s", body)
	}

	// And the data behind it is refused outright rather than rendered empty.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", "/api/state/", ""))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wizard state was readable without claiming: %d", w.Code)
	}
}

func TestARightCodeClaimsAndSpendsItself(t *testing.T) {
	s, p, code := claimable(t)
	h := s.routes()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", "/claim/", "code="+code))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("a correct code was not accepted: %d %s", w.Code, w.Body)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "holistic_setup" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("claiming issued no session")
	}

	// The code is removed from disk, not marked used. One left lying in /etc
	// after a successful claim is a second key to a door that is already open.
	if _, err := os.Stat(p.claim); !os.IsNotExist(err) {
		t.Error("the setup code is still on disk after being redeemed")
	}

	// And the session actually opens the wizard.
	r := req("GET", "/api/state/", "")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("a claimed session could not read the wizard state: %d", w.Code)
	}
}

// If somebody else on the network was trying codes, the owner should learn it
// at the moment they can still do something about it.
func TestWrongCodesAreCountedAndShown(t *testing.T) {
	s, _, code := claimable(t)
	h := s.routes()

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		bad := req("POST", "/claim/", "code=aaaaa-bbbbb-ccccc-ddddd")
		bad.RemoteAddr = "192.168.178.99:41000"
		h.ServeHTTP(w, bad)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("a wrong code returned %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "not the setup code") {
			t.Error("a wrong code was not explained")
		}
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", "/claim/", "code="+code))
	cookie := w.Result().Cookies()[0]

	r := req("GET", "/", "")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	body := w.Body.String()
	if !strings.Contains(body, "2 wrong code") {
		t.Errorf("the owner is not told somebody else was knocking: %s", body)
	}
	if !strings.Contains(body, "192.168.178.99") {
		t.Error("the owner is not told where from")
	}
}

// Once claimed, the setup routes are gone rather than disabled. A flag consulted
// by live code is a flag some later branch can read the wrong way.
func TestASealedInstanceHasNoSetupRoutesAtAll(t *testing.T) {
	p := tmp(t)
	if err := os.WriteFile(p.seal, []byte("claimed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newServer(p.claim, p.ledger, p.seal)
	if err != nil {
		t.Fatal(err)
	}
	h := s.routes()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", "/claim/", "code=anything"))
	if w.Code == http.StatusSeeOther || w.Code == http.StatusOK {
		t.Errorf("a sealed instance still answers /claim: %d", w.Code)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", "/", ""))
	body := w.Body.String()
	if strings.Contains(body, "Setup code") {
		t.Error("a sealed instance still renders the claim form")
	}
	if !strings.Contains(body, "set up") {
		t.Errorf("the status page does not say what it is: %s", body)
	}
	// Not a sign-in form: after the hand-off the session cookie is scoped to the
	// real domain and marked Secure, so a form here could never succeed.
	if strings.Contains(strings.ToLower(body), "password") {
		t.Error("the status page offers a login that could never work")
	}
}

// The pages take a secret and create an administrator. A copy in a shared cache
// or inside somebody else's frame is not a page, it is a hazard.
func TestTheGateIsNeitherCachedNorFramed(t *testing.T) {
	s, _, _ := claimable(t)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req("GET", "/", ""))
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control is %q", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options is %q", got)
	}
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy is %q", got)
	}
}
