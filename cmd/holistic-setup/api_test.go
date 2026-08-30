package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sxty9/Holistic/internal/claim"
	"github.com/sxty9/Holistic/internal/steps"
	"os"
	"time"
)

// inertMachine is the only Machine these tests ever hand the engine. Nothing
// here starts, stops or restarts anything: this suite runs on a developer's own
// workstation and on whatever builds it, and a test that bounces a unit is a
// test that has already gone wrong by the time it fails.
type inertMachine struct{}

func (inertMachine) Restart(string) error                  { return nil }
func (inertMachine) EnableNow(string) error                { return nil }
func (inertMachine) IsActive(string) bool                  { return true }
func (inertMachine) IsEnabled(string) bool                 { return true }
func (inertMachine) Run(string, ...string) (string, error) { return "", nil }

func testPaths(t *testing.T) steps.Paths {
	t.Helper()
	d := t.TempDir()
	p := steps.DefaultPaths()
	p.CoreXConfig = filepath.Join(d, "corex", "config.json")
	p.CoreXEnv = filepath.Join(d, "corex", "corex.env")
	p.SolisuiteConfig = filepath.Join(d, "solisuite", "config.json")
	p.SolisuiteEnv = filepath.Join(d, "solisuite", "solisuite.env")
	p.WarpgateConfig = filepath.Join(d, "warpgate", "config.json")
	p.WarpgateIngress = filepath.Join(d, "warpgate", "ingress.json")
	p.WarpgateToken = filepath.Join(d, "warpgate", "cloudflare.token")
	p.DataDir = filepath.Join(d, "data")
	p.Corexctl = "corexctl-that-is-never-executed"
	return p
}

// claimedAPI is a server that has been claimed, with a cookie that opens it.
func claimedAPI(t *testing.T) (http.Handler, *http.Cookie) {
	t.Helper()
	p := tmp(t)
	code, err := claim.Mint(p.claim)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServerWith(p.claim, p.ledger, p.seal, testPaths(t), inertMachine{},
		func(context.Context, string) (steps.Response, error) {
			return steps.Response{Status: 200}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	h := s.routes()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("POST", "/claim/", "code="+code))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("could not claim: %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "holistic_setup" {
			return h, c
		}
	}
	t.Fatal("claiming issued no session")
	return nil, nil
}

func call(t *testing.T, h http.Handler, cookie *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := req(method, path, "")
	if body != "" {
		r = httptest.NewRequest(method, "http://holistic.local"+path, strings.NewReader(body))
		r.RemoteAddr = "192.168.178.42:50000"
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// The rule the contract states and this is the enforcement of it: a `secret` is
// submitted and never returned, not even masked. A masked secret in a JSON
// response is still a secret in a browser's memory, in a proxy log, and in
// whatever the page later serialises — and this page is served over plain HTTP
// on a name anyone on the network can claim.
func TestASubmittedSecretNeverComesBackOutOfTheState(t *testing.T) {
	h, cookie := claimedAPI(t)

	// Fixed rather than random, so that the substring sweep below is
	// deterministic and a failure is reproducible.
	const token = "cf-Zq7Z4mR2xLp9vT1nB8kW6yH3jD5sG0aEQhVuJcRt"

	w := call(t, h, cookie, "POST", "/api/answer/token-verify", `{"value":`+quoteJSON(token)+`}`)
	if w.Code != http.StatusOK {
		t.Fatalf("the token was not accepted: %d %s", w.Code, w.Body)
	}
	seen := map[string]string{"the answer's own response": whole(w)}

	state := call(t, h, cookie, "GET", "/api/state/", "")
	if state.Code != http.StatusOK {
		t.Fatalf("state: %d", state.Code)
	}
	seen["GET /api/state"] = whole(state)

	// And after the step that holds it has been run, which is the moment a
	// step is most tempted to report what it was given.
	seen["the run response"] = whole(call(t, h, cookie, "POST", "/api/step/token-verify/run", ""))
	seen["GET /api/state after running it"] = whole(call(t, h, cookie, "GET", "/api/state/", ""))

	for where, response := range seen {
		if strings.Contains(response, token) {
			t.Errorf("%s contains the token verbatim", where)
			continue
		}
		// Not just the whole thing. A masked or truncated secret is still the
		// secret, and it is the half that gets shipped by accident.
		for i := 0; i+10 <= len(token); i++ {
			if frag := token[i : i+10]; strings.Contains(response, frag) {
				t.Errorf("%s contains %q, a fragment of the token", where, frag)
				break
			}
		}
	}

	// The need still asks for it, and still carries no value.
	var env steps.Envelope
	if err := json.Unmarshal(state.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	for _, row := range env.Steps {
		if row.Needs == nil {
			continue
		}
		if row.Needs.Kind == "secret" && row.Needs.Value != "" {
			t.Errorf("%s asks for a secret and hands one back: %q", row.ID, row.Needs.Value)
		}
	}
}

// The envelope the pages were built against, checked as a wire shape rather
// than as a Go type. The two halves of this were built by different hands; a
// field renamed on this side is a page that renders nothing on the other.
func TestTheStateEnvelopeIsTheShapeTheContractFixes(t *testing.T) {
	h, cookie := claimedAPI(t)
	w := call(t, h, cookie, "GET", "/api/state/", "")
	if w.Code != http.StatusOK {
		t.Fatalf("state: %d", w.Code)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"readAt", "sealed", "domain", "steps", "resources", "refused"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("the envelope has no %q", key)
		}
	}

	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(raw["steps"], &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("the wizard has no steps")
	}
	for _, key := range []string{"id", "title", "kind", "status", "detail", "proof", "at", "desired"} {
		if _, ok := rows[0][key]; !ok {
			t.Errorf("a step row has no %q — detail, proof and at are present even when empty, "+
				"so a page does not need two code paths for the same row", key)
		}
	}

	var env steps.Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	kinds := map[steps.Kind]int{}
	for _, row := range env.Steps {
		kinds[row.Kind]++
	}
	// Every kind in the contract's table is represented, which is the check
	// that the wizard describes the whole job rather than only the half that is
	// written.
	for _, k := range []steps.Kind{steps.Local, steps.Shell, steps.Foreign, steps.Theirs} {
		if kinds[k] == 0 {
			t.Errorf("no step of kind %q, so the page cannot tell who has to act", k)
		}
	}
}

func TestTheActionRoutesAreBehindTheSession(t *testing.T) {
	h, _ := claimedAPI(t)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/state/", ""},
		{"POST", "/api/step/domain/run", ""},
		{"POST", "/api/step/domain/skip", `{"reason":"later"}`},
		{"POST", "/api/answer/domain", `{"value":"example.org"}`},
	} {
		w := call(t, h, nil, c.method, c.path, c.body)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d without a session", c.method, c.path, w.Code)
		}
	}
}

// A wrong request is a 4xx; a step that failed, conflicted or is still waiting
// is a 200 carrying an envelope that says so. Those are different things and
// collapsing them costs the page the ability to tell a bug from a fact.
func TestWrongRequestsAreRefusedAndOutcomesAreNot(t *testing.T) {
	h, cookie := claimedAPI(t)

	if w := call(t, h, cookie, "POST", "/api/step/not-a-step/run", ""); w.Code != http.StatusNotFound {
		t.Errorf("an unknown step ran: %d", w.Code)
	}
	if w := call(t, h, cookie, "POST", "/api/step/domain/skip", `{"reason":"  "}`); w.Code != http.StatusBadRequest {
		t.Errorf("a step was skipped with no reason: %d", w.Code)
	}
	if w := call(t, h, cookie, "POST", "/api/answer/domain", `{"value":"https://example.org/setup"}`); w.Code != http.StatusBadRequest {
		t.Errorf("a URL was accepted as a domain: %d", w.Code)
	}
	if w := call(t, h, cookie, "POST", "/api/answer/token-store", `{"value":"anything"}`); w.Code != http.StatusBadRequest {
		t.Errorf("a step that asks for nothing accepted an answer: %d", w.Code)
	}

	// A step that cannot run yet is not an error.
	w := call(t, h, cookie, "POST", "/api/step/domain/run", "")
	if w.Code != http.StatusOK {
		t.Fatalf("a step that is waiting to be told something returned %d", w.Code)
	}
	var env steps.Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	for _, row := range env.Steps {
		if row.ID == "domain" && row.Status != "pending" {
			t.Errorf("a step with nothing to work from is %q", row.Status)
		}
	}
}

// There is never a way past a conflict from inside the page. The point is not
// to get past the obstacle; it is to leave the operator's own things alone.
func TestThereIsNoRouteThatOverridesAConflict(t *testing.T) {
	h, cookie := claimedAPI(t)
	for _, path := range []string{
		"/api/step/apps/force",
		"/api/step/apps/override",
		"/api/step/apps/resolve",
		"/api/conflict/apps/clear",
		"/api/state/force",
	} {
		if w := call(t, h, cookie, "POST", path, ""); w.Code != http.StatusNotFound {
			t.Errorf("POST %s answered %d — there is a way past a conflict", path, w.Code)
		}
	}
}

// The wizard is driven end to end over its own routes, so that the engine's
// tests are not the only thing that has ever exercised it.
func TestTheWizardCanBeDrivenOverItsOwnRoutes(t *testing.T) {
	h, cookie := claimedAPI(t)

	if w := call(t, h, cookie, "POST", "/api/answer/domain", `{"value":"example.org"}`); w.Code != http.StatusOK {
		t.Fatalf("answer: %d %s", w.Code, w.Body)
	}
	w := call(t, h, cookie, "POST", "/api/step/domain/run", "")
	if w.Code != http.StatusOK {
		t.Fatalf("run: %d %s", w.Code, w.Body)
	}
	var env steps.Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Domain != "example.org" {
		t.Errorf("the envelope does not carry the domain: %q", env.Domain)
	}
	for _, row := range env.Steps {
		if row.ID == "domain" {
			if row.Status != "passed" {
				t.Fatalf("domain: %s — %s", row.Status, row.Detail)
			}
			if !strings.Contains(row.Proof, "Nothing was contacted") {
				t.Errorf("the domain step does not say it observed nothing: %q", row.Proof)
			}
		}
	}

	if w := call(t, h, cookie, "POST", "/api/step/engines/skip", `{"reason":"no AI on this machine"}`); w.Code != http.StatusOK {
		t.Fatalf("skip: %d %s", w.Code, w.Body)
	}
	w = call(t, h, cookie, "GET", "/api/state/", "")
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	for _, row := range env.Steps {
		if row.ID == "engines" && (row.Status != "skipped" || row.Detail != "no AI on this machine") {
			t.Errorf("the skip did not survive: %s %q", row.Status, row.Detail)
		}
	}
}

// whole is the entire response — status line, every header, and the body.
//
// Checking only the body is not enough, and that is not a hypothetical: the
// first version of this test watched the body alone, an echo was added to a
// response header to see the test bite, and the test stayed green. A secret in a
// header is a secret in every proxy log between here and the browser, which is
// one of the three places the contract says a secret must never reach.
func whole(w *httptest.ResponseRecorder) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d\n", w.Code)
	for name, values := range w.Result().Header {
		for _, v := range values {
			fmt.Fprintf(&b, "%s: %s\n", name, v)
		}
	}
	b.WriteString(w.Body.String())
	return b.String()
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// An instance with a spent code and no seal must stay up.
//
// Redeeming a code destroys it — correct, a spent code lying in /etc is a second
// key to an open door — but the seal is only written when setup FINISHES. In
// between, the instance is claimed and unsealed, which is the normal state for
// as long as setup takes, and two of its steps wait on a registrar.
//
// newServer used to return an error there, so systemd restarted the daemon into
// a loop: 398 restarts on the machine this was found on, the LAN listener gone,
// and the only explanation in a journal nobody was reading.
func TestAnInstanceWithNoCodeAndNoSealStaysUp(t *testing.T) {
	dir := t.TempDir()
	srv, err := newServer(
		filepath.Join(dir, "setup.claim"), // never created: the code was spent
		filepath.Join(dir, "provisioned.json"),
		filepath.Join(dir, "claimed"), // never created: setup did not finish
	)
	if err != nil {
		t.Fatalf("the daemon refused to start on a claimed, unsealed instance: %v", err)
	}
	if !srv.needsCode {
		t.Fatal("it started, but does not know it has no code")
	}

	h := srv.routes()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "192.168.178.98"
	req.RemoteAddr = "192.168.178.20:5000"
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("GET / answered %d, want 200 — the operator gets no explanation", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "holistic code") {
		t.Error("the page does not name the command that gets back in")
	}

	// The gate must not be offered: a form with nothing behind it is worse than
	// no form.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/claim/", nil)
	req.Host = "192.168.178.98"
	req.RemoteAddr = "192.168.178.20:5000"
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("POST /claim/ answered %d, want 404 — it cannot work and should not exist", rec.Code)
	}
}

// An expired code is not a probe, and the journal has to say which refusal it
// was.
//
// Both had one line — "wrong setup code offered by …" — and one counter. So an
// operator who took longer than an hour saw their own attempt reported back to
// them on the first screen as somebody trying to claim their machine, and
// anybody reading the journal went looking for an intruder who was the person
// holding the terminal.
func TestAnExpiredCodeIsNotCountedAsAProbe(t *testing.T) {
	dir := t.TempDir()
	claimAt := filepath.Join(dir, "setup.claim")
	code, err := claim.Mint(claimAt)
	if err != nil {
		t.Fatal(err)
	}
	// Age the file past the lifetime. Load takes `born` from its mtime, which
	// is what makes a code outlive the process that minted it — and what makes
	// this reachable without waiting an hour.
	old := time.Now().Add(-claim.Lifetime - time.Minute)
	if err := os.Chtimes(claimAt, old, old); err != nil {
		t.Fatal(err)
	}

	srv, err := newServer(claimAt, filepath.Join(dir, "provisioned.json"), filepath.Join(dir, "claimed"))
	if err != nil {
		t.Fatal(err)
	}
	h := srv.routes()

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/claim/", strings.NewReader("code="+code))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "192.168.178.98"
	r.RemoteAddr = "192.168.178.42:50000"
	h.ServeHTTP(rec, r)

	if rec.Code == http.StatusSeeOther {
		t.Fatal("an expired code was accepted")
	}
	if n := len(srv.refusedCount()); n != 0 {
		t.Errorf("an expired code was counted as a probe (%d), so the operator's own attempt "+
			"appears on their first screen as somebody else's", n)
	}

	// A genuinely wrong one still counts — and it needs a guard that is not
	// already expired, because the lifetime is checked before the code is.
	// Reusing the aged one above would have tested nothing: every attempt
	// against it is expired, including a deliberately wrong one.
	fresh := t.TempDir()
	freshClaim := filepath.Join(fresh, "setup.claim")
	if _, err := claim.Mint(freshClaim); err != nil {
		t.Fatal(err)
	}
	srv2, err := newServer(freshClaim, filepath.Join(fresh, "provisioned.json"), filepath.Join(fresh, "claimed"))
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/claim/", strings.NewReader("code=not-the-code"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "192.168.178.98"
	r.RemoteAddr = "192.168.178.99:50000"
	srv2.routes().ServeHTTP(rec, r)
	if n := len(srv2.refusedCount()); n != 1 {
		t.Errorf("a wrong code was counted %d times, want 1", n)
	}
}
