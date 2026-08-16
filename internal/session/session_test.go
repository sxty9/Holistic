package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func issued(t *testing.T, s *Store) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	if _, err := s.Issue(w); err != nil {
		t.Fatal(err)
	}
	res := w.Result()
	for _, c := range res.Cookies() {
		if c.Name == Name {
			return c
		}
	}
	t.Fatal("no session cookie was set")
	return nil
}

func TestASessionIsOnlyValidWithItsCookie(t *testing.T) {
	s := NewStore()
	c := issued(t, s)

	with := httptest.NewRequest("GET", "/", nil)
	with.AddCookie(c)
	if !s.Valid(with) {
		t.Error("a freshly issued session was rejected")
	}

	without := httptest.NewRequest("GET", "/", nil)
	if s.Valid(without) {
		t.Error("a request with no cookie was accepted")
	}

	forged := httptest.NewRequest("GET", "/", nil)
	forged.AddCookie(&http.Cookie{Name: Name, Value: "not-a-real-token"})
	if s.Valid(forged) {
		t.Error("an invented token was accepted")
	}
}

// The gate covers the page, not only the final action. Jellyfin guards only its
// last step, so an unauthenticated visitor can walk the wizard from the start
// and reset the administrator's password.
func TestTheGateCoversEverythingNotJustTheLastStep(t *testing.T) {
	s := NewStore()
	reached := false
	h := s.Require(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if reached {
		t.Error("an unclaimed browser reached the wizard")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", w.Code)
	}

	c := issued(t, s)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !reached {
		t.Error("a claimed browser was refused")
	}
}

func TestSessionsExpire(t *testing.T) {
	s := NewStore()
	c := issued(t, s)
	s.now = func() time.Time { return time.Now().Add(Lifetime + time.Minute) }

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	if s.Valid(r) {
		t.Error("an expired session was still accepted")
	}
}

// Sealing setup ends every session: the tab that performed the installation
// must not keep talking to a surface that is about to stop existing.
func TestSealingEndsEverySession(t *testing.T) {
	s := NewStore()
	c := issued(t, s)
	s.Clear()

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	if s.Valid(r) {
		t.Error("a session survived setup being sealed")
	}
}

// Two sessions must not collide, and one being ended must not end the other.
func TestSessionsAreIndependent(t *testing.T) {
	s := NewStore()
	a, b := issued(t, s), issued(t, s)
	if a.Value == b.Value {
		t.Fatal("two sessions were issued the same token")
	}
	for _, c := range []*http.Cookie{a, b} {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(c)
		if !s.Valid(r) {
			t.Error("a valid session was rejected")
		}
	}
}

// The cookie cannot be Secure over plain HTTP, and it should not pretend
// otherwise — but the protections that ARE available over HTTP must be set.
func TestTheCookieUsesWhatItCan(t *testing.T) {
	s := NewStore()
	c := issued(t, s)
	if !c.HttpOnly {
		t.Error("the session cookie is readable by scripts")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("the session cookie is not SameSite=Strict")
	}
	if c.Domain != "" {
		t.Error("the session cookie carries a Domain attribute; it must be host-only")
	}
	if c.Path != "/" {
		t.Errorf("unexpected cookie path %q", c.Path)
	}
}
