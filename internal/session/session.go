// Package session holds the setup process's own idea of who is at the keyboard.
//
// This is deliberately not a coreX session, and the reason is a sequencing
// problem rather than a preference. Partway through the hand-off, setup writes
// the instance's real domain into coreX's configuration, flips
// auth.insecureCookies to false, and restarts corex-api. Any coreX cookie the
// setup page were holding would die at that instant — and a cookie scoped to
// the new domain and marked Secure is neither sent to nor accepted by
// http://holistic.local. The wizard would sign the operator out of the very
// thing performing the installation, halfway through, over plain HTTP.
//
// So the wizard's authority is the setup code and nothing else, and its session
// is disjoint from every session the instance itself will ever issue.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// Name is the cookie. No __Host- prefix and no Secure attribute: neither is
// available over plain HTTP on a LAN name, and claiming otherwise in the name
// would be worse than the honest version.
const Name = "holistic_setup"

// Lifetime is long enough to sit through a nameserver change without being
// signed out, and short enough that an abandoned tab does not stay authorised
// overnight.
const Lifetime = 12 * time.Hour

type Store struct {
	mu   sync.Mutex
	live map[string]time.Time
	now  func() time.Time
}

func NewStore() *Store {
	return &Store{live: map[string]time.Time{}, now: time.Now}
}

// Issue mints a session. Called only after the setup code has been redeemed.
func (s *Store) Issue(w http.ResponseWriter) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	s.live[tok] = s.now().Add(Lifetime)
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:  Name,
		Value: tok,
		Path:  "/",
		// Host-only: no Domain attribute. The setup process answers on
		// holistic.local and on a bare address, and a cookie that tried to span
		// them would be a cookie scoped to nothing useful.
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(Lifetime.Seconds()),
	})
	return tok, nil
}

func (s *Store) Valid(r *http.Request) bool {
	c, err := r.Cookie(Name)
	if err != nil || c.Value == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.live[c.Value]
	if !ok {
		return false
	}
	if s.now().After(exp) {
		delete(s.live, c.Value)
		return false
	}
	return true
}

// Clear ends every session. Called when setup seals itself, so the tab that
// performed the installation cannot keep talking to a surface that is about to
// stop existing.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.live = map[string]time.Time{}
}

// Require gates everything the wizard does behind a redeemed setup code.
//
// It is applied to the page as well as to the actions, not only to the final
// "create the administrator" call. Jellyfin guards only the last step, so an
// unauthenticated visitor can walk its wizard from the start and reset the
// administrator's password — reported, and closed as not planned.
func (s *Store) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Valid(r) {
			http.Error(w, "This instance has not been claimed in this browser. "+
				"Enter the setup code printed by the installer.", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
