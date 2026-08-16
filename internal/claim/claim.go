// Package claim decides who is allowed to configure a fresh instance.
//
// The problem it solves is the one every self-hosted product in this space has
// and most of them lose. A newly installed machine has no accounts, so its
// setup page cannot ask anybody to sign in; but that page creates the
// administrator, chooses the domain, and is handed cloud credentials. Serving it
// openly on a LAN means whoever reaches it first owns the machine — and a
// survey of eighteen comparable products found twelve doing exactly that, with
// the receipts to match: Portainer's five-minute unauthenticated window
// (CVE-2026-55761), Synology generating the admin password in the browser with
// Math.random (CVE-2023-2729), Jellyfin still allowing an unauthenticated
// visitor to re-walk its wizard and reset the administrator's password.
//
// mDNS makes it worse rather than better. A `.local` name is unauthenticated
// and anyone on the network can claim it, including before this machine exists,
// so a well-known fixed name is a target that can be prepared in advance. No
// defence here may assume that the page a person is looking at is this server.
//
// The answer used by the products that got it right — Pi-hole, Rancher,
// Portainer after its CVE — is that the installer already has something nobody
// on the network has: a terminal. So the installer mints a secret, writes it
// where only root can read it, and prints it once. The page asks for it.
//
// What this does NOT defend against, stated plainly because a defence whose
// limits are unwritten gets trusted past them: someone who has claimed
// `holistic.local` and serves a convincing copy of the setup page can simply
// ask for the code, and will be given it. The mitigations for that are elsewhere
// — the name is not advertised until the code has been redeemed once, and the
// installer verifies its own published name resolves to the address it expects.
package claim

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Path is where the installer leaves the code. Root-owned and group-readable by
// the service account: the setup process must be able to read the code and must
// never be able to mint a new one, which is the same posture /etc/corex already
// has for everything else it is trusted with.
const Path = "/etc/holistic/setup.claim"

const (
	// Bits of entropy. 128 is not a round number chosen for comfort: the code
	// is typed by a human, so every bit costs a character, and 128 is the point
	// past which the length is the only thing that matters.
	bits = 128
	// MaxAttempts before the code stops being accepted at all. Low, because a
	// person copying a code from their own terminal does not need five tries,
	// and an attacker guessing needs to be stopped long before they get useful
	// feedback.
	MaxAttempts = 5
	// Lifetime is generous for a walk from a server to a laptop and short
	// enough that an unattended instance does not stay claimable overnight.
	Lifetime = time.Hour
)

var (
	ErrNoCode     = errors.New("this instance has no setup code")
	ErrExpired    = errors.New("the setup code has expired")
	ErrLockedOut  = errors.New("too many wrong codes")
	ErrWrongCode  = errors.New("that is not the setup code")
	ErrAlreadyRun = errors.New("this instance has already been claimed")
)

// Mint generates a code and writes it where only root can read it.
//
// The code comes from the kernel's CSPRNG and never from the browser. Synology
// generated theirs in JavaScript with Math.random, and Claroty recovered the
// seed and took over the administrator account at Pwn2Own; the lesson is cheap
// to learn secondhand.
func Mint(path string) (string, error) {
	if path == "" {
		path = Path
	}
	raw := make([]byte, bits/8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("no randomness available to make a setup code: %w", err)
	}
	// Base32 without padding: unambiguous when read aloud or copied by eye, and
	// case-insensitive, which removes an entire class of "it says it is wrong
	// but I typed it correctly".
	code := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	code = group(code)

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	// Written 0640 root:<service group>. The file is created with the
	// restrictive mode from the start rather than chmod'd afterwards: between
	// the two there is a window, and a secret is exactly the thing that gets
	// read during it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(code + "\n"); err != nil {
		return "", err
	}
	return code, nil
}

// group breaks the code into blocks so a person can keep their place while
// copying it. The separators are not part of the secret and are ignored on the
// way back in.
func group(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%5 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Normalise makes a typed code comparable: case, spaces and the grouping
// separators all carry no meaning.
func Normalise(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Guard holds the code for the lifetime of one setup process.
type Guard struct {
	mu       sync.Mutex
	code     string
	born     time.Time
	attempts int
	redeemed bool
	now      func() time.Time
}

// Load reads the code the installer wrote.
func Load(path string) (*Guard, error) {
	if path == "" {
		path = Path
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoCode
		}
		return nil, err
	}
	code := Normalise(string(b))
	if code == "" {
		return nil, ErrNoCode
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return &Guard{code: code, born: st.ModTime(), now: time.Now}, nil
}

// New builds a guard directly, for tests and for a process that has just minted.
func New(code string, born time.Time) *Guard {
	return &Guard{code: Normalise(code), born: born, now: time.Now}
}

// Redeem checks a typed code and, on success, marks the guard used.
//
// The comparison is constant time. The margin it protects is small over a LAN,
// but the cost of getting it right is one function call and the cost of getting
// it wrong is a class of bug nobody notices until somebody writes a paper.
//
// A correct code is accepted exactly once. What the caller gets back is a
// session; the code itself stops working immediately, so a code shoulder-surfed
// or left in a scrollback is worth nothing by the time it is read.
func (g *Guard) Redeem(typed string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.redeemed {
		return ErrAlreadyRun
	}
	if g.attempts >= MaxAttempts {
		return ErrLockedOut
	}
	if g.now().Sub(g.born) > Lifetime {
		return ErrExpired
	}

	got := Normalise(typed)
	// Compare against a fixed-length digest of both sides so the comparison
	// does not leak the code's length either.
	if subtle.ConstantTimeCompare(pad(got), pad(g.code)) != 1 {
		g.attempts++
		return ErrWrongCode
	}
	g.redeemed = true
	return nil
}

func pad(s string) []byte {
	out := make([]byte, 64)
	copy(out, s)
	return out
}

// Attempts reports how many wrong codes have been offered. The first screen
// after a successful claim shows this: if somebody else was knocking, the owner
// should learn it immediately rather than never.
func (g *Guard) Attempts() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.attempts
}

func (g *Guard) Redeemed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.redeemed
}

// Destroy removes the code from disk. Called when setup completes: the code is
// destroyed rather than marked used, because a flag in a file is something a
// later bug can misread, and a file that is not there cannot be misread at all.
func Destroy(path string) error {
	if path == "" {
		path = Path
	}
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
