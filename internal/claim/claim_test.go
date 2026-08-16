package claim

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mintIn(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "setup.claim")
	code, err := Mint(path)
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	return code, path
}

func TestTheCodeIsNotGuessable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		code, _ := mintIn(t)
		if seen[code] {
			t.Fatal("two mints produced the same code")
		}
		seen[code] = true
		if n := len(Normalise(code)); n < 24 {
			t.Fatalf("code carries too little entropy to type-guard: %d characters", n)
		}
	}
}

// The file is created restrictive from the start rather than chmod'd
// afterwards. Between an open and a chmod there is a window, and a secret is
// exactly the thing that gets read during it.
func TestTheCodeIsNotWorldReadable(t *testing.T) {
	_, path := mintIn(t)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode&0o007 != 0 {
		t.Errorf("the setup code is readable by every account on the machine: %o", mode)
	}
	if mode := st.Mode().Perm(); mode&0o020 != 0 {
		t.Errorf("the setup code is writable by its group, so the service could reissue it: %o", mode)
	}
}

// Separators and case are presentation. A person copying a code out of a
// terminal should not be told they got it wrong because of a capital letter.
func TestTypingIsForgivingWithoutBeingLoose(t *testing.T) {
	code, path := mintIn(t)
	for _, variant := range []string{
		code,
		strings.ToUpper(code),
		strings.ReplaceAll(code, "-", ""),
		strings.ReplaceAll(code, "-", " "),
		"  " + code + "\n",
	} {
		g, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := g.Redeem(variant); err != nil {
			t.Errorf("a correct code typed as %q was rejected: %v", variant, err)
		}
	}
	// Being forgiving about layout must not make it forgiving about content.
	g, _ := Load(path)
	wrong := Normalise(code)
	wrong = wrong[:len(wrong)-1] + string(rune(wrong[len(wrong)-1])+1)
	if err := g.Redeem(wrong); !errors.Is(err, ErrWrongCode) {
		t.Errorf("a code differing by one character was accepted: %v", err)
	}
}

// A correct code works exactly once. What the caller gets is a session; the
// code stops working immediately, so one left in a scrollback or seen over a
// shoulder is worth nothing by the time it is read.
func TestACodeIsSpentWhenItIsUsed(t *testing.T) {
	code, path := mintIn(t)
	g, _ := Load(path)
	if err := g.Redeem(code); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	if err := g.Redeem(code); !errors.Is(err, ErrAlreadyRun) {
		t.Errorf("the same code was accepted twice: %v", err)
	}
}

// Portainer shipped a five-minute unauthenticated window and it became
// CVE-2026-55761: the window was the vulnerability, and every restart re-armed
// it. A guessing attacker gets a small, fixed number of tries and then nothing,
// and no restart of the browser or the page changes that.
func TestGuessingStopsBeingPossible(t *testing.T) {
	code, path := mintIn(t)
	g, _ := Load(path)
	for i := 0; i < MaxAttempts; i++ {
		if err := g.Redeem("aaaaa-bbbbb-ccccc-ddddd-eeeee"); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := g.Redeem("aaaaa"); !errors.Is(err, ErrLockedOut) {
		t.Errorf("guessing was still possible after %d attempts: %v", MaxAttempts, err)
	}
	// And the lockout is not a way to get a free pass with the real code.
	if err := g.Redeem(code); !errors.Is(err, ErrLockedOut) {
		t.Error("the correct code was accepted after the guard had locked out")
	}
	if g.Attempts() != MaxAttempts {
		t.Errorf("the owner is shown %d failed attempts, expected %d", g.Attempts(), MaxAttempts)
	}
}

// An instance left unattended must not stay claimable indefinitely.
func TestTheCodeExpires(t *testing.T) {
	code, _ := mintIn(t)
	g := New(code, time.Now().Add(-Lifetime-time.Minute))
	if err := g.Redeem(code); !errors.Is(err, ErrExpired) {
		t.Errorf("an hours-old code was still accepted: %v", err)
	}
}

// A missing file is a specific, actionable state — not a generic read error and
// certainly not "no code required".
func TestNoCodeIsNotAnOpenDoor(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, ErrNoCode) {
		t.Errorf("a missing setup code reported as %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(empty); !errors.Is(err, ErrNoCode) {
		t.Errorf("an empty setup code file reported as %v", err)
	}
}

// Destroy is idempotent, because completing setup twice — a retry, a crash
// midway — must not turn into an error the operator has to interpret.
func TestDestroyIsIdempotent(t *testing.T) {
	_, path := mintIn(t)
	for i := 0; i < 3; i++ {
		if err := Destroy(path); err != nil {
			t.Fatalf("destroy %d: %v", i, err)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("the code is still on disk after being destroyed")
	}
}
