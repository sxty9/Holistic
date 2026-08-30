package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sxty9/Holistic/internal/release"
)

// A sealed instance opened again: a code exists before the listener does, the
// seal is gone, and the unit is enabled rather than merely started.
func TestReopeningSetupMintsACodeBeforeItOpensTheDoor(t *testing.T) {
	conf := t.TempDir()
	if err := os.WriteFile(filepath.Join(conf, "claimed"), []byte("sealed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var calls []string
	code, err := reopenSetup(conf, func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		// By the time the listener is asked for, the way in must already exist.
		if _, err := os.Stat(filepath.Join(conf, "setup.claim")); err != nil {
			t.Errorf("the unit was started with no setup code on disk: %v", err)
		}
		if release.Claimed(conf) {
			t.Error("the unit was started while the seal was still there; " +
				"ConditionPathExists would have refused it and we would have reported success")
		}
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(code) < 16 {
		t.Errorf("the code is too short to be worth anything: %q", code)
	}
	on, err := os.ReadFile(filepath.Join(conf, "setup.claim"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(on)) != code {
		t.Errorf("the code printed is not the code on disk: %q vs %q", code, strings.TrimSpace(string(on)))
	}
	if fi, err := os.Stat(filepath.Join(conf, "setup.claim")); err == nil && fi.Mode().Perm() != 0o640 {
		t.Errorf("the setup code is %v, not 0640", fi.Mode().Perm())
	}
	if release.Claimed(conf) {
		t.Error("the instance is still recorded as claimed")
	}
	want := "systemctl enable --now " + setupUnit
	if len(calls) != 1 || calls[0] != want {
		t.Errorf("systemctl calls = %v, want exactly [%q]. `start` alone would not survive a reboot, "+
			"which is the one property the seal had", calls, want)
	}
}

// If the unit will not come up, the operator is left unclaimed with a code and
// has to be told so — otherwise they read a failure and assume nothing changed.
func TestAFailedListenerSaysTheInstanceIsAlreadyUnclaimed(t *testing.T) {
	conf := t.TempDir()
	if err := os.WriteFile(filepath.Join(conf, "claimed"), []byte("sealed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := reopenSetup(conf, func(string, ...string) (string, error) {
		return "Unit holistic-setup.service not found.", os.ErrNotExist
	})
	if err == nil {
		t.Fatal("a dead unit was reported as a successful reopen")
	}
	if !strings.Contains(err.Error(), "unclaimed") {
		t.Errorf("the failure does not say the seal is already gone: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("systemctl's own words were dropped, and they are the only place the reason is: %v", err)
	}
}

// The reopen is a door: it does not get to open on a stdin that happens to
// carry a "y". cmdSetup refuses an unclaimed instance outright, which is the
// one branch reachable without root.
func TestReopeningAnInstanceThatWasNeverSealedIsRefused(t *testing.T) {
	conf := t.TempDir()
	if _, err := reopenSetup(conf, func(string, ...string) (string, error) {
		t.Error("the listener was touched for an instance with no seal")
		return "", nil
	}); err == nil {
		t.Fatal("removing a seal that does not exist was reported as a reopen")
	}
	if _, err := os.Stat(filepath.Join(conf, "setup.claim")); err == nil {
		t.Error("a setup code was left behind by a reopen that failed")
	}
}
