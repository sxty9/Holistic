package ledger

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) (*Ledger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provisioned.json")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return l, path
}

// The page's state is a file, so closing the tab while waiting on a registrar
// does not cost an hour of work.
func TestStateSurvivesTheBrowser(t *testing.T) {
	l, path := open(t)
	if err := l.Mark("cloudflare.token", Passed, ""); err != nil {
		t.Fatal(err)
	}
	if err := l.Mark("cloudflare.zone", WaitingOnThem, "nameservers not yet pointing at Cloudflare"); err != nil {
		t.Fatal(err)
	}

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Status("cloudflare.token") != Passed {
		t.Error("a finished step was forgotten")
	}
	if again.Status("cloudflare.zone") != WaitingOnThem {
		t.Error("a step waiting on somebody else came back in the wrong state")
	}
	steps := again.Steps()
	if len(steps) != 2 || steps[0].ID != "cloudflare.token" {
		t.Errorf("rows came back in the wrong order: %+v", steps)
	}
	if steps[1].Detail == "" {
		t.Error("the reason for waiting was lost, which is the only useful part of waiting")
	}
}

// The ordering that the whole package exists for. If a resource were recorded
// after the call, a process that died in between would leave a tunnel or a
// verified identity in somebody's account with nothing on the machine that
// knows it is there.
func TestAnInterruptedCreateIsVisibleAfterwards(t *testing.T) {
	l, path := open(t)
	if err := l.Intend(Resource{Provider: "cloudflare", Kind: "tunnel", Ref: "abc-123"}); err != nil {
		t.Fatal(err)
	}
	// ... and the process dies here, after Cloudflare created the tunnel.

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	un := again.Unconfirmed()
	if len(un) != 1 || un[0].Ref != "abc-123" {
		t.Fatalf("an interrupted create left nothing to find: %+v", un)
	}
	if again.Created("cloudflare", "tunnel", "abc-123") {
		t.Error("an unconfirmed resource was reported as definitely ours")
	}
}

func TestConfirmedResourcesAreOwnershipEvidence(t *testing.T) {
	l, _ := open(t)
	r := Resource{Provider: "cloudflare", Kind: "dns_record", Ref: "rec1"}
	if err := l.Intend(r); err != nil {
		t.Fatal(err)
	}
	if err := l.Confirm(r.Provider, r.Kind, r.Ref); err != nil {
		t.Fatal(err)
	}
	if !l.Created("cloudflare", "dns_record", "rec1") {
		t.Error("a record this machine created is not recognised as its own")
	}
	if l.Created("cloudflare", "dns_record", "somebody-elses") {
		t.Error("a record this machine never touched was claimed")
	}
	if got := l.Unconfirmed(); len(got) != 0 {
		t.Errorf("a confirmed resource is still listed as needing attention: %+v", got)
	}
}

// Confirming something that was never intended means the write-ahead order was
// broken. Dropping it would be the worst response: an unexplained resource is
// still a resource somebody has to clean up.
func TestAnUnrecordedConfirmIsKeptAndFlagged(t *testing.T) {
	l, _ := open(t)
	if err := l.Confirm("aws", "sns_topic", "holistic-bounces"); err != nil {
		t.Fatal(err)
	}
	if !l.Created("aws", "sns_topic", "holistic-bounces") {
		t.Error("the resource was dropped")
	}
}

// A step passed because an API returned 200 and a step passed because a real
// message came back through the whole chain are not the same claim. Only one of
// them would have caught the week where every component reported success and
// inbound mail reached nobody.
func TestProofIsRecordedSeparatelyFromStatus(t *testing.T) {
	l, path := open(t)
	if err := l.Prove("mail.inbound", "message with nonce 4f2a accepted by routedge at 21:04:11"); err != nil {
		t.Fatal(err)
	}
	again, _ := Open(path)
	steps := again.Steps()
	if len(steps) != 1 {
		t.Fatalf("expected one step, got %d", len(steps))
	}
	if steps[0].Status != Passed {
		t.Error("a proven step is not passed")
	}
	if steps[0].Proof == "" {
		t.Error("the observation that proved it was not kept")
	}
}

// A corrupt ledger is not an empty one. Treating "cannot read it" as "nothing
// has happened yet" is how Nextcloud's installer reappeared over live data, and
// how Immich re-offered administrator registration when a disk was not mounted.
func TestACorruptLedgerIsNotAFreshOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provisioned.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("an unreadable ledger was silently treated as a fresh instance")
	}
}

func TestTheLedgerIsNotWorldReadable(t *testing.T) {
	_, path := open(t)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("the ledger is readable beyond its owner: %o", st.Mode().Perm())
	}
}

// The last write must not be able to leave a half-written file: it is what the
// next run reads to decide what already exists in somebody's cloud account.
func TestSaveIsAtomic(t *testing.T) {
	l, path := open(t)
	for i := 0; i < 20; i++ {
		if err := l.Mark("step", Running, "working"); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); err != nil {
			t.Fatalf("the ledger was unreadable mid-write: %v", err)
		}
	}
	if _, err := os.Stat(path + ".incoming"); !os.IsNotExist(err) {
		t.Error("a temporary file was left behind")
	}
}

// A wait that keeps saying "since just now" is the six-hour lie about a
// nameserver change, told in a timestamp instead of a spinner. Mark used to set
// At unconditionally, so every re-check of an unchanged status pushed the
// moment the wait began forward to the present.
func TestReMarkingAStatusDoesNotMoveWhenItBegan(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(filepath.Join(dir, "provisioned.json"))
	if err != nil {
		t.Fatal(err)
	}
	tick := time.Date(2026, 8, 30, 1, 0, 0, 0, time.UTC)
	l.now = func() time.Time { tick = tick.Add(time.Hour); return tick }

	if err := l.Mark("cert-wait", WaitingOnThem, "Cloudflare"); err != nil {
		t.Fatal(err)
	}
	began := l.Steps()[0].At

	for i := 0; i < 3; i++ {
		if err := l.Mark("cert-wait", WaitingOnThem, "Cloudflare"); err != nil {
			t.Fatal(err)
		}
	}
	got := l.Steps()[0]
	if got.At != began {
		t.Errorf("three re-checks moved the start of the wait from %s to %s", began, got.At)
	}
	if got.LookedAt == began {
		t.Errorf("lookedAt did not move: a row nobody is watching would look the same as this one")
	}

	// A real change does move it. Otherwise the field is frozen, not honest.
	if err := l.Mark("cert-wait", Passed, ""); err != nil {
		t.Fatal(err)
	}
	if l.Steps()[0].At == began {
		t.Errorf("the status changed and At stayed at %s", began)
	}
}
