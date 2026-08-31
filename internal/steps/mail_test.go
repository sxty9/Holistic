package steps

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sxty9/Holistic/internal/ledger"
)

// The DMARC record must not name an address that does not yet accept mail.
//
// rua=mailto:dmarc@<domain> asks every receiver on the internet to send its
// aggregate reports there. Published first, the reports are refused for as long
// as nobody looks — and nobody looks, because the record is there and the step
// said passed. That is the failure this whole file is ordered around, so it is
// the one asserted first.
func TestTheReportAddressExistsBeforeItIsPublished(t *testing.T) {
	k := newKit(t)
	// Everything except the mailboxes, so the assertion reaches the edge being
	// tested rather than being blocked by some unrelated unfinished step.
	for _, st := range k.e.order {
		if st.ID != "role-mailboxes" && st.ID != "mail-apply" && st.ID != "dmarc-published" {
			k.standIn(st.ID)
		}
	}
	row := k.run("mail-apply")
	if row.Status == ledger.Passed {
		t.Fatal("the mail records were published with no mailbox to receive the reports")
	}
	if !strings.Contains(row.Detail, "role-mailboxes") {
		t.Errorf("the refusal does not name what is missing: %q", row.Detail)
	}
}

// A role address that already belongs to a person is a conflict, not a failure
// and not something to take away from them.
func TestRoleMailboxThatBelongsToSomebody(t *testing.T) {
	k := newKit(t)
	k.drive()
	k.mailboxesAnswer()
	// corexctl's own words, which is what the step reads. EnsureRoleMailbox
	// returns this when the address is an account's or an alias's.
	key := k.p.Corexctl + " mailbox create -address postmaster -name Postmaster"
	k.m.out[key] = "mail: postmaster@" + testDomain + " already belongs to somebody"
	k.m.fail["run "+key] = fmt.Errorf("exit status 1")

	before := k.snapshot()
	row := k.run("role-mailboxes")
	if row.Status != ledger.Conflict {
		t.Fatalf("role-mailboxes: %s — %s", row.Status, row.Detail)
	}
	if row.Conflict == nil {
		t.Fatal("a conflict row with no conflict on it")
	}
	if !strings.Contains(row.Conflict.Object, "postmaster@"+testDomain) {
		t.Errorf("the conflict does not name the address: %q", row.Conflict.Object)
	}
	if row.Conflict.Unchanged != Unchanged {
		t.Error("the conflict does not carry the promise")
	}
	if d := diffSnapshots(before, k.snapshot()); len(d) > 0 {
		t.Errorf("it changed files anyway: %v", d)
	}
}

// Three creates exiting 0 is not the same fact as three mailboxes existing.
func TestRoleMailboxesAreReadBackFromTheInstance(t *testing.T) {
	k := newKit(t)
	k.drive()
	k.mailboxesAnswer()
	// The injected defect: every create succeeds and the instance holds
	// nothing. Without the read-back this passes.
	k.m.out[k.p.Corexctl+" mailbox list"] = ""

	row := k.run("role-mailboxes")
	if row.Status == ledger.Passed {
		t.Fatal("it reported role mailboxes that the instance does not list")
	}
	for _, r := range roleMailboxes() {
		if !strings.Contains(row.Detail, r.Local+"@"+testDomain) {
			t.Errorf("the failure does not name %s as missing: %q", r.Local, row.Detail)
		}
	}
}

// Somebody else's report address is not this wizard's to repoint.
func TestMailDNSWillNotRedirectSomebodyElsesReports(t *testing.T) {
	k := newKit(t)
	k.drive()
	// Written into Warpgate's configuration by somebody, before this step ever
	// ran. mail-dns has passed once during drive(), so the ledger has to be put
	// back to the state the guard is about: a step that has never run here.
	if err := k.led.Mark("mail-dns", ledger.Pending, "reset by the test"); err != nil {
		t.Fatal(err)
	}
	theirs := "dmarc-reports@somewhere.invalid"
	k.setInWarpgate("mail.reportTo", theirs)

	before := k.snapshot()
	row := k.run("mail-dns")
	if row.Status != ledger.Conflict {
		t.Fatalf("mail-dns: %s — %s", row.Status, row.Detail)
	}
	if !strings.Contains(row.Conflict.Found, theirs) {
		t.Errorf("the conflict does not quote what is there: %q", row.Conflict.Found)
	}
	if d := diffSnapshots(before, k.snapshot()); len(d) > 0 {
		t.Errorf("it wrote anyway: %v", d)
	}
}

// The record is read back from a resolver that is not the one it was written
// to. Cloudflare holding the record is not the fact being established.
func TestDMARCIsReadBackFromOutside(t *testing.T) {
	k := newKit(t)
	k.drive()
	k.standIn("mail-apply")

	answer := func(txt string) string {
		b, err := json.Marshal(map[string]any{
			"Status": 0,
			"Answer": []map[string]any{{"data": `"` + txt + `"`}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	// Nothing there yet: waiting, never failed. A record published a minute ago
	// is not visible everywhere, and calling that a failure sends somebody to
	// Cloudflare to look at a record that is already correct.
	k.resp = Response{Status: 200, Body: `{"Status":3,"Answer":[]}`}
	if row := k.run("dmarc-published"); row.Status != ledger.WaitingOnThem {
		t.Errorf("an absent record read as %s, not as waiting: %s", row.Status, row.Detail)
	}

	// There, and saying something else. quarantine was answered in drive();
	// p=none is a different promise to every receiver on the internet.
	k.resp = Response{Status: 200, Body: answer("v=DMARC1; p=none; rua=mailto:dmarc@" + testDomain)}
	row := k.run("dmarc-published")
	if row.Status != ledger.Failed {
		t.Errorf("a record with the wrong policy read as %s: %s", row.Status, row.Detail)
	}

	// There, and addressed somewhere else. This is the one that would otherwise
	// pass on the strength of "a DMARC record exists".
	k.resp = Response{Status: 200, Body: answer("v=DMARC1; p=quarantine; rua=mailto:someone@somewhere.invalid")}
	if row := k.run("dmarc-published"); row.Status != ledger.Failed {
		t.Errorf("a record pointing somewhere else read as %s: %s", row.Status, row.Detail)
	}

	// Correct.
	want := "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + testDomain
	k.resp = Response{Status: 200, Body: answer(want)}
	row = k.run("dmarc-published")
	if row.Status != ledger.Passed {
		t.Fatalf("dmarc-published: %s — %s", row.Status, row.Detail)
	}
	if !strings.Contains(row.Proof, want) {
		t.Errorf("the proof does not carry the record it read: %q", row.Proof)
	}
}

// The mail domain, which nothing wrote before this. Its absence is silent:
// coreX reads an empty mail.domain as "outbound is off", so an instance that
// followed the wizard to the end had eight hostnames and no mail, and no step
// reported anything.
func TestCoreXWriteSetsTheMailDomain(t *testing.T) {
	k := newKit(t)
	k.drive()
	tree, _, err := readTree(k.p.CoreXConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got := atString(tree, "mail.domain"); got != testDomain {
		t.Fatalf("mail.domain is %q, so mail is off and nothing says so", got)
	}
	row := k.row("corex-write")
	if !strings.Contains(row.Proof, "mail.domain="+testDomain) {
		t.Errorf("corex-write's proof does not mention the mail domain: %q", row.Proof)
	}
}

// setInWarpgate puts a value into Warpgate's configuration the way somebody
// else's hand would have.
func (k *kit) setInWarpgate(path string, v any) {
	k.t.Helper()
	tree, _, err := readTree(k.p.WarpgateConfig)
	if err != nil {
		k.t.Fatal(err)
	}
	if tree == nil {
		tree = map[string]any{}
	}
	parts := strings.Split(path, ".")
	cur := tree
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = v
	b, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		k.t.Fatal(err)
	}
	if err := os.WriteFile(k.p.WarpgateConfig, b, 0o640); err != nil {
		k.t.Fatal(err)
	}
}
