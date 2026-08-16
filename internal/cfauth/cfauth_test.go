package cfauth

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// The link is the whole reason manual is acceptable. It has to carry the four
// permission rows exactly, because those are the step people get wrong and then
// over-grant out of frustration.
func TestTheLinkPreFillsExactlyWhatIsAskedFor(t *testing.T) {
	raw := TokenURL(Setup(), "zone-abc", "holistic-setup")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "dash.cloudflare.com" || u.Path != "/profile/api-tokens" {
		t.Fatalf("link points somewhere unexpected: %s", raw)
	}
	q := u.Query()

	var got []map[string]string
	if err := json.Unmarshal([]byte(q.Get("permissionGroupKeys")), &got); err != nil {
		t.Fatalf("permissionGroupKeys is not the JSON array Cloudflare expects: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 permission rows, got %d: %v", len(got), got)
	}
	want := map[string]string{
		"zone": "read", "dns": "edit", "zone_settings": "edit", "email_routing_rule": "edit",
	}
	for _, p := range got {
		if want[p["key"]] != p["type"] {
			t.Errorf("unexpected row %v", p)
		}
		delete(want, p["key"])
	}
	if len(want) != 0 {
		t.Errorf("rows missing from the link: %v", want)
	}

	if q.Get("zoneId") != "zone-abc" {
		t.Errorf("the zone was not pre-selected: %q", q.Get("zoneId"))
	}
	if q.Get("name") != "holistic-setup" {
		t.Errorf("token name is %q", q.Get("name"))
	}
}

// Without a zone id the form cannot pre-select one, so the instructions have to
// tell the person to do it — and to avoid the "All zones" default that would
// widen the grant to the whole account.
func TestWithoutAZoneTheInstructionsSayToNarrowItByHand(t *testing.T) {
	raw := TokenURL(Setup(), "", "holistic-setup")
	u, _ := url.Parse(raw)
	if u.Query().Get("zoneId") != "all" {
		t.Errorf("expected the documented 'all' placeholder, got %q", u.Query().Get("zoneId"))
	}
	steps := strings.Join(ManualSteps(""), " ")
	if !strings.Contains(steps, "Specific zone") {
		t.Error("nothing tells the person to scope the token to one zone")
	}
	if !strings.Contains(steps, "All zones") {
		t.Error("the instructions do not warn against the wider default")
	}
}

// The two things the URL cannot carry. Cloudflare's documentation is explicit
// that the form still has to be completed by hand, and naming which two is the
// difference between finishing and wondering what was missed.
func TestTheInstructionsCoverWhatTheLinkCannot(t *testing.T) {
	steps := strings.ToLower(strings.Join(ManualSteps("zone-abc"), " "))
	if !strings.Contains(steps, "expiry") {
		t.Error("nothing tells the person to set a time limit on a setup credential")
	}
	if !strings.Contains(steps, "once") {
		t.Error("nothing warns that Cloudflare shows the token exactly once")
	}
}

// The runtime credential is narrower than the setup one, and stays that way.
func TestTheRuntimeTokenIsSmallerThanTheSetupToken(t *testing.T) {
	if len(Runtime()) >= len(Setup()) {
		t.Fatal("the credential that survives setup is not narrower than the one that does not")
	}
	for _, p := range Runtime() {
		if p.Key != "dns" {
			t.Errorf("the runtime token carries %s, which it does not need to reconcile DNS", p.Key)
		}
	}
}

const activeToken = `{
  "status": "active",
  "policies": [{
    "effect": "allow",
    "resources": { "com.cloudflare.api.account.zone.abc123": "*" },
    "permission_groups": [
      {"id":"1","name":"Zone Read"},
      {"id":"2","name":"DNS Write"},
      {"id":"3","name":"Zone Settings Write"},
      {"id":"4","name":"Email Routing Rules Write"}
    ]
  }]
}`

// The form says Edit where the API says Write for the same group. A comparison
// that does not know this reports every correct token as missing everything.
func TestEditAndWriteAreTheSameGroup(t *testing.T) {
	v, err := Judge([]byte(activeToken), Setup())
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK() {
		t.Fatalf("a correct token was rejected: %v", v.Explain())
	}
	if len(v.Excess) != 0 {
		t.Errorf("a correct token was reported as carrying extras: %v", v.Excess)
	}
	if v.AllZones {
		t.Error("a single-zone token was reported as covering the account")
	}
}

// Without the read-back, a missing row shows up three steps later as a 403 on
// an unrelated-looking call.
func TestAMissingPermissionIsNamedImmediately(t *testing.T) {
	short := strings.Replace(activeToken, `{"id":"3","name":"Zone Settings Write"},`, "", 1)
	v, err := Judge([]byte(short), Setup())
	if err != nil {
		t.Fatal(err)
	}
	if v.OK() {
		t.Fatal("a token missing a permission was accepted")
	}
	if len(v.Missing) != 1 || v.Missing[0].Key != "zone_settings" {
		t.Fatalf("wrong permission reported missing: %+v", v.Missing)
	}
	expl := strings.Join(v.Explain(), " ")
	if !strings.Contains(expl, "Zone Settings") {
		t.Error("the explanation does not name the row as the form labels it")
	}
	if !strings.Contains(expl, "Email Routing") {
		t.Error("the explanation does not say what the missing permission is for")
	}
}

// Nobody else checks this direction, and it is cheap. "I asked for exactly these
// four rows and yours has five" turns a paste box into an auditable grant.
func TestATokenWiderThanAskedForIsReported(t *testing.T) {
	wide := strings.Replace(activeToken,
		`{"id":"4","name":"Email Routing Rules Write"}`,
		`{"id":"4","name":"Email Routing Rules Write"},{"id":"5","name":"Workers Scripts Write"}`, 1)
	v, err := Judge([]byte(wide), Setup())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Excess) != 1 || !strings.Contains(v.Excess[0], "workers") {
		t.Fatalf("an extra permission was not noticed: %+v", v.Excess)
	}
	// Reported, not refused. It is the operator's account, and blocking over a
	// grant that is merely wider than necessary would be the wizard overruling
	// the person whose account it is.
	if !v.OK() {
		t.Error("setup refused to continue over a permission the operator chose to grant")
	}
	if !strings.Contains(strings.Join(v.Explain(), " "), "not asked for") {
		t.Error("the extra permission is not explained")
	}
}

// The common over-grant, and the one with a concrete consequence.
func TestAnAllZonesTokenIsCalledOut(t *testing.T) {
	wide := strings.Replace(activeToken,
		`"com.cloudflare.api.account.zone.abc123": "*"`,
		`"com.cloudflare.api.account.zone.*": "*"`, 1)
	v, err := Judge([]byte(wide), Setup())
	if err != nil {
		t.Fatal(err)
	}
	if !v.AllZones {
		t.Fatal("an all-zones token was not noticed")
	}
	expl := strings.Join(v.Explain(), " ")
	if !strings.Contains(expl, "EVERY zone") {
		t.Error("the consequence is not stated plainly")
	}
	if !v.OK() {
		t.Error("an all-zones token should be reported, not refused")
	}
}

func TestAnInactiveTokenIsRefused(t *testing.T) {
	dead := strings.Replace(activeToken, `"status": "active"`, `"status": "disabled"`, 1)
	v, err := Judge([]byte(dead), Setup())
	if err != nil {
		t.Fatal(err)
	}
	if v.OK() {
		t.Fatal("a disabled token was accepted")
	}
	if !strings.Contains(strings.Join(v.Explain(), " "), "not active") {
		t.Error("the explanation does not say the token is not active")
	}
}

// A deny policy grants nothing, and counting it as a grant would report a token
// as sufficient when it is not.
func TestDenyPoliciesGrantNothing(t *testing.T) {
	denied := strings.Replace(activeToken, `"effect": "allow"`, `"effect": "deny"`, 1)
	v, err := Judge([]byte(denied), Setup())
	if err != nil {
		t.Fatal(err)
	}
	if v.OK() {
		t.Fatal("a token whose only policy is a deny was accepted")
	}
	if len(v.Missing) != 4 {
		t.Errorf("expected all four to be missing, got %d", len(v.Missing))
	}
}

func TestUnreadableAnswersAreAnError(t *testing.T) {
	if _, err := Judge([]byte("<html>gateway timeout</html>"), Setup()); err == nil {
		t.Fatal("an unparseable answer was treated as a verdict")
	}
}
