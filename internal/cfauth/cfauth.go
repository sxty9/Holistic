// Package cfauth builds the Cloudflare credential the setup process needs, and
// checks the one it is given.
//
// The automated path was investigated and declined, and the reason is worth
// recording so it is re-tested rather than re-argued. Cloudflare does now offer
// OAuth to third-party applications — self-service registration, PKCE, no
// client secret to ship — but consent selects an ACCOUNT, not a zone. On an
// account holding more than one zone, an OAuth grant of dns:edit is therefore
// WIDER than the hand-scoped token it would replace. The day Cloudflare adds
// zone-level scoping to the consent screen, this decision changes; until then,
// manual is not a compromise but the narrower option.
//
// What makes manual acceptable is that it does not have to mean transcription.
// Cloudflare documents template URLs that pre-fill the custom-token form, so
// the person reviews a form that is already correct and clicks Create. The four
// permission rows are precisely the step people get wrong and then over-grant
// out of frustration.
//
// Nothing here mints, stores or transmits a token. It builds a link and reads
// back what the person created.
package cfauth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Permission is one row on Cloudflare's token form.
//
// It carries three names for the same thing, because Cloudflare uses three.
// Key and Type are what the template URL wants. Label is what the dashboard
// prints, which is what somebody is scanning the screen for. APIName is what
// /user/tokens/verify hands back, and it is neither of the other two: the form
// says "Zone → DNS → Edit" and the API says "DNS Write".
//
// Matching on the name is a known weak point — Cloudflare documents the group
// ID as authoritative and the name as cosmetic, and the IDs cannot be known
// without asking the API for them. The failure mode is chosen deliberately: an
// unrecognised name reports the permission as missing and prints what the token
// actually carries, so the operator sees both lists and can tell it is a naming
// drift rather than a wrong token. A silent pass would be the alternative, and
// it would be worse.
type Permission struct {
	Key     string `json:"key"`
	Type    string `json:"type"` // read | edit
	Label   string `json:"-"`
	APIName string `json:"-"`
	Why     string `json:"-"`
	// AskCloudflare marks a permission the zone's own answer cannot report, so
	// judging it means asking the endpoint whether the write is allowed instead
	// of looking it up. JudgeZone skips these entirely; the caller supplies the
	// answer through JudgeZoneWith.
	AskCloudflare bool `json:"-"`
}

// Setup is the credential the wizard needs, and the whole of it.
//
// Every entry is zone-scoped. Nothing account-scoped appears here, and that is
// a property worth defending rather than a coincidence: the routing rules this
// instance writes all point at a Worker, never at a forwarding address, so no
// verified destination address is ever created and the account-category
// "Email Routing Addresses" permission is never needed. If a step ever needs a
// forward action, this list changes shape and the claim that it touches one
// zone stops being true.
func Setup() []Permission {
	return []Permission{
		{Key: "zone", Type: "read", Label: "Zone → Zone → Read", APIName: "Zone Read",
			Why: "Confirm the zone is active before publishing into it. A record written to a pending zone answers nobody."},
		{Key: "dns", Type: "edit", Label: "Zone → DNS → Edit", APIName: "DNS Write",
			Why: "Publish the app hostnames, and the mail records if mail is set up."},
		{Key: "zone_settings", Type: "edit", Label: "Zone → Zone Settings → Edit", APIName: "Zone Settings Write",
			Why: "Turn on Email Routing, which is what makes inbound mail arrive."},
		{Key: "email_routing_rule", Type: "edit", Label: "Zone → Email Routing Rules → Edit", APIName: "Email Routing Rules Write",
			Why: "Route the addresses this instance answers to its own inbound Worker.",
			// NOT judged from the zone's permissions array, and this is the one
			// entry that cannot be. GET /zones reports dns_records, zone,
			// zone_settings, ssl and page_shield; it does not report email
			// routing at all, whether the token carries it or not.
			//
			// Measured on 2026-08-30 against a token whose Cloudflare form
			// shows all four rows: the array listed nine entries and none of
			// them was email routing, while POST to the rules endpoint got
			// through to body validation. So absence in the array meant
			// nothing, and reading it as "missing" refused a correct token
			// with no way for the operator to satisfy the check — they had
			// already added the row.
			//
			// AskCloudflare says how the real answer is obtained.
			AskCloudflare: true},
	}
}

// Runtime is what stays on the machine afterwards: DNS alone, on one zone.
//
// Deliberately not the setup token. Once the edge exists, the only reason to
// hold a credential at all is to reconcile DNS when an app is added or a policy
// changes; keeping the ability to enable Email Routing or rewrite zone settings
// past the moment it is needed is a standing risk for no standing benefit.
func Runtime() []Permission {
	return []Permission{
		{Key: "dns", Type: "edit", Label: "Zone → DNS → Edit", APIName: "DNS Write",
			Why: "Reconcile the hostnames this instance publishes."},
	}
}

// TokenURL builds Cloudflare's documented pre-filled token form.
//
// zoneID may be empty, in which case the form opens with the zone unselected
// and the operator picks it. Passing it is much better: it is on the zone's
// Overview page, it is not a secret, and supplying it is what keeps the token
// scoped to one zone instead of needing to list them all — which is also what
// lets the Zone→Read row cover a single zone rather than the account.
func TokenURL(perms []Permission, zoneID, name string) string {
	// The API wants a JSON array of {key,type}. Only those two fields; the
	// labels are ours.
	slim := make([]map[string]string, 0, len(perms))
	for _, p := range perms {
		slim = append(slim, map[string]string{"key": p.Key, "type": p.Type})
	}
	b, _ := json.Marshal(slim)

	q := url.Values{}
	q.Set("permissionGroupKeys", string(b))
	q.Set("accountId", "*")
	if zoneID == "" {
		q.Set("zoneId", "all")
	} else {
		q.Set("zoneId", zoneID)
	}
	if name != "" {
		q.Set("name", name)
	}
	return "https://dash.cloudflare.com/profile/api-tokens?" + q.Encode()
}

// ManualSteps are the parts the URL cannot carry, rendered next to the button.
//
// The template URL pre-fills the permission rows, the account and zone scope
// and the name. It does not carry the time-to-live or the client-IP filter,
// and Cloudflare's own documentation is explicit that the form still has to be
// completed by hand. Saying which two things are left is the difference between
// a person finishing and a person wondering what they missed.
func ManualSteps(zoneID string) []string {
	steps := []string{
		"Open the link. The four permission rows are already filled in — check them and change nothing.",
	}
	if zoneID == "" {
		steps = append(steps,
			"Under Zone Resources, choose Include → Specific zone → your domain. Not 'All zones'.")
	} else {
		steps = append(steps,
			"Under Zone Resources, confirm it names your domain and not 'All zones'.")
	}
	steps = append(steps,
		"Set the expiry to tomorrow's date. This token is for setting up, not for running.",
		"Continue to summary, create the token, and copy it. Cloudflare shows it once.",
	)
	return steps
}

// --- reading back what was actually created --------------------------------

// Verdict is what a token turned out to be.
type Verdict struct {
	Valid bool
	// Missing are permissions the wizard asked for and did not get. Naming
	// these is why the read-back exists at all: without it a missing row shows
	// up three steps later as a 403 on an unrelated-looking call.
	Missing []Permission
	// Excess are permissions the token carries that were not asked for.
	//
	// No comparable project checks this, and it is cheap. A token wider than
	// the request is not an error — Cloudflare will happily let somebody paste
	// an all-zones DNS token, or one that also carries Workers — but the person
	// should be told, because "I asked for exactly these four rows and yours
	// has six" is the difference between a paste box and an auditable grant.
	Excess []string
	// AllZones is the specific over-grant worth its own field, because it is
	// the common one and the consequence is concrete: every other domain in
	// the account is inside the blast radius of this machine.
	AllZones bool
}

// tokenBody is the shape of GET /user/tokens/verify plus the token read-back.
type tokenBody struct {
	Status   string `json:"status"`
	Policies []struct {
		Effect           string `json:"effect"`
		PermissionGroups []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"permission_groups"`
		Resources map[string]any `json:"resources"`
	} `json:"policies"`
}

// Judge compares a token's actual permissions against what was asked for.
//
// IT CANNOT BE REACHED WITH A CORRECTLY SCOPED TOKEN, and that is measured
// rather than suspected. GET /user/tokens/verify returns {id, status} and
// nothing else — no policies, no permission groups. Reading a token's own
// definition needs GET /user/tokens/{id}, which needs "User API Tokens Read",
// an account-category permission the setup token deliberately does not carry.
// Asked with the real token on 2026-08-30, that call answers "Unauthorized to
// access requested resource".
//
// So the pattern this was written for — reject a token that carries more than
// was asked for — requires the token to be broader than the rule is meant to
// enforce. It is kept for the case where a read-back genuinely is available,
// and JudgeZone below is what the wizard uses.
//
// It takes the decoded body rather than making the call, so the comparison is
// testable without a network and without a credential.
func Judge(raw []byte, want []Permission) (Verdict, error) {
	var body tokenBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return Verdict{}, fmt.Errorf("could not read Cloudflare's answer: %w", err)
	}
	v := Verdict{Valid: strings.EqualFold(body.Status, "active")}

	granted := map[string]bool{}
	for _, p := range body.Policies {
		if !strings.EqualFold(p.Effect, "allow") {
			continue
		}
		for _, g := range p.PermissionGroups {
			granted[normalise(g.Name)] = true
		}
		for res := range p.Resources {
			// "com.cloudflare.api.account.zone.*" is every zone in the
			// account; a specific zone ends in its id.
			if strings.HasSuffix(res, ".zone.*") || res == "com.cloudflare.api.account.*" {
				v.AllZones = true
			}
		}
	}

	asked := map[string]bool{}
	for _, p := range want {
		asked[normalise(p.APIName)] = true
		if !granted[normalise(p.APIName)] {
			v.Missing = append(v.Missing, p)
		}
	}
	for name := range granted {
		if !asked[name] {
			v.Excess = append(v.Excess, name)
		}
	}
	sort.Strings(v.Excess)
	return v, nil
}

// zoneScope maps a form key onto the name Cloudflare uses in a zone's own
// permissions list. Only one differs, and it is the one that matters most: the
// form says "dns" and the zone says "dns_records".
var zoneScope = map[string]string{
	"dns": "dns_records",
}

// JudgeZone reads what a token can actually do ON ONE ZONE.
//
// GET /zones?name=… returns a "permissions" array — ["#dns_records:edit",
// "#dns_records:read", "#zone:read"] — and that is the effective grant, from
// the zone's own answer, for the token that asked. It is a better question than
// the one Judge asks: what matters is what this credential can do here, not
// what it was nominally created with.
//
// What it CANNOT tell you is what else the token reaches. A token scoped to
// every zone in the account answers identically on this one. Verdict.AllZones
// is therefore left false rather than guessed at, and Explain says so — an
// unanswered question reported as a clean answer is the failure this whole
// package is written against.
func JudgeZone(active bool, zonePerms []string, want []Permission) Verdict {
	v := Verdict{Valid: active}

	granted := map[string]bool{}
	asked := map[string]bool{}
	for _, p := range zonePerms {
		granted[strings.TrimPrefix(strings.ToLower(strings.TrimSpace(p)), "#")] = true
	}
	for _, p := range want {
		if p.AskCloudflare {
			// Not in the array, and never will be. Judged by JudgeZoneWith.
			continue
		}
		scope := p.Key
		if alt, ok := zoneScope[scope]; ok {
			scope = alt
		}
		// An edit implies the read, and Cloudflare lists both; asking for edit
		// and finding only read is missing, not satisfied.
		if !granted[scope+":"+p.Type] {
			v.Missing = append(v.Missing, p)
		}
		asked[scope+":"+p.Type] = true
		// An edit implies the read, so a token that carries both when only edit
		// was asked for is not carrying anything extra.
		if p.Type == "edit" {
			asked[scope+":read"] = true
		}
	}

	// The other direction, which the Missing loop above does not cover and
	// which no comparable project checks: what did this token bring that
	// nobody asked for? Verdict has carried an Excess field and Explain has
	// printed it since this package was written; nothing ever filled it, so
	// the read-back only ever answered half its own question.
	//
	// Reported, not refused. A token wider than the request still does the
	// job, and turning "you gave me more than I need" into a hard stop makes
	// the wizard unusable for anybody reusing a token they already trust. What
	// it must not do is stay silent: "I asked for exactly these four rows and
	// yours has nine" is the difference between a paste box and a grant
	// somebody can audit.
	for g := range granted {
		if !asked[g] {
			v.Excess = append(v.Excess, g)
		}
	}
	sort.Strings(v.Excess)
	return v
}

// JudgeZoneWith is JudgeZone plus the answers to the permissions the zone
// cannot report. asked maps a permission Key to what Cloudflare said when the
// caller tried the write — true for allowed.
//
// A key missing from asked is treated as unanswered, not as denied: a probe
// that could not run is not evidence of anything, and refusing a token because
// a check failed to happen is the shape of failure this whole wizard exists to
// avoid.
func JudgeZoneWith(active bool, zonePerms []string, want []Permission, asked map[string]bool) Verdict {
	v := JudgeZone(active, zonePerms, want)
	for _, p := range want {
		if !p.AskCloudflare {
			continue
		}
		if allowed, answered := asked[p.Key]; answered && !allowed {
			v.Missing = append(v.Missing, p)
		}
	}
	return v
}

// normalise reduces Cloudflare's user-facing permission names to something
// comparable. The form says "Edit" where the API says "Write" for the same
// group, and the arrows and spacing vary between the dashboard and the API.
func normalise(s string) string {
	s = strings.ToLower(s)
	for _, sep := range []string{"→", "->", ":", "  "} {
		s = strings.ReplaceAll(s, sep, " ")
	}
	s = strings.ReplaceAll(s, " write", " edit")
	return strings.Join(strings.Fields(s), " ")
}

// Explain turns a verdict into what the operator should read.
func (v Verdict) Explain() []string {
	var out []string
	if !v.Valid {
		out = append(out, "Cloudflare says this token is not active. Check it was copied whole.")
	}
	for _, p := range v.Missing {
		out = append(out, fmt.Sprintf("Missing: %s — %s", p.Label, p.Why))
	}
	if v.AllZones {
		out = append(out, "This token covers EVERY zone in your account, not just this domain. "+
			"It will work, and it means every other domain you host is inside this machine's reach. "+
			"Creating one scoped to a single zone takes the same number of clicks.")
	}
	for _, e := range v.Excess {
		out = append(out, fmt.Sprintf("Carries a permission that was not asked for: %s", e))
	}
	return out
}

// OK reports whether setup can proceed. Excess permissions are reported and do
// not block: it is the operator's account, and refusing to continue over a
// grant that is merely wider than necessary would be the wizard overruling the
// person whose account it is.
func (v Verdict) OK() bool { return v.Valid && len(v.Missing) == 0 }
