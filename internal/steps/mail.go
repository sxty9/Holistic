package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// The mail half of the wizard: the addresses this domain owes the outside
// world, and the records that say who may send for it.
//
// The order in here is the whole design, and it is the opposite of the obvious
// one. A DMARC record carries rua=mailto:dmarc@<domain>, which asks every
// receiver on the internet to send aggregate reports to that address. Publish
// it before the address accepts mail and the reports are refused for as long as
// nobody looks — and nobody looks, because the record is there and the step
// said passed. That is the same shape as the worker that answered 530 for three
// days: every component reported success and the message reached no one.
//
// So role-mailboxes comes first and mail-apply consumes it. The mailbox is not
// a nicety that can follow later; it is what makes the record true.

// roleMailbox is one address the instance answers on its own behalf.
//
// Three, and each is here for a reason that can be named. dmarc receives the
// aggregate reports this domain asks for — it is the only instrument that can
// see mail this instance never touches, which is what the vanishing apex mail
// needs. postmaster and abuse are RFC 2142: a receiver that cannot reach either
// one has no way to tell an operator that something is wrong, and some of them
// treat the absence as a signal about the domain.
//
// They are role mailboxes rather than aliases on a person, which is the
// distinction coreX already draws: an alias sends and receives as somebody, and
// nobody should be sending as postmaster by accident.
type roleMailbox struct {
	Local string
	Name  string
	Why   string
}

func roleMailboxes() []roleMailbox {
	return []roleMailbox{
		{"dmarc", "DMARC reports", "receives the aggregate reports the DMARC record asks for"},
		{"postmaster", "Postmaster", "RFC 2142: where a receiver writes when delivery is going wrong"},
		{"abuse", "Abuse", "RFC 2142: where a complaint about mail from this domain goes"},
	}
}

func stepRoleMailboxes() Step {
	return Step{
		ID:    "role-mailboxes",
		Title: "The addresses this domain owes",
		Kind:  Local,
		// corex-write, because that is the step that puts the domain into
		// coreX's configuration, and EnsureRoleMailbox refuses without one.
		After: []string{"corex-write"},
		desired: func(e *Engine) string {
			var names []string
			for _, r := range roleMailboxes() {
				names = append(names, r.Local+"@"+domainOr(e, "<domain>"))
			}
			return "create the role mailboxes " + strings.Join(names, ", ") +
				" through " + e.paths.Corexctl + ". They receive and never send."
		},
		run: func(e *Engine) result {
			d := e.catalogue().Domain
			if d == "" {
				return blocked("waiting on the domain")
			}
			for _, r := range roleMailboxes() {
				// Idempotent by construction: EnsureRoleMailbox returns the
				// mailbox that is already there, and refuses only when the
				// address belongs to a person. That refusal is a conflict and
				// not a failure — somebody is called postmaster, and taking
				// their address away from them is not this wizard's to do.
				out, err := e.machine.Run(e.paths.Corexctl, "mailbox", "create",
					"-address", r.Local, "-name", r.Name)
				if err == nil {
					continue
				}
				if strings.Contains(out, "already belongs to somebody") {
					return held(Conflict{
						Object:      r.Local + "@" + d,
						Found:       "an account or an alias already answers on it",
						FoundNote:   e.paths.Corexctl + " said: " + firstLine(out),
						Desired:     "a role mailbox that " + r.Why,
						Summary:     r.Local + "@" + d + " already belongs to somebody.",
						Why:         "A role address that lands in a person's mailbox routes the whole domain's " + r.Local + " mail to one account, and that account can then send as it.",
						Resolution:  "Give that account a different address, then run this step again.",
						Consequence: "the " + r.Local + " address stays where it is. Nothing else in this wizard depends on it except the DMARC record, which will not be published without it.",
					})
				}
				return failed(fmt.Sprintf("%s mailbox create -address %s did not finish: %v\n%s",
					e.paths.Corexctl, r.Local, err, out))
			}
			// Read back, from the instance rather than from the exit status of
			// the command that just ran. Three creates returning 0 is not the
			// same fact as three mailboxes existing.
			out, err := e.machine.Run(e.paths.Corexctl, "mailbox", "list")
			if err != nil {
				return failed(fmt.Sprintf("%s mailbox list could not be asked: %v\n%s", e.paths.Corexctl, err, out))
			}
			var missing []string
			for _, r := range roleMailboxes() {
				if !strings.Contains(out, r.Local+"@"+d) {
					missing = append(missing, r.Local+"@"+d)
				}
			}
			if len(missing) > 0 {
				return failed(fmt.Sprintf("%s mailbox list does not show %s after creating them. Its output was:\n%s",
					e.paths.Corexctl, strings.Join(missing, ", "), out))
			}
			return passed(fmt.Sprintf("%d role mailboxes", len(roleMailboxes())),
				"read back from `"+e.paths.Corexctl+" mailbox list`:\n"+strings.TrimSpace(out))
		},
	}
}

// spfSender is the mechanism that authorises this landscape's outbound mail.
//
// It is a constant and not an answer because it is not the operator's choice:
// corex-routedge relays through Amazon SES, so this is a fact about the
// software, in the same way the upstream ports in the catalogue are. The day
// the relay changes, this changes with it — and the wrong shape would be to ask
// a person to type the name of a service they did not choose.
//
// Cloudflare Email Routing carries mail INTO this domain and never out of it,
// so it needs no mechanism here. A forwarder that re-sends would.
const spfSender = "include:amazonses.com"

// dmarcPolicies are what a receiver is asked to do with mail from this domain
// that cannot be shown to be ours.
func dmarcPolicies() []Option {
	return []Option{
		{Value: "quarantine", Label: "Quarantine — file it as spam",
			Note: "The recommended start for a domain that already signs with DKIM. Mail this instance sends is signed and aligned, so it is not affected. Anything else claiming to be this domain lands in a spam folder rather than an inbox."},
		{Value: "none", Label: "None — do nothing, only report",
			Note: "Enforces nothing. It still turns on the aggregate reports, which is the only way to see who is sending as this domain. Choose this to watch first and enforce later."},
		{Value: "reject", Label: "Reject — refuse it outright",
			Note: "The strongest, and the least forgiving: a legitimate sender nobody remembered about stops being delivered at all, with a bounce to the sender rather than a message in a spam folder."},
	}
}

func stepMailDNS() Step {
	return Step{
		ID:    "mail-dns",
		Title: "What this domain says about its mail",
		Kind:  Local,
		// The mailbox first. See the note at the top of this file.
		After: []string{"role-mailboxes"},
		desired: func(e *Engine) string {
			return fmt.Sprintf("write mail.enabled, mail.spfIncludes=%q, mail.dmarcPolicy and mail.reportTo=%s into %s. "+
				"This writes a file. Nothing is published until mail-apply.",
				spfSender, reportAddress(e, "<domain>"), e.paths.WarpgateConfig)
		},
		need: func(e *Engine) *Need {
			return &Need{
				Kind:    "choice",
				Label:   "What should receivers do with mail that claims to be from this domain and cannot prove it?",
				Help:    "This is the DMARC policy. It applies to everybody else's mail, not to yours: what this instance sends is signed with DKIM and aligned, and passes under all three answers. Aggregate reports come to " + reportAddress(e, "this domain") + " either way, and the policy can be changed later — it is one record.",
				Options: dmarcPolicies(),
				Value:   e.dmarcPolicy(),
			}
		},
		accept: acceptString(func(e *Engine, s string) error {
			for _, o := range dmarcPolicies() {
				if o.Value == s {
					e.given.dmarcPolicy = s
					return nil
				}
			}
			return fmt.Errorf("%w: %q is not a DMARC policy", ErrBadAnswer, s)
		}),
		run: func(e *Engine) result {
			d := e.catalogue().Domain
			if d == "" {
				return blocked("waiting on the domain")
			}
			policy := e.dmarcPolicy()
			if policy == "" {
				return blocked("waiting to be told what receivers should do with unauthenticated mail")
			}
			ed, err := openEdit(e.paths.WarpgateConfig, confMode)
			if err != nil {
				return failed(err.Error())
			}
			want := reportAddress(e, d)
			// A reportTo pointing somewhere else was put there by somebody, and
			// redirecting a domain's DMARC reports is exactly the kind of quiet
			// change this wizard does not make. It is only a conflict when this
			// step did not write it: on a second run, the value it wrote is its
			// own.
			if had := atString(ed.tree, "mail.reportTo"); had != "" && had != want && !e.ours("mail-dns") {
				return held(Conflict{
					Object:      "mail.reportTo in " + e.paths.WarpgateConfig,
					Found:       quote(had),
					FoundNote:   "this step has never run on this machine, so nothing here wrote it",
					Desired:     quote(want),
					Summary:     "DMARC reports are already addressed to " + had + ".",
					Why:         "The address in the DMARC record is where every receiver on the internet sends its aggregate reports. Repointing it takes that stream away from whoever is reading it today, and nothing anywhere announces that it stopped.",
					Resolution:  "If the reports should come to this instance, clear mail.reportTo in " + e.paths.WarpgateConfig + " deliberately, then run this step again.",
					Consequence: "the DMARC record is not written. Mail keeps flowing exactly as it does now.",
				})
			}
			ed.set("mail.enabled", true)
			// The list field, not the single one. spfInclude is what
			// configurations written before there could be more than one
			// sender carry; writing both would publish the mechanism twice.
			ed.set("mail.spfIncludes", []any{spfSender})
			ed.set("mail.dmarcPolicy", policy)
			ed.set("mail.reportTo", want)
			return e.applyOne(ed, "mail.enabled", "mail.spfIncludes", "mail.dmarcPolicy", "mail.reportTo")
		},
	}
}

func stepMailApply() Step {
	return Step{
		ID:    "mail-apply",
		Title: "Publish who may send for this domain",
		Kind:  Foreign,
		// role-mailboxes directly, and not only through mail-dns. The
		// dependency is transitive today — mail-dns cannot pass without the
		// mailboxes — and naming it anyway is the point: the record this step
		// publishes says dmarc@<domain> receives, and one edge stood in for by
		// a later hand would make that a promise nothing keeps.
		//
		// dns-apply as well: both run the same warpgate against the same zone,
		// and two of them planning at once would each compute a plan against a
		// zone the other is halfway through changing.
		After: []string{"role-mailboxes", "mail-dns", "mailfrom", "dns-apply"},
		desired: fixed("run warpgate again, which publishes the SPF record at the apex and the DMARC record at " +
			"_dmarc — and refuses, per record, where something is already standing there that it did not create"),
		run: func(e *Engine) result {
			return runWarpgate(e, "the mail records for "+e.given.domain)
		},
	}
}

func stepDMARCPublished() Step {
	return Step{
		ID:        "dmarc-published",
		Title:     "The DMARC record reads back from outside",
		Kind:      Theirs,
		After:     []string{"mail-apply"},
		WaitingOn: "the public DNS",
		desired: fixed("ask a public resolver for _dmarc.<domain> and read the policy and the report address back " +
			"out of the answer. Cloudflare holding the record is not the same fact as the internet seeing it."),
		run: func(e *Engine) result {
			d := e.catalogue().Domain
			if d == "" {
				return blocked("waiting on the domain")
			}
			name := "_dmarc." + d
			// A resolver that is not ours, on purpose. Reading the record back
			// from Cloudflare would prove that Cloudflare stored what warpgate
			// sent it, which nobody doubts; the question this step answers is
			// whether a receiver somewhere else can see it.
			u := "https://dns.google/resolve?type=TXT&name=" + url.QueryEscape(name)
			res, err := e.fetch(context.Background(), u)
			if err != nil {
				return waitingOnThem("a public resolver could not be asked about " + name + ": " + err.Error())
			}
			if res.Status != 200 {
				return waitingOnThem(fmt.Sprintf("the public resolver answered %d for %s", res.Status, name))
			}
			var body struct {
				Status int `json:"Status"`
				Answer []struct {
					Data string `json:"data"`
				} `json:"Answer"`
			}
			if err := json.Unmarshal([]byte(res.Body), &body); err != nil {
				return failed("the public resolver's answer about " + name + " could not be read: " + err.Error())
			}
			var found string
			for _, a := range body.Answer {
				got := strings.Trim(strings.TrimSpace(a.Data), `"`)
				if strings.HasPrefix(strings.ToUpper(got), "V=DMARC1") {
					found = got
					break
				}
			}
			if found == "" {
				// Waiting rather than failed, and named: a record published a
				// minute ago is not visible everywhere yet, and calling that a
				// failure sends somebody to Cloudflare to look at a record that
				// is already correct.
				return waitingOnThem("no DMARC record at " + name + " yet. Cloudflare caches a miss for 30 minutes, " +
					"so a record published just now takes up to that long to appear here.")
			}
			want := reportAddress(e, d)
			var wrong []string
			if p := e.dmarcPolicy(); p != "" && !strings.Contains(found, "p="+p) {
				wrong = append(wrong, "the policy is not p="+p)
			}
			if !strings.Contains(found, "rua=mailto:"+want) {
				wrong = append(wrong, "the reports are not addressed to "+want)
			}
			if len(wrong) > 0 {
				return failed(fmt.Sprintf("%s reads %q from outside, and %s", name, found, strings.Join(wrong, ", and ")))
			}
			return passed("published and visible from outside",
				fmt.Sprintf("a public resolver that is not Cloudflare answered for %s:\n  %s\n\n"+
					"Reports go to %s, which %s answers as a role mailbox. The first ones arrive within 24 to 48 hours, "+
					"one per receiver per day.", name, found, want, e.paths.Corexctl))
		},
	}
}

// reportAddress is the one address the DMARC record names, derived rather than
// answered: it is dmarc@ on this domain because that is the role mailbox
// role-mailboxes creates, and the two being separately configurable is how they
// come to disagree.
func reportAddress(e *Engine, fallback string) string {
	d := e.catalogue().Domain
	if d == "" {
		return "dmarc@" + fallback
	}
	return "dmarc@" + d
}

func domainOr(e *Engine, fallback string) string {
	if d := e.catalogue().Domain; d != "" {
		return d
	}
	return fallback
}

// dmarcPolicy is what has been chosen, from the answer given in this process or
// from the file if the process is a later one. The file is the state; `given`
// is only what has been said since it was last read.
func (e *Engine) dmarcPolicy() string {
	if e.given.dmarcPolicy != "" {
		return e.given.dmarcPolicy
	}
	tree, _, err := readTree(e.paths.WarpgateConfig)
	if err != nil {
		return ""
	}
	return atString(tree, "mail.dmarcPolicy")
}

// The envelope domain — Custom MAIL FROM at the relay, and the two records here
// that make it work.
//
// What it buys, precisely: a message relayed through a provider carries that
// provider's domain in the SMTP envelope, so SPF passes for the provider and
// DMARC counts the result as unaligned. DKIM still aligns, so mail is
// authenticated on one leg. The envelope domain gives it a second one, and the
// second one is what survives a mailing list that rewrites a message and breaks
// its signature.
//
// It is optional, and staying optional is deliberate. It requires a change at
// the provider that this wizard cannot make and must not pretend to have made:
// the records below are one half of a pair, and the provider verifies them
// before it uses the domain. An operator who has not been to the console yet
// answers nothing, and the step passes saying what is not in place.

// mailFromLabel is the subdomain the envelope uses. It is named for what it is
// rather than for where it sits, and it is a constant because a name that can
// differ between the wizard, the provider and the zone is a name that will.
const mailFromLabel = "mailfrom"

// sesRegionPattern is the shape of a region name, not a list of them. A list
// goes stale the week a region opens, and the failure of a stale list is a
// correct answer being refused.
var sesRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)

// bounceHost is where the relay accepts bounces for the envelope domain. It is
// derived from the region and never asked for: two answers that have to agree
// are two answers that will not.
func bounceHost(region string) string {
	if region == "" {
		return ""
	}
	return "feedback-smtp." + region + ".amazonses.com"
}

func stepMailFrom() Step {
	return Step{
		ID:    "mailfrom",
		Title: "The envelope domain",
		Kind:  Local,
		After: []string{"mail-dns"},
		desired: func(e *Engine) string {
			return fmt.Sprintf("write mail.mailFrom and mail.mailFromMX into %s, so %s.%s gets an MX for bounces "+
				"and an SPF record that points at the apex. Left empty, nothing is published and outbound mail "+
				"aligns on DKIM alone.", e.paths.WarpgateConfig, mailFromLabel, domainOr(e, "<domain>"))
		},
		need: func(e *Engine) *Need {
			envelope := mailFromLabel + "." + domainOr(e, "<domain>")
			return &Need{
				Kind:        "text",
				Label:       "Which region does this instance send mail from?",
				Placeholder: "eu-central-1",
				Value:       e.given.sesRegion,
				Help: "In the SES console, on the sending identity, set the custom MAIL FROM domain to " +
					envelope + " and choose \"Use default MAIL FROM domain\" as the behaviour on failure — " +
					"\"Reject message\" stops all outbound mail on a single DNS error. Then give the region here " +
					"and this wizard publishes the two records it needs.\n\n" +
					"The provider checks for those records for up to 72 hours and then gives up, so publish them " +
					"soon after setting the name.\n\n" +
					"Leave this empty to skip it: mail still authenticates with DKIM, which is what receivers " +
					"weigh most heavily. It is the second, independent proof that is missing.",
			}
		},
		accept: acceptString(func(e *Engine, s string) error {
			s = strings.ToLower(strings.TrimSpace(s))
			// Empty is an answer, and it means "not this". A step that refuses
			// to record a decision not to do something is a step that stays
			// amber forever with nothing wrong.
			if s != "" && !sesRegionPattern.MatchString(s) {
				return fmt.Errorf("%w: %q is not a region name — they look like eu-central-1", ErrBadAnswer, s)
			}
			e.given.sesRegion = s
			e.given.sesRegionSaid = true
			return nil
		}),
		run: func(e *Engine) result {
			d := e.catalogue().Domain
			if d == "" {
				return blocked("waiting on the domain")
			}
			region := e.sesRegion()
			if region == "" && !e.given.sesRegionSaid && !e.ours("mailfrom") {
				return blocked("waiting to be told which region mail is sent from, or told to skip it")
			}
			ed, err := openEdit(e.paths.WarpgateConfig, confMode)
			if err != nil {
				return failed(err.Error())
			}
			envelope := mailFromLabel + "." + d
			if region == "" {
				// Cleared rather than left behind. A mailFrom in the file with
				// no decision behind it publishes a subdomain on the next run
				// of a step nobody was thinking about.
				ed.set("mail.mailFrom", "")
				ed.set("mail.mailFromMX", "")
				res := e.applyOne(ed, "mail.mailFrom", "mail.mailFromMX")
				if res.status != passedStatus {
					return res
				}
				return passed("no envelope domain",
					"Nothing is published at "+envelope+", and warpgate publishes the envelope records only when "+
						"both mail.mailFrom and mail.mailFromMX are set.\n\n"+
						"Outgoing mail is authenticated by DKIM and aligns on that alone. SPF passes for the relay "+
						"rather than for "+d+", so a receiver weighing SPF alignment sees none.")
			}
			ed.set("mail.mailFrom", mailFromLabel)
			ed.set("mail.mailFromMX", bounceHost(region))
			return e.applyOne(ed, "mail.mailFrom", "mail.mailFromMX")
		},
	}
}

func stepMailFromVisible() Step {
	return Step{
		ID:        "mailfrom-visible",
		Title:     "The envelope domain reads back from outside",
		Kind:      Theirs,
		After:     []string{"mailfrom", "mail-apply"},
		WaitingOn: "the public DNS, and then the provider's own check",
		desired: fixed("ask a public resolver for the envelope domain's MX and SPF records. The provider looks for " +
			"exactly these two before it will use the domain, and it looks from outside, as this does."),
		run: func(e *Engine) result {
			d := e.catalogue().Domain
			if d == "" {
				return blocked("waiting on the domain")
			}
			region := e.sesRegion()
			if region == "" {
				// Not a pass dressed up as one: there is genuinely nothing to
				// observe, and the row says which decision led here rather than
				// reporting a success.
				return passed("no envelope domain to look for",
					"mailfrom recorded that no envelope domain is configured, so nothing was published at "+
						mailFromLabel+"."+d+" and there is nothing to read back.")
			}
			envelope := mailFromLabel + "." + d
			mx, err := e.dnsAnswers(envelope, "MX")
			if err != nil {
				return waitingOnThem(err.Error())
			}
			txt, err := e.dnsAnswers(envelope, "TXT")
			if err != nil {
				return waitingOnThem(err.Error())
			}
			want := bounceHost(region)
			var missing []string
			if !containsFold(mx, want) {
				missing = append(missing, "no MX at "+envelope+" naming "+want)
			}
			if !containsFold(txt, "v=spf1 redirect="+d) {
				missing = append(missing, "no SPF record at "+envelope+" reading v=spf1 redirect="+d)
			}
			if len(missing) > 0 {
				return waitingOnThem(strings.Join(missing, "; ") +
					". Cloudflare caches a miss for 30 minutes, so records published just now take up to that " +
					"long to appear here.")
			}
			return passed("both records are visible from outside", fmt.Sprintf(
				"a public resolver that is not Cloudflare answered for %s:\n  MX  %s\n  TXT %s\n\n"+
					"The provider looks for exactly these before it will use %s as the envelope domain, and it "+
					"gives up after 72 hours. Once it accepts them, a delivered message carries %s in its "+
					"Return-Path and SPF counts for %s rather than for the relay.",
				envelope, strings.Join(mx, ", "), strings.Join(txt, ", "), envelope, envelope, d))
		},
	}
}

// dnsAnswers asks a public resolver, and it is the one place the wizard reads
// DNS. The resolver is deliberately not the one the records were written to:
// reading them back from Cloudflare would establish that Cloudflare stored what
// it was sent, which nobody doubts.
func (e *Engine) dnsAnswers(name, typ string) ([]string, error) {
	u := "https://dns.google/resolve?type=" + url.QueryEscape(typ) + "&name=" + url.QueryEscape(name)
	res, err := e.fetch(context.Background(), u)
	if err != nil {
		return nil, fmt.Errorf("a public resolver could not be asked about %s %s: %v", typ, name, err)
	}
	if res.Status != 200 {
		return nil, fmt.Errorf("the public resolver answered %d for %s %s", res.Status, typ, name)
	}
	var body struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal([]byte(res.Body), &body); err != nil {
		return nil, fmt.Errorf("the public resolver's answer about %s %s could not be read: %v", typ, name, err)
	}
	var out []string
	for _, a := range body.Answer {
		out = append(out, strings.Trim(strings.TrimSpace(a.Data), `"`))
	}
	return out, nil
}

func containsFold(in []string, want string) bool {
	for _, s := range in {
		if strings.Contains(strings.ToLower(s), strings.ToLower(want)) {
			return true
		}
	}
	return false
}

// sesRegion is what was answered in this process, or what the file already
// says. The file is the state; `given` is only what has been said since.
func (e *Engine) sesRegion() string {
	if e.given.sesRegionSaid {
		return e.given.sesRegion
	}
	tree, _, err := readTree(e.paths.WarpgateConfig)
	if err != nil {
		return ""
	}
	host := atString(tree, "mail.mailFromMX")
	// The region is carried by the host name and derived back out of it, rather
	// than stored twice. Two fields that have to agree are two fields that will
	// not, and the one that goes stale is the one nothing reads.
	const prefix, suffix = "feedback-smtp.", ".amazonses.com"
	if !strings.HasPrefix(host, prefix) || !strings.HasSuffix(host, suffix) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, prefix), suffix)
}
