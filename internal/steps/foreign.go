package steps

import (
	"fmt"
	"strconv"

	"context"
	"encoding/json"
	"github.com/sxty9/Holistic/internal/cfauth"
	"os"
	"strings"
)

// The steps that talk to somebody else.
//
// They are defined here — id, kind, what they need, what they intend, and where
// they sit in the order — and their run() says it is not implemented. That is a
// deliberate half, not an omission, and the halves are chosen rather than
// arbitrary.
//
// Defining them costs nothing and is worth a lot: the page can render the whole
// wizard, the dependency graph is complete, the plan can name what is coming,
// and the ledger has a row for every one of them from the first run. A wizard
// that only lists the steps it can already do is a wizard that cannot tell you
// what it is waiting for.
//
// Not writing the calls is the other half. Two of these — tunnel-ensure and
// dns-apply — create things in somebody's Cloudflare account that this machine
// cannot un-create, and one of them writes into a zone that may be carrying
// their real website and their real mail. Guessing at an API's shape from this
// side of the wire and then running it unattended is precisely the sequence
// that turns "setup" into "an afternoon restoring a zone from memory". They go
// in when they can be written against the real API, with the write-ahead ledger
// entry in front of every create and a conflict path for every record that is
// already there.
//
// A run of one of these records pending rather than failed, because pending is
// what it is: the step is ahead of the wizard, not broken by it.

func stepTokenVerify() Step {
	return Step{
		ID:    "token-verify",
		Title: "Verify the Cloudflare token",
		Kind:  Foreign,
		desired: fixed("ask Cloudflare what this token actually carries, and compare it with the four rows that were " +
			"asked for — before it is written anywhere on this machine"),
		need: func(e *Engine) *Need {
			// Never a Value. A `secret` need is submitted and never returned,
			// not even masked: a masked secret in a JSON response is still a
			// secret in a browser's memory, in a proxy log, and in whatever the
			// page later serialises.
			var help string
			for _, p := range cfauth.Setup() {
				help += p.Label + " — " + p.Why + "\n"
			}
			return &Need{
				Kind:  "secret",
				Label: "Cloudflare API token",
				Help: "Create a custom token with exactly these four rows:\n\n" + help +
					"\nThe link below opens Cloudflare's form with them already filled in.",
				Link: cfauth.TokenURL(cfauth.Setup(), "", "Holistic setup"),
			}
		},
		accept: acceptString(func(e *Engine, s string) error {
			if s == "" {
				return fmt.Errorf("%w: the token is empty", ErrBadAnswer)
			}
			// Into secrets, never into `given`. Everything in `given` is
			// eligible to be rendered back to the page; nothing in here is, and
			// the separation is the guarantee rather than a convention.
			e.secrets["token-verify"] = s
			return nil
		}),
		run: func(e *Engine) result {
			if e.secret("token-verify") == "" {
				return blocked("waiting for a Cloudflare API token")
			}
			tok := e.secret("token-verify")
			if e.given.domain == "" {
				return blocked("waiting on the domain, which is what the token is checked against")
			}
			active, err := e.cf.TokenActive(context.Background(), tok)
			if err != nil {
				return failed("Cloudflare would not answer about this token: " + err.Error())
			}
			z, err := e.cf.Zone(context.Background(), tok, e.given.domain)
			if err != nil {
				return failed("the token is live, but " + err.Error())
			}
			e.given.zone = z

			// Email routing has to be asked about; the zone's permissions
			// array does not report it either way. An error asking is not a
			// refusal: the answer is left out of the map, and JudgeZoneWith
			// treats an unanswered permission as unjudged rather than missing.
			// Refusing a token because a check could not run is the failure
			// this wizard exists to prevent.
			asked := map[string]bool{}
			mailNote := ""
			if ok, err := e.cf.CanWriteEmailRouting(context.Background(), tok, z.ID); err != nil {
				mailNote = " Whether it may create email routing rules could not be established: " + err.Error() +
					" — the mail steps will say so when they get there."
			} else {
				asked["email_routing_rule"] = ok
				if ok {
					mailNote = " It may create email routing rules, asked directly: " +
						"the zone's permissions array does not report that one either way."
				}
			}

			v := cfauth.JudgeZoneWith(active, z.Permissions, cfauth.Setup(), asked)

			// Said whether the token passes or fails. A grant wider than the
			// request is not a reason to refuse — it does the job, and a hard
			// stop would make the wizard unusable for anybody reusing a token
			// they already trust — but it must not pass in silence. The whole
			// point of reading the grant back is to compare it with what was
			// asked for, and that comparison has two directions.
			excess := ""
			if len(v.Excess) > 0 {
				excess = "\n\nThis token also carries " + strconv.Itoa(len(v.Excess)) +
					" thing(s) the wizard did not ask for: " + strings.Join(v.Excess, ", ") +
					". They are not needed here, and each one is something this machine could do to " +
					"your zone if it were ever taken. Removing them is the same edit as adding a row."
			}

			if !v.OK() {
				var want []string
				for _, m := range v.Missing {
					want = append(want, m.Label)
				}
				return held(Conflict{
					Summary:   "the Cloudflare token cannot do everything this instance needs on " + z.Name + ".",
					Object:    "the Cloudflare API token, on " + z.Name,
					Found:     strings.Join(z.Permissions, ", "),
					FoundNote: "what this token can do on this zone, from the zone's own answer",
					Desired:   strings.Join(want, ", ") + " (in addition to what it already has)",
					Why: "Without these the wizard cannot turn on Email Routing, and inbound mail never " +
						"arrives. Everything else would appear to succeed.",
					Resolution: "Cloudflare -> My Profile -> API Tokens -> edit this token, add the rows above, " +
						"and Continue to summary -> Update token. Then check again.\n\n" +
						"The token itself does not change, so nothing on this machine has to be updated." + excess,
					Consequence: "inbound mail is not set up. Everything that does not need it still works.",
				})
			}
			// How far the token reaches. This used to say the question could
			// not be asked without User API Tokens Read; that is true of the
			// token's own definition and false of its reach, which the zones
			// answer themselves. Measured on 2026-08-30 against a token that
			// looked single-zone here and turned out to carry two.
			//
			// A failure to list is not a failure of the step: the grant on
			// THIS zone is what the wizard needs, and this is a warning it
			// would like to give rather than one it depends on.
			reach := ""
			if names, err := e.cf.ZoneNames(context.Background(), tok); err != nil {
				reach = " How far the token reaches beyond this zone could not be read: " + err.Error()
			} else if len(names) > 1 {
				reach = " It also reaches " + strconv.Itoa(len(names)-1) + " other zone(s): " +
					strings.Join(without(names, z.Name), ", ") +
					". A token scoped to one zone takes the same number of clicks and keeps them out of reach."
			} else {
				reach = " It reaches this zone and no other."
			}

			return passed(
				"valid, and carries what this zone needs"+shorten(excess),
				"zone "+z.Name+" reports: "+strings.Join(z.Permissions, ", ")+
					" — this is the grant ON THIS ZONE."+mailNote+reach)
		},
	}
}

func stepZoneResolve() Step {
	return Step{
		ID:    "zone-resolve",
		Title: "Find the zone",
		Kind:  Foreign,
		After: []string{"token-verify"},
		desired: fixed("look the domain up as a zone, require status == active, and keep the zone id and account id. " +
			"A record written into a pending zone answers nobody."),
		run: func(e *Engine) result {
			tok := e.secret("token-verify")
			if tok == "" || e.given.domain == "" {
				return blocked("waiting on the token and the domain")
			}
			z, err := e.cf.Zone(context.Background(), tok, e.given.domain)
			if err != nil {
				return failed(err.Error())
			}
			e.given.zone = z
			if !strings.EqualFold(z.Status, "active") {
				// Not a failure. The zone is waiting on a registrar, and the
				// nameservers step is where that wait is shown — naming whose
				// clock it is on, which is the whole reason that state exists.
				return waitingOnThem("the zone is " + z.Status + ", not active. Cloudflare is waiting for the " +
					"registrar to point at " + strings.Join(z.Nameservers, " and "))
			}
			return passed("active",
				"zone "+z.ID+" in account "+z.AccountID+", status "+z.Status+
					", nameservers "+strings.Join(z.Nameservers, " "))
		},
	}
}

func stepNameservers() Step {
	return Step{
		ID:        "nameservers",
		Title:     "The registrar's nameservers",
		Kind:      Theirs,
		After:     []string{"zone-resolve"},
		WaitingOn: "your registrar",
		desired: fixed("wait for the zone to go active after the nameservers are changed at the registrar. " +
			"Registrars have no API for this, so it is done by hand and then watched for."),
		need: func(e *Engine) *Need {
			// See the note on the admin step: a manual instruction is withdrawn
			// once the thing has been done.
			if e.ours("nameservers") {
				return nil
			}
			return &Need{
				Kind:  "manual",
				Label: "Point your domain at Cloudflare's nameservers",
				Instructions: "Cloudflare shows two nameservers on the zone's Overview page. Set them at your " +
					"registrar, replacing what is there now.\n\nThis can take minutes or a day, and nothing here can " +
					"make it faster. Leave this page open or come back to it — the wizard's place is kept on the " +
					"machine, not in this tab.",
				Recheck: true,
			}
		},
		run: func(e *Engine) result {
			tok := e.secret("token-verify")
			if tok == "" || e.given.domain == "" {
				return blocked("waiting on the token and the domain")
			}
			z, err := e.cf.Zone(context.Background(), tok, e.given.domain)
			if err != nil {
				return failed(err.Error())
			}
			e.given.zone = z
			if strings.EqualFold(z.Status, "active") {
				return passed("the registrar is pointing at Cloudflare",
					"zone "+z.Name+" is active; nameservers "+strings.Join(z.Nameservers, " "))
			}
			// The nameservers go in the detail, because they are what the
			// operator has to type somewhere this wizard cannot reach.
			return waitingOnThem("the zone is " + z.Status + ". Set these two at your registrar: " +
				strings.Join(z.Nameservers, " and "))
		},
	}
}

func stepZoneInventory() Step {
	return Step{
		ID:    "zone-inventory",
		Title: "Read the zone before changing it",
		Kind:  Foreign,
		After: []string{"token-store"},
		desired: fixed("export every record in the zone into the ledger before anything is written to it. " +
			"It is the only copy of what was there that this machine will ever have."),
		run: func(e *Engine) result {
			tok := e.secret("token-verify")
			z := e.given.zone
			if tok == "" || z.ID == "" {
				return blocked("waiting on the zone, which zone-resolve finds")
			}
			recs, err := e.cf.Records(context.Background(), tok, z.ID)
			if err != nil {
				return failed("the zone could not be read: " + err.Error())
			}
			// One line per record, in the zone file's own shape. It is written
			// into the ledger as the proof, which means it survives this
			// process and can be read back after everything has changed.
			var b strings.Builder
			var foreign int
			for _, r := range recs {
				if !r.Ours() {
					foreign++
				}
				fmt.Fprintf(&b, "%s\t%d\tIN\t%s\t%s", r.Name, r.TTL, r.Type, r.Content)
				if r.Proxied {
					b.WriteString("\t; proxied")
				}
				if r.Comment != "" {
					fmt.Fprintf(&b, "\t; %s", r.Comment)
				}
				b.WriteString("\n")
			}
			return passed(
				fmt.Sprintf("%d record(s), %d of them not created here", len(recs), foreign),
				b.String())
		},
	}
}

func stepTunnelEnsure() Step {
	return Step{
		ID:    "tunnel-ensure",
		Title: "The tunnel",
		Kind:  Foreign,
		After: []string{"zone-inventory"},
		desired: fixed("create the tunnel this instance is reached through, writing it to the ledger BEFORE the call " +
			"that creates it. This is the first thing that exists in somebody's account because of this machine."),
		run: func(e *Engine) result {
			// Creating a tunnel is an account-scoped call, and the setup token
			// is deliberately zone-scoped — cfauth.Setup() has nothing
			// account-category in it, and that property is defended there
			// rather than incidental. So this step does not create; it checks,
			// and hands back the one command that does.
			cfgPath := e.paths.WarpgateConfig
			id, credsPath := warpgateTunnel(cfgPath)
			if id == "" || credsPath == "" {
				return held(Conflict{
					Object:    "tunnel.id and tunnel.credentialsFile in " + cfgPath,
					Found:     "not set",
					FoundNote: "no tunnel has been created for this instance yet",
					Desired:   "a tunnel this machine owns, and the credentials file that proves it",
					Why: "Creating a tunnel is an account-scoped call, and this instance's Cloudflare token is " +
						"scoped to one zone on purpose. A token that could create tunnels could also delete " +
						"every other one in the account.",
					Resolution: "On this machine:\n\n    cloudflared tunnel create warpgate\n\n" +
						"then put the id and the credentials path it prints into " + cfgPath + ".",
					Consequence: "nothing can be published. Every hostname would resolve to a tunnel that is not there.",
				})
			}
			if _, err := os.Stat(credsPath); err != nil {
				return held(Conflict{
					Object:    credsPath,
					Found:     "missing",
					FoundNote: "the configuration names a tunnel, and the file that proves this machine owns it is not there",
					Desired:   "the credentials file cloudflared writes when it creates a tunnel",
					Why: "The connector cannot start without it. DNS would be published pointing at a tunnel " +
						"nothing is serving, and every hostname would answer Cloudflare error 1033 — which in a " +
						"browser is indistinguishable from the origin being down, and has the opposite fix.",
					Resolution:  "Restore the file, or create the tunnel again:\n\n    cloudflared tunnel create warpgate",
					Consequence: "nothing can be published.",
				})
			}
			return passed("tunnel "+id+" is configured and its credentials are on disk", credsPath+" exists")
		},
	}
}

func stepDNSApply() Step {
	return Step{
		ID:    "dns-apply",
		Title: "Publish the hostnames",
		Kind:  Foreign,
		After: []string{"plan-show", "tunnel-ensure"},
		desired: fixed("create one proxied CNAME per app hostname, pointing at the tunnel — and refuse, per record, " +
			"where something is already standing there"),
		run: func(e *Engine) result {
			// This step writes nothing. It runs warpgate, which is the only
			// thing in this landscape that writes DNS — and which refuses to
			// overwrite a record it did not create, marks what it does create,
			// asks separately before deleting, and keeps a journal. Teaching a
			// second thing to do all of that is how the two come to disagree,
			// and the day they disagree is the day somebody's website is
			// replaced by a launcher.
			bin := e.paths.WarpgateBin
			cfg := e.paths.WarpgateConfig
			plan, err := e.machine.Run(bin, "-config", cfg, "plan")
			if err != nil {
				return failed("warpgate could not plan the edge:\n" + plan)
			}
			if strings.Contains(plan, "CONFLICT") {
				return held(Conflict{
					Object:    "the zone " + e.given.domain,
					Found:     firstConflictBlock(plan),
					FoundNote: "warpgate found records it did not create",
					Desired:   "the hostnames this instance publishes",
					Why: "Publishing over a record warpgate did not create would replace whatever is " +
						"being served there today, and warpgate refuses rather than guessing which of you is right.",
					Resolution:  "The block above names what is in the way and what to do about it. Then check again.",
					Consequence: "the apps are not published yet. Everything already published keeps working.",
				})
			}
			// A settled edge is something warpgate SAYS, not something absent
			// from its output. Reading silence as "nothing to do" would turn a
			// warpgate that printed nothing — the wrong binary, a truncated
			// pipe, a version that changed its wording — into a successful
			// publish that published nothing, reported as passed.
			settled := strings.Contains(plan, "Nothing to do") || strings.Contains(plan, "0 change(s)")
			hasWork := strings.Contains(plan, "change(s)") && !settled
			switch {
			case settled:
				return passed("the edge already matches the configuration", strings.TrimSpace(plan))
			case !hasWork:
				return failed("warpgate did not say what it would change. Its output was:\n" + strings.TrimSpace(plan))
			}
			out, err := e.machine.Run(bin, "-config", cfg, "apply", "--yes")
			if err != nil {
				return failed("warpgate apply did not finish:\n" + out)
			}
			return passed("published", strings.TrimSpace(out))
		},
	}
}

func stepConnectorRegistered() Step {
	return Step{
		ID:        "connector-registered",
		Title:     "The connector is registered",
		Kind:      Theirs,
		After:     []string{"ingress-write"},
		WaitingOn: "Cloudflare's edge",
		desired: fixed("wait for `Registered tunnel connection` in the connector's log — not for the unit to be " +
			"active. A running connector that has not registered is the failure that looks exactly like success."),
		run: func(e *Engine) result {
			// "Registered tunnel connection", not "unit active". A connector
			// that is running and has not registered is a connector serving
			// nobody, and systemd cannot tell the difference — it is the same
			// class of mistake as reporting a 200 from an API as proof that
			// mail arrived.
			unit := e.paths.ConnectorUnit
			out, err := e.machine.Run("journalctl", "-u", unit, "-b", "--no-pager", "-n", "200")
			if err != nil {
				return failed("the connector's journal could not be read: " + out)
			}
			var n int
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "Registered tunnel connection") {
					n++
				}
			}
			if n == 0 {
				if !e.machine.IsActive(unit) {
					return failed(unit + " is not running, so nothing is serving the hostnames that were published")
				}
				return waitingOnThem(unit + " is running and has not registered with Cloudflare yet")
			}
			return passed(fmt.Sprintf("%d connection(s) registered", n),
				"from "+unit+"'s journal this boot, not from systemctl is-active")
		},
	}
}

func stepCertWait() Step {
	return Step{
		ID:        "cert-wait",
		Title:     "The certificate",
		Kind:      Theirs,
		After:     []string{"dns-apply"},
		WaitingOn: "Cloudflare's certificate authority",
		desired: fixed("wait for the universal certificate to cover the app hostnames. This runs on their clock and " +
			"can outlive a session."),
		run: func(e *Engine) result {
			// Asked of the certificate rather than of Cloudflare's API: the
			// question is whether a stranger's browser can complete a
			// handshake, and only a handshake answers that.
			d := e.given.domain
			if d == "" {
				return blocked("waiting on the domain")
			}
			res, err := e.fetch(context.Background(), "https://"+d+"/")
			if err != nil {
				if isTLSProblem(err) {
					return waitingOnThem("the certificate for " + d + " is not serving yet: " + err.Error())
				}
				return waitingOnThem("https://" + d + " did not answer: " + err.Error())
			}
			return passed(fmt.Sprintf("https answered %d", res.Status),
				"a TLS handshake with "+d+" completed from this machine's own network stack")
		},
	}
}

func stepNonceProbe() Step {
	return Step{
		ID:        "nonce-probe",
		Title:     "Each hostname answers, from outside",
		Kind:      Theirs,
		After:     []string{"cert-wait"},
		WaitingOn: "the public internet",
		desired: fixed("fetch every app hostname from the public internet with a nonce, and add an origin to coreX's " +
			"appOrigins only for the ones that come back. An origin map listing eight hostnames that do not resolve " +
			"is the populated-but-wrong state that shipped once already."),
		run: func(e *Engine) result {
			// Every hostname, from outside, one at a time, each with a value
			// that has never been requested before. The unique query defeats
			// every cache between here and there, so a 200 is this instance
			// answering now rather than something remembering an earlier one.
			//
			// It is not a full round trip — nothing echoes the value back —
			// and saying so matters: this proves the path from the public
			// internet through Cloudflare and the tunnel to the local service,
			// which is exactly the path that was silently broken for three
			// days, but it does not prove which process answered.
			cat := e.catalogue()
			var proof strings.Builder
			var bad []string
			for _, h := range cat.WebHostnames() {
				nonce := fmt.Sprintf("%d-%d", e.now().UnixNano(), len(proof.String()))
				res, err := e.fetch(context.Background(), "https://"+h+"/?holistic-probe="+nonce)
				if err != nil {
					bad = append(bad, h+": "+err.Error())
					continue
				}
				if res.Status < 200 || res.Status >= 400 {
					bad = append(bad, fmt.Sprintf("%s: %d", h, res.Status))
					continue
				}
				fmt.Fprintf(&proof, "%s -> %d (probe %s, via %s)\n",
					h, res.Status, nonce, firstNonEmpty(res.Header.Get("cf-ray"), "no cf-ray"))
			}
			if len(bad) > 0 {
				return waitingOnThem("not answering from the public internet yet: " + strings.Join(bad, "; "))
			}
			return passed(fmt.Sprintf("%d hostname(s) answered from outside", len(cat.WebHostnames())), proof.String())
		},
	}
}

// warpgateTunnel reads the tunnel this instance is configured to use.
//
// Warpgate's configuration is read rather than duplicated here. The wizard
// writes those two fields in the warpgate-config step and then asks the file
// what they are, instead of remembering — because a restart between the two
// would otherwise lose the answer, and because the file is what warpgate
// itself will read.
func warpgateTunnel(cfgPath string) (id, credentialsFile string) {
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", ""
	}
	var cfg struct {
		Tunnel struct {
			ID              string `json:"id"`
			CredentialsFile string `json:"credentialsFile"`
		} `json:"tunnel"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return "", ""
	}
	return cfg.Tunnel.ID, cfg.Tunnel.CredentialsFile
}

// firstConflictBlock lifts warpgate's own conflict report out of its output.
//
// Quoted rather than summarised: the operator has to recognise their own zone
// in it, and a paraphrase of somebody else's DNS record is a paraphrase of the
// one thing they need to look at.
func firstConflictBlock(out string) string {
	i := strings.Index(out, "CONFLICT")
	if i < 0 {
		return strings.TrimSpace(out)
	}
	rest := out[i:]
	// Warpgate separates blocks with a blank line followed by a non-indented
	// line; stopping at the first of those keeps one conflict rather than all
	// of them, which is what a single held row can carry.
	if j := strings.Index(rest, "\n\n  The rest of the plan"); j > 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// isTLSProblem separates "the certificate is not there yet" from "the host did
// not answer at all". They look identical in a failed fetch and they are
// different waits: one is on Cloudflare, the other is on this machine.
func isTLSProblem(err error) bool {
	s := strings.ToLower(err.Error())
	for _, m := range []string{"certificate", "tls", "handshake", "x509"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// shorten turns the excess note into something that fits on a ledger line. The
// full sentence belongs in a conflict report; a passed step gets the count and
// the names, because a line nobody can read is a line nobody reads.
func shorten(excess string) string {
	if excess == "" {
		return ""
	}
	i := strings.Index(excess, "did not ask for: ")
	return " — and " + excess[i+len("did not ask for: "):strings.Index(excess, ". They are not")] + ", which it did not need"
}

// without is names minus one of them, so a list of "the others" reads as one.
func without(names []string, drop string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !strings.EqualFold(n, drop) {
			out = append(out, n)
		}
	}
	return out
}
