package steps

import (
	"fmt"

	"github.com/sxty9/Holistic/internal/cfauth"
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
			return notYet("this calls Cloudflare's /user/tokens/verify and compares the answer with cfauth.Setup(). " +
				"cfauth.Judge already does the comparison; the call is what is missing.")
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
			return notYet("this lists zones filtered by name and reads status and account from the answer.")
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
			return notYet("this re-reads the zone and looks for status == active.")
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
			return notYet("this lists every record in the zone and records the export.")
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
			return notYet("this is one of the two irreversible creates. It is not going in unattended: it needs the " +
				"write-ahead ledger entry, the credential handling, and a decision about what to do with a tunnel of " +
				"the same name that is already there.")
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
			return notYet("this is the other irreversible create, and it writes into a zone that may be carrying a " +
				"live website and live mail. Every record needs the ownership check and the six-field conflict before " +
				"any of them is written.")
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
			return notYet("this reads the connector's journal for the registration line. It deliberately does not " +
				"accept `systemctl is-active` as the answer.")
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
			return notYet("this polls the zone's certificate status until the hostnames are covered.")
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
			return notYet("this probes each hostname with a nonce and writes instance.appOrigins one app at a time. " +
				"catalogue.CoreXOrigins already takes the proven set; the probe is what is missing.")
		},
	}
}
