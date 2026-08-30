package steps

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"encoding/json"
	"github.com/sxty9/Holistic/internal/catalogue"
	"github.com/sxty9/Holistic/internal/instance"
	"github.com/sxty9/Holistic/internal/ledger"
)

// Configuration files are written 0640. The service accounts read them; nobody
// else on the machine has any business doing so. The credential is 0600 and has
// its own writer.
const confMode os.FileMode = 0o640

const tokenMode os.FileMode = 0o600

// stepDomain records the domain and contacts nothing.
//
// It is a step rather than a field on a form because it is the one decision
// every later step is derived from, and because it has a real failure mode of
// its own: what a person pastes into a domain box is very often a URL.
func stepDomain() Step {
	return Step{
		ID:    "domain",
		Title: "The domain this instance answers on",
		Kind:  Local,
		desired: func(e *Engine) string {
			if d := e.given.domain; d != "" {
				return "record " + d + " as this instance's domain. Nothing is contacted."
			}
			return "record the domain you already own. Nothing is contacted at this step: no DNS query, no provider call."
		},
		need: func(e *Engine) *Need {
			return &Need{
				Kind:        "text",
				Label:       "Domain",
				Placeholder: "example.org",
				Value:       e.given.domain,
				Help: "The domain you already own, on its own — no https:// and no path. " +
					"Every app is published one label under it.",
			}
		},
		accept: acceptString(func(e *Engine, s string) error {
			d, err := cleanDomain(s)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrBadAnswer, err)
			}
			e.given.domain = d
			return nil
		}),
		run: func(e *Engine) result {
			d := e.given.domain
			if d == "" {
				return blocked("waiting to be told the domain")
			}
			// Written to the ledger only when it is new. Running a step twice
			// has to leave the machine as it was, and that includes the file
			// this process keeps its own state in.
			if !(e.ours("domain") && e.recordedDetail("domain") == d) {
				if err := e.led.Domain(d); err != nil {
					return failed("the ledger could not record the domain: " + err.Error())
				}
			}
			// Detail is the domain verbatim, and deliberately so: it is the
			// only field the ledger exposes that a restarted process can read
			// back to learn what was decided. See Engine.reread.
			return result{
				status: passedStatus,
				detail: d,
				proof: d + " is recorded as this instance's domain. Nothing was contacted to establish it: " +
					"no DNS query was made and no provider was called, so this is a decision rather than an observation.",
			}
		},
	}
}

func stepDisplayName() Step {
	return Step{
		ID:    "display-name",
		Title: "What this instance calls itself",
		Kind:  Local,
		desired: func(e *Engine) string {
			return "write instance.displayName into " + e.paths.CoreXConfig
		},
		need: func(e *Engine) *Need {
			return &Need{
				Kind:        "text",
				Label:       "Name",
				Placeholder: "Home",
				Value:       e.given.displayName,
				Help:        "Shown in the launcher and in the sign-in page. It is not the domain and nothing derives from it.",
			}
		},
		accept: acceptString(func(e *Engine, s string) error {
			if s == "" {
				return fmt.Errorf("%w: a name is needed", ErrBadAnswer)
			}
			if len(s) > 64 {
				return fmt.Errorf("%w: that is longer than a name anybody reads", ErrBadAnswer)
			}
			e.given.displayName = s
			return nil
		}),
		run: func(e *Engine) result {
			name := e.given.displayName
			if name == "" {
				return blocked("waiting to be told what this instance calls itself")
			}
			ed, err := openEdit(e.paths.CoreXConfig, confMode)
			if err != nil {
				return failed(err.Error())
			}
			// No conflict check here, and that is a decision rather than an
			// oversight. A display name has no dependents — nothing resolves
			// it, nothing is scoped to it — and the person was asked. Refusing
			// the reply the wizard solicited would be the conflict rule used
			// against the thing it exists to protect.
			ed.set("instance.displayName", name)
			return e.applyOne(ed, "instance.displayName")
		},
	}
}

func stepStorage() Step {
	return Step{
		ID:    "storage",
		Title: "Where data lives",
		Kind:  Local,
		desired: func(e *Engine) string {
			return "write dataDir into " + e.paths.CoreXConfig + ", and create the directory if it is not there"
		},
		need: func(e *Engine) *Need {
			v := e.given.dataDir
			if v == "" {
				tree, _, err := readTree(e.paths.CoreXConfig)
				if err == nil {
					v = atString(tree, "dataDir")
				}
			}
			return &Need{
				Kind:        "text",
				Label:       "Data directory",
				Placeholder: e.paths.DataDir,
				Value:       v,
				Help: "Mail, files, calendars and the database live here. Put it on the disk you back up. " +
					"It can be moved later, but not by this wizard.",
			}
		},
		accept: acceptString(func(e *Engine, s string) error {
			if !strings.HasPrefix(s, "/") {
				return fmt.Errorf("%w: an absolute path, starting with /", ErrBadAnswer)
			}
			e.given.dataDir = strings.TrimRight(s, "/")
			return nil
		}),
		run: func(e *Engine) result {
			want := e.given.dataDir
			if want == "" {
				return blocked("waiting to be told where data lives")
			}
			ed, err := openEdit(e.paths.CoreXConfig, confMode)
			if err != nil {
				return failed(err.Error())
			}
			// The one setting in this file where being wrong costs data. A
			// dataDir already pointing somewhere else, with something in it, is
			// an instance that already has state; pointing coreX at a new empty
			// directory would not move that state, it would orphan it, and
			// every check afterwards would report a healthy empty instance.
			if had := atString(ed.tree, "dataDir"); had != "" && had != want && !e.ours("storage") && notEmptyDir(had) {
				return held(Conflict{
					Object:    "dataDir in " + e.paths.CoreXConfig,
					Found:     quote(had),
					FoundNote: "the directory exists and is not empty",
					Desired:   quote(want),
					Why: "Changing where data lives does not move what is already there. coreX would start against an empty " +
						want + " and report a healthy instance with nobody's mail, files or calendars in it.",
					Resolution: "Keep " + had + ", or move its contents to " + want + " yourself and run this step again.",
					Consequence: "Nothing is lost while this is unresolved — the existing data is untouched at " + had +
						" and coreX is still pointed at it.",
				})
			}
			if err := os.MkdirAll(want, 0o750); err != nil {
				return failed("could not create " + want + ": " + err.Error())
			}
			ed.set("dataDir", want)
			return e.applyOne(ed, "dataDir")
		},
	}
}

// engineBinaries maps the offered choice onto the program that has to be on the
// machine for it to be true.
var engineBinaries = map[string]string{
	"claude": "claude",
	"ollama": "ollama",
}

func stepEngines() Step {
	return Step{
		ID:    "engines",
		Title: "Which AI engines are configured",
		Kind:  Local,
		desired: func(e *Engine) string {
			return "check the chosen engine is actually on this machine, then write ai.engines into " + e.paths.CoreXConfig
		},
		need: func(e *Engine) *Need {
			return &Need{
				Kind:  "choice",
				Label: "AI engine",
				Value: e.given.engine,
				Help: "The Assistant app needs one of these. Choosing none leaves Assistant off; " +
					"it does not affect mail, files or calendars.",
				Options: []Option{
					{Value: "none", Label: "None"},
					{Value: "claude", Label: "Claude CLI on this machine"},
					{Value: "ollama", Label: "A local model through Ollama"},
				},
			}
		},
		accept: acceptString(func(e *Engine, s string) error {
			if s != "none" && engineBinaries[s] == "" {
				return fmt.Errorf("%w: %q is not one of the offered engines", ErrBadAnswer, s)
			}
			e.given.engine = s
			return nil
		}),
		run: func(e *Engine) result {
			choice := e.given.engine
			if choice == "" {
				return blocked("waiting to be told which AI engine to configure")
			}
			ed, err := openEdit(e.paths.CoreXConfig, confMode)
			if err != nil {
				return failed(err.Error())
			}
			if choice == "none" {
				ed.set("ai.engines", []string{})
				res := e.applyOne(ed, "ai.engines")
				if res.status == passedStatus {
					res.proof = "no AI engine is configured. Assistant will not be offered."
				}
				return res
			}
			// The observation, rather than the checkbox. Writing "claude" into
			// a config file is not evidence that a claude binary exists, and
			// the failure it produces later is an app that opens and does
			// nothing, three steps away from anything that mentions engines.
			bin := engineBinaries[choice]
			out, runErr := e.machine.Run(bin, "--version")
			if runErr != nil {
				return failed(fmt.Sprintf("%s is not usable on this machine: %v\n%s", bin, runErr, out))
			}
			ed.set("ai.engines", []string{choice})
			res := e.applyOne(ed, "ai.engines")
			if res.status == passedStatus {
				res.proof = fmt.Sprintf("%s answered `%s --version` with %q, and ai.engines is [%q] in %s.",
					bin, bin, firstLine(out), choice, e.paths.CoreXConfig)
			}
			return res
		},
	}
}

func stepAdmin() Step {
	return Step{
		ID:        "admin",
		Title:     "An administrator exists",
		Kind:      Shell,
		WaitingOn: "you, at this machine's terminal",
		desired: func(e *Engine) string {
			return "ask " + e.paths.Corexctl + " whether this instance has an administrator"
		},
		need: func(e *Engine) *Need {
			// A `manual` need is an instruction to go and do something, not a
			// value to edit, so it stops being asked for once it has been done.
			// A text need stays — editing it is what a later domain change is —
			// but a page still telling somebody to create an administrator they
			// already created is a page telling them they failed.
			if e.ours("admin") {
				return nil
			}
			return &Need{
				Kind:  "manual",
				Label: "Create the administrator on the machine",
				Instructions: "On the machine itself, run:\n\n    sudo " + e.paths.Corexctl + " admin create\n\n" +
					"It asks for the password over stdin. This page will not ask for one, and that is not caution for " +
					"its own sake: it is served over plain HTTP on a name anyone on this network can claim, so a password " +
					"typed here would be saved by a password manager against an origin every Holistic instance in the " +
					"world shares, and offered back on somebody else's machine.",
				Recheck: true,
			}
		},
		run: func(e *Engine) result {
			out, err := e.machine.Run(e.paths.Corexctl, "admin", "list")
			if err != nil {
				return failed(fmt.Sprintf("%s could not be asked: %v\n%s", e.paths.Corexctl, err, out))
			}
			if strings.TrimSpace(out) == "" {
				return waitingOnThem("no administrator exists yet. It is created on the machine, over stdin.")
			}
			return passed(
				"an administrator exists",
				fmt.Sprintf("`%s admin list` answered: %s", e.paths.Corexctl, firstLine(out)),
			)
		},
	}
}

// stepApps is the one answer and the three outputs.
//
// The three files are written as one act because two of them agreeing and the
// third not is worse than none of them being written. Solisuite's apps[] is the
// half nothing has ever generated: appFor() maps a Host header to an app, and
// without host and origin in that list it falls back to defaultApp for every
// hostname — so an instance whose DNS and ingress are perfect serves the same
// document at eight different names, and nothing anywhere reports an error.
func stepApps() Step {
	return Step{
		ID:    "apps",
		Title: "Which apps this instance publishes",
		Kind:  Local,
		After: []string{"domain"},
		desired: func(e *Engine) string {
			c := e.catalogue()
			if c.Domain == "" {
				return "write the app list into Warpgate, Solisuite and coreX — all three, or none"
			}
			return fmt.Sprintf("publish %d apps under %s, and write all three configurations that have to agree: "+
				"%s apps[], %s apps[] with host and origin, %s instance.appOrigins",
				len(c.Enabled()), c.Domain, e.paths.WarpgateConfig, e.paths.SolisuiteConfig, e.paths.CoreXConfig)
		},
		need: func(e *Engine) *Need {
			c := e.catalogue()
			opts := make([]Option, 0, len(c.Apps))
			for _, a := range c.Apps {
				opts = append(opts, Option{
					ID: a.ID, Label: a.Label, On: on(a.Enabled), Note: a.Note, Fixed: a.Required,
				})
			}
			return &Need{Kind: "apps", Label: "Apps", Options: opts}
		},
		accept: acceptApps,
		run:    runApps,
	}
}

func runApps(e *Engine) result {
	c := e.catalogue()
	if err := c.Validate(); err != nil {
		return failed(err.Error())
	}

	warp, err := openEdit(e.paths.WarpgateConfig, confMode)
	if err != nil {
		return failed(err.Error())
	}
	soli, err := openEdit(e.paths.SolisuiteConfig, confMode)
	if err != nil {
		return failed(err.Error())
	}
	core, err := openEdit(e.paths.CoreXConfig, confMode)
	if err != nil {
		return failed(err.Error())
	}

	if conflict := appsConflict(e, c, warp, soli, core); conflict != nil {
		return *conflict
	}

	origins := c.CoreXOrigins(e.proven())
	warp.set("apps", c.Warpgate())
	soli.set("apps", c.Solisuite())
	core.set("instance.appOrigins", origins)

	edits := []*edit{warp, soli, core}
	var changes []Change
	for _, ed := range edits {
		changes = append(changes, ed.changes()...)
	}
	changes = append(changes, droppedOrigins(e.paths.CoreXConfig, core.was("instance.appOrigins"), origins)...)
	if len(changes) == 0 {
		return passed("all three already say the same thing", appsProof(e, c))
	}
	if err := applyAll(edits); err != nil {
		return failed(err.Error())
	}
	return passed(fmt.Sprintf("%d settings across three files", len(changes)), appsProof(e, c))
}

// appsProof reads the three files back. What was intended is not evidence; what
// is in the file afterwards is.
func appsProof(e *Engine, c catalogue.Catalogue) string {
	var b strings.Builder
	count := func(path, dotted string) int {
		tree, _, err := readTree(path)
		if err != nil {
			return -1
		}
		switch v := at(tree, dotted).(type) {
		case []any:
			return len(v)
		case map[string]any:
			return len(v)
		}
		return -1
	}
	fmt.Fprintf(&b, "%s apps[] has %d entries; ", e.paths.WarpgateConfig, count(e.paths.WarpgateConfig, "apps"))
	fmt.Fprintf(&b, "%s apps[] has %d entries with host and origin; ", e.paths.SolisuiteConfig, count(e.paths.SolisuiteConfig, "apps"))
	fmt.Fprintf(&b, "%s instance.appOrigins has %d of %d (an origin is added when its hostname has answered a probe, not before). ",
		e.paths.CoreXConfig, count(e.paths.CoreXConfig, "instance.appOrigins"), len(c.Solisuite()))
	b.WriteString("Hostnames: " + strings.Join(c.Hostnames(), ", "))
	return b.String()
}

// appsConflict looks for things in the three files that this machine did not
// put there.
func appsConflict(e *Engine, c catalogue.Catalogue, warp, soli, core *edit) *result {
	// An app in Warpgate's list that this instance has never heard of. Our
	// write replaces the array, so it would be erased — and unlike a hostname
	// under an old domain, it can never be something we wrote, whether or not
	// this step has run before.
	known := map[string]bool{}
	for _, a := range catalogue.Default() {
		known[a.ID] = true
	}
	if arr, ok := warp.was("apps").([]any); ok {
		var strangers []string
		for _, item := range arr {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if name, _ := m["name"].(string); name != "" && !known[name] {
				strangers = append(strangers, name)
			}
		}
		if len(strangers) > 0 {
			sort.Strings(strangers)
			return conflictPtr(Conflict{
				Object:    "apps[] in " + e.paths.WarpgateConfig,
				Found:     quote(strangers),
				FoundNote: "not in this instance's catalogue, so nothing here created them",
				Desired:   quote(appNames(c)),
				Why: "This step writes the whole list. Publishing the catalogue would delete these entries, " +
					"and with them the DNS records and ingress rules derived from them.",
				Resolution: "Remove them from " + e.paths.WarpgateConfig + " if they are stale, or add them to this " +
					"instance's catalogue if they are wanted. Then run this step again.",
				Consequence: "The apps you chose are not published yet. Everything already published keeps working.",
			})
		}
	}

	// Hostnames under a different domain. If this step has passed before, they
	// are our own previous domain and replacing them is the point — that is
	// what a domain change is. If it has not, they belong to somebody else's
	// configuration of this machine.
	if e.ours("apps") {
		return nil
	}
	var foreign []string
	if arr, ok := soli.was("apps").([]any); ok {
		for _, item := range arr {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			host, _ := m["host"].(string)
			if host != "" && !strings.HasSuffix(host, "."+c.Domain) {
				foreign = append(foreign, host)
			}
		}
	}
	if m, ok := core.was("instance.appOrigins").(map[string]any); ok {
		for id, v := range m {
			s, _ := v.(string)
			if s != "" && s != c.Origin(id) {
				foreign = append(foreign, s)
			}
		}
	}
	if len(foreign) == 0 {
		return nil
	}
	sort.Strings(foreign)
	return conflictPtr(Conflict{
		Object:    "the app list in " + e.paths.SolisuiteConfig + " and " + e.paths.CoreXConfig,
		Found:     quote(foreign),
		FoundNote: "hostnames under a domain that is not " + c.Domain + ", and this step has never run here",
		Desired:   quote(c.Hostnames()),
		Why: "Solisuite maps a Host header to an app from this list and coreX advertises these origins to the launcher. " +
			"Two instances cannot both own them, and replacing them would take an already-working instance off the air.",
		Resolution: "If this machine is being moved to " + c.Domain + ", clear the old app lists deliberately and run this " +
			"step again. If it is not, this is the wrong machine.",
		Consequence: "Nothing this instance publishes is live yet. The instance those hostnames belong to is untouched.",
	})
}

// droppedOrigins lists the app origins that are in the file now and will not be
// after this write.
//
// It exists because of a hole in the diff, not because of a hole in the write.
// instance.File.Changes() walks the tree it is ABOUT TO WRITE and looks each
// path up in what was on disk, so it reports a value that appears or changes
// and cannot report one that disappears — there is no path in the new tree to
// walk to. Everything else this package writes is a scalar or a whole array,
// and an array compares as one leaf, so removals inside it are visible. Only
// instance.appOrigins is a map replaced wholesale, and an origin removed from
// it would otherwise be written having never been shown to anybody. Writing
// something that was not shown is the one thing this package must not do.
func droppedOrigins(path string, was any, now map[string]string) []Change {
	old, ok := was.(map[string]any)
	if !ok {
		return nil
	}
	var out []Change
	for id, v := range old {
		if _, kept := now[id]; kept {
			continue
		}
		from, isString := v.(string)
		if !isString {
			from = quote(v)
		}
		out = append(out, Change{
			Path: path + "  instance.appOrigins." + id,
			From: from,
			To:   "(removed)",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func conflictPtr(c Conflict) *result {
	r := held(c)
	return &r
}

func appNames(c catalogue.Catalogue) []string {
	var out []string
	for _, a := range c.Enabled() {
		out = append(out, a.ID)
	}
	return out
}

func stepTokenStore() Step {
	return Step{
		ID:    "token-store",
		Title: "Store the Cloudflare token",
		Kind:  Local,
		After: []string{"token-verify"},
		desired: func(e *Engine) string {
			return "write the verified token to " + e.paths.WarpgateToken + ", mode 0600, owned by root, and nowhere else"
		},
		run: func(e *Engine) result {
			// The token arrives through token-verify's `secret` need and lives
			// only in memory until here. It is never in the ledger, never in an
			// envelope and never in a log line, so the only place it is written
			// down is the file Warpgate reads.
			tok := e.secret("token-verify")
			if tok == "" {
				return blocked("no token has been submitted")
			}
			existing, err := os.ReadFile(e.paths.WarpgateToken)
			switch {
			case err == nil && strings.TrimSpace(string(existing)) == tok:
				return passed("already stored", tokenProof(e))
			case err == nil && !e.ours("token-store"):
				return held(Conflict{
					Object:    e.paths.WarpgateToken,
					Found:     "a credential of " + fmt.Sprintf("%d", len(strings.TrimSpace(string(existing)))) + " characters, not the one just verified",
					FoundNote: "this step has never run on this machine, so nothing here wrote it",
					Desired:   "the token verified in the previous step",
					Why: "Warpgate reads exactly one credential from this path. Overwriting it would take away whatever " +
						"is using it now, and the token that is there cannot be read back out of Cloudflare to put it back.",
					Resolution: "Move " + e.paths.WarpgateToken + " aside yourself if it is stale, then run this step again.",
					Consequence: "The new token is not stored, so nothing further can be published. Whatever is using the " +
						"existing token keeps working.",
				})
			case err != nil && !os.IsNotExist(err):
				return failed("could not read " + e.paths.WarpgateToken + ": " + err.Error())
			}
			if err := writeSecret(e.paths.WarpgateToken, tok, tokenMode); err != nil {
				return failed(err.Error())
			}
			return passed("stored", tokenProof(e))
		},
	}
}

// tokenProof records where the credential is and how it is protected, and
// nothing derived from the credential itself. A fingerprint would be safe
// arithmetic and an unsafe habit: the rule worth keeping is that no function in
// this package ever puts a secret, or a function of one, into a string that
// something else will render.
func tokenProof(e *Engine) string {
	fi, err := os.Stat(e.paths.WarpgateToken)
	if err != nil {
		return e.paths.WarpgateToken + " could not be checked after writing: " + err.Error()
	}
	owner := "the user this process runs as"
	if os.Geteuid() == 0 {
		owner = "root"
	}
	return fmt.Sprintf("%s exists, mode %04o, owned by %s. Its contents are not recorded anywhere.",
		e.paths.WarpgateToken, fi.Mode().Perm(), owner)
}

func stepWarpgateConfig() Step {
	return Step{
		ID:    "warpgate-config",
		Title: "Warpgate's configuration",
		Kind:  Local,
		After: []string{"apps"},
		desired: func(e *Engine) string {
			return fmt.Sprintf("pin configPath to %s and reloadUnit to %s in %s",
				e.paths.WarpgateIngress, e.paths.ConnectorUnit, e.paths.WarpgateConfig)
		},
		run: func(e *Engine) result {
			ed, err := openEdit(e.paths.WarpgateConfig, confMode)
			if err != nil {
				return failed(err.Error())
			}
			// Pinned rather than defaulted. Warpgate writing its ingress
			// wherever its built-in default happens to point, and reloading
			// whatever unit it guesses at, is how a config change lands in a
			// file nothing reads and reports success for doing it.
			pins := map[string]string{
				"configPath": e.paths.WarpgateIngress,
				"reloadUnit": e.paths.ConnectorUnit,
			}
			for k, want := range pins {
				if had := atString(ed.tree, k); had != "" && had != want && !e.ours("warpgate-config") {
					return held(Conflict{
						Object:    k + " in " + e.paths.WarpgateConfig,
						Found:     quote(had),
						FoundNote: "this step has never run on this machine, so nothing here pinned it",
						Desired:   quote(want),
						Why: "Warpgate reads its ingress from configPath and reloads reloadUnit when it changes. " +
							"Repointing either one takes an already-configured edge apart while every check still passes.",
						Resolution:  "Reconcile " + e.paths.WarpgateConfig + " yourself, then run this step again.",
						Consequence: "The edge is not reconfigured. Whatever is running keeps running.",
					})
				}
				ed.set(k, want)
			}
			return e.applyOne(ed, "configPath", "reloadUnit")
		},
	}
}

func stepPlanShow() Step {
	return Step{
		ID:    "plan-show",
		Title: "The plan",
		Kind:  Local,
		After: []string{"apps"},
		desired: func(e *Engine) string {
			return "show everything that will be created or changed, and wait. This is the last free stop."
		},
		need: func(e *Engine) *Need {
			return &Need{
				Kind:    "confirm",
				Label:   "Everything below happens when you continue. Nothing has been changed yet.",
				Changes: plan(e),
			}
		},
		accept: acceptConfirm(func(e *Engine, ok bool) { e.given.planOK = ok }),
		run: func(e *Engine) result {
			if !e.given.planOK {
				return blocked("the plan has not been confirmed. Nothing beyond this point has been done.")
			}
			// The proof is the plan, verbatim, as it stood when it was agreed
			// to. What was consented to is the fact worth keeping: a plan
			// summarised after the event is a record of what happened, not of
			// what was agreed.
			var b strings.Builder
			b.WriteString("confirmed, having been shown:\n")
			for _, c := range plan(e) {
				from := c.From
				if from == "" {
					from = "(nothing)"
				}
				fmt.Fprintf(&b, "  %s: %s -> %s\n", c.Path, from, c.To)
			}
			return passed("confirmed", strings.TrimRight(b.String(), "\n"))
		},
	}
}

// plan is the projection of the catalogue into what will exist afterwards. It
// is derived and never written: showing it changes nothing, which is what makes
// it a free stop.
func plan(e *Engine) []Change {
	c := e.catalogue()
	if c.Domain == "" {
		return nil
	}
	target := "the tunnel created by tunnel-ensure"
	if ref := e.tunnelRef(); ref != "" {
		target = ref + ".cfargotunnel.com"
	}
	var out []Change
	for _, a := range c.Enabled() {
		out = append(out, Change{
			Path: "DNS      " + c.Hostname(a.ID),
			To:   "CNAME to " + target + ", proxied",
		})
	}
	for _, a := range c.Enabled() {
		out = append(out, Change{
			Path: "ingress  " + c.Hostname(a.ID),
			To:   a.Upstream,
		})
	}
	tree, _, _ := readTree(e.paths.CoreXConfig)
	out = append(out,
		Change{Path: e.paths.CoreXConfig + "  instance.publicBaseUrl",
			From: atString(tree, "instance.publicBaseUrl"), To: "https://" + c.Domain},
		Change{Path: e.paths.CoreXConfig + "  instance.cookieDomain",
			From: atString(tree, "instance.cookieDomain"), To: c.Domain},
		Change{Path: e.paths.CoreXConfig + "  auth.insecureCookies",
			From: quoteBool(at(tree, "auth.insecureCookies")), To: "false"},
	)
	return out
}

func quoteBool(v any) string {
	b, ok := v.(bool)
	if !ok {
		return ""
	}
	if b {
		return "true"
	}
	return "false"
}

func stepIngressWrite() Step {
	return Step{
		ID:    "ingress-write",
		Title: "The ingress, and the connector",
		Kind:  Local,
		After: []string{"warpgate-config"},
		desired: func(e *Engine) string {
			return fmt.Sprintf("write the hostname-to-upstream map to %s, then enable AND start %s",
				e.paths.WarpgateIngress, e.paths.ConnectorUnit)
		},
		run: func(e *Engine) result {
			c := e.catalogue()
			if err := c.Validate(); err != nil {
				return failed(err.Error())
			}
			ed, err := openEdit(e.paths.WarpgateIngress, confMode)
			if err != nil {
				return failed(err.Error())
			}
			rules := make([]map[string]string, 0, len(c.Enabled())+1)
			for _, a := range c.Enabled() {
				rules = append(rules, map[string]string{"hostname": c.Hostname(a.ID), "service": a.Upstream})
			}
			// The catch-all is not decoration. Without a final rule the
			// connector has no answer for a hostname that is not in the list,
			// and "no answer" from an edge that terminates TLS for a whole
			// domain is a far worse thing to serve than a 404.
			rules = append(rules, map[string]string{"service": "http_status:404"})
			ed.set("ingress", rules)
			if ref := e.tunnelRef(); ref != "" {
				ed.set("tunnel", ref)
			}

			changed := len(ed.changes()) > 0
			if changed {
				if err := applyAll([]*edit{ed}); err != nil {
					return failed(err.Error())
				}
			}

			// Enabled AND started. A connector that is running but not enabled
			// is an instance that is on the internet until the next power cut,
			// and nothing about it looks wrong until then.
			unit := e.paths.ConnectorUnit
			switch {
			case !e.machine.IsEnabled(unit) || !e.machine.IsActive(unit):
				if err := e.machine.EnableNow(unit); err != nil {
					return failed(err.Error())
				}
			case changed:
				if err := e.machine.Restart(unit); err != nil {
					return failed(err.Error())
				}
			}
			if !e.machine.IsActive(unit) {
				return failed(unit + " is not running after being started")
			}
			detail := "already as wanted"
			if changed {
				detail = fmt.Sprintf("%d ingress rules", len(rules))
			}
			return passed(detail, fmt.Sprintf(
				"%s holds %d rules ending in a 404 catch-all, and %s is enabled and active. "+
					"That the unit is active is NOT proof the tunnel is registered — connector-registered is.",
				e.paths.WarpgateIngress, len(rules), unit))
		},
	}
}

func stepSolisuiteWrite() Step {
	return Step{
		ID:    "solisuite-write",
		Title: "Solisuite's app map",
		Kind:  Local,
		After: []string{"apps", "connector-registered"},
		desired: func(e *Engine) string {
			return "check nothing in " + e.paths.SolisuiteEnv + " overrides the app list, reconcile it, and restart " + e.paths.SolisuiteUnit
		},
		run: func(e *Engine) result {
			c := e.catalogue()
			if err := c.Validate(); err != nil {
				return failed(err.Error())
			}
			// The same trap as coreX's, and the half nobody remembers exists.
			// SOLISUITE_APP_HOST_<ID> is applied after the JSON is read, so a
			// line left here decides which Host maps to which app no matter
			// what the file says.
			if res := envConflict(e, e.paths.SolisuiteEnv, instance.SolisuiteOverrides, e.paths.SolisuiteConfig); res != nil {
				return *res
			}
			ed, err := openEdit(e.paths.SolisuiteConfig, confMode)
			if err != nil {
				return failed(err.Error())
			}
			ed.set("apps", c.Solisuite())
			changed := len(ed.changes()) > 0
			if changed {
				if err := applyAll([]*edit{ed}); err != nil {
					return failed(err.Error())
				}
			}
			if changed || !e.machine.IsActive(e.paths.SolisuiteUnit) {
				if err := e.machine.Restart(e.paths.SolisuiteUnit); err != nil {
					return failed(err.Error())
				}
			}
			tree, _, err := readTree(e.paths.SolisuiteConfig)
			if err != nil {
				return failed(err.Error())
			}
			apps, _ := at(tree, "apps").([]any)
			withHost := 0
			for _, a := range apps {
				m, _ := a.(map[string]any)
				if m != nil && m["host"] != nil && m["origin"] != nil {
					withHost++
				}
			}
			detail := "already as wanted"
			if changed {
				detail = fmt.Sprintf("%d apps", len(apps))
			}
			return passed(detail, fmt.Sprintf(
				"%s lists %d apps, %d of them carrying both host and origin, and nothing in %s overrides them. "+
					"%s is active. appFor() has a map to work from rather than falling back to defaultApp.",
				e.paths.SolisuiteConfig, len(apps), withHost, e.paths.SolisuiteEnv, e.paths.SolisuiteUnit))
		},
	}
}

func stepCoreXWrite() Step {
	return Step{
		ID:    "corex-write",
		Title: "coreX takes the domain",
		Kind:  Local,
		After: []string{"apps", "domain", "connector-registered"},
		desired: func(e *Engine) string {
			d := e.given.domain
			if d == "" {
				d = "the domain"
			}
			return fmt.Sprintf("check %s sets none of the COREX_ variables that would beat the file, then write "+
				"instance.publicBaseUrl=https://%s, instance.cookieDomain=%s and auth.insecureCookies=false, and restart %s",
				e.paths.CoreXEnv, d, d, e.paths.CoreXUnit)
		},
		run: runCoreXWrite,
	}
}

func runCoreXWrite(e *Engine) result {
	c := e.catalogue()
	if c.Domain == "" {
		return blocked("waiting on the domain")
	}
	// Before anything is opened for writing, and this order is the whole point
	// of the step. coreX runs applyEnv AFTER unmarshalling its JSON, so a
	// COREX_PUBLIC_BASE_URL left in an environment file beats whatever is
	// written below — and the result is not a failure, it is a switch that
	// reports success and changes nothing. That is the defect that had two
	// services running entirely on a stale domain while their configuration
	// said otherwise, with every check that read the JSON reporting correct.
	if res := envConflict(e, e.paths.CoreXEnv, instance.CoreXOverrides, e.paths.CoreXConfig); res != nil {
		return *res
	}

	ed, err := openEdit(e.paths.CoreXConfig, confMode)
	if err != nil {
		return failed(err.Error())
	}
	want := "https://" + c.Domain
	if had := atString(ed.tree, "instance.publicBaseUrl"); had != "" && had != want && !e.ours("corex-write") {
		return held(Conflict{
			Object:    "instance.publicBaseUrl in " + e.paths.CoreXConfig,
			Found:     quote(had),
			FoundNote: "this step has never run on this machine, so nothing here wrote it",
			Desired:   quote(want),
			Why: "Every session cookie, every link in an outgoing message and every origin the launcher offers is " +
				"derived from this. Two instances cannot both be it, and changing it signs out everybody signed in " +
				"against the old one.",
			Resolution: "If this machine really is moving to " + c.Domain + ", clear instance.publicBaseUrl in " +
				e.paths.CoreXConfig + " deliberately and run this step again.",
			Consequence: "coreX keeps answering as " + had + ". Nothing published under " + c.Domain + " will sign anyone in yet.",
		})
	}

	ed.set("instance.publicBaseUrl", want)
	// The bare domain, with no leading dot. RFC 6265 says a Domain attribute
	// always covers subdomains and that a leading dot is stripped, so ".x.org"
	// and "x.org" mean the same thing to every current browser — and only one
	// of them says so.
	ed.set("instance.cookieDomain", c.Domain)
	// The flip that makes the instance real, and the one that strands the
	// operator if it happens early. Its dependency on connector-registered is
	// not ordering: a Secure cookie is neither sent to nor accepted by
	// http://holistic.local, so flipping this before a tunnel answers signs the
	// operator out of the thing performing the installation.
	ed.set("auth.insecureCookies", false)

	changed := len(ed.changes()) > 0
	if changed {
		if err := applyAll([]*edit{ed}); err != nil {
			return failed(err.Error())
		}
	}
	if changed || !e.machine.IsActive(e.paths.CoreXUnit) {
		if err := e.machine.Restart(e.paths.CoreXUnit); err != nil {
			return failed(err.Error())
		}
	}
	tree, _, err := readTree(e.paths.CoreXConfig)
	if err != nil {
		return failed(err.Error())
	}
	detail := "already as wanted"
	if changed {
		detail = c.Domain
	}
	return passed(detail, fmt.Sprintf(
		"read back from %s: instance.publicBaseUrl=%s, instance.cookieDomain=%s, auth.insecureCookies=%v. "+
			"%s sets none of the COREX_ variables that would override them, so what is in the file is what coreX will use. "+
			"%s was restarted.",
		e.paths.CoreXConfig,
		atString(tree, "instance.publicBaseUrl"),
		atString(tree, "instance.cookieDomain"),
		at(tree, "auth.insecureCookies"),
		e.paths.CoreXEnv, e.paths.CoreXUnit))
}

// envConflict turns an environment override into the six-field shape.
//
// It is a conflict rather than a failure because it is exactly what a conflict
// is: something on this machine that this wizard did not put there, that
// collides with what it wants to write, and that it must not quietly remove.
// Somebody set that variable for a reason, and the wizard does not know what it
// was.
func envConflict(e *Engine, envPath string, watched map[string]string, confPath string) *result {
	overrides, err := instance.CheckOverrides(envPath, watched)
	if err != nil {
		r := failed("could not read " + envPath + ": " + err.Error())
		return &r
	}
	// And the environment this process was started with, which is the same
	// channel by a different route. systemd's manager environment —
	// `systemctl set-environment`, DefaultEnvironment= in system.conf, or a
	// variable exported where the manager reads it — is inherited by every
	// service on the machine, this one and coreX alike. So a watched variable
	// visible here is evidence that coreX will see it too, and it is invisible
	// to anything that only reads EnvironmentFiles.
	overrides = append(overrides, processOverrides(watched)...)
	if len(overrides) == 0 {
		return nil
	}
	// Every variable is named, and so is the file it is in. "An environment
	// variable is overriding this" without saying which one and where is a
	// message that sends somebody grepping /etc, which is where the hour goes.
	var names, lines, wheres []string
	seenWhere := map[string]bool{}
	for _, o := range overrides {
		names = append(names, o.Variable)
		lines = append(lines, fmt.Sprintf("%s=%s  in %s  (beats %s)", o.Variable, o.Value, o.File, o.Beats))
		if !seenWhere[o.File] {
			seenWhere[o.File] = true
			wheres = append(wheres, o.File)
		}
	}
	return conflictPtr(Conflict{
		Object:    strings.Join(names, ", ") + " — set in " + strings.Join(wheres, " and "),
		Found:     strings.Join(lines, "\n"),
		FoundNote: "applied to the service after its JSON is read, so these are what it will actually use",
		Desired:   "no override, so that " + confPath + " is what the service actually uses",
		Why: "The environment is applied AFTER the JSON is unmarshalled, so these win. Writing " + confPath +
			" while they are set would change nothing, succeed, and report success — which is worse than failing, " +
			"because every check that reads the JSON would agree with it.",
		Resolution: "Remove " + strings.Join(names, ", ") + " from " + strings.Join(wheres, " and ") +
			", then run this step again. Nothing else in those files is touched.",
		Consequence: "This instance keeps whatever those variables say. Nothing written here would have taken effect.",
	})
}

func stepCoreXRestart2() Step {
	return Step{
		ID:    "corex-restart-2",
		Title: "Restart, and look at the front door",
		Kind:  Local,
		After: []string{"corex-write", "nonce-probe"},
		desired: func(e *Engine) string {
			d := e.given.domain
			if d == "" {
				d = "the domain"
			}
			return "restart " + e.paths.CoreXUnit + " so it picks up the proven origins, then fetch https://" + d +
				"/ from outside with no cookies and see what a stranger sees"
		},
		run: func(e *Engine) result {
			d := e.given.domain
			if d == "" {
				return blocked("waiting on the domain")
			}
			if err := e.machine.Restart(e.paths.CoreXUnit); err != nil {
				return failed(err.Error())
			}
			// Logged out, deliberately. Every earlier check in this wizard has
			// been made by something holding a session; the question nobody has
			// asked yet is what an unauthenticated request to the apex gets,
			// and that is the only question the owner's friends will ever ask.
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			url := "https://" + d + "/"
			resp, err := e.fetch(ctx, url)
			if err != nil {
				return failed(fmt.Sprintf("%s could not be reached from outside: %v", url, err))
			}
			if resp.Status >= 500 {
				return failed(fmt.Sprintf("%s answered %d to a request carrying no cookies:\n%s",
					url, resp.Status, firstLine(resp.Body)))
			}
			tree, _, terr := readTree(e.paths.CoreXConfig)
			if terr != nil {
				return failed(terr.Error())
			}
			if insecure, _ := at(tree, "auth.insecureCookies").(bool); insecure {
				return failed("auth.insecureCookies is true again in " + e.paths.CoreXConfig +
					" — something rewrote it after corex-write")
			}
			return passed("the apex answers", fmt.Sprintf(
				"%s was restarted, then GET %s from outside, carrying no cookies, answered %d. "+
					"auth.insecureCookies reads false in %s.",
				e.paths.CoreXUnit, url, resp.Status, e.paths.CoreXConfig))
		},
	}
}

// applyOne is the single-file case of the same discipline: nothing is written
// if nothing differs, and what is written is read back before it is claimed.
func (e *Engine) applyOne(ed *edit, report ...string) result {
	changes := ed.changes()
	if len(changes) == 0 {
		return passed("already as wanted", readBackProof(ed.path, report))
	}
	if err := applyAll([]*edit{ed}); err != nil {
		return failed(err.Error())
	}
	var what []string
	for _, c := range changes {
		what = append(what, c.Path)
	}
	return passed(strings.Join(what, ", "), readBackProof(ed.path, report))
}

func readBackProof(path string, dotted []string) string {
	tree, _, err := readTree(path)
	if err != nil {
		return path + " could not be read back after writing: " + err.Error()
	}
	var parts []string
	for _, d := range dotted {
		parts = append(parts, fmt.Sprintf("%s=%s", d, quote(at(tree, d))))
	}
	return "read back from " + path + ": " + strings.Join(parts, ", ")
}

// processOverrides finds watched variables in this process's own environment.
// The wildcard families are matched by prefix, the same way CheckOverrides
// matches them in a file — SOLISUITE_APP_HOST_<ID> is the one whose name cannot
// be known in advance, and it is also the one nobody remembers exists.
func processOverrides(watched map[string]string) []instance.Override {
	const where = "this process's environment (systemd's manager environment reaches every service)"
	var out []instance.Override
	for _, kv := range os.Environ() {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		beats, ok := watched[name]
		if !ok {
			for k, v := range watched {
				if strings.HasSuffix(k, "*") && strings.HasPrefix(name, strings.TrimSuffix(k, "*")) {
					beats, ok = v, true
					break
				}
			}
		}
		if ok {
			out = append(out, instance.Override{File: where, Variable: name, Value: value, Beats: beats})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Variable < out[j].Variable })
	return out
}

func notEmptyDir(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

// stepSeal is the last one, and it is a transaction rather than a step.
//
// Plan 7.7: the same act that records this instance as claimed destroys the
// setup code and takes the LAN listener away. Never both doors open at once —
// an instance that is live on its own domain and still answering an
// unauthenticated setup page on the network is the shape of Jellyfin #6486, and
// of every other product on that list.
//
// Destroyed, not marked used. A spent code lying in /etc is a second key to a
// door that is already open, and "used: true" is a flag some later branch can
// read the wrong way.
func stepSeal() Step {
	return Step{
		ID:    "seal",
		Title: "Close setup",
		Kind:  Local,
		// Everything, because this is the act that makes the rest unreachable.
		After: []string{"corex-restart-2"},
		desired: fixed("record this instance as claimed, destroy the setup code, and stop answering setup on " +
			"the local network. This is one act: never both doors open at once."),
		need: func(e *Engine) *Need {
			if e.ours("seal") {
				return nil
			}
			return &Need{
				Kind:  "confirm",
				Label: "Close setup",
				Help: "After this, this address serves a status page and nothing else. Signing in happens on " +
					"your own domain. Re-opening setup is a separate, deliberate act on the machine itself.",
				Changes: []Change{
					{Path: "the setup code", From: "on disk", To: "destroyed"},
					{Path: "this address", From: "the wizard", To: "a status page"},
					{Path: "holistic-setup.service", From: "enabled", To: "disabled"},
				},
			}
		},
		accept: func(e *Engine, raw json.RawMessage) error {
			var ok bool
			if err := json.Unmarshal(raw, &ok); err != nil || !ok {
				return fmt.Errorf("%w: setup is closed only on a yes", ErrBadAnswer)
			}
			e.given.sealOK = true
			return nil
		},
		run: func(e *Engine) result {
			if !e.given.sealOK {
				return blocked("waiting to be told to close setup")
			}
			// Refuses while anything is unfinished. Sealing over a conflict
			// would leave the operator with a half-built instance and no way
			// back in except a deliberate re-open on the machine.
			var open []string
			for _, st := range e.order {
				if st.ID == "seal" {
					continue
				}
				switch e.led.Status(st.ID) {
				case ledger.Passed, ledger.Skipped:
				default:
					open = append(open, st.ID)
				}
			}
			if len(open) > 0 {
				return blocked("not while these are unfinished: " + strings.Join(open, ", ") +
					". Skip a step deliberately if it is not wanted.")
			}

			// The seal first. If anything after it fails, the instance is
			// claimed and the listener is still up — recoverable. The other
			// order leaves a machine with no code, no seal and no way in.
			if err := os.WriteFile(e.paths.Seal, []byte(e.now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
				return failed("the seal could not be written: " + err.Error())
			}
			if err := os.Remove(e.paths.Claim); err != nil && !os.IsNotExist(err) {
				return failed("this instance is sealed, but the setup code could not be destroyed: " + err.Error())
			}
			if err := e.machine.Disable(e.paths.SetupUnit); err != nil {
				return failed("this instance is sealed and its code is gone, but the setup service is still " +
					"enabled and will come back on the next boot: " + err.Error())
			}
			return passed("setup is closed",
				e.paths.Seal+" written, "+e.paths.Claim+" destroyed, "+e.paths.SetupUnit+" disabled")
		},
	}
}
