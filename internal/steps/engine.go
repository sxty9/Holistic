package steps

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sxty9/Holistic/internal/catalogue"
	"github.com/sxty9/Holistic/internal/ledger"
)

// Engine holds the steps, what they have been told, and the three seams
// through which they touch anything outside this process.
type Engine struct {
	mu      sync.Mutex
	led     *ledger.Ledger
	paths   Paths
	machine Machine
	fetch   Fetch
	// cf reads from Cloudflare and cannot write to it. See cloudflare.go: every
	// write in this wizard runs `warpgate`, which is where the ownership marker
	// and the conflict path live.
	cf  Cloudflare
	now func() time.Time

	order []*Step
	byID  map[string]*Step

	given given
	// secrets are submitted and never returned. They are held apart from
	// `given` rather than beside it with a flag, because the guarantee is
	// "no code path can put one in an envelope", and a flag is something a
	// later code path can forget to read.
	secrets map[string]string
	// conflicts hold the six fields for a step that is currently held. The
	// ledger keeps the fact and the summary line; the full account is
	// re-derived by running the step again, which is what [Check again] does
	// and is the right source anyway — the operator may have fixed it since.
	conflicts map[string]*Conflict
	lastLook  map[string]time.Time
}

// given is what the operator has told the wizard. It is separate from what is
// on disk on purpose: an answer is a wish, and the step is what turns it into a
// fact, or refuses to.
type given struct {
	domain      string
	displayName string
	// zone is what Cloudflare answered about the domain, kept so the steps
	// after zone-resolve do not each ask again — and so a re-run of a later
	// step does not depend on the network being up.
	zone    Zone
	dataDir string
	engine  string
	// apps is an overlay on the catalogue defaults rather than a replacement,
	// so an answer that mentions three apps does not silently turn off the
	// five it did not mention.
	apps   map[string]bool
	planOK bool
}

// New builds the engine and reads the machine before it is asked anything.
//
// The read matters. This process is short-lived and restartable — a tab closed
// during a nameserver change may be reopened an hour later against a fresh
// process — so the wizard's idea of what has been decided has to come from what
// is on disk, not from what somebody typed into a form that no longer exists.
func New(led *ledger.Ledger, p Paths, m Machine, f Fetch) *Engine {
	return NewWith(led, p, m, f, LiveCloudflare(20*time.Second))
}

// NewWith takes the Cloudflare seam too, so a test can run every provider step
// without a credential and without a network.
func NewWith(led *ledger.Ledger, p Paths, m Machine, f Fetch, cf Cloudflare) *Engine {
	e := &Engine{
		led:       led,
		paths:     p,
		machine:   m,
		fetch:     f,
		cf:        cf,
		now:       time.Now,
		byID:      map[string]*Step{},
		secrets:   map[string]string{},
		conflicts: map[string]*Conflict{},
		lastLook:  map[string]time.Time{},
		given:     given{apps: map[string]bool{}},
	}
	for _, s := range definitions() {
		st := s
		e.order = append(e.order, &st)
		e.byID[st.ID] = &st
	}
	e.reread()
	return e
}

// reread recovers the decisions from where they actually live.
//
// The domain comes back out of the ledger's own row for the domain step, whose
// Detail is the domain verbatim for exactly this purpose. The app selection
// comes back out of Warpgate's config, which is the file that lists what is
// published. Neither is a cache: they are the state, and this is the reconciler
// reading it.
func (e *Engine) reread() {
	for _, row := range e.led.Steps() {
		if row.ID == "domain" && row.Status == ledger.Passed && row.Detail != "" {
			e.given.domain = row.Detail
		}
	}
	tree, _, err := readTree(e.paths.WarpgateConfig)
	if err != nil {
		// An unreadable file is not an empty one. Say nothing here and let the
		// step that needs it fail with the parse error, rather than starting
		// from defaults that would look like a considered selection.
		return
	}
	apps, ok := at(tree, "apps").([]any)
	if !ok || len(apps) == 0 {
		return
	}
	known := map[string]bool{}
	for _, a := range catalogue.Default() {
		known[a.ID] = true
	}
	// The published list is the selection, so anything not in it is off. An
	// overlay that only ever turns things on could not represent "the operator
	// unchecked Gallery" across a restart.
	for id := range known {
		e.given.apps[id] = false
	}
	for _, a := range apps {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if name, ok := m["name"].(string); ok && known[name] {
			e.given.apps[name] = true
		}
	}
}

// Domain is what the instance answers on, as far as anything has been decided.
func (e *Engine) Domain() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.given.domain
}

// State is the whole thing. sealed and the refusals are the server's facts
// rather than the engine's, so they are passed in rather than guessed at.
//
// refusedFrom carries the addresses, not just the count. Somebody who has been
// probed should be told by whom, on the first screen — a number alone tells
// them something happened and gives them nothing to do about it.
func (e *Engine) State(sealed bool, refused int, refusedFrom []string) Envelope {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.envelope(sealed, refused, refusedFrom)
}

func (e *Engine) envelope(sealed bool, refused int, refusedFrom []string) Envelope {
	recorded := map[string]ledger.Step{}
	for _, s := range e.led.Steps() {
		recorded[s.ID] = s
	}

	env := Envelope{
		ReadAt:      e.now().UTC().Format(time.RFC3339),
		Sealed:      sealed,
		Domain:      e.given.domain,
		Refused:     refused,
		RefusedFrom: refusedFrom,
		Steps:       make([]Row, 0, len(e.order)),
		Resources:   []Resource{},
	}
	for _, st := range e.order {
		rec := recorded[st.ID]
		row := Row{
			ID:      st.ID,
			Title:   st.Title,
			Kind:    st.Kind,
			Status:  rec.Status,
			Detail:  rec.Detail,
			Proof:   rec.Proof,
			At:      rec.At,
			Desired: st.desired(e),
		}
		if row.Status == "" {
			row.Status = ledger.Pending
		}
		if st.need != nil {
			row.Needs = st.need(e)
		}
		if row.Status == ledger.WaitingOnThem {
			row.WaitingOn = st.WaitingOn
			// The in-memory map is this process's own record and is the more
			// precise of the two. The ledger's is what survives a restart —
			// without the fallback, a wait that outlives the daemon comes back
			// with no last-looked at all, which reads as nothing watching it.
			if t, ok := e.lastLook[st.ID]; ok {
				row.LastLooked = t.UTC().Format(time.RFC3339)
			} else {
				row.LastLooked = rec.LookedAt
			}
		}
		if row.Status == ledger.Conflict {
			row.Conflict = e.conflicts[st.ID]
		}
		env.Steps = append(env.Steps, row)
	}

	// Only the unconfirmed ones, because that is the only list the ledger
	// exposes. Every entry here is one somebody has to go and look for, which
	// is the list worth a person's attention anyway — but it is not the whole
	// truth, and calling it `resources` while it is only half of them is worth
	// knowing about.
	for _, r := range e.led.Unconfirmed() {
		env.Resources = append(env.Resources, Resource{
			Provider: r.Provider, Kind: r.Kind, Ref: r.Ref,
			Note: r.Note, Intended: r.Intended, Confirmed: r.Confirmed,
		})
	}
	return env
}

// Run reconciles one step: read what is there, compare it with what is wanted,
// apply only the difference.
func (e *Engine) Run(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	st, ok := e.byID[id]
	if !ok {
		return fmt.Errorf("%q: %w", id, ErrUnknownStep)
	}

	res := e.reconcile(st)
	return e.record(st, res)
}

func (e *Engine) reconcile(st *Step) result {
	if missing := e.unmet(st); len(missing) > 0 {
		return blocked("waiting on " + strings.Join(missing, ", ") + ", whose result this step uses")
	}
	e.lastLook[st.ID] = e.now()
	return st.run(e)
}

// unmet lists the steps this one consumes that have not passed. A skipped step
// counts as unmet: skipping is the operator saying "not now", not "pretend it
// worked".
func (e *Engine) unmet(st *Step) []string {
	var out []string
	for _, dep := range st.After {
		if e.led.Status(dep) != ledger.Passed {
			out = append(out, dep)
		}
	}
	return out
}

func (e *Engine) record(st *Step, res result) error {
	if res.conflict != nil {
		e.conflicts[st.ID] = res.conflict
	} else {
		delete(e.conflicts, st.ID)
	}
	// Mark first, then Prove. Prove carries the existing Detail through, so
	// this order leaves a passed row with both its summary and its evidence;
	// the other order would lose the summary.
	if err := e.led.Mark(st.ID, res.status, res.detail); err != nil {
		return err
	}
	if res.status == ledger.Passed {
		return e.led.Prove(st.ID, res.proof)
	}
	return nil
}

// Skip marks a step as the operator's own to do, with the reason written down.
func (e *Engine) Skip(id, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	st, ok := e.byID[id]
	if !ok {
		return fmt.Errorf("%q: %w", id, ErrUnknownStep)
	}
	if strings.TrimSpace(reason) == "" {
		return ErrNoReason
	}
	delete(e.conflicts, st.ID)
	return e.led.Mark(st.ID, ledger.Skipped, strings.TrimSpace(reason))
}

// Answer gives a step what it asked for. It stores; it does not act. Running is
// a separate route because deciding and doing are separate acts, and a wizard
// that applies on keystroke is a wizard with no last free stop.
func (e *Engine) Answer(id string, value json.RawMessage) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	st, ok := e.byID[id]
	if !ok {
		return fmt.Errorf("%q: %w", id, ErrUnknownStep)
	}
	if st.accept == nil {
		return fmt.Errorf("%s: %w", id, ErrNotAsked)
	}
	return st.accept(e, value)
}

// --- what the steps use ----------------------------------------------------

// catalogue is the one answer, assembled from the defaults, what is already
// published, and what the operator last said — in that order, so the operator
// wins and the disk beats the defaults.
func (e *Engine) catalogue() catalogue.Catalogue {
	apps := catalogue.Default()
	for i := range apps {
		if want, told := e.given.apps[apps[i].ID]; told {
			// Required apps are not offered as a choice, so an answer that
			// turns one off is a page bug rather than a decision. Validate
			// would refuse it; honouring Required here means the refusal never
			// has to happen.
			apps[i].Enabled = want || apps[i].Required
		}
	}
	return catalogue.New(e.given.domain, apps)
}

// proven is the set of apps whose hostname has actually answered from the
// public internet, seeded from what coreX already advertises.
//
// Seeding from the file is what stops appOrigins shrinking. The set lives in
// coreX's own configuration and nowhere else, so a restarted setup process that
// started from an empty set would write {} over a map that nonce-probe had
// spent ten minutes filling, and would report success for doing it.
func (e *Engine) proven() map[string]bool {
	out := map[string]bool{}
	d := e.given.domain
	if d == "" {
		return out
	}
	tree, _, err := readTree(e.paths.CoreXConfig)
	if err != nil {
		return out
	}
	origins, ok := at(tree, "instance.appOrigins").(map[string]any)
	if !ok {
		return out
	}
	for id, v := range origins {
		s, ok := v.(string)
		if !ok {
			continue
		}
		// Only origins under the domain in force. One under a previous domain
		// is not proof of anything about this one, and carrying it over is how
		// a domain change half-happens.
		if s == "https://"+id+"."+d {
			out[id] = true
		}
	}
	return out
}

func (e *Engine) secret(id string) string { return e.secrets[id] }

// ours reports whether a step has passed before, which is this package's answer
// to the ownership question for a local file.
//
// The ledger answers it for a provider — "did this machine create that record?"
// — and there is no equivalent marker to put inside somebody's /etc. So the
// evidence used here is the one thing that is both recorded and true: if this
// step has passed, the values it owns in that file are the values it wrote, and
// finding different ones now means the wizard is being asked to change its own
// work. That is a reconcile, and it is exactly what a later domain change is.
// If the step has never passed, whatever is there was put there by somebody
// else, and that is a conflict.
func (e *Engine) ours(id string) bool { return e.led.Status(id) == ledger.Passed }

// recordedDetail is what the ledger last recorded next to a step's state.
func (e *Engine) recordedDetail(id string) string {
	for _, s := range e.led.Steps() {
		if s.ID == id {
			return s.Detail
		}
	}
	return ""
}

// tunnelRef is the tunnel this machine created, if it got that far. It is read
// from the ledger's unconfirmed list, which is all the ledger exposes; a
// confirmed tunnel is therefore invisible here and the plan says so in words
// rather than inventing a reference.
func (e *Engine) tunnelRef() string {
	for _, r := range e.led.Unconfirmed() {
		if r.Provider == "cloudflare" && r.Kind == "tunnel" {
			return r.Ref
		}
	}
	return ""
}
