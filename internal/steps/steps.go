// Package steps is the wizard's engine, and it is a reconciler rather than a
// form runner.
//
// The distinction decides everything else in here. A form runner asks a
// question, writes the answer, and is finished; it can only be run once, on a
// blank machine, in one direction. A reconciler reads what is actually on the
// machine, compares it with what is wanted, and applies only the difference —
// which means the same code is the first-run wizard, the later "why is mail not
// arriving" diagnosis, and the later change of domain. It also means every step
// has to be safe to run twice, because running it twice is the normal case and
// not the exceptional one.
//
// Three rules follow from that and are enforced here rather than left to each
// step's author.
//
// A step never writes what it has not first shown. Every local write goes
// through instance.File, which edits the file rather than replacing it, keeps a
// copy of the previous version, renames the new one into place, and can list
// what it is about to change key by key before it changes it.
//
// A step that finds something it did not create does not write. It returns a
// conflict in the fixed six-field shape and stops, and there is deliberately no
// route that overrides one. The point is not to get past the obstacle; it is to
// leave the operator's own things alone.
//
// And a step ends in an observation rather than in the absence of an error. An
// API returning 200 and a file having been written are pre-checks that buy a
// better error message. The proof recorded in the ledger is meant to be the
// thing itself — the hostname that answered, the unit that is running, the
// value read back out of the file after writing it.
package steps

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/sxty9/Holistic/internal/ledger"
)

// Kind says who has to act, and it is what decides whether a step can run
// unattended.
type Kind string

const (
	// Local reads and writes this machine and nothing else.
	Local Kind = "local"
	// Shell runs a command on this machine, or tells the operator to.
	Shell Kind = "shell"
	// Foreign calls somebody else's API. Two of these create things in an
	// account that cannot be un-created, which is why kind is a field and not a
	// comment.
	Foreign Kind = "foreign"
	// Theirs waits on somebody else's clock — a registrar, a certificate
	// authority, the public DNS system. Nothing here can make one go faster and
	// pretending otherwise is what a spinner does.
	Theirs Kind = "theirs"
)

// Option is one entry in a `choice` or an `apps` need.
//
// The two shapes share a JSON key in the contract (`options`), so they share a
// struct here. Value is what a choice submits and ID is what an app list
// submits; both names are fixed by the contract, so neither can be dropped in
// favour of the other. On is a pointer for the one reason a pointer is ever
// worth it: an unchecked app has to serialise as "on": false, and a choice
// option has to carry no "on" at all, which a plain bool cannot express.
type Option struct {
	Value string `json:"value,omitempty"`
	ID    string `json:"id,omitempty"`
	Label string `json:"label"`
	On    *bool  `json:"on,omitempty"`
	Note  string `json:"note,omitempty"`
	// Fixed marks an option the wizard shows and refuses to unset — the
	// launcher, without which there is no way in.
	Fixed bool `json:"fixed,omitempty"`
}

func on(b bool) *bool { return &b }

// Change is one setting a `confirm` need is asking about. It is
// instance.Change on the wire; the conversion exists so that the file-editing
// package and the HTTP contract can be changed independently of each other.
type Change struct {
	Path string `json:"path"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Need is what a step is asking for. The page renders it without knowing what
// any particular step means, which is the whole reason it is one shape with a
// kind rather than a field per step.
type Need struct {
	// Kind is one of text, choice, apps, secret, confirm, manual.
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Help        string `json:"help,omitempty"`
	Link        string `json:"link,omitempty"`
	// Value is what was last given. A `secret` need never carries one, and
	// that is not a rendering preference: a masked secret in a JSON response is
	// still a secret in a browser's memory, in a proxy log, and in whatever the
	// page later serialises.
	Value        string   `json:"value,omitempty"`
	Options      []Option `json:"options,omitempty"`
	Changes      []Change `json:"changes,omitempty"`
	Instructions string   `json:"instructions,omitempty"`
	// Recheck means the page offers "check again" and nothing else. There is
	// never a "continue anyway".
	Recheck bool `json:"recheck,omitempty"`
}

// Unchanged is the product promise, and it is a field rather than a sentence
// the page is trusted to remember. A promise that lives in the front end is a
// promise a redesign can drop.
const Unchanged = "Holistic has not changed anything."

// Conflict is what a step returns when it finds something it did not create.
//
// The fields are fixed and always in this order: the object, what is theirs,
// what was wanted, why the two collide, that nothing was changed, and what to
// do about it. Consequence closes it out — what actually breaks if it is left
// alone — because "this is a conflict" without "and here is what it costs you"
// is a dialog people click through.
type Conflict struct {
	Object string `json:"object"`
	Found  string `json:"found"`
	// FoundNote is how it can be told that the thing is not ours — a TTL, a
	// missing comment, an owner. Quoted rather than paraphrased.
	FoundNote   string `json:"foundNote,omitempty"`
	Desired     string `json:"desired"`
	Why         string `json:"why"`
	Unchanged   string `json:"unchanged"`
	Resolution  string `json:"resolution"`
	Consequence string `json:"consequence,omitempty"`
}

// Row is one step as the page sees it.
//
// detail, proof and at are present even when empty: a page that has to
// distinguish "absent" from "empty" is a page with two code paths for the same
// row.
type Row struct {
	ID      string        `json:"id"`
	Title   string        `json:"title"`
	Kind    Kind          `json:"kind"`
	Status  ledger.Status `json:"status"`
	Detail  string        `json:"detail"`
	Proof   string        `json:"proof"`
	At      string        `json:"at"`
	Needs   *Need         `json:"needs,omitempty"`
	Desired string        `json:"desired"`
	// WaitingOn names who is being waited on, and it exists because the
	// Stepper's rule is that an unattributed wait reads as this machine being
	// slow. A step that waits without naming its subject is the six-hour lie
	// about a nameserver change.
	WaitingOn  string    `json:"waitingOn,omitempty"`
	LastLooked string    `json:"lastLooked,omitempty"`
	Conflict   *Conflict `json:"conflict,omitempty"`
}

// Resource is an entry from the ledger, rendered for the page.
//
// It is not ledger.Resource directly because Confirmed must appear even when it
// is empty — the empty string is the whole point of the field, and a resource
// row without it reads as confirmed rather than as unknown.
type Resource struct {
	Provider  string `json:"provider"`
	Kind      string `json:"kind"`
	Ref       string `json:"ref"`
	Note      string `json:"note,omitempty"`
	Intended  string `json:"intended"`
	Confirmed string `json:"confirmed"`
}

// Envelope is the answer to every route in this package. One shape, so a page
// never has to merge two representations of the same thing.
type Envelope struct {
	ReadAt    string     `json:"readAt"`
	Sealed    bool       `json:"sealed"`
	Domain    string     `json:"domain"`
	Steps     []Row      `json:"steps"`
	Resources []Resource `json:"resources"`
	Refused   int        `json:"refused"`
	// RefusedFrom names where the wrong codes came from. The count says
	// something happened; the addresses are what somebody can act on.
	RefusedFrom []string `json:"refusedFrom"`
}

// Step is one row's definition. The functions are unexported because a step is
// declared in this package and nowhere else: the order and the dependencies
// between them are the design, not configuration.
type Step struct {
	ID    string
	Title string
	Kind  Kind
	// After are the steps whose RESULT this one consumes — never merely the
	// ones that come before it. An ordinal dependency would make every local
	// step unreachable behind the first unimplemented foreign one, and would
	// say something false besides: writing Solisuite's app list does not
	// require a Cloudflare token, and flipping coreX's cookies to Secure
	// genuinely does require a tunnel that answers.
	After []string
	// WaitingOn is who this step waits on when it waits. Empty for steps that
	// only wait on this machine.
	WaitingOn string

	desired func(*Engine) string
	need    func(*Engine) *Need
	accept  func(*Engine, json.RawMessage) error
	run     func(*Engine) result
}

// result is what a run says happened. It is deliberately not (error, proof):
// conflict and waiting are outcomes, not failures, and squeezing them through
// an error would lose the distinction the ledger exists to keep.
type result struct {
	status   ledger.Status
	detail   string
	proof    string
	conflict *Conflict
}

// passedStatus is ledger.Passed under a local name, so that a file full of step
// definitions does not have to import the ledger to build one result by hand.
const passedStatus = ledger.Passed

func passed(detail, proof string) result {
	return result{status: passedStatus, detail: detail, proof: proof}
}

func failed(detail string) result { return result{status: ledger.Failed, detail: detail} }

// blocked is a step that cannot run yet through nobody's fault — it has not
// been told something, or a step it consumes has not passed. It is pending
// rather than failed: the page renders it as "ahead", which is what it is.
func blocked(detail string) result { return result{status: ledger.Pending, detail: detail} }

// waitingOnThem is the state that must never be confused with running.
func waitingOnThem(detail string) result {
	return result{status: ledger.WaitingOnThem, detail: detail}
}

// held fills in the promise and derives the one-line summary, so no step author
// can produce a conflict without it.
func held(c Conflict) result {
	c.Unchanged = Unchanged
	return result{
		status:   ledger.Conflict,
		detail:   c.Object + " is already there. " + Unchanged,
		conflict: &c,
	}
}

// ErrNotImplemented is returned, as a pending row rather than an error, by
// every step that talks to a provider. Those are not written yet on purpose:
// two of them create things in somebody's account that cannot be un-created,
// and neither the shape of the call nor the shape of the failure should be
// guessed at from this side of the wire.
var ErrNotImplemented = errors.New("not implemented yet")

func notYet(what string) result {
	return blocked(ErrNotImplemented.Error() + " — " + what)
}

var (
	// ErrUnknownStep means the id in the URL is not a step. It is a request
	// error rather than a step outcome, which is why it is an error here and a
	// 404 at the handler.
	ErrUnknownStep = errors.New("no such step")
	// ErrNoReason guards a skip with nothing written down. A skipped step
	// nobody can explain later is the one that gets un-skipped by somebody
	// guessing.
	ErrNoReason = errors.New("a skipped step needs a reason")
	// ErrNotAsked is an answer to a step that is not asking for one.
	ErrNotAsked = errors.New("this step is not asking for anything")
	// ErrBadAnswer is an answer that does not fit what was asked for.
	ErrBadAnswer = errors.New("that is not what this step asked for")
)

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
