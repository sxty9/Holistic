// Package ledger records what setup did, as it does it.
//
// It has three jobs, and the third is the one that decides its shape.
//
// It is the page's state. Reopening the setup URL lands on the same rows in the
// same condition, because those rows live in a file rather than in a browser
// tab. A person who closes the tab while waiting on a nameserver change should
// not lose an hour of work to it.
//
// It is the evidence half of ownership. A record in somebody's DNS zone carries
// a comment claiming Warpgate wrote it, but a comment is free text; before
// anything is deleted the useful question is "did this machine create it?", and
// only a local file can answer that.
//
// And it is what makes an abandoned setup cleanable. Every off-box create is
// written down BEFORE the call that creates it, never after. That ordering
// looks pedantic until the call succeeds and the process dies before it can
// record the result: with write-after, a tunnel, a DNS record or a verified SES
// identity exists in somebody's account with nothing on the machine that knows
// it is there. With write-ahead, the worst case is an entry marked intended and
// unconfirmed — which reads as "this might exist, go and look", and that is a
// state a person can act on.
package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const DefaultPath = "/var/lib/holistic/provisioned.json"

// Status is where a step stands. The set is deliberately small, and
// WaitingOnThem is deliberately distinct from Pending: "we are working" and
// "a registrar is working" feel identical in a spinner and are completely
// different facts, and conflating them is how a wizard ends up lying for six
// hours about a nameserver change.
type Status string

const (
	Pending       Status = "pending"
	Running       Status = "running"
	WaitingOnThem Status = "waiting_on_them"
	Passed        Status = "passed"
	Failed        Status = "failed"
	Conflict      Status = "conflict"
	Skipped       Status = "skipped"
)

type Step struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	// Detail is what the row says next to its state — an error, a conflict
	// summary, or what is being waited for.
	Detail string `json:"detail,omitempty"`
	// Proof is how this step was shown to be true. A step that passed on an
	// API returning 200 records that; a step proven by an end-to-end
	// observation records the observation, including its nonce. The difference
	// matters enough to keep: everything reported success the week inbound mail
	// was being destroyed.
	Proof string `json:"proof,omitempty"`
	At    string `json:"at,omitempty"`
}

// Resource is something created outside this machine.
type Resource struct {
	Provider string `json:"provider"` // cloudflare | aws
	Kind     string `json:"kind"`     // tunnel | dns_record | ses_identity | sns_topic | iam_user
	Ref      string `json:"ref"`      // whatever identifies it at the provider
	Note     string `json:"note,omitempty"`
	Intended string `json:"intended"`
	// Confirmed is empty until the provider has acknowledged the create. An
	// entry that stays unconfirmed is the one worth a human's attention.
	Confirmed string `json:"confirmed,omitempty"`
}

type State struct {
	Started   string              `json:"started"`
	Domain    string              `json:"domain,omitempty"`
	Steps     map[string]Step     `json:"steps"`
	Order     []string            `json:"order"`
	Resources map[string]Resource `json:"resources"`
}

type Ledger struct {
	mu    sync.Mutex
	path  string
	state State
	now   func() time.Time
}

// Open loads an existing ledger or starts one.
func Open(path string) (*Ledger, error) {
	if path == "" {
		path = DefaultPath
	}
	l := &Ledger{
		path: path,
		now:  time.Now,
		state: State{
			Steps:     map[string]Step{},
			Resources: map[string]Resource{},
		},
	}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		l.state.Started = l.now().UTC().Format(time.RFC3339)
		return l, l.save()
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &l.state); err != nil {
		// A corrupt ledger is not an empty one, and treating it as empty is
		// how Nextcloud's installer reappeared over live data. Refuse, and let
		// a person decide.
		return nil, fmt.Errorf("%s is not readable as a ledger (%w) — move it aside deliberately if you mean to start over", path, err)
	}
	if l.state.Steps == nil {
		l.state.Steps = map[string]Step{}
	}
	if l.state.Resources == nil {
		l.state.Resources = map[string]Resource{}
	}
	return l, nil
}

func (l *Ledger) save() error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(l.state, "", "  ")
	if err != nil {
		return err
	}
	// Written through a temporary file and renamed. A half-written ledger is
	// worse than none: it is the file the next run reads to decide what already
	// exists in somebody's cloud account.
	tmp := l.path + ".incoming"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

func (l *Ledger) Domain(d string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.state.Domain = d
	return l.save()
}

// Mark records where a step stands.
func (l *Ledger) Mark(id string, st Status, detail string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state.Steps[id]
	s.ID, s.Status, s.Detail = id, st, detail
	s.At = l.now().UTC().Format(time.RFC3339)
	if _, seen := l.state.Steps[id]; !seen {
		l.state.Order = append(l.state.Order, id)
	}
	l.state.Steps[id] = s
	return l.save()
}

// Prove records that a step was shown to be true, and how.
//
// Separate from Mark on purpose. A step marked passed because an API returned
// 200 and a step passed because a real message came back through the whole
// chain are not the same claim, and only one of them would have caught the week
// where every component reported success and inbound mail reached nobody.
func (l *Ledger) Prove(id, proof string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state.Steps[id]
	if s.ID == "" {
		s.ID = id
		l.state.Order = append(l.state.Order, id)
	}
	s.Status, s.Proof = Passed, proof
	s.At = l.now().UTC().Format(time.RFC3339)
	l.state.Steps[id] = s
	return l.save()
}

// Intend records an off-box resource before the call that creates it.
func (l *Ledger) Intend(r Resource) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r.Intended = l.now().UTC().Format(time.RFC3339)
	l.state.Resources[resKey(r)] = r
	return l.save()
}

// Confirm records that the provider acknowledged it.
func (l *Ledger) Confirm(provider, kind, ref string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := resKey(Resource{Provider: provider, Kind: kind, Ref: ref})
	r, ok := l.state.Resources[k]
	if !ok {
		// Confirming something never intended means the write-ahead order was
		// broken somewhere. Record it rather than dropping it: an unexplained
		// resource is still a resource somebody has to clean up.
		r = Resource{Provider: provider, Kind: kind, Ref: ref,
			Note:     "confirmed without having been recorded first",
			Intended: l.now().UTC().Format(time.RFC3339)}
	}
	r.Confirmed = l.now().UTC().Format(time.RFC3339)
	l.state.Resources[k] = r
	return l.save()
}

// Unconfirmed lists everything recorded as intended that was never
// acknowledged. This is the list a person is shown when a run was interrupted:
// each entry may or may not exist in their account, and only they can look.
func (l *Ledger) Unconfirmed() []Resource {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Resource
	for _, r := range l.state.Resources {
		if r.Confirmed == "" {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return resKey(out[i]) < resKey(out[j]) })
	return out
}

// Created reports whether this machine created a particular thing. It is the
// evidence half of the ownership rule: a provider-side marker is a claim, and
// this is the corroboration.
func (l *Ledger) Created(provider, kind, ref string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.state.Resources[resKey(Resource{Provider: provider, Kind: kind, Ref: ref})]
	return ok && r.Confirmed != ""
}

// Steps returns the rows in the order they were first touched, which is the
// order the page renders them in.
func (l *Ledger) Steps() []Step {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Step, 0, len(l.state.Order))
	for _, id := range l.state.Order {
		out = append(out, l.state.Steps[id])
	}
	return out
}

func (l *Ledger) Status(id string) Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.state.Steps[id]; ok {
		return s.Status
	}
	return Pending
}

func resKey(r Resource) string { return r.Provider + "/" + r.Kind + "/" + r.Ref }
