// Command holistic-setup turns a blank Holistic instance into somebody's own.
//
// It is a separate program from everything it configures, and that is not
// tidiness. corex-api and solisuite both run under IPAddressDeny=any with
// IPAddressAllow=localhost, an empty CapabilityBoundingSet and no ambient
// capabilities: neither of them CAN accept a packet from a laptop, and opening
// one of them up would mean uncaging a steady-state daemon for a job that
// happens once. Setup also has to run before those services have a domain, an
// administrator or a certificate, so it cannot depend on them to authenticate
// anybody.
//
// It answers on the local network, guarded by a code the installer printed, and
// it removes itself when it is finished. What stays behind at holistic.local
// afterwards is a status page: services, versions, and where to sign in. Not a
// login form — after the hand-off the instance's session cookie is scoped to
// the real domain and marked Secure, so a form served over http://holistic.local
// could never succeed, and a login that can never work is worse than none at
// all because it is discovered in an emergency.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sxty9/Holistic/internal/claim"
	"github.com/sxty9/Holistic/internal/lan"
	"github.com/sxty9/Holistic/internal/ledger"
	"github.com/sxty9/Holistic/internal/session"
	"github.com/sxty9/Holistic/internal/steps"
	"path/filepath"
)

// SealPath marks an instance as claimed. It is root-owned and the setup process
// can read it and never write it — the same posture /etc/corex has, and for the
// same reason: a program that can rescind the fact that it has already run is a
// program that can be talked into running again.
const SealPath = "/etc/holistic/claimed"

func main() {
	var (
		port      = flag.String("port", "80", "port to answer on")
		claimPath = flag.String("claim", claim.Path, "file holding the setup code")
		ledgerAt  = flag.String("ledger", ledger.DefaultPath, "file recording what setup did")
		sealAt    = flag.String("seal", SealPath, "file marking this instance as claimed")
		webDir    = flag.String("web", "", "directory holding the built setup pages; empty serves the plain ones")
	)
	flag.Parse()

	srv, err := newServer(*claimPath, *ledgerAt, *sealAt)
	if err == nil {
		srv.webDir = usableWeb(*webDir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "holistic-setup:", err)
		os.Exit(1)
	}
	if err := srv.run(*port); err != nil {
		fmt.Fprintln(os.Stderr, "holistic-setup:", err)
		os.Exit(1)
	}
}

type server struct {
	guard    *claim.Guard
	led      *ledger.Ledger
	steps    *steps.Engine
	sessions *session.Store
	sealed   bool
	sealAt   string
	claimAt  string
	// needsCode marks an instance with neither a code nor a seal: claimed and
	// unsealed with its code spent, or one whose code was removed by hand.
	needsCode bool
	// webDir holds the built pages, or is empty. Empty is not a failure: the
	// server-rendered pages below still claim an instance and still say what is
	// happening. A release that shipped without the frontend should be poorer,
	// not broken — and finding out which one you have should not require
	// reading a stack trace.
	webDir string

	mu      sync.Mutex
	refused []string // source addresses that offered a wrong code
}

func newServer(claimAt, ledgerAt, sealAt string) (*server, error) {
	return newServerWith(claimAt, ledgerAt, sealAt,
		steps.DefaultPaths(), steps.LocalMachine(), steps.LiveFetch(30*time.Second))
}

// newServerWith is the same server pointed somewhere else. It exists so the
// tests can hand the engine a t.TempDir() and a Machine that records instead of
// acting — nothing in the test suite may start, stop or restart anything on the
// machine running it, and that is only true if there is a way to say so.
func newServerWith(claimAt, ledgerAt, sealAt string, p steps.Paths, m steps.Machine, f steps.Fetch) (*server, error) {
	s := &server{sessions: session.NewStore(), sealAt: sealAt, claimAt: claimAt}

	_, sealErr := os.Stat(sealAt)
	s.sealed = sealErr == nil

	led, ledErr := ledger.Open(ledgerAt)

	// Fail closed, and this is the specific failure worth spelling out. Immich
	// re-offered administrator registration to the whole network whenever its
	// data directory looked empty — which happened every time an encrypted disk
	// was not mounted before the service started. The empty directory was read
	// as "nothing has been set up yet", and the correct reading was "I cannot
	// see what has been set up."
	//
	// So: if this instance is marked claimed and the ledger cannot be read, the
	// answer is not "start over". It is to refuse and say so.
	if s.sealed && ledErr != nil {
		return nil, fmt.Errorf(
			"this instance is marked as claimed (%s exists) but its ledger cannot be read: %w\n"+
				"Refusing to serve setup. Nothing is being offered to the network.\n"+
				"If the storage holding %s is not mounted, mount it and start this again.",
			sealAt, ledErr, ledgerAt)
	}
	if ledErr != nil && !s.sealed {
		return nil, ledErr
	}
	s.led = led

	if s.sealed {
		return s, nil
	}

	// Built after the seal check and never on a sealed instance. The engine
	// reads the machine as it is constructed, and a sealed instance is one
	// whose setup surface is supposed to be gone rather than merely idle.
	s.steps = steps.New(led, p, m, f)

	g, err := claim.Load(claimAt)
	if err != nil {
		if errors.Is(err, claim.ErrNoCode) {
			// No code and no seal. This is not a reason to die, and dying here
			// was measured doing real damage: redeeming a code destroys it —
			// correctly, a spent code lying in /etc is a second key to an open
			// door — but the seal is only written when setup FINISHES. Between
			// those two moments the instance is claimed and unsealed, which is
			// the normal state for as long as setup takes, and two of its steps
			// wait on a registrar.
			//
			// Exiting there meant any restart in that window put the daemon
			// into a loop: 398 restarts on the machine this was found on, the
			// LAN listener gone, and the only explanation in a journal nobody
			// was reading. That is the same shape as the nine-day outage this
			// project spent a night diagnosing.
			//
			// So it stays up and says what to do. That reveals nothing: a page
			// saying a setup code is needed tells an attacker what they could
			// already infer from the gate.
			s.needsCode = true
			return s, nil
		}
		return nil, err
	}
	s.guard = g
	return s, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	// Every pattern below is anchored with {$}. A bare "/" in Go's ServeMux is
	// a catch-all for every path AND every method, so registering the status
	// page at "/" on a sealed instance left it answering POST /claim with 200 —
	// the setup route was not gone, it was merely unregistered, and the
	// catch-all quietly stood in for it. Routes that do not exist should 404.
	if s.sealed {
		// Everything the setup process used to answer is gone, not disabled.
		// A flag consulted by live code is a flag some later branch can read
		// the wrong way; a route that does not exist cannot be reached by a
		// mistake nobody has made yet.
		mux.HandleFunc("GET /{$}", s.status)
		return lan.OnlyLocal(mux)
	}

	if s.needsCode {
		// One route, and it is not the gate. Registering /claim here would
		// offer a form with nothing behind it; a route that cannot work should
		// not exist.
		mux.HandleFunc("GET /{$}", s.noCode)
		return lan.OnlyLocal(mux)
	}

	if s.webDir != "" {
		// The pages decide which screen to show by asking /api/state, never by
		// reading a cookie of their own — so this is served to anybody, and the
		// unauthorised answer from the API is what puts the setup code in front
		// of them. index.html carries no secret; the gate is the API.
		mux.HandleFunc("GET /{$}", s.page)
		mux.Handle("GET /assets/", http.StripPrefix("/assets/",
			http.FileServer(http.Dir(filepath.Join(s.webDir, "assets")))))
	} else {
		mux.HandleFunc("GET /{$}", s.gate)
	}
	mux.HandleFunc("POST /claim/{$}", s.redeem)
	mux.Handle("GET /api/state/{$}", s.sessions.Require(http.HandlerFunc(s.state)))

	// The three action routes carry no trailing slash, which anchors them just
	// as {$} does: a pattern that does not end in "/" is not a subtree and
	// matches that path and nothing else. The trailing slash is what would need
	// anchoring, and these must not have one — ServeMux answers a missing
	// trailing slash with a redirect, and a redirected POST is a POST that
	// arrives somewhere with its body gone.
	mux.Handle("POST /api/step/{id}/run", s.sessions.Require(http.HandlerFunc(s.runStep)))
	mux.Handle("POST /api/step/{id}/skip", s.sessions.Require(http.HandlerFunc(s.skipStep)))
	mux.Handle("POST /api/answer/{id}", s.sessions.Require(http.HandlerFunc(s.answer)))
	return lan.OnlyLocal(mux)
}

// gate is the first thing anybody sees. It asks for the code, and it asks
// before rendering anything else — the wizard is not served and then guarded at
// its last step.
// usableWeb answers whether a directory really holds pages, rather than whether
// somebody passed a path. A -web pointing at an empty directory would otherwise
// serve a 404 at / and nothing would say why.
func usableWeb(dir string) string {
	if dir == "" {
		return ""
	}
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		fmt.Fprintf(os.Stderr,
			"holistic-setup: no index.html under %s, serving the plain pages instead\n", dir)
		return ""
	}
	return dir
}

func (s *server) noCode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	fmt.Fprint(w, pageNoCode())
}

func (s *server) page(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.ServeFile(w, r, filepath.Join(s.webDir, "index.html"))
}

func (s *server) gate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Nothing here is cacheable and nothing may be framed. The page creates an
	// administrator; a copy of it sitting in a shared cache or inside somebody
	// else's iframe is not a page, it is a hazard.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if s.sessions.Valid(r) {
		fmt.Fprint(w, pageClaimed(s.refusedCount()))
		return
	}
	fmt.Fprint(w, pageGate(""))
}

func (s *server) redeem(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable form", http.StatusBadRequest)
		return
	}
	err := s.guard.Redeem(r.PostFormValue("code"))
	if err != nil {
		// An expired code is not a probe. It is the operator being slower than
		// an hour, which is an ordinary thing to be, and counting it as a wrong
		// code puts their own attempt into the "somebody tried to claim this
		// machine" banner on their first screen. Two different events had one
		// line, and the line named the wrong one.
		s.noteRefusal(r.RemoteAddr, err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, pageGate(explain(err)))
		return
	}
	if _, err := s.sessions.Issue(w); err != nil {
		http.Error(w, "could not start a session", http.StatusInternalServerError)
		return
	}
	// The code is spent the moment it is redeemed. It is also removed from
	// disk: one left lying in /etc after a successful claim is a second key to
	// a door that is already open.
	if err := claim.Destroy(s.claimAt); err != nil {
		fmt.Fprintf(os.Stderr, "holistic-setup: the setup code could not be removed from %s: %v\n", s.claimAt, err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func explain(err error) string {
	switch {
	case errors.Is(err, claim.ErrWrongCode):
		return "That is not the setup code. It was printed by the installer, on the machine itself."
	case errors.Is(err, claim.ErrLockedOut):
		return "Too many wrong codes. Mint a new one on the machine before trying again."
	case errors.Is(err, claim.ErrExpired):
		return "That code has expired. Mint a new one on the machine."
	case errors.Is(err, claim.ErrAlreadyRun):
		return "This instance has already been claimed in another browser."
	}
	return "The code was not accepted."
}

func (s *server) noteRefusal(remote string, why error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if host, _, ok := strings.Cut(remote, ":"); ok {
		remote = host
	}
	// Only a wrong code is a probe. An expired one is the operator being
	// slower than an hour, a spent one is a second browser tab, and a locked
	// guard is the consequence of earlier attempts rather than a new one.
	// Counting those into `refused` would put the operator's own attempts into
	// the "somebody tried to claim this machine" banner on their first screen,
	// which is how a warning that matters becomes one nobody reads.
	if errors.Is(why, claim.ErrWrongCode) {
		s.refused = append(s.refused, remote)
	}
	// Every refusal is logged, and named. "wrong setup code" for an expired one
	// sends whoever reads the journal looking for an intruder who is the person
	// holding the terminal.
	fmt.Fprintf(os.Stderr, "holistic-setup: setup code refused from %s: %s\n", remote, reason(why))
}

// reason turns a refusal into the sentence a journal should carry.
func reason(err error) string {
	switch {
	case errors.Is(err, claim.ErrWrongCode):
		return "wrong code"
	case errors.Is(err, claim.ErrExpired):
		return "the code has expired; mint a new one on the machine"
	case errors.Is(err, claim.ErrLockedOut):
		return "too many wrong codes; the guard is locked until a new code is minted"
	case errors.Is(err, claim.ErrAlreadyRun):
		return "the code was already spent"
	}
	return err.Error()
}

func (s *server) refusedCount() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.refused...)
}

// state is the whole thing, and it is the answer to every route below too. A
// page that gets the same envelope back from every call never has to merge two
// representations of the same thing, and never has to guess which one is newer.
func (s *server) state(w http.ResponseWriter, r *http.Request) {
	s.writeState(w)
}

func (s *server) writeState(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	from := s.refusedCount()
	writeJSON(w, s.steps.State(s.sealed, len(from), from))
}

func (s *server) runStep(w http.ResponseWriter, r *http.Request) {
	// A step that fails, conflicts or is still waiting is a 200 carrying an
	// envelope that says so: those are outcomes, and the row is where an
	// outcome lives. Only a request that is wrong — an id that is not a step,
	// a body that is not what was asked for — is a 4xx, because that is a
	// mistake by the caller rather than a fact about the machine.
	if err := s.steps.Run(r.PathValue("id")); err != nil {
		s.stepError(w, err)
		return
	}
	s.writeState(w)
}

func (s *server) skipStep(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	if err := s.steps.Skip(r.PathValue("id"), body.Reason); err != nil {
		s.stepError(w, err)
		return
	}
	s.writeState(w)
}

func (s *server) answer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Value json.RawMessage `json:"value"`
	}
	// Bounded: this is an unauthenticated-by-design surface on a LAN, and the
	// body arrives before anything has decided it is reasonable.
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&body); err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	if err := s.steps.Answer(r.PathValue("id"), body.Value); err != nil {
		s.stepError(w, err)
		return
	}
	// The envelope, and nothing else — in particular not the value that was
	// just submitted. A `secret` need is submitted and never returned, and the
	// only way to be sure of that is for no handler on this surface to have a
	// path that echoes what it was given.
	s.writeState(w)
}

func (s *server) stepError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, steps.ErrUnknownStep):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, steps.ErrNoReason), errors.Is(err, steps.ErrBadAnswer), errors.Is(err, steps.ErrNotAsked):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, pageStatus(s.led))
}

func (s *server) run(port string) error {
	addrs, err := lan.Listen(port)
	if err != nil {
		return err
	}
	handler := s.routes()

	var servers []*http.Server
	errs := make(chan error, len(addrs))
	for _, addr := range addrs {
		srv := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		servers = append(servers, srv)
		go func(srv *http.Server) {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("%s: %w", srv.Addr, err)
			}
		}(srv)
	}

	if s.sealed {
		fmt.Printf("holistic: this instance is claimed. Serving the status page on %d address(es).\n", len(addrs))
	} else {
		fmt.Printf("holistic: waiting to be claimed. Listening on %d address(es).\n", len(addrs))
		if urls, err := lan.URLs(port); err == nil {
			for _, u := range urls {
				fmt.Println("   ", u)
			}
		}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errs:
		return err
	case <-stop:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
	return nil
}
