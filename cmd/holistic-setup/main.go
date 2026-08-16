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
	"errors"
	"flag"
	"fmt"
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
	)
	flag.Parse()

	srv, err := newServer(*claimPath, *ledgerAt, *sealAt)
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
	sessions *session.Store
	sealed   bool
	sealAt   string
	claimAt  string

	mu      sync.Mutex
	refused []string // source addresses that offered a wrong code
}

func newServer(claimAt, ledgerAt, sealAt string) (*server, error) {
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

	g, err := claim.Load(claimAt)
	if err != nil {
		if errors.Is(err, claim.ErrNoCode) {
			return nil, fmt.Errorf(
				"there is no setup code at %s, so nobody could prove they installed this machine.\n"+
					"Run the installer, or mint one on the machine itself.", claimAt)
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

	mux.HandleFunc("GET /{$}", s.gate)
	mux.HandleFunc("POST /claim/{$}", s.redeem)
	mux.Handle("GET /api/state/{$}", s.sessions.Require(http.HandlerFunc(s.state)))
	return lan.OnlyLocal(mux)
}

// gate is the first thing anybody sees. It asks for the code, and it asks
// before rendering anything else — the wizard is not served and then guarded at
// its last step.
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
		s.noteRefusal(r.RemoteAddr)
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

func (s *server) noteRefusal(remote string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if host, _, ok := strings.Cut(remote, ":"); ok {
		remote = host
	}
	s.refused = append(s.refused, remote)
	// Logged as well as counted. The owner sees the count on their first
	// screen; the journal is where it stays afterwards.
	fmt.Fprintf(os.Stderr, "holistic-setup: wrong setup code offered by %s\n", remote)
}

func (s *server) refusedCount() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.refused...)
}

func (s *server) state(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{
		"steps":       s.led.Steps(),
		"unconfirmed": s.led.Unconfirmed(),
	})
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
