package steps

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Machine is the one seam through which this package touches the machine it
// runs on. Everything that starts, stops, enables or interrogates a service
// goes through here, and so does every command run on the operator's behalf.
//
// It is one interface rather than a helper per call site for a single reason:
// the test suite must not be able to start, stop or restart anything on the
// machine running it, and that is only enforceable if there is exactly one door
// and every test closes it. A second exec.Command anywhere in this package
// would be a second door, and nothing in a test would fail to tell you.
type Machine interface {
	// Restart brings a unit back with its new configuration.
	Restart(unit string) error
	// EnableNow starts a unit and makes it survive a reboot. Both halves, and
	// the second is the one that gets forgotten: a tunnel connector that is
	// running but not enabled is an instance that is on the internet until the
	// next power cut.
	EnableNow(unit string) error
	// Disable keeps a unit from coming back at the next boot. It does NOT stop
	// it — see StopSoon, and the reason they are two calls.
	Disable(unit string) error
	// StopSoon asks systemd to stop a unit and returns without waiting.
	//
	// It is separate from Disable because of the one unit that stops itself.
	// `systemctl disable --now holistic-setup.service` is run BY
	// holistic-setup.service: the --now kills the process mid-call, systemctl
	// never returns, and the step reports "signal: terminated" — a failure
	// message for work that had already succeeded. Seen live on 2026-08-30:
	// the instance was sealed, the code was gone and the unit was disabled and
	// stopped, and the ledger said failed.
	//
	// So: disable, which returns because it stops nothing; write the result;
	// then ask for the stop and do not wait for an answer that cannot come.
	StopSoon(unit string) error
	IsActive(unit string) bool
	IsEnabled(unit string) bool
	// Run executes a command and returns its combined output. The output is
	// returned on failure too, because a command's own words are a better error
	// than anything this package could write about it.
	Run(name string, args ...string) (string, error)
}

// LocalMachine is the real one.
func LocalMachine() Machine { return systemd{} }

type systemd struct{}

func (systemd) Restart(unit string) error {
	out, err := exec.Command("systemctl", "restart", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s did not come back: %v\n%s", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (systemd) EnableNow(unit string) error {
	out, err := exec.Command("systemctl", "enable", "--now", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s could not be enabled and started: %v\n%s", unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// is-active and is-enabled exit non-zero for anything that is not, which is the
// question being asked, so the exit code is the answer.
func (systemd) Disable(unit string) error {
	out, err := exec.Command("systemctl", "disable", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s could not be kept from coming back at the next boot: %v\n%s",
			unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (systemd) StopSoon(unit string) error {
	// --no-block: systemd queues the job and systemctl returns at once. Without
	// it, stopping the unit this process belongs to kills the process before
	// systemctl can report, and the caller reads its own death as an error.
	out, err := exec.Command("systemctl", "--no-block", "stop", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s was asked to stop and systemd refused: %v\n%s",
			unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (systemd) IsActive(unit string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

func (systemd) IsEnabled(unit string) bool {
	return exec.Command("systemctl", "is-enabled", "--quiet", unit).Run() == nil
}

func (systemd) Run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Response is what came back from the public internet.
type Response struct {
	Status int
	Header http.Header
	Body   string
}

// Fetch is how this package looks at the instance from outside. It is a seam
// for the same reason Machine is, plus one more: the request it makes carries
// no cookies and no credentials on purpose, because the question it answers is
// "what does a stranger see", and a client that has been anywhere else in this
// process cannot answer that.
type Fetch func(ctx context.Context, url string) (Response, error)

// LiveFetch is the real one. No redirect following and no cookie jar: a
// redirect that is followed silently is a redirect nobody saw, and a jar is a
// way for one probe to answer for another.
func LiveFetch(timeout time.Duration) Fetch {
	c := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return func(ctx context.Context, url string) (Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return Response{}, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return Response{}, err
		}
		defer resp.Body.Close()
		// Bounded: this reads whatever a hostname somebody else controls
		// decides to send.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return Response{Status: resp.StatusCode, Header: resp.Header, Body: string(body)}, nil
	}
}
