package steps

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func fixed(s string) func(*Engine) string { return func(*Engine) string { return s } }

// acceptString is the accept function for every `text`, `choice` and `secret`
// need. The validate hook is where a step says what it will take.
func acceptString(validate func(*Engine, string) error) func(*Engine, json.RawMessage) error {
	return func(e *Engine, raw json.RawMessage) error {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("%w: expected a string", ErrBadAnswer)
		}
		return validate(e, strings.TrimSpace(s))
	}
}

// appChoice mirrors one entry of an `apps` need's options, which is the shape
// the contract fixes for the question and therefore the shape of the answer.
type appChoice struct {
	ID string `json:"id"`
	On bool   `json:"on"`
}

func acceptApps(e *Engine, raw json.RawMessage) error {
	var chosen []appChoice
	if err := json.Unmarshal(raw, &chosen); err != nil {
		return fmt.Errorf(`%w: expected [{"id":"…","on":true}, …]`, ErrBadAnswer)
	}
	known := map[string]bool{}
	for _, a := range e.catalogue().Apps {
		known[a.ID] = true
	}
	for _, c := range chosen {
		if !known[c.ID] {
			// Refused rather than ignored. An id nobody recognises is a page
			// and an engine that disagree about what exists, and silently
			// dropping it means they go on disagreeing.
			return fmt.Errorf("%w: %q is not an app this instance knows about", ErrBadAnswer, c.ID)
		}
		e.given.apps[c.ID] = c.On
	}
	return nil
}

func acceptConfirm(set func(*Engine, bool)) func(*Engine, json.RawMessage) error {
	return func(e *Engine, raw json.RawMessage) error {
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return fmt.Errorf("%w: expected true or false", ErrBadAnswer)
		}
		set(e, b)
		return nil
	}
}

// cleanDomain takes what somebody typed and returns the bare domain, or says
// why it is not one.
//
// Strict on purpose, and specifically about the things a person pastes. A URL,
// a host with a port, or a trailing path all look right in a text box and all
// produce hostnames that resolve to nothing — and the first place that shows up
// is a DNS record in somebody's real zone.
func cleanDomain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.TrimSuffix(d, ".")
	switch {
	case d == "":
		return "", errors.New("a domain is needed")
	case strings.Contains(d, "://"):
		return "", errors.New("that is a URL. The domain on its own, with no https:// in front of it")
	case strings.ContainsAny(d, "/\\ \t@?#"):
		return "", errors.New("a domain has no path, space or @ in it")
	case strings.Contains(d, ":"):
		return "", errors.New("a domain has no port. The instance answers on 443 through the tunnel")
	case strings.Contains(d, ".."):
		return "", errors.New("that has an empty label in it")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", errors.New("that is a single label, not a domain — it needs at least one dot")
	}
	for _, l := range labels {
		if l == "" {
			return "", errors.New("that has an empty label in it")
		}
		if len(l) > 63 {
			return "", fmt.Errorf("%q is longer than a DNS label may be", l)
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", fmt.Errorf("%q starts or ends with a hyphen", l)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return "", fmt.Errorf("%q has a character a hostname cannot carry: %q", l, string(r))
			}
		}
	}
	// Every app is published one label deeper, so the longest hostname this
	// domain will ever carry is checked here rather than at the record.
	if len(d)+len("assistant.") > 253 {
		return "", errors.New("that domain is too long to hang app hostnames under")
	}
	return d, nil
}
