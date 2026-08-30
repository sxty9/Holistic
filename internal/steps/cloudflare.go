package steps

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Cloudflare is the seam through which this package reads from Cloudflare.
//
// IT HAS NO WRITE, and that is the design rather than an unfinished half.
// Warpgate owns the edge: it is where the ownership marker lives, where a
// record that was not created here becomes a Conflict instead of an overwrite,
// where deletions get their own confirmation, and where the journal of what was
// changed is kept. A second thing in this landscape that can write DNS would be
// a second thing that has to be taught all of that, and the day the two
// disagree is the day somebody's website is replaced by a launcher.
//
// So every write in this wizard runs `warpgate`, through Machine, and every
// question this package asks Cloudflare directly is a question.
type Cloudflare interface {
	// TokenActive answers whether the token is valid and live. It cannot answer
	// what else the token reaches — see Zone.Permissions.
	TokenActive(ctx context.Context, token string) (bool, error)
	// Zone looks a domain up as a zone.
	Zone(ctx context.Context, token, domain string) (Zone, error)
	// Records lists the zone as it stands.
	Records(ctx context.Context, token, zoneID string) ([]DNSRecord, error)
}

type Zone struct {
	ID        string
	Name      string
	Status    string
	AccountID string
	// Nameservers are the ones Cloudflare expects the registrar to be pointing
	// at. They are what a pending zone is waiting for and are worth showing
	// verbatim, because the operator has to type them somewhere else entirely.
	Nameservers []string
	// Permissions is what the ASKING TOKEN can do on this zone —
	// ["#dns_records:edit", "#zone:read", …]. It is the only permission
	// read-back available to a correctly scoped token: GET /user/tokens/verify
	// returns {id, status} and nothing more, and reading a token's own
	// definition needs an account-category permission the setup token
	// deliberately does not carry. Measured against the live API on 2026-08-30.
	Permissions []string
}

type DNSRecord struct {
	ID      string
	Type    string
	Name    string
	Content string
	TTL     int
	Proxied bool
	Comment string
}

// Ours answers whether Warpgate created this record. The marker is Warpgate's
// and is read here rather than re-derived, because two places deciding what
// "ours" means is how a foreign record gets adopted and later deleted.
func (r DNSRecord) Ours() bool { return strings.HasPrefix(r.Comment, "warpgate:") }

// LiveCloudflare is the real one.
func LiveCloudflare(timeout time.Duration) Cloudflare {
	return &liveCF{c: &http.Client{Timeout: timeout}}
}

type liveCF struct{ c *http.Client }

const cfAPI = "https://api.cloudflare.com/client/v4"

// envelope is Cloudflare's uniform reply. Errors come back inside a 200 as
// often as not, so success is read from the body rather than from the status.
type envelope struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (l *liveCF) get(ctx context.Context, token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", cfAPI+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := l.c.Do(req)
	if err != nil {
		// The token is never in the message. A transport error carries the URL,
		// and the URL is safe; the header is not, and an error string is the
		// most-copied text in any incident.
		return fmt.Errorf("could not reach Cloudflare: %w", err)
	}
	defer res.Body.Close()

	var env envelope
	if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
		return fmt.Errorf("Cloudflare answered %s with something that is not JSON: %w", res.Status, err)
	}
	if !env.Success {
		var msgs []string
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		if len(msgs) == 0 {
			msgs = []string{res.Status}
		}
		return fmt.Errorf("Cloudflare refused: %s", strings.Join(msgs, "; "))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

func (l *liveCF) TokenActive(ctx context.Context, token string) (bool, error) {
	var r struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := l.get(ctx, token, "/user/tokens/verify", &r); err != nil {
		return false, err
	}
	return strings.EqualFold(r.Status, "active"), nil
}

func (l *liveCF) Zone(ctx context.Context, token, domain string) (Zone, error) {
	var zs []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Status  string `json:"status"`
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
		NameServers []string `json:"name_servers"`
		Permissions []string `json:"permissions"`
	}
	if err := l.get(ctx, token, "/zones?name="+url.QueryEscape(domain), &zs); err != nil {
		return Zone{}, err
	}
	if len(zs) == 0 {
		return Zone{}, fmt.Errorf("this Cloudflare account has no zone called %s", domain)
	}
	z := zs[0]
	return Zone{
		ID: z.ID, Name: z.Name, Status: z.Status, AccountID: z.Account.ID,
		Nameservers: z.NameServers, Permissions: z.Permissions,
	}, nil
}

func (l *liveCF) Records(ctx context.Context, token, zoneID string) ([]DNSRecord, error) {
	// One page of 500. A zone with more than that is beyond what this wizard
	// should be silently summarising, and the count is reported so a truncation
	// would be visible rather than assumed away.
	var rs []struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
		Proxied bool   `json:"proxied"`
		Comment string `json:"comment"`
	}
	if err := l.get(ctx, token, "/zones/"+url.PathEscape(zoneID)+"/dns_records?per_page=500", &rs); err != nil {
		return nil, err
	}
	out := make([]DNSRecord, 0, len(rs))
	for _, r := range rs {
		out = append(out, DNSRecord{
			ID: r.ID, Type: r.Type, Name: r.Name, Content: r.Content,
			TTL: r.TTL, Proxied: r.Proxied, Comment: r.Comment,
		})
	}
	return out, nil
}
