package lan

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOnlyPrivateAddressesCount(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"192.168.178.98", true},
		{"10.10.0.2", true},
		{"172.16.4.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"fd00::1", true}, // unique local
		{"fe80::1", true}, // link-local
		// A globally routable IPv6 address, which is the shape an ISP hands a
		// home connection and the one a wildcard bind would publish to the
		// internet. 2001:db8::/32 is reserved for documentation (RFC 3849) —
		// the development machine's own prefix would work identically here and
		// has no business in a public repository.
		{"2001:db8:4701::1", false},
		{"8.8.8.8", false},
		{"203.0.113.7", false},
	} {
		if got := IsPrivate(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("IsPrivate(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if IsPrivate(nil) {
		t.Error("a nil address was treated as private")
	}
}

// The check CasaOS got wrong. Reading X-Forwarded-For to decide "is this local"
// let an attacker set the header and reach an unauthenticated root path
// (CVE-2023-37265). Nothing here may believe a header.
func TestProxyHeadersAreNotEvidence(t *testing.T) {
	served := false
	h := OnlyLocal(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true }))

	for _, header := range []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded", "Client-Ip"} {
		served = false
		r := httptest.NewRequest("GET", "http://"+SetupName+"/", nil)
		r.RemoteAddr = "203.0.113.7:41234" // genuinely off-network
		r.Header.Set(header, "192.168.1.5")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if served {
			t.Errorf("%s persuaded the guard that a remote client was local", header)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", header, w.Code)
		}
	}
}

func TestLocalClientsAreServed(t *testing.T) {
	served := false
	h := OnlyLocal(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true }))
	r := httptest.NewRequest("GET", "http://"+SetupName+"/", nil)
	r.RemoteAddr = "192.168.178.42:50000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !served {
		t.Fatalf("a client on the local network was refused: %d %s", w.Code, w.Body)
	}
}

// A request that arrives under some other name is either a misconfiguration or
// somebody pointing a hostname at this box. Neither gets a page that creates an
// administrator.
func TestOnlyOurOwnNamesAreAnswered(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"holistic.local", true},
		{"holistic.local:8080", true},
		{"HOLISTIC.LOCAL", true},
		{"localhost:8080", true},
		{"192.168.178.98", true},
		{"192.168.178.98:8080", true},
		{"[fd00::1]:8080", true},
		{"example.org", false},
		{"setup.example.org", false},
		{"8.8.8.8", false},
		{"", false},
	} {
		if got := HostAllowed(tc.host); got != tc.want {
			t.Errorf("HostAllowed(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestForeignHostIsRefusedEvenFromTheLan(t *testing.T) {
	served := false
	h := OnlyLocal(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true }))
	r := httptest.NewRequest("GET", "http://setup.example.org/", nil)
	r.Host = "setup.example.org"
	r.RemoteAddr = "192.168.178.42:50000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if served {
		t.Error("a request under a foreign hostname was served")
	}
}

// A VPN tunnel and a container bridge are technically reachable and are not
// "your local network". A wildcard bind would have offered both.
func TestTunnelsAndBridgesAreNotOffered(t *testing.T) {
	cases := []struct {
		name  string
		flags net.Flags
		ip    string
		want  bool
	}{
		{"wlp8s0", net.FlagUp, "192.168.178.98", true},
		{"enp4s0", 0, "192.168.178.20", false},                         // down
		{"wg0", net.FlagUp | net.FlagPointToPoint, "10.10.0.2", false}, // WireGuard
		{"docker0", net.FlagUp, "172.17.0.1", false},                   // bridge
		{"br-abc123", net.FlagUp, "172.18.0.1", false},                 // bridge
		{"lo", net.FlagUp | net.FlagLoopback, "127.0.0.1", false},      // loopback
		{"wlp8s0", net.FlagUp, "2001:db8:4701:f100::1", false},         // routable v6
		{"wlp8s0", net.FlagUp, "fd00::1", true},                        // unique local v6
	}
	for _, tc := range cases {
		got := classify(net.Interface{Name: tc.name, Flags: tc.flags}, net.ParseIP(tc.ip))
		if got.Usable != tc.want {
			t.Errorf("%s %s: usable=%v want %v (%s)", tc.name, tc.ip, got.Usable, tc.want, got.Why)
		}
		if !got.Usable && got.Why == "" {
			t.Errorf("%s %s was skipped without saying why", tc.name, tc.ip)
		}
	}
}

// Loopback is always bound: it is the whole of the documented fallback for the
// networks where .local does not survive, where the answer is ssh -L.
func TestLoopbackIsAlwaysBound(t *testing.T) {
	got, err := Listen("8080")
	if err != nil {
		t.Fatal(err)
	}
	var v4, v6 bool
	for _, a := range got {
		switch a {
		case "127.0.0.1:8080":
			v4 = true
		case "[::1]:8080":
			v6 = true
		}
	}
	if !v4 || !v6 {
		t.Errorf("loopback missing from %v — an ssh -L tunnel would not reach setup", got)
	}
}

// A bare host in an omnibox is ambiguous, and a failed resolution becomes a web
// search — which sends somebody to a search engine at the exact moment they are
// least equipped to work out what went wrong.
func TestPrintedURLsAreUnambiguous(t *testing.T) {
	got, err := URLs("80")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("nothing to print")
	}
	if got[0] != "http://holistic.local/" {
		t.Errorf("first URL is %q; it should be the memorable one, with scheme and trailing slash", got[0])
	}
	withPort, _ := URLs("8080")
	if withPort[0] != "http://holistic.local:8080/" {
		t.Errorf("a non-default port must appear in the printed URL, got %q", withPort[0])
	}
}

// The default port is omitted everywhere it appears, not only in the .local
// name: ":80" in a printed URL is noise that invites somebody to retype it
// wrongly.
func TestDefaultPortIsOmittedFromEveryPrintedURL(t *testing.T) {
	got, err := URLs("80")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range got {
		if len(u) > 7 && u[len(u)-4:] == ":80/" {
			t.Errorf("printed URL still carries the default port: %s", u)
		}
	}
}
