// Package lan decides which addresses the setup process answers on, and which
// requests it will answer at all.
//
// Binding 0.0.0.0 would be the obvious thing and it is wrong here. This machine
// is a homeserver: it routinely holds a WireGuard interface, and it may later
// hold a Docker bridge. A wildcard bind puts an unauthenticated-by-design setup
// page on the far end of the VPN and on every container network, which is a
// wider surface than "reachable from my laptop" and nobody would have chosen it
// deliberately. So the interfaces are enumerated and the plausible ones are
// bound by name.
//
// The Host check is the other half. CasaOS decided whether a request was local
// by reading X-Forwarded-For, an attacker set the header, and the result was
// unauthenticated root (CVE-2023-37265, CVSS 9.8). Nothing in here believes a
// header. Locality is decided from the connection and from the Host the client
// asked for, both of which the client cannot forge past what it actually
// reached.
package lan

import (
	"net"
	"net/http"
	"strings"
)

// SetupName is the mDNS name the installer publishes. It is a constant rather
// than configuration because it is printed by the installer, typed by a person,
// and lives for the duration of one setup — three good reasons for it never to
// vary, and none for it to.
const SetupName = "holistic.local"

// Interface is one place the setup process could be reached.
type Interface struct {
	Name string
	IP   net.IP
	// Usable is false for addresses that would technically work but should not
	// be offered: a VPN tunnel, a container bridge, loopback.
	Usable bool
	// Why explains an unusable address, so the installer can say what it
	// skipped instead of silently narrowing.
	Why string
}

// Interfaces reports every address on this machine and whether the setup
// process should listen on it.
func Interfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			out = append(out, classify(ifc, ipnet.IP))
		}
	}
	return out, nil
}

func classify(ifc net.Interface, ip net.IP) Interface {
	in := Interface{Name: ifc.Name, IP: ip}
	switch {
	case ifc.Flags&net.FlagUp == 0:
		in.Why = "the interface is down"
	case ip.IsLoopback():
		// Bound anyway, elsewhere: loopback is what an ssh -L tunnel arrives
		// on, and that is the documented fallback for networks where mDNS does
		// not survive. It is simply not a LAN address.
		in.Why = "loopback"
	case ifc.Flags&net.FlagPointToPoint != 0:
		in.Why = "a point-to-point link — a VPN tunnel, not your local network"
	case isContainerBridge(ifc.Name):
		in.Why = "a container bridge, reachable only from containers on this host"
	case ip.IsLinkLocalUnicast():
		in.Why = "link-local, which needs a zone identifier to be usable"
	case ip.To4() == nil && !isULA(ip):
		// A globally routable IPv6 address on the interface is normal on a
		// home connection, and putting the setup page on one would publish it
		// to the internet.
		in.Why = "a globally routable IPv6 address, which is not local at all"
	case !IsPrivate(ip):
		in.Why = "not an address on a private network"
	default:
		in.Usable = true
	}
	return in
}

func isContainerBridge(name string) bool {
	for _, p := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "podman"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func isULA(ip net.IP) bool {
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}

// IsPrivate reports whether an address belongs to a private network — the only
// kind the setup process will answer for.
func IsPrivate(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	return isULA(ip)
}

// Listen returns the addresses to bind for a given port: every usable LAN
// address, plus loopback in both families.
//
// Loopback is always included. It costs nothing, and it is the whole of the
// documented fallback for the networks where `.local` does not survive — AP
// isolation, a guest SSID, a VLAN between the server and the laptop — where the
// answer is `ssh -L` and the setup page arrives on 127.0.0.1.
func Listen(port string) ([]string, error) {
	ifs, err := Interfaces()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []string{net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("::1", port)}
	for _, a := range out {
		seen[a] = true
	}
	for _, in := range ifs {
		if !in.Usable {
			continue
		}
		addr := net.JoinHostPort(in.IP.String(), port)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out, nil
}

// URLs are what the installer prints, most likely to work first.
func URLs(port string) ([]string, error) {
	ifs, err := Interfaces()
	if err != nil {
		return nil, err
	}
	// The trailing slash matters. A bare host typed into an omnibox is
	// ambiguous, and a failed resolution turns into a web search — sending
	// somebody to a search engine at the exact moment they are least equipped
	// to work out what went wrong.
	out := []string{"http://" + SetupName + hostPort(port) + "/"}
	for _, in := range ifs {
		if !in.Usable || in.IP.To4() == nil {
			continue
		}
		out = append(out, "http://"+in.IP.String()+hostPort(port)+"/")
	}
	return out, nil
}

// hostPort omits the default port. ":80" in a printed URL is noise that invites
// somebody to retype it wrongly, and a person copying an address by eye should
// be given the shortest thing that works.
func hostPort(port string) string {
	if port == "80" || port == "" {
		return ""
	}
	return ":" + port
}

// OnlyLocal refuses anything that did not arrive over a private network or ask
// for a name the setup process answers to.
//
// It reads the connection and the Host header, and nothing else. In particular
// it does not read X-Forwarded-For, X-Real-IP or Forwarded: those describe a
// proxy chain the client controls, and treating them as evidence of locality is
// precisely how CasaOS turned a header into unauthenticated root.
func OnlyLocal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip == nil || !IsPrivate(ip) {
			http.Error(w, "The setup process answers only on your local network.", http.StatusForbidden)
			return
		}
		if !HostAllowed(r.Host) {
			// A request that reached us under some other name is either a
			// misconfiguration or somebody pointing a hostname at this box.
			// Neither should be served a page that creates an administrator.
			http.Error(w, "The setup process is reached at http://"+SetupName+
				" or at this machine's address on your network.", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HostAllowed reports whether a Host header names something the setup process
// answers to: its own mDNS name, a private address literal, or loopback.
func HostAllowed(hostHeader string) bool {
	h := strings.TrimSpace(strings.ToLower(hostHeader))
	if h == "" {
		return false
	}
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	}
	h = strings.Trim(h, "[]")
	if h == SetupName || h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return IsPrivate(ip)
	}
	return false
}
