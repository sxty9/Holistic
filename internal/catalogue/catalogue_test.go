package catalogue

import (
	"errors"
	"strings"
	"testing"
)

func testCat() Catalogue { return New("example.org", Default()) }

// The whole point of the package: one decision, three files, and they agree.
// Before this, publishing an app meant editing three configurations by hand and
// discovering you had missed one when a hostname served the wrong document.
func TestOneAnswerReachesAllThreeConsistently(t *testing.T) {
	apps := Default()
	for i := range apps {
		if apps[i].ID == "gallery" {
			apps[i].Enabled = true
		}
		if apps[i].ID == "calendar" {
			apps[i].Enabled = false
		}
	}
	c := New("example.org", apps)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}

	inWarpgate := map[string]bool{}
	for _, a := range c.Warpgate() {
		inWarpgate[a.Name] = true
	}
	// An app has one canonical hostname and may have further names that reach
	// it. What must hold for every entry: the host is under the configured
	// domain, and the ORIGIN is the canonical one — it is where the launcher
	// sends people, and that should be the same place whichever name they
	// arrived under.
	inSolisuite := map[string]bool{}
	for _, a := range c.Solisuite() {
		inSolisuite[a.ID] = true
		if !strings.HasSuffix(a.Host, ".example.org") {
			t.Errorf("%s: host %q is not under the configured domain", a.ID, a.Host)
		}
		if a.Origin != "https://"+a.ID+".example.org" {
			t.Errorf("%s: origin is %q, want the app's canonical one", a.ID, a.Origin)
		}
	}

	if !inWarpgate["gallery"] || !inSolisuite["gallery"] {
		t.Error("an app that was switched on did not reach every file")
	}
	if inWarpgate["calendar"] || inSolisuite["calendar"] {
		t.Error("an app that was switched off still appears somewhere")
	}
}

// RoomSense has its own server. Listing it in Solisuite's app map would point
// appFor() at a Solisuite document that does not exist — it still needs DNS and
// ingress, which is exactly why it is easy to get wrong.
func TestStandaloneAppsGetDNSButNotASolisuiteEntry(t *testing.T) {
	apps := Default()
	for i := range apps {
		if apps[i].ID == "roomsense" {
			apps[i].Enabled = true
		}
	}
	c := New("example.org", apps)

	var inWarpgate bool
	for _, a := range c.Warpgate() {
		if a.Name == "roomsense" {
			inWarpgate = true
			if a.Upstream == solisuite {
				t.Error("roomsense was pointed at Solisuite's port")
			}
		}
	}
	if !inWarpgate {
		t.Error("a standalone app got no DNS or ingress, so it is unreachable")
	}
	for _, a := range c.Solisuite() {
		if a.ID == "roomsense" {
			t.Error("a standalone app was listed as a Solisuite app")
		}
	}
	if _, ok := c.CoreXOrigins(map[string]bool{"roomsense": true})["roomsense"]; ok {
		t.Error("a standalone app was advertised as one of coreX's own")
	}
}

// An origin map listing hostnames that do not resolve is the populated-but-wrong
// state that shipped once already. Origins are written as each hostname is
// proven, which also turns the launcher into an honest progress display, since
// shellApps() already filters to apps that have an origin.
func TestOriginsAppearOnlyAsHostnamesAreProven(t *testing.T) {
	c := testCat()

	if got := c.CoreXOrigins(nil); len(got) != 0 {
		t.Errorf("with nothing proven, %d origin(s) were advertised: %v", len(got), got)
	}

	half := c.CoreXOrigins(map[string]bool{"launcher": true, "mail": true})
	if len(half) != 2 {
		t.Fatalf("expected 2 origins, got %v", half)
	}
	if half["mail"] != "https://mail.example.org" {
		t.Errorf("mail origin is %q", half["mail"])
	}
	if _, ok := half["files"]; ok {
		t.Error("an unproven hostname was advertised")
	}
}

// An instance with no launcher has no way in.
func TestTheWayInCannotBeSwitchedOff(t *testing.T) {
	apps := Default()
	for i := range apps {
		if apps[i].ID == "launcher" {
			apps[i].Enabled = false
		}
	}
	err := New("example.org", apps).Validate()
	if err == nil {
		t.Fatal("an instance with no launcher validated")
	}
	if !errors.Is(err, ErrNoLauncher) && !strings.Contains(err.Error(), "cannot be disabled") {
		t.Errorf("unhelpful refusal: %v", err)
	}
}

// Nothing in this repository may contain an instance's domain, so every
// hostname has to be derived from one passed in — including the failure when
// none was.
func TestNoDomainMeansNoHostnames(t *testing.T) {
	if err := New("", Default()).Validate(); !errors.Is(err, ErrNoDomain) {
		t.Errorf("a catalogue with no domain validated: %v", err)
	}
	if err := New("https://example.org/", Default()).Validate(); err == nil {
		t.Error("a URL was accepted where a bare domain belongs")
	}
}

func TestDuplicateAppsAreRefused(t *testing.T) {
	apps := append(Default(), App{ID: "mail", Label: "Mail again", Upstream: solisuite, Enabled: true})
	if err := New("example.org", apps).Validate(); err == nil {
		t.Error("two apps claiming the same subdomain validated")
	}
}

// The defaults are a function so that a caller editing them — which the wizard
// does, straight from a UI — cannot change them for everybody else.
func TestDefaultsCannotBeMutatedForEveryoneElse(t *testing.T) {
	a := Default()
	a[0].Enabled = false
	a[0].Label = "vandalised"
	b := Default()
	if !b[0].Enabled || b[0].Label == "vandalised" {
		t.Error("editing one catalogue changed the defaults for the next one")
	}
}

// Every enabled app needs its hostname to answer before the instance is done;
// this is the list the wizard probes.
func TestHostnamesCoverEveryEnabledApp(t *testing.T) {
	c := testCat()
	names := c.Hostnames()
	want := 0
	for _, a := range c.Enabled() {
		want += 1 + len(a.Aliases)
	}
	if len(names) != want {
		t.Fatalf("%d hostnames for %d enabled apps and their aliases (want %d)", len(names), len(c.Enabled()), want)
	}
	for _, n := range names {
		if !strings.HasSuffix(n, ".example.org") {
			t.Errorf("hostname %q is not under the configured domain", n)
		}
	}
}

// The domain is normalised once, here, rather than by each consumer.
func TestTheDomainIsNormalisedOnce(t *testing.T) {
	c := New("  EXAMPLE.ORG  ", Default())
	if c.Domain != "example.org" {
		t.Errorf("domain is %q", c.Domain)
	}
	if c.Hostname("mail") != "mail.example.org" {
		t.Errorf("hostname is %q", c.Hostname("mail"))
	}
}

// Inbound mail arrives at routedge and nowhere else. A catalogue without it
// produces an instance whose setup completed and whose mail silently never
// comes — which is the failure this project was started over, rebuilt.
//
// It was genuinely missing until 2026-08-30, and it was found by running the
// wizard against a machine that already had the entry: the reconciler refused
// to publish a list that would have deleted it. On a fresh machine there would
// have been no conflict and no entry.
func TestTheCatalogueCarriesTheMailIntake(t *testing.T) {
	var found *App
	for i := range Default() {
		if Default()[i].ID == "routedge" {
			a := Default()[i]
			found = &a
		}
	}
	if found == nil {
		t.Fatal("no routedge in the catalogue: an instance built from it receives no mail")
	}
	if !found.Required {
		t.Error("routedge is not Required, so somebody can uncheck inbound mail without being told")
	}
	if !found.Enabled {
		t.Error("routedge is not Enabled by default; a fresh instance would start with no mail intake")
	}
	if !found.Standalone {
		t.Error("routedge is not Standalone, so Solisuite would be asked to serve a document it does not have")
	}

	// It has to reach DNS and ingress, and must not reach Solisuite's app list.
	c := New("example.org", Default())
	var inWarpgate bool
	for _, w := range c.Warpgate() {
		if w.Name == "routedge" {
			inWarpgate = true
		}
	}
	if !inWarpgate {
		t.Error("routedge is not in the Warpgate projection, so no hostname is published for it")
	}
	for _, s := range c.Solisuite() {
		if s.ID == "routedge" {
			t.Error("routedge reached Solisuite's app list, which would map its Host to a document that does not exist")
		}
	}
}

// The second entry the reconciler found for us. `ssh.<domain>` is how this
// machine is reached from outside since the legacy tunnel came down, and
// publishing a catalogue that had never heard of it would have deleted the DNS
// record and the ingress rule for the operator's own way back in — from inside
// a step called "which apps this instance publishes".
//
// The shape that matters is known-but-unchecked: a fresh instance must not
// publish its SSH port through a public tunnel because a catalogue said so, and
// an instance that already does must not lose it because the catalogue was
// silent.
func TestSSHIsKnownAndOffByDefault(t *testing.T) {
	var found *App
	for i := range Default() {
		if Default()[i].ID == "ssh" {
			a := Default()[i]
			found = &a
		}
	}
	if found == nil {
		t.Fatal("no ssh in the catalogue: publishing the list deletes the operator's own way in")
	}
	if found.Enabled {
		t.Error("ssh is enabled by default, so a fresh instance publishes its shell without being asked")
	}
	if found.Required {
		t.Error("ssh is Required, so it cannot be turned off — an instance with no remote shell is fine")
	}
	if !found.Standalone {
		t.Error("ssh is not Standalone, so Solisuite would be asked to serve a document for it")
	}
	if !strings.HasPrefix(found.Upstream, "ssh://") {
		t.Errorf("ssh upstream is %q; cloudflared proxies the stream to sshd, it is not http", found.Upstream)
	}

	// Unchecked means absent from every projection until somebody ticks it.
	c := New("example.org", Default())
	for _, w := range c.Warpgate() {
		if w.Name == "ssh" {
			t.Error("ssh reached the Warpgate projection while unchecked")
		}
	}
	for _, s := range c.Solisuite() {
		if s.ID == "ssh" {
			t.Error("ssh reached Solisuite's app list, which has no document for it")
		}
	}

	// Ticked, it must reach Warpgate and only Warpgate.
	apps := Default()
	for i := range apps {
		if apps[i].ID == "ssh" {
			apps[i].Enabled = true
		}
	}
	on := New("example.org", apps)
	var inWarpgate bool
	for _, w := range on.Warpgate() {
		if w.Name == "ssh" {
			inWarpgate = true
			if w.Upstream != "ssh://localhost:22" {
				t.Errorf("published ssh upstream is %q", w.Upstream)
			}
		}
	}
	if !inWarpgate {
		t.Error("ssh was ticked and no hostname is published for it")
	}
	for _, s := range on.Solisuite() {
		if s.ID == "ssh" {
			t.Error("a ticked ssh reached Solisuite's app list")
		}
	}
}

// The nonce probe is the last real check before setup closes, and it asks every
// hostname for an HTTP answer. `ssh` is handed to sshd by cloudflared and will
// never give one — so probing it would fail that step forever, on a hostname
// that is working perfectly, one step from the end.
//
// Judged by the upstream scheme, not by an app id: the next non-HTTP route
// added is then right without anybody remembering this.
func TestOnlyNamesThatSpeakHTTPAreProbed(t *testing.T) {
	apps := Default()
	for i := range apps {
		apps[i].Enabled = true
	}
	c := New("example.org", apps)

	all := strings.Join(c.Hostnames(), " ")
	web := strings.Join(c.WebHostnames(), " ")

	if !strings.Contains(all, "ssh.example.org") {
		t.Error("ssh is not in Hostnames, so DNS and ingress would not carry it")
	}
	if strings.Contains(web, "ssh.example.org") {
		t.Error("ssh is in WebHostnames: the nonce probe would wait forever on sshd to answer a GET")
	}
	// And the ones that do speak HTTP are all still there, routedge included —
	// it is standalone but it is an HTTP endpoint and it must be proven.
	for _, h := range []string{"mail.example.org", "routedge.example.org", "roomsense.example.org"} {
		if !strings.Contains(web, h) {
			t.Errorf("%s speaks HTTP and is not probed", h)
		}
	}
	if len(c.WebHostnames()) != len(c.Hostnames())-1 {
		t.Errorf("WebHostnames dropped %d names, want exactly one (ssh): %v",
			len(c.Hostnames())-len(c.WebHostnames()), c.WebHostnames())
	}
}

// The operator asked for three names for the launcher: the apex, which Warpgate
// publishes through rootServes, launcher.<domain>, and hub.<domain>.
//
// A second name is not a second app. It gets its own DNS record, its own
// ingress rule and its own entry in Solisuite's host map — because appFor
// resolves a Host header through that map, and without an entry hub would work
// only by falling through to DefaultApp, which answers for every unknown host.
// It does NOT get its own origin: an app has one place the launcher sends
// people to.
func TestAnAliasIsAnotherNameAndNotAnotherApp(t *testing.T) {
	c := New("example.org", Default())

	var warpNames []string
	for _, w := range c.Warpgate() {
		warpNames = append(warpNames, w.Name)
	}
	if !contains(warpNames, "hub") {
		t.Errorf("hub gets no DNS record and no ingress rule: %v", warpNames)
	}
	for _, w := range c.Warpgate() {
		if w.Name == "hub" && w.Upstream != solisuite {
			t.Errorf("hub points at %q, not at the launcher's own upstream", w.Upstream)
		}
	}

	var hubEntries, launcherEntries int
	for _, a := range c.Solisuite() {
		switch a.Host {
		case "hub.example.org":
			hubEntries++
			if a.ID != "launcher" {
				t.Errorf("hub.example.org maps to app %q, not the launcher", a.ID)
			}
			if a.Origin != "https://launcher.example.org" {
				t.Errorf("hub's origin is %q; an app has one origin whichever name you arrive under", a.Origin)
			}
		case "launcher.example.org":
			launcherEntries++
		}
	}
	if hubEntries != 1 {
		t.Errorf("hub has %d entries in Solisuite's host map; without exactly one it falls through to DefaultApp", hubEntries)
	}
	if launcherEntries != 1 {
		t.Errorf("launcher.example.org has %d entries, want 1", launcherEntries)
	}

	// coreX advertises origins, not names. Two entries for one app would offer
	// the launcher twice.
	origins := c.CoreXOrigins(map[string]bool{"launcher": true})
	if _, in := origins["hub"]; in {
		t.Errorf("hub reached appOrigins: %v", origins)
	}
	if origins["launcher"] != "https://launcher.example.org" {
		t.Errorf("appOrigins[launcher] = %q", origins["launcher"])
	}

	// And it has to be probed, or the wizard proves a name it published works
	// without ever asking it.
	if !contains(c.WebHostnames(), "hub.example.org") {
		t.Errorf("hub is published and never probed: %v", c.WebHostnames())
	}
}

// Two names for one thing is fine; one name for two things is not — whichever
// entry Solisuite's host map took last would win and nothing would say which.
func TestAnAliasThatCollidesWithAnAppIsRefused(t *testing.T) {
	apps := Default()
	for i := range apps {
		if apps[i].ID == "launcher" {
			apps[i].Aliases = []string{"mail"}
		}
	}
	err := New("example.org", apps).Validate()
	if err == nil {
		t.Fatal("an alias that is already an app id was accepted")
	}
	// It must name BOTH claimants. The check used to run as the list was
	// walked, so an alias colliding with an app further down slipped past and
	// was caught later by the duplicate-id check, which reported "app \"mail\"
	// appears twice" — the wrong one of the two, and a message that sends the
	// reader to look at an entry that is fine.
	for _, want := range []string{"mail", "launcher"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q as one of the two claimants: %v", want, err)
		}
	}
}

// The same, with the collision the other way round in the list, because that is
// the order the old check happened to survive.
func TestACollisionIsFoundWhicheverWayRound(t *testing.T) {
	apps := Default()
	for i := range apps {
		if apps[i].ID == "system" {
			apps[i].Aliases = []string{"launcher"}
		}
	}
	err := New("example.org", apps).Validate()
	if err == nil {
		t.Fatal("an alias claiming an app named earlier in the list was accepted")
	}
	for _, want := range []string{"launcher", "system"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// And two apps reaching for the same alias.
func TestTwoAppsCannotShareAnAlias(t *testing.T) {
	apps := Default()
	for i := range apps {
		if apps[i].ID == "mail" || apps[i].ID == "files" {
			apps[i].Aliases = []string{"inbox"}
		}
	}
	err := New("example.org", apps).Validate()
	if err == nil {
		t.Fatal("two apps were allowed to claim one name")
	}
	if !strings.Contains(err.Error(), "inbox") {
		t.Errorf("the refusal does not name the contested name: %v", err)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
