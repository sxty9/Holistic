package steps

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/sxty9/Holistic/internal/ledger"
)

// Nothing in this file may start, stop or restart anything on the machine
// running it, and nothing may write outside t.TempDir(). Both are structural
// rather than promised: every step reaches systemd through Machine, every step
// reaches a file through Paths, and the recorder below is the only Machine any
// test ever hands it.

// fakeCF stands in for Cloudflare. It answers, and it records what it was
// asked, so a test can assert that a step read rather than guessing that it
// did. It has no write, because the interface has none — see cloudflare.go.
type fakeCF struct {
	mu      sync.Mutex
	asked   []string
	active  bool
	zone    Zone
	zoneErr error
	records []DNSRecord
	recErr  error
	names   []string
	nameErr error
}

func newFakeCF() *fakeCF {
	return &fakeCF{
		active: true,
		zone: Zone{
			ID: "zone-1", Name: testDomain, Status: "active", AccountID: "acct-1",
			Nameservers: []string{"one.ns.invalid", "two.ns.invalid"},
			Permissions: []string{"#zone:read", "#dns_records:read", "#dns_records:edit",
				"#zone_settings:edit", "#email_routing_rule:edit"},
		},
		names: []string{testDomain},
	}
}

func (f *fakeCF) ZoneNames(_ context.Context, _ string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, "zone-names")
	return f.names, f.nameErr
}

func (f *fakeCF) note(s string) { f.mu.Lock(); f.asked = append(f.asked, s); f.mu.Unlock() }

func (f *fakeCF) TokenActive(context.Context, string) (bool, error) {
	f.note("token-verify")
	return f.active, nil
}

func (f *fakeCF) Zone(_ context.Context, _, domain string) (Zone, error) {
	f.note("zone " + domain)
	return f.zone, f.zoneErr
}

func (f *fakeCF) Records(_ context.Context, _, id string) ([]DNSRecord, error) {
	f.note("records " + id)
	return f.records, f.recErr
}

type recorder struct {
	mu      sync.Mutex
	calls   []string
	active  map[string]bool
	enabled map[string]bool
	out     map[string]string
	fail    map[string]error
}

func newRecorder() *recorder {
	return &recorder{
		active:  map[string]bool{},
		enabled: map[string]bool{},
		out:     map[string]string{},
		fail:    map[string]error{},
	}
}

func (r *recorder) note(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, s)
}

func (r *recorder) Restart(unit string) error {
	r.note("restart " + unit)
	r.active[unit] = true
	return r.fail["restart "+unit]
}

func (r *recorder) EnableNow(unit string) error {
	r.note("enable-now " + unit)
	if err := r.fail["enable-now "+unit]; err != nil {
		return err
	}
	r.active[unit], r.enabled[unit] = true, true
	return nil
}

func (r *recorder) Disable(unit string) error {
	r.note("disable " + unit)
	r.active[unit] = false
	return nil
}

func (r *recorder) IsActive(unit string) bool  { return r.active[unit] }
func (r *recorder) IsEnabled(unit string) bool { return r.enabled[unit] }

func (r *recorder) Run(name string, args ...string) (string, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	r.note("run " + key)
	return r.out[key], r.fail["run "+key]
}

// unitCalls are the ones that would have touched a service. Everything else the
// recorder saw is a read.
func (r *recorder) unitCalls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.calls {
		if strings.HasPrefix(c, "restart ") || strings.HasPrefix(c, "enable-now ") {
			out = append(out, c)
		}
	}
	return out
}

type kit struct {
	t    *testing.T
	e    *Engine
	led  *ledger.Ledger
	p    Paths
	m    *recorder
	cf   *fakeCF
	etc  string
	resp Response
	ferr error
}

// example.org and .invalid throughout, and every path under t.TempDir(). A test
// that names this machine's real /etc is a test that passes here and fails, or
// worse succeeds, somewhere else.
const testDomain = "example.org"

func newKit(t *testing.T) *kit {
	t.Helper()
	d := t.TempDir()
	etc := filepath.Join(d, "etc")
	p := Paths{
		CoreXConfig:     filepath.Join(etc, "corex", "config.json"),
		CoreXEnv:        filepath.Join(etc, "corex", "corex.env"),
		SolisuiteConfig: filepath.Join(etc, "solisuite", "config.json"),
		SolisuiteEnv:    filepath.Join(etc, "solisuite", "solisuite.env"),
		WarpgateConfig:  filepath.Join(etc, "warpgate", "config.json"),
		WarpgateIngress: filepath.Join(etc, "warpgate", "ingress.json"),
		WarpgateToken:   filepath.Join(etc, "warpgate", "cloudflare.token"),
		CoreXUnit:       "corex-api.test",
		SolisuiteUnit:   "solisuite.test",
		ConnectorUnit:   "warpgate.test",
		WarpgateBin:     "warpgate-that-is-recorded-not-run",
		Seal:            filepath.Join(etc, "holistic", "claimed"),
		Claim:           filepath.Join(etc, "holistic", "setup.claim"),
		SetupUnit:       "holistic-setup.test",
		Corexctl:        "corexctl-that-is-never-executed",
		DataDir:         filepath.Join(d, "data"),
	}
	led, err := ledger.Open(filepath.Join(d, "var", "provisioned.json"))
	if err != nil {
		t.Fatal(err)
	}
	k := &kit{t: t, led: led, p: p, m: newRecorder(), cf: newFakeCF(), etc: etc,
		resp: Response{Status: 200, Body: "<!doctype html>"}}
	k.m.out[p.Corexctl+" admin list"] = "henry@" + testDomain + "  (administrator)"
	k.m.out["claude --version"] = "claude 2.4.1"
	// NewWith, never New: New builds a real Cloudflare client, and a test that
	// can reach the internet is a test whose result depends on somebody else's
	// uptime.
	k.e = NewWith(led, p, k.m, func(ctx context.Context, url string) (Response, error) {
		return k.resp, k.ferr
	}, k.cf)
	return k
}

func (k *kit) answer(id string, v any) {
	k.t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		k.t.Fatal(err)
	}
	if err := k.e.Answer(id, raw); err != nil {
		k.t.Fatalf("answering %s: %v", id, err)
	}
}

func (k *kit) run(id string) Row {
	k.t.Helper()
	if err := k.e.Run(id); err != nil {
		k.t.Fatalf("running %s: %v", id, err)
	}
	return k.row(id)
}

func (k *kit) row(id string) Row {
	k.t.Helper()
	for _, r := range k.e.State(false, 0, nil).Steps {
		if r.ID == id {
			return r
		}
	}
	k.t.Fatalf("%s is not a step", id)
	return Row{}
}

func (k *kit) mustPass(id string) Row {
	k.t.Helper()
	r := k.run(id)
	if r.Status != ledger.Passed {
		k.t.Fatalf("%s: %s — %s", id, r.Status, r.Detail)
	}
	if r.Proof == "" {
		k.t.Errorf("%s passed without recording how it was shown to be true", id)
	}
	return r
}

// standIn marks a step this build does not implement as passed, so the local
// steps that genuinely consume its result can be exercised. It is spelled out
// rather than hidden in a helper name because it is the one place a test asserts
// something the engine did not establish.
func (k *kit) standIn(ids ...string) {
	k.t.Helper()
	for _, id := range ids {
		if err := k.led.Mark(id, ledger.Passed, "stood in for by the test suite"); err != nil {
			k.t.Fatal(err)
		}
	}
}

const testToken = "cf-Zq7Z4mR2xLp9vT1nB8kW6yH3jD5sG0aEQhVuJcRt"

// drive takes the wizard as far as it goes, standing in only for the steps that
// talk to a provider.
func (k *kit) drive() {
	k.t.Helper()
	k.answer("domain", testDomain)
	k.mustPass("domain")
	k.answer("display-name", "Henry's box")
	k.mustPass("display-name")
	k.answer("storage", filepath.Join(k.p.DataDir, "corex"))
	k.mustPass("storage")
	k.answer("engines", "claude")
	k.mustPass("engines")
	k.mustPass("admin")
	k.answer("apps", []appChoice{{ID: "gallery", On: true}})
	k.mustPass("apps")

	k.answer("token-verify", testToken)
	k.standIn("token-verify")
	k.mustPass("token-store")

	k.mustPass("warpgate-config")
	k.answer("plan-show", true)
	k.mustPass("plan-show")
	k.mustPass("ingress-write")

	k.standIn("connector-registered")
	k.mustPass("solisuite-write")
	k.mustPass("corex-write")

	k.standIn("nonce-probe")
	k.mustPass("corex-restart-2")
}

// snapshot is every configuration file, by content. The ledger is deliberately
// outside it: its timestamps move on every run and that is what it is for.
func (k *kit) snapshot() map[string]string {
	k.t.Helper()
	out := map[string]string{}
	if _, err := os.Stat(k.etc); os.IsNotExist(err) {
		// Nothing written at all is a snapshot too, and it is the one the
		// "wrote nothing" assertions are usually comparing against.
		return out
	}
	err := filepath.Walk(k.etc, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = string(b)
		return nil
	})
	if err != nil {
		k.t.Fatal(err)
	}
	return out
}

func diffSnapshots(a, b map[string]string) []string {
	var out []string
	for path, before := range a {
		after, still := b[path]
		switch {
		case !still:
			out = append(out, path+" was removed")
		case before != after:
			out = append(out, path+" changed")
		}
	}
	for path := range b {
		if _, had := a[path]; !had {
			out = append(out, path+" appeared")
		}
	}
	sort.Strings(out)
	return out
}

// The rule the whole design rests on. A reconciler is run repeatedly by
// definition — it is the later diagnosis and the later domain change as well as
// the first-run wizard — so a second run that rewrites files and bounces
// services is not a cosmetic flaw, it is the wizard restarting somebody's mail
// server every time they refresh a page.
func TestEveryLocalStepIsSafeToRunTwice(t *testing.T) {
	k := newKit(t)
	k.drive()

	for _, id := range []string{
		"domain", "display-name", "storage", "engines", "admin", "apps",
		"token-store", "warpgate-config", "plan-show", "ingress-write",
		"solisuite-write", "corex-write", "corex-restart-2",
	} {
		t.Run(id, func(t *testing.T) {
			before := k.snapshot()
			unitsBefore := len(k.m.unitCalls())

			k.mustPass(id)

			if d := diffSnapshots(before, k.snapshot()); len(d) > 0 {
				t.Errorf("a second run changed the machine: %s", strings.Join(d, "; "))
			}
			units := k.m.unitCalls()[unitsBefore:]
			// corex-restart-2 restarts on purpose — restarting is what it is —
			// so it is the one step whose second run is allowed to touch a
			// unit. It still must not change a file.
			if id != "corex-restart-2" && len(units) > 0 {
				t.Errorf("a second run touched services with nothing to apply: %v", units)
			}
		})
	}
}

// The three-file write, which is the reason this repository exists. Two of them
// agreeing and the third not is worse than none of them being written: DNS and
// ingress would be perfect and Solisuite would serve the same document at every
// hostname, with nothing anywhere reporting an error.
func TestTheThreeConfigWriteIsAllOrNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this makes a directory unwritable, which root ignores")
	}
	for _, tc := range []struct {
		name    string
		already bool
	}{
		{name: "nothing was there before"},
		{name: "all three were already written", already: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKit(t)
			k.answer("domain", testDomain)
			k.mustPass("domain")

			if tc.already {
				k.mustPass("apps")
			}
			// Everything before the write is fine; the write itself fails
			// partway. That is the case the rollback exists for — a bad value
			// or an unparseable file is caught before the first byte.
			soliDir := filepath.Dir(k.p.SolisuiteConfig)
			if err := os.MkdirAll(soliDir, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(soliDir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(soliDir, 0o750) })

			before := k.snapshot()
			// Change the answer so all three files have something to write.
			k.answer("apps", []appChoice{{ID: "gallery", On: true}, {ID: "files", On: false}})

			row := k.run("apps")
			if row.Status != ledger.Failed {
				t.Fatalf("a failed write reported %s: %s", row.Status, row.Detail)
			}
			if d := diffSnapshots(before, k.snapshot()); len(d) > 0 {
				t.Errorf("a partial write was left behind: %s", strings.Join(d, "; "))
			}
			if !tc.already {
				for _, p := range []string{k.p.WarpgateConfig, k.p.CoreXConfig} {
					if _, err := os.Stat(p); !os.IsNotExist(err) {
						t.Errorf("%s exists after a write that did not complete", p)
					}
				}
			}
		})
	}
}

// Conflicts. Every one of these is something on the machine that this wizard
// did not put there, and the only acceptable behaviour is to say so in full and
// change nothing.
func TestSomethingWeDidNotCreateIsAConflictAndNotAnOverwrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		step    string
		setUp   func(k *kit)
		mention []string
	}{
		{
			name: "data already lives somewhere else",
			step: "storage",
			setUp: func(k *kit) {
				other := filepath.Join(k.t.TempDir(), "existing-data")
				mkdirWithSomethingIn(k.t, other)
				writeJSONFile(k.t, k.p.CoreXConfig, map[string]any{"dataDir": other})
				k.answer("storage", filepath.Join(k.p.DataDir, "corex"))
			},
			mention: []string{"dataDir"},
		},
		{
			name: "the app lists belong to another domain",
			step: "apps",
			setUp: func(k *kit) {
				k.answer("domain", testDomain)
				k.mustPass("domain")
				writeJSONFile(k.t, k.p.SolisuiteConfig, map[string]any{
					"apps": []any{map[string]any{"id": "mail", "host": "mail.someone-else.invalid"}},
				})
			},
			mention: []string{"someone-else.invalid"},
		},
		{
			name: "warpgate publishes an app we have never heard of",
			step: "apps",
			setUp: func(k *kit) {
				k.answer("domain", testDomain)
				k.mustPass("domain")
				writeJSONFile(k.t, k.p.WarpgateConfig, map[string]any{
					"apps": []any{
						map[string]any{"name": "launcher", "upstream": "http://127.0.0.1:8795"},
						map[string]any{"name": "wiki", "upstream": "http://127.0.0.1:9999"},
					},
				})
			},
			mention: []string{"wiki"},
		},
		{
			name: "warpgate is already pinned elsewhere",
			step: "warpgate-config",
			setUp: func(k *kit) {
				k.answer("domain", testDomain)
				k.mustPass("domain")
				k.mustPass("apps")
				f := readJSONFile(k.t, k.p.WarpgateConfig)
				f["configPath"] = "/etc/somewhere-else/ingress.json"
				writeJSONFile(k.t, k.p.WarpgateConfig, f)
			},
			mention: []string{"configPath", "somewhere-else"},
		},
		{
			name: "a different credential is already at the token path",
			step: "token-store",
			setUp: func(k *kit) {
				k.standIn("token-verify")
				k.answer("token-verify", testToken)
				if err := os.MkdirAll(filepath.Dir(k.p.WarpgateToken), 0o750); err != nil {
					k.t.Fatal(err)
				}
				if err := os.WriteFile(k.p.WarpgateToken, []byte("somebody-elses-token\n"), 0o600); err != nil {
					k.t.Fatal(err)
				}
			},
			mention: []string{"Warpgate reads exactly one credential"},
		},
		{
			name: "coreX already answers as somebody else",
			step: "corex-write",
			setUp: func(k *kit) {
				k.answer("domain", testDomain)
				k.mustPass("domain")
				k.mustPass("apps")
				k.standIn("connector-registered")
				f := readJSONFile(k.t, k.p.CoreXConfig)
				inst := f["instance"].(map[string]any)
				inst["publicBaseUrl"] = "https://already-live.invalid"
				writeJSONFile(k.t, k.p.CoreXConfig, f)
			},
			mention: []string{"already-live.invalid", "publicBaseUrl"},
		},
		{
			name: "an environment file overrides what would be written",
			step: "corex-write",
			setUp: func(k *kit) {
				k.answer("domain", testDomain)
				k.mustPass("domain")
				k.mustPass("apps")
				k.standIn("connector-registered")
				writeFile(k.t, k.p.CoreXEnv,
					"# left over from the migration\nCOREX_PUBLIC_BASE_URL=https://stale.invalid\n")
			},
			mention: []string{"COREX_PUBLIC_BASE_URL", "stale.invalid"},
		},
		{
			name: "solisuite's per-app host family is overridden",
			step: "solisuite-write",
			setUp: func(k *kit) {
				k.answer("domain", testDomain)
				k.mustPass("domain")
				k.mustPass("apps")
				k.standIn("connector-registered")
				writeFile(k.t, k.p.SolisuiteEnv, "SOLISUITE_APP_HOST_MAIL=mail.stale.invalid\n")
			},
			mention: []string{"SOLISUITE_APP_HOST_MAIL"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKit(t)
			tc.setUp(k)

			before := k.snapshot()
			row := k.run(tc.step)

			if row.Status != ledger.Conflict {
				t.Fatalf("%s returned %s, not a conflict: %s", tc.step, row.Status, row.Detail)
			}
			c := row.Conflict
			if c == nil {
				t.Fatal("a conflict row carries no conflict")
			}
			// The six fields, all of them, every time. A conflict missing its
			// "why" or its "what to do" is a dead end with a red icon on it.
			for name, v := range map[string]string{
				"object": c.Object, "found": c.Found, "desired": c.Desired,
				"why": c.Why, "unchanged": c.Unchanged, "resolution": c.Resolution,
			} {
				if strings.TrimSpace(v) == "" {
					t.Errorf("the conflict has no %s", name)
				}
			}
			if c.Unchanged != Unchanged {
				t.Errorf("the promise is not stated as its own field: %q", c.Unchanged)
			}
			if c.Consequence == "" {
				t.Error("the conflict does not say what it costs to leave it alone")
			}
			blob := c.Object + c.Found + c.FoundNote + c.Desired + c.Why + c.Resolution + c.Consequence
			for _, want := range tc.mention {
				if !strings.Contains(blob, want) {
					t.Errorf("the conflict never mentions %q, so nobody can find it:\n%s", want, blob)
				}
			}

			if d := diffSnapshots(before, k.snapshot()); len(d) > 0 {
				t.Errorf("%q was promised and %s: %s", Unchanged, "the machine changed anyway", strings.Join(d, "; "))
			}

			// And there is no way past it. Running it again with the obstacle
			// still there gives the same answer; nothing accumulates, nothing
			// escalates into an overwrite.
			if again := k.run(tc.step); again.Status != ledger.Conflict {
				t.Errorf("running a conflicted step again got past it: %s", again.Status)
			}
		})
	}
}

// The failure this whole package is shaped around. coreX runs applyEnv after
// unmarshalling its JSON, so a variable that reaches the service beats the file
// the wizard just wrote — and the result is not an error, it is a switch that
// changes nothing and reports success, with every check that reads the JSON
// agreeing with it.
func TestCoreXWriteRefusesWhileAWatchedVariableIsSet(t *testing.T) {
	// systemd's manager environment reaches every service on the machine, this
	// one and coreX alike, so a watched variable visible to this process is
	// evidence coreX will see it too.
	t.Setenv("COREX_PUBLIC_BASE_URL", "https://left-over.invalid")

	k := newKit(t)
	k.answer("domain", testDomain)
	k.mustPass("domain")
	k.mustPass("apps")
	k.standIn("connector-registered")

	before := k.snapshot()
	row := k.run("corex-write")

	if row.Status != ledger.Conflict {
		t.Fatalf("corex-write went ahead with an override in force: %s — %s", row.Status, row.Detail)
	}
	c := row.Conflict
	if !strings.Contains(c.Object, "COREX_PUBLIC_BASE_URL") {
		t.Errorf("the refusal does not name the variable: %q", c.Object)
	}
	if !strings.Contains(c.Found, "environment") {
		t.Errorf("the refusal does not say where the variable is: %q", c.Found)
	}
	if !strings.Contains(c.Found, "left-over.invalid") {
		t.Errorf("the refusal does not quote what the variable says: %q", c.Found)
	}
	if !strings.Contains(c.Why, "applied AFTER") {
		t.Errorf("the refusal does not explain why a write would look like it worked: %q", c.Why)
	}
	if d := diffSnapshots(before, k.snapshot()); len(d) > 0 {
		t.Errorf("corex-write wrote anyway: %s", strings.Join(d, "; "))
	}
	if calls := k.m.unitCalls(); len(calls) > 0 {
		t.Errorf("corex-write restarted a service it had refused to configure: %v", calls)
	}
}

// The three outputs, checked as three files rather than as one intention. The
// third is the one nothing has ever written.
func TestOneAnswerReachesAllThreeFiles(t *testing.T) {
	k := newKit(t)
	k.answer("domain", testDomain)
	k.mustPass("domain")
	k.answer("apps", []appChoice{{ID: "gallery", On: false}, {ID: "roomsense", On: true}})
	k.mustPass("apps")

	warp := readJSONFile(t, k.p.WarpgateConfig)
	names := map[string]bool{}
	for _, a := range warp["apps"].([]any) {
		names[a.(map[string]any)["name"].(string)] = true
	}
	if !names["roomsense"] {
		t.Error("an app that was turned on is not in Warpgate's list, so it gets no DNS and no ingress")
	}
	if names["gallery"] {
		t.Error("an app that was turned off is still published")
	}

	soli := readJSONFile(t, k.p.SolisuiteConfig)
	seen := map[string]string{}
	for _, a := range soli["apps"].([]any) {
		m := a.(map[string]any)
		host, _ := m["host"].(string)
		origin, _ := m["origin"].(string)
		if host == "" || origin == "" {
			t.Errorf("a Solisuite app carries no host/origin pair, so appFor() falls back to defaultApp: %v", m)
		}
		seen[m["id"].(string)] = host
	}
	if seen["mail"] != "mail."+testDomain {
		t.Errorf("Solisuite's Host map is wrong: %v", seen)
	}
	// RoomSense has its own server. Listing it here would map its hostname to a
	// Solisuite document that does not exist.
	if _, listed := seen["roomsense"]; listed {
		t.Error("a standalone app was written into Solisuite's app list")
	}

	core := readJSONFile(t, k.p.CoreXConfig)
	origins := core["instance"].(map[string]any)["appOrigins"].(map[string]any)
	if len(origins) != 0 {
		t.Errorf("appOrigins was populated before any hostname had answered a probe: %v", origins)
	}
}

// An origin only exists once a hostname has answered, and once it exists it
// must survive a restart of this process. Rebuilding the set from memory would
// write {} over what the probes established, and report success for it.
func TestProvenOriginsAreNotForgottenBetweenRuns(t *testing.T) {
	k := newKit(t)
	k.answer("domain", testDomain)
	k.mustPass("domain")
	k.mustPass("apps")

	core := readJSONFile(t, k.p.CoreXConfig)
	core["instance"].(map[string]any)["appOrigins"] = map[string]any{
		"mail": "https://mail." + testDomain,
	}
	writeJSONFile(t, k.p.CoreXConfig, core)

	k.mustPass("apps")
	got := readJSONFile(t, k.p.CoreXConfig)["instance"].(map[string]any)["appOrigins"].(map[string]any)
	if got["mail"] != "https://mail."+testDomain {
		t.Errorf("a proven origin was erased by a later run of the apps step: %v", got)
	}
}

// A step whose result another step consumes must block it, and say which one.
// The alternative is a wizard that writes coreX's public base URL and flips
// cookies to Secure before anything answers on the domain — which signs the
// operator out of the page performing the installation.
func TestAStepBlocksOnWhatItActuallyConsumes(t *testing.T) {
	k := newKit(t)
	k.answer("domain", testDomain)
	k.mustPass("domain")
	k.mustPass("apps")

	before := k.snapshot()
	row := k.run("corex-write")
	if row.Status != ledger.Pending {
		t.Fatalf("corex-write ran without a tunnel that answers: %s", row.Status)
	}
	if !strings.Contains(row.Detail, "connector-registered") {
		t.Errorf("the block does not name what it is waiting for: %q", row.Detail)
	}
	if d := diffSnapshots(before, k.snapshot()); len(d) > 0 {
		t.Errorf("a blocked step wrote anyway: %s", strings.Join(d, "; "))
	}

	// And the ordering is not the graph: plan-show sits below tunnel-ensure in
	// the contract's table and does not consume it, so the last free stop can
	// be shown while nothing has happened yet.
	k.answer("plan-show", true)
	if row := k.mustPass("plan-show"); !strings.Contains(row.Proof, "mail."+testDomain) {
		t.Errorf("the plan does not name what it is about to publish: %q", row.Proof)
	}
}

// The provider steps are defined and honest about being unwritten. Pending, not
// failed: they are ahead of the wizard, not broken by it.
// The nine steps that talk to somebody else, run against a stand-in for that
// somebody. They used to answer "not implemented yet"; this is what they answer
// now, and the check is on the guarantees rather than on the wording.
func TestTheProviderStepsRead(t *testing.T) {
	k := newKit(t)
	k.answer("domain", testDomain)
	k.run("domain")
	k.answer("token-verify", testToken)
	k.standIn("token-store", "plan-show", "ingress-write")
	// warpgate is recorded rather than run, and its answers are what a settled
	// edge and a registered connector look like.
	k.m.out[k.p.WarpgateBin+" -config "+k.p.WarpgateConfig+" plan"] =
		"Edge plan for the configured root domain (2 apps)\n\nNothing to do. The edge already matches the configuration."
	k.m.out["journalctl -u "+k.p.ConnectorUnit+" -b --no-pager -n 200"] =
		"INF Registered tunnel connection connIndex=0\nINF Registered tunnel connection connIndex=1"
	k.m.active[k.p.ConnectorUnit] = true

	for _, id := range []string{
		"token-verify", "zone-resolve", "nameservers", "zone-inventory",
		"tunnel-ensure", "dns-apply", "connector-registered", "cert-wait", "nonce-probe",
	} {
		row := k.run(id)
		if row.Desired == "" {
			t.Errorf("%s does not say what it would do, so the page cannot show what is coming", id)
		}
		if row.Status == ledger.Failed {
			t.Errorf("%s failed against a healthy stand-in: %s", id, row.Detail)
		}
		if strings.Contains(row.Detail, "not implemented") {
			t.Errorf("%s still reports itself unwritten: %q", id, row.Detail)
		}
		k.standIn(id)
	}

	// Each one asked for the thing its verdict is about. "Something read
	// something" is not the claim — a step that returns a verdict without
	// making the call it is a verdict about is a step whose answer is about
	// nothing, and with nine of them sharing one stand-in, a single reader
	// would have satisfied a check that only counted.
	asked := strings.Join(k.cf.asked, "\n")
	for _, want := range []string{
		"token-verify",       // the token was checked
		"zone " + testDomain, // and the zone it was checked against
		"records zone-1",     // the inventory really listed the zone
	} {
		if !strings.Contains(asked, want) {
			t.Errorf("nothing asked Cloudflare for %q; the steps that report on it did not look", want)
		}
	}
}

// THE ARCHITECTURAL GUARANTEE: this package never writes to a provider.
//
// The Cloudflare seam has no write method, which the compiler enforces. What it
// cannot enforce is that a step does not shell out to curl, or to cloudflared,
// or to anything else that could. Warpgate is the one thing in this landscape
// that writes DNS — it is where the ownership marker, the refusal to overwrite
// a foreign record, the separate confirmation for a deletion and the journal
// live — and a second writer would be a second thing that has to be taught all
// of it.
func TestNoProviderStepWritesAnythingItself(t *testing.T) {
	k := newKit(t)
	k.answer("domain", testDomain)
	k.run("domain")
	k.answer("token-verify", testToken)
	k.standIn("token-store", "plan-show", "ingress-write")
	k.m.out[k.p.WarpgateBin+" -config "+k.p.WarpgateConfig+" plan"] =
		"Edge plan for the configured root domain (2 apps)\n\nNothing to do. The edge already matches the configuration."
	k.m.active[k.p.ConnectorUnit] = true

	for _, id := range []string{
		"token-verify", "zone-resolve", "nameservers", "zone-inventory",
		"tunnel-ensure", "dns-apply", "connector-registered", "cert-wait", "nonce-probe",
	} {
		k.run(id)
		k.standIn(id)
	}

	for _, c := range k.m.calls {
		cmd, ok := strings.CutPrefix(c, "run ")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(cmd, " ")
		switch name {
		case k.p.WarpgateBin, "journalctl":
			// warpgate is the only writer, and journalctl is a read.
		default:
			t.Errorf("a provider step ran %q. Every write goes through warpgate; nothing else may reach a provider", cmd)
		}
	}
}

func TestSkippingNeedsAReason(t *testing.T) {
	k := newKit(t)
	if err := k.e.Skip("engines", "   "); err == nil {
		t.Error("a step was skipped with nothing written down about why")
	}
	if err := k.e.Skip("engines", "no AI on this machine"); err != nil {
		t.Fatal(err)
	}
	if r := k.row("engines"); r.Status != ledger.Skipped || r.Detail != "no AI on this machine" {
		t.Errorf("the reason was not kept: %s %q", r.Status, r.Detail)
	}
	if err := k.e.Skip("not-a-step", "because"); err == nil {
		t.Error("a step that does not exist was skipped")
	}
}

func TestWhatSomebodyPastesIntoADomainBox(t *testing.T) {
	for _, tc := range []struct {
		in, want, because string
	}{
		{in: " Example.ORG ", want: testDomain},
		{in: testDomain + ".", want: testDomain},
		{in: "https://" + testDomain, because: "a URL"},
		{in: testDomain + "/setup", because: "a path"},
		{in: testDomain + ":8443", because: "a port"},
		{in: "localhost", because: "a single label"},
		{in: "not a domain", because: "spaces"},
		{in: "-bad." + testDomain, because: "a label starting with a hyphen"},
		{in: "", because: "empty"},
	} {
		got, err := cleanDomain(tc.in)
		if tc.because != "" {
			if err == nil {
				t.Errorf("%q was accepted despite being %s", tc.in, tc.because)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("cleanDomain(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

// --- small helpers ---------------------------------------------------------

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(b)+"\n")
}

func readJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

func mkdirWithSomethingIn(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "mail.db"), "not really a database")
}

// Two steps end in an observation of the machine rather than in a file being
// written, and both of their unhappy branches matter more than their happy one.
func TestTheStepsThatObserveTheMachineRatherThanWriteToIt(t *testing.T) {
	t.Run("no administrator yet is a wait on a person, not a failure", func(t *testing.T) {
		k := newKit(t)
		k.m.out[k.p.Corexctl+" admin list"] = ""

		row := k.run("admin")
		if row.Status != ledger.WaitingOnThem {
			t.Fatalf("admin is %s, and a wait on a person is not a failure", row.Status)
		}
		// An unattributed wait reads as this machine being slow. This one is
		// somebody standing at a terminal, and the row has to say so.
		if row.WaitingOn == "" {
			t.Error("the wait names nobody")
		}
		if row.Needs == nil || row.Needs.Kind != "manual" || !row.Needs.Recheck {
			t.Errorf("the row does not offer the instructions and a recheck: %+v", row.Needs)
		}
		if row.Needs != nil && !strings.Contains(row.Needs.Instructions, "admin create") {
			t.Error("the instructions do not say what to run")
		}
		if row.Needs != nil && strings.Contains(strings.ToLower(row.Needs.Instructions), "type your password here") {
			t.Error("the page is asking for a password over plain HTTP")
		}
	})

	t.Run("an administrator that exists withdraws the instructions", func(t *testing.T) {
		k := newKit(t)
		k.mustPass("admin")
		if row := k.row("admin"); row.Needs != nil {
			t.Errorf("the page still tells somebody to do a thing they have done: %+v", row.Needs)
		}
	})

	t.Run("an engine that is not on the machine is a failure, in the tool's own words", func(t *testing.T) {
		k := newKit(t)
		k.m.fail["run ollama --version"] = errNotThere
		k.answer("engines", "ollama")

		before := k.snapshot()
		row := k.run("engines")
		if row.Status != ledger.Failed {
			t.Fatalf("engines is %s despite the engine not being installed", row.Status)
		}
		if !strings.Contains(row.Detail, "ollama") {
			t.Errorf("the failure does not name what is missing: %q", row.Detail)
		}
		// Writing "ollama" into a config file is not evidence that ollama
		// exists, and the failure it produces later is an app that opens and
		// does nothing, three steps from anything that mentions engines.
		if d := diffSnapshots(before, k.snapshot()); len(d) > 0 {
			t.Errorf("a configuration was written for an engine that is not there: %s", strings.Join(d, "; "))
		}
	})

	t.Run("the apex is checked while logged out", func(t *testing.T) {
		k := newKit(t)
		k.drive()
		k.resp = Response{Status: 502, Body: "Bad gateway"}

		row := k.run("corex-restart-2")
		if row.Status != ledger.Failed {
			t.Fatalf("the apex answered 502 and the step reported %s", row.Status)
		}
		if !strings.Contains(row.Detail, "502") {
			t.Errorf("the failure does not carry what came back: %q", row.Detail)
		}
	})
}

var errNotThere = errors.New(`exec: "ollama": executable file not found in $PATH`)

// The domain change, which is the same code as the first run and is the reason
// it had to be. It is also the one write that removes something, and a removal
// that is written without being shown is the failure this whole package is
// built to avoid.
func TestChangingTheDomainReportsWhatItTakesAwayAsWellAsWhatItAdds(t *testing.T) {
	k := newKit(t)
	k.answer("domain", testDomain)
	k.mustPass("domain")
	k.mustPass("apps")

	// nonce-probe's work, standing in: one hostname has answered, so coreX
	// advertises it.
	core := readJSONFile(t, k.p.CoreXConfig)
	core["instance"].(map[string]any)["appOrigins"] = map[string]any{
		"mail": "https://mail." + testDomain,
	}
	writeJSONFile(t, k.p.CoreXConfig, core)

	const moved = "example.net"
	k.answer("domain", moved)
	k.mustPass("domain")

	// The step has passed here before, so the old hostnames are this machine's
	// own work rather than somebody else's — a reconcile, not a conflict.
	row := k.mustPass("apps")
	if row.Status != ledger.Passed {
		t.Fatalf("a domain change was refused as a conflict: %s", row.Detail)
	}

	got := readJSONFile(t, k.p.CoreXConfig)["instance"].(map[string]any)["appOrigins"].(map[string]any)
	if _, still := got["mail"]; still {
		t.Errorf("an origin under the old domain survived the move: %v", got)
	}
	soli := readJSONFile(t, k.p.SolisuiteConfig)["apps"].([]any)
	for _, a := range soli {
		host := a.(map[string]any)["host"].(string)
		if !strings.HasSuffix(host, "."+moved) {
			t.Errorf("Solisuite still maps a hostname under the old domain: %q", host)
		}
	}

	// And the removal was in the diff. instance.File.Changes() walks the tree
	// it is about to write, so it cannot see a key that disappears; this is the
	// check that the gap is covered rather than merely known about.
	dropped := droppedOrigins(k.p.CoreXConfig,
		map[string]any{"mail": "https://mail." + testDomain, "files": "https://files." + moved},
		map[string]string{"files": "https://files." + moved})
	if len(dropped) != 1 {
		t.Fatalf("a removed origin was not reported: %+v", dropped)
	}
	if dropped[0].From != "https://mail."+testDomain || dropped[0].To != "(removed)" {
		t.Errorf("the removal does not say what is going: %+v", dropped[0])
	}
}

// Closing setup is one act, and the order inside it is the whole design.
//
// Plan 7.7: the same transaction that records the instance as claimed destroys
// the setup code and takes the LAN listener away. Never both doors open at
// once — an instance live on its own domain and still answering an
// unauthenticated setup page on the network is the shape of Jellyfin #6486.
func TestClosingSetupIsOneAct(t *testing.T) {
	k := newKit(t)
	if err := os.MkdirAll(filepath.Dir(k.p.Claim), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k.p.Claim, []byte("a-code\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	// It refuses while anything is unfinished — and the case that matters is
	// NOT the one the dependency graph already covers. `After` names
	// corex-restart-2 alone, so standing everything in except a step in the
	// middle reaches the guard rather than the graph. The first version of this
	// check stood in nothing, was blocked by After, and passed with the guard
	// deleted.
	k.answer("seal", true)
	for _, st := range k.e.order {
		if st.ID != "seal" && st.ID != "zone-inventory" {
			k.standIn(st.ID)
		}
	}
	row := k.run("seal")
	if row.Status == ledger.Passed {
		t.Fatal("setup was closed with zone-inventory still open")
	}
	if !strings.Contains(row.Detail, "zone-inventory") {
		t.Errorf("the refusal does not name what is unfinished: %q", row.Detail)
	}
	if _, err := os.Stat(k.p.Seal); err == nil {
		t.Fatal("it wrote the seal anyway")
	}
	if _, err := os.Stat(k.p.Claim); err != nil {
		t.Error("it destroyed the setup code without closing setup")
	}

	// Now everything is finished, one way or the other.
	k.standIn("zone-inventory")
	row = k.run("seal")
	if row.Status != ledger.Passed {
		t.Fatalf("seal: %s — %s", row.Status, row.Detail)
	}
	if _, err := os.Stat(k.p.Seal); err != nil {
		t.Error("setup reported closed and nothing records the instance as claimed")
	}
	if _, err := os.Stat(k.p.Claim); !os.IsNotExist(err) {
		t.Error("the setup code survived: a spent code in /etc is a second key to an open door")
	}
	var disabled bool
	for _, c := range k.m.calls {
		if c == "disable "+k.p.SetupUnit {
			disabled = true
		}
	}
	if !disabled {
		t.Errorf("the setup listener was not disabled, so it returns at the next boot. Calls: %v", k.m.calls)
	}
}

// Without the confirmation, nothing happens. The default is no.
func TestSetupIsNotClosedWithoutBeingAsked(t *testing.T) {
	k := newKit(t)
	if err := os.MkdirAll(filepath.Dir(k.p.Claim), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k.p.Claim, []byte("a-code\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, s := range k.e.order {
		if s.ID != "seal" {
			k.standIn(s.ID)
		}
	}
	if row := k.run("seal"); row.Status == ledger.Passed {
		t.Error("setup closed itself without being told to")
	}
	if _, err := os.Stat(k.p.Seal); err == nil {
		t.Error("it wrote the seal without being told to")
	}
}

// The token step used to end by saying the question could not be asked: "whether
// the token also reaches other zones cannot be read back: that needs User API
// Tokens Read". That is true of the token's own definition and false of its
// reach — GET /zones with no filter answers it. Measured against a real token
// on 2026-08-30 that looked single-zone on this zone's own answer and carried
// two.
func TestATokenThatReachesOtherZonesSaysWhichOnes(t *testing.T) {
	k := newKit(t)
	k.cf.names = []string{testDomain, "somewhere-else.invalid", "third.invalid"}
	k.answer("domain", testDomain)
	k.run("domain")
	k.answer("token-verify", "cfut-whatever")
	row := k.run("token-verify")

	if row.Status != ledger.Passed {
		t.Fatalf("a sufficient token did not pass: %s %s", row.Status, row.Detail)
	}
	for _, other := range []string{"somewhere-else.invalid", "third.invalid"} {
		if !strings.Contains(row.Proof, other) {
			t.Errorf("%s is inside this machine's reach and is not named: %q", other, row.Proof)
		}
	}
	if strings.Contains(row.Proof, "cannot be read back") {
		t.Error("the proof still claims the reach is unknowable")
	}
}

// A single-zone token is the shape the whole design asks for, and must be told
// so plainly — a warning that appears on the correct case teaches people to
// skip warnings.
func TestASingleZoneTokenIsSaidToBeSingleZone(t *testing.T) {
	k := newKit(t)
	k.answer("domain", testDomain)
	k.run("domain")
	k.answer("token-verify", "cfut-whatever")
	row := k.run("token-verify")

	if !strings.Contains(row.Proof, "no other") {
		t.Errorf("a single-zone token was not confirmed as one: %q", row.Proof)
	}
	if strings.Contains(row.Proof, "also reaches") {
		t.Errorf("a single-zone token was reported as reaching further: %q", row.Proof)
	}
}

// Listing zones is a warning the step would like to give, not one it depends
// on: the grant on THIS zone is what the wizard needs. A token whose account
// forbids the listing must still get through, and must say why it is quiet.
func TestAFailedReachLookupDoesNotFailTheStep(t *testing.T) {
	k := newKit(t)
	k.cf.nameErr = errors.New("403 forbidden")
	k.answer("domain", testDomain)
	k.run("domain")
	k.answer("token-verify", "cfut-whatever")
	row := k.run("token-verify")

	if row.Status != ledger.Passed {
		t.Fatalf("a sufficient token was rejected because a warning could not be produced: %s %s", row.Status, row.Detail)
	}
	if !strings.Contains(row.Proof, "could not be read") {
		t.Errorf("the step went quiet about the reach without saying so: %q", row.Proof)
	}
}

// A token wider than the four rows asked for still works, and must not pass in
// silence. This is the token this instance was handed on 2026-08-30.
func TestAWiderTokenPassesAndIsNamedAsWider(t *testing.T) {
	k := newKit(t)
	k.cf.zone.Permissions = append(k.cf.zone.Permissions,
		"#zone:edit", "#page_shield:edit", "#page_shield:read", "#ssl:read")
	k.answer("domain", testDomain)
	k.run("domain")
	k.answer("token-verify", "cfut-whatever")
	row := k.run("token-verify")

	if row.Status != ledger.Passed {
		t.Fatalf("a token that carries everything needed was refused for carrying more: %s", row.Detail)
	}
	for _, extra := range []string{"page_shield:edit", "ssl:read", "zone:edit"} {
		if !strings.Contains(row.Detail, extra) {
			t.Errorf("%s was carried and the ledger line does not say so: %q", extra, row.Detail)
		}
	}
}

// A running instance was told its own apex belonged to somebody else.
//
// The check was `!strings.HasSuffix(host, "."+domain)`, and example.org does not
// end in ".example.org" — so the apex, the one hostname every instance has,
// read as foreign, and the report ended "if it is not, this is the wrong
// machine". Seen live on 2026-08-30 against this machine's own configuration.
//
// The two findings had one report between them and needed two: a name under
// somebody else's domain, and a name under this one that this instance
// published earlier and differently.
func TestOurOwnHostnamesAreNotCalledSomebodyElses(t *testing.T) {
	k := newKit(t)
	k.answer("domain", testDomain)
	k.mustPass("domain")
	writeJSONFile(k.t, k.p.SolisuiteConfig, map[string]any{
		"apps": []any{
			map[string]any{"id": "launcher", "host": testDomain, "origin": "https://" + testDomain},
		},
	})
	row := k.run("apps")

	if row.Status != ledger.Conflict {
		t.Fatalf("an existing app list was overwritten instead of held: %s %s", row.Status, row.Detail)
	}
	c := row.Conflict
	if c == nil {
		t.Fatal("a conflict with no report")
	}
	if strings.Contains(c.Resolution, "wrong machine") {
		t.Errorf("the right machine was called the wrong one:\n  found: %s\n  %s", c.Found, c.Resolution)
	}
	if strings.Contains(c.FoundNote, "is not "+testDomain) {
		t.Errorf("this instance's own apex was reported as belonging to another domain: %q", c.FoundNote)
	}
	if !strings.Contains(c.FoundNote, "this instance") {
		t.Errorf("the report does not say whose these are: %q", c.FoundNote)
	}
	if !strings.Contains(c.Found, testDomain) {
		t.Errorf("the report does not quote what it found: %q", c.Found)
	}
}

// And a name that really does belong elsewhere still gets the harder sentence.
func TestAHostnameUnderAnotherDomainStillSaysWrongMachine(t *testing.T) {
	k := newKit(t)
	k.answer("domain", testDomain)
	k.mustPass("domain")
	writeJSONFile(k.t, k.p.SolisuiteConfig, map[string]any{
		"apps": []any{map[string]any{"id": "mail", "host": "mail.someone-else.invalid"}},
	})
	row := k.run("apps")
	if row.Status != ledger.Conflict {
		t.Fatalf("another instance's hostnames were overwritten: %s", row.Status)
	}
	c := row.Conflict
	if c == nil || !strings.Contains(c.Resolution, "wrong machine") {
		t.Errorf("a foreign hostname did not get the wrong-machine sentence: %+v", c)
	}
}
