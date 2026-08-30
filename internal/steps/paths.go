package steps

// Paths are the files and units this engine reconciles.
//
// Every one is a field rather than a constant, and not for elegance: the whole
// point is that the entire engine can be pointed at a t.TempDir() and at a
// Machine that records rather than acts, so the test suite exercises the real
// code without touching this machine's /etc or its services. A constant
// anywhere in here would be a line the tests have to route around, and the
// routed-around line is the one that ships broken.
type Paths struct {
	// CoreXConfig holds identity: the public base URL, the cookie domain, the
	// display name, the data directory, the app origins.
	CoreXConfig string
	// CoreXEnv is the systemd EnvironmentFile whose contents beat that file.
	// coreX runs applyEnv after unmarshalling the JSON, so a line left in here
	// wins over anything written above — which is why it is read before every
	// coreX write and not after.
	CoreXEnv string

	SolisuiteConfig string
	SolisuiteEnv    string

	// WarpgateConfig is Warpgate's own configuration: the app list that becomes
	// DNS and ingress, and the two pins that say where the connector's
	// configuration lives and what to reload when it changes.
	WarpgateConfig string
	// WarpgateIngress is the connector's configuration — the hostname to
	// upstream map. It is the file WarpgateConfig's configPath points at.
	WarpgateIngress string
	// WarpgateToken is where the Cloudflare credential lands, 0600 root:root,
	// and nowhere else. Never in the ledger, never in an envelope, never in a
	// log line.
	WarpgateToken string

	// WarpgateBin is the command that plans and applies the edge. The wizard
	// never writes DNS itself — see cloudflare.go — so this is how every
	// provider write happens.
	WarpgateBin string

	CoreXUnit     string
	SolisuiteUnit string
	// ConnectorUnit is the tunnel connector. It is what warpgate-config pins as
	// reloadUnit and what ingress-write enables and starts.
	ConnectorUnit string

	// Seal records that setup finished, Claim is the setup code, and SetupUnit
	// is the listener. All three are named here because the act that closes
	// setup touches all three at once, and a path it guessed at would be a path
	// that half-closes it.
	Seal      string
	Claim     string
	SetupUnit string

	// Corexctl is the instance's own command line. Administrators are created
	// through it, on the machine, over stdin — never in a page served over
	// plain HTTP on a name anyone on the network can claim.
	Corexctl string

	// DataDir is what the storage step offers as a default. It is here rather
	// than inline so that a test never proposes a real directory on the machine
	// running it.
	DataDir string
}

// DefaultPaths is where these things live on a machine the installer built. The
// three /etc directories are exactly the ones holistic-setup.service grants
// itself in ReadWritePaths; if one is added here it has to be added there too,
// or the write fails at run time with a permission error that says nothing
// about the cause.
func DefaultPaths() Paths {
	return Paths{
		CoreXConfig:     "/etc/corex/config.json",
		CoreXEnv:        "/etc/corex/corex.env",
		SolisuiteConfig: "/etc/solisuite/config.json",
		SolisuiteEnv:    "/etc/solisuite/solisuite.env",
		WarpgateConfig:  "/etc/warpgate/config.json",
		// .yml, not .json. Warpgate generates cloudflared's own ingress file
		// and cloudflared reads YAML; the name here was a guess and the guess
		// was wrong. Checked against the running machine on 2026-08-30.
		WarpgateIngress: "/etc/warpgate/ingress.yml",
		WarpgateToken:   "/etc/warpgate/cloudflare.token",
		WarpgateBin:     "/opt/holistic/bin/warpgate",
		CoreXUnit:       "corex-api.service",
		SolisuiteUnit:   "solisuite.service",
		// The connector's unit is cloudflared-warpgate, not warpgate: warpgate
		// is the command that plans and applies, and the connector is
		// cloudflared running against the ingress warpgate writes. Naming the
		// wrong one meant every reload would have restarted nothing, and
		// `is-active` would have answered about a unit that does not exist.
		ConnectorUnit: "cloudflared-warpgate.service",
		Seal:          "/etc/holistic/claimed",
		Claim:         "/etc/holistic/setup.claim",
		SetupUnit:     "holistic-setup.service",
		// Absolute, like WarpgateBin beside it. This was a bare "corexctl" and
		// the admin step failed on the running machine with `exec: "corexctl":
		// executable file not found in $PATH` — holistic-setup.service is a
		// systemd unit, and a unit's PATH does not include /opt/holistic/bin.
		// The two fields describe the same kind of thing and only one of them
		// had been given a path.
		Corexctl: "/opt/holistic/bin/corexctl",
		DataDir:  "/var/lib/corex",
	}
}
