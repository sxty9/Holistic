package steps

// definitions is the wizard, in order.
//
// The order is the contract's, and it is the order a person reads down the
// page. It is NOT the dependency graph — that lives in each step's After, and
// it is deliberately narrower. An engine that treated position as dependency
// would put every local step behind the first provider call, which would be
// both wrong and untestable: writing Solisuite's app list does not require a
// Cloudflare token, and it is worth being able to prove that.
//
// Where the two differ is where the design is. corex-write sits four rows below
// connector-registered in the table and genuinely consumes it: flipping
// auth.insecureCookies to false before a tunnel answers signs the operator out
// of the page performing the installation, over plain HTTP, halfway through.
// plan-show sits below tunnel-ensure and does not consume it: the plan is a
// projection of the app catalogue, it can be shown before the tunnel exists,
// and being able to show somebody what is about to happen while nothing has
// happened yet is the entire point of it.
func definitions() []Step {
	return []Step{
		stepDomain(),
		stepDisplayName(),
		stepStorage(),
		stepEngines(),
		stepAdmin(),
		stepApps(),
		stepTokenVerify(),
		stepZoneResolve(),
		// nameservers sits here, between resolving the zone and everything
		// after it, and only bites when the zone comes back pending. It is
		// where the wizard stops and waits rather than pretending.
		stepNameservers(),
		stepTokenStore(),
		stepZoneInventory(),
		stepTunnelEnsure(),
		stepWarpgateConfig(),
		stepPlanShow(),
		stepDNSApply(),
		stepIngressWrite(),
		stepConnectorRegistered(),
		stepSolisuiteWrite(),
		stepCoreXWrite(),
		stepCertWait(),
		stepNonceProbe(),
		stepCoreXRestart2(),
		// The mail half sits here, after the instance answers on its own
		// domain and before setup closes. It is last because of what it
		// consumes, not because it matters least: the role mailbox needs
		// coreX to hold the domain, and the DMARC record must not name an
		// address that does not yet accept mail.
		stepRoleMailboxes(),
		stepMailDNS(),
		stepMailApply(),
		stepDMARCPublished(),
		stepSeal(),
	}
}
