// Command holistic is the instance's own command line.
//
// It exists because install.sh already told people it did. The installer's
// closing message says
//
//	Lost it?  sudo /opt/holistic/bin/holistic code
//
// and until now there was no such binary — the same shape of defect as a
// documented flag that was never built: it costs nothing until the day somebody
// actually loses their setup code, and then it costs them the instance.
//
// It has three jobs and deliberately no more. Anything that configures this
// instance belongs to the setup assistant, which has a screen for it and a
// record of what it did.
package main

import (
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sxty9/Holistic/internal/release"
)

// Injected by release.sh at build time, the same way install.sh gets its copy
// of the public key. A build without them can report its own ignorance, which
// is the only honest thing it could do.
var (
	version   = "dev"
	pubkeyB64 = "REPLACE_ME"
)

const (
	defaultPrefix = "/opt/holistic"
	defaultConf   = "/etc/holistic"
	defaultState  = "/var/lib/holistic"

	// The unit the seal disables and reopen brings back. Named here rather
	// than discovered: it is the same string as internal/steps/paths.go, and a
	// reopen that enabled a different unit than the seal disabled would report
	// success and leave nothing listening.
	setupUnit = "holistic-setup.service"
)

// The units this tool may restart. Named rather than discovered: a glob over
// /etc/systemd/system would pick up units this instance does not own, and
// restarting somebody else's service because it happened to match a pattern is
// the failure Warpgate already had once.
var managedUnits = []string{
	"holistic-setup.service",
	"corex-api.service",
	"corex-routedge.service",
	"solisuite.service",
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version":
		err = cmdVersion(os.Args[2:])
	case "code":
		err = cmdCode(os.Args[2:])
	case "upgrade":
		err = cmdUpgrade(os.Args[2:])
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "holistic: no such command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nholistic: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `holistic — this instance's command line

  holistic version              what is installed here, and what is available
  holistic code                 mint a fresh setup code (before the instance is claimed)
  holistic upgrade              fetch the latest release, verify it, swap it in
  holistic setup reopen         put the assistant back on the LAN, with a fresh code

Every command takes -prefix, -conf and -state if this instance does not live in
the usual places. upgrade takes -dry-run, -version and -base-url.
`)
}

func paths(fs *flag.FlagSet) (prefix, conf, state *string) {
	prefix = fs.String("prefix", defaultPrefix, "where the binaries live")
	conf = fs.String("conf", defaultConf, "where the configuration lives")
	state = fs.String("state", defaultState, "where this instance's own state lives")
	return
}

func cmdVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	_, _, state := paths(fs)
	baseURL := fs.String("base-url", release.DefaultBaseURL, "where releases are published")
	check := fs.Bool("check", false, "also ask what the latest release is")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Printf("holistic %s\n", version)

	in, err := release.ReadInstalled(*state)
	switch {
	case err == nil:
		fmt.Printf("installed  %s (%s), %s\n", in.Version, in.Platform,
			in.InstalledAt.Local().Format("2006-01-02 15:04"))
	case os.IsNotExist(err):
		// Every installer before this one omitted the record. Say what that
		// means rather than reporting an error for a file that was never
		// written.
		fmt.Println("installed  unrecorded — this instance predates the version record.")
		fmt.Println("           The next upgrade will start recording it.")
	default:
		return err
	}

	if !*check {
		return nil
	}
	pub, err := release.ParsePublicKey(pubkeyB64)
	if err != nil {
		return err
	}
	c := &release.Client{BaseURL: *baseURL, PublicKey: pub}
	dir, err := os.MkdirTemp("", "holistic-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	rel, err := c.Fetch(dir, platform(), "latest")
	if err != nil {
		return err
	}
	fmt.Printf("available  %s\n", rel.SHA256[:12])
	return nil
}

func cmdCode(args []string) error {
	fs := flag.NewFlagSet("code", flag.ExitOnError)
	_, conf, _ := paths(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("this writes %s/setup.claim, so it needs root:\n  sudo %s code",
			*conf, filepath.Join(defaultPrefix, "bin", "holistic"))
	}

	// The claim is one-way. Minting a fresh code on a claimed instance would
	// reopen the door that claiming closed — that is Jellyfin #6486, where an
	// unauthenticated visitor could walk the setup again and take the admin
	// account. There is a way back, but it is `holistic setup reopen`, refused
	// unless somebody confirms it at the terminal. Until 2026-08-30 this named
	// `corexctl setup reopen`, which lives in another binary and was never
	// written: the one instruction for somebody already locked out pointed at
	// nothing.
	if release.Claimed(*conf) {
		return fmt.Errorf("this instance is already claimed, so there is nothing to let anyone in with.\n"+
			"A setup code now would reopen a door that was deliberately shut.\n"+
			"If you genuinely need to run setup again:  sudo holistic setup reopen\n"+
			"(%s/claimed is what records it.)", *conf)
	}

	code, err := mintCode()
	if err != nil {
		return err
	}
	if err := writeClaim(*conf, code); err != nil {
		return err
	}

	fmt.Printf("\n  setup code   %s\n\n", code)
	fmt.Println("  It is shown here and nowhere else. The previous code, if there was one,")
	fmt.Println("  no longer works.")
	return nil
}

// mintCode takes 128 bits from the kernel and groups them for copying by eye.
// Never generated in a browser: Synology did that with Math.random, the seed was
// recovered, and the administrator account went with it (CVE-2023-2729).
func mintCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))
	var out []string
	for i := 0; i < len(s); i += 5 {
		end := i + 5
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return strings.Join(out, "-"), nil
}

func cmdUpgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	prefix, conf, state := paths(fs)
	baseURL := fs.String("base-url", release.DefaultBaseURL, "where releases are published")
	want := fs.String("version", "latest", "a release tag, or latest")
	dry := fs.Bool("dry-run", false, "say what would change, change nothing")
	force := fs.Bool("force", false, "reinstall even if the version already matches")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 && !*dry {
		return fmt.Errorf("this replaces files under %s and restarts services, so it needs root:\n  sudo %s upgrade",
			*prefix, filepath.Join(*prefix, "bin", "holistic"))
	}

	pub, err := release.ParsePublicKey(pubkeyB64)
	if err != nil {
		return err
	}

	current, err := release.ReadInstalled(*state)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	dir, err := os.MkdirTemp("", "holistic-upgrade-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	fmt.Printf("== Fetching %s\n", *want)
	c := &release.Client{BaseURL: *baseURL, PublicKey: pub}
	rel, err := c.Fetch(dir, platform(), *want)
	if err != nil {
		return err
	}
	fmt.Println("   manifest signature: ok")
	fmt.Printf("   %s checksum: ok\n", rel.Archive)

	// Compared by checksum rather than by tag. "latest" is not a version, and a
	// tag can be moved; the archive's hash is the only thing that actually says
	// whether this is the same software.
	if current != nil && current.SHA256 == rel.SHA256 && !*force {
		fmt.Printf("\nAlready running this release (%s, %s). Nothing to do.\n",
			current.Version, rel.SHA256[:12])
		return nil
	}

	fmt.Println()
	if current != nil {
		fmt.Printf("   from  %s  %s\n", current.Version, current.SHA256[:12])
	} else {
		fmt.Printf("   from  unrecorded\n")
	}
	fmt.Printf("   to    %s  %s\n", rel.Version, rel.SHA256[:12])

	if *dry {
		fmt.Println("\n== Would change")
		names, _ := binariesIn(rel)
		for _, n := range names {
			fmt.Printf("   %s\n", filepath.Join(*prefix, "bin", n))
		}
		for _, u := range managedUnits {
			fmt.Printf("   restart %s (only if it is running)\n", u)
		}
		fmt.Println("\n   The setup state is not touched: " + *conf + "/claimed stays as it is.")
		return nil
	}

	fmt.Println("\n== Installing")
	replaced, undo, err := release.Swap(rel, filepath.Join(*prefix, "bin"))
	if err != nil {
		return err
	}
	for _, n := range replaced {
		fmt.Printf("   %s\n", filepath.Join(*prefix, "bin", n))
	}

	fmt.Println("\n== Restarting what is running")
	restarted, err := release.RestartUnits(managedUnits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n   a service did not come back — putting the previous binaries back\n")
		if e := undo(); e != nil {
			// Both halves failed. Say exactly that rather than hiding the
			// second failure behind the first: the operator now has to look.
			return fmt.Errorf("%w\n\nand the rollback also failed: %v\nThe binaries under %s are in a mixed state and need a manual look",
				err, e, filepath.Join(*prefix, "bin"))
		}
		if _, e := release.RestartUnits(restarted); e != nil {
			return fmt.Errorf("%w\n\nthe previous binaries are back, but restarting with them also failed: %v", err, e)
		}
		return fmt.Errorf("%w\n\nThe previous release has been put back and is running. Nothing was upgraded", err)
	}
	for _, u := range restarted {
		fmt.Printf("   %s\n", u)
	}
	if len(restarted) == 0 {
		fmt.Println("   nothing was running, so nothing was restarted")
	}

	if err := release.WriteInstalled(*state, &release.Installed{
		Version:     rel.Version,
		Platform:    rel.Platform,
		Archive:     rel.Archive,
		SHA256:      rel.SHA256,
		InstalledAt: time.Now().UTC(),
		Binaries:    replaced,
	}); err != nil {
		return fmt.Errorf("upgraded, but the version record could not be written: %w", err)
	}

	fmt.Printf("\nNow running %s.\n", rel.Version)
	if release.Claimed(*conf) {
		fmt.Println("Setup stays closed — this instance is already claimed.")
	}
	return nil
}

// binariesIn lists what the unpacked release would lay down, so --dry-run can
// name the files rather than describe them.
func binariesIn(rel *release.Release) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(rel.Dir, "holistic", "bin"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func platform() string { return runtime.GOOS + "-" + runtime.GOARCH }

// cmdSetup is the way back in, and the only one. The wizard's last act seals
// the instance: it writes `claimed`, destroys the setup code and disables the
// listener, all in one transaction, so that the LAN door is shut before the
// tunnel opens. That is deliberate and it is one-way over the network.
//
// It cannot be one-way on the machine. A domain moves, a Cloudflare account is
// suspended, an operator inherits a server — and an instance that can never be
// reconfigured is a brick with data in it. So: a way back, from a root shell,
// that says out loud what it is doing.
//
// What it must NOT be is what Jellyfin #6486 was: setup reachable again by
// anyone who can reach the port. Hence a fresh code, minted here and shown
// once, before the listener is allowed to come back.
func cmdSetup(args []string) error {
	if len(args) == 0 || args[0] != "reopen" {
		return fmt.Errorf("the only thing to do to a finished setup is reopen it:\n  sudo %s setup reopen",
			filepath.Join(defaultPrefix, "bin", "holistic"))
	}
	fs := flag.NewFlagSet("setup reopen", flag.ExitOnError)
	_, conf, _ := paths(fs)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("this removes %s/claimed and starts a listener, so it needs root:\n  sudo %s setup reopen",
			*conf, filepath.Join(defaultPrefix, "bin", "holistic"))
	}
	if !release.Claimed(*conf) {
		return fmt.Errorf("this instance is not claimed, so setup was never closed.\n"+
			"If nothing is listening, %s is what starts it, and `holistic code` mints a code for it.",
			setupUnit)
	}

	if !*yes && !confirm(
		"This puts the setup assistant back on the local network.",
		"Anyone who can reach this machine's LAN address will see it, and the code below",
		"is all that stands between them and it. Do it while you are at the machine, and",
		"finish or re-close the setup rather than leaving it open.") {
		return fmt.Errorf("nothing was changed")
	}

	code, err := reopenSetup(*conf, runCmd)
	if err != nil {
		return err
	}

	fmt.Printf("\n  setup code   %s\n\n", code)
	fmt.Println("  Setup is open again on this machine's LAN address.")
	fmt.Println("  Your accounts, mail and files are untouched — this reopens the assistant,")
	fmt.Println("  not the sign-up. Closing setup at the end of the run seals it again.")
	return nil
}

// confirm asks on the terminal, not on stdin: `holistic` may be run from a
// script whose stdin is a pipe, and reading a reopen out of a pipe is how an
// unattended job would silently reopen setup.
func confirm(lines ...string) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nno terminal to ask on. If you mean it: holistic setup reopen -yes")
		return false
	}
	defer tty.Close()
	fmt.Fprintln(tty)
	for _, l := range lines {
		fmt.Fprintln(tty, "  "+l)
	}
	fmt.Fprint(tty, "\n  Reopen setup? [y/N] ")
	var answer string
	fmt.Fscanln(tty, &answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y")
}

// writeClaim puts the code on disk at 0640, written at its final mode. Between
// an open and a later chmod there is a window, and a secret is what gets read
// during it. Shared by `code` and `setup reopen` so the two cannot drift into
// writing the same file two ways.
func writeClaim(conf, code string) error {
	if err := os.MkdirAll(conf, 0o750); err != nil {
		return err
	}
	tmp := filepath.Join(conf, ".setup.claim.tmp")
	if err := os.WriteFile(tmp, []byte(code+"\n"), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(conf, "setup.claim"))
}

// runCmd is systemctl and nothing else; it returns the output because a
// systemctl failure says why in its output and nowhere else.
func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// reopenSetup is the reopen itself, with systemctl passed in so the order can
// be proven without a machine to break.
//
// The code first, then the unclaim, then the listener — the inverse of the
// seal's order, and for the inverse reason. A failure partway leaves an
// instance that is unclaimed with nothing listening, which is inert and is
// fixed by running this again. The other order opens the door and then goes
// looking for a key.
func reopenSetup(conf string, systemctl func(string, ...string) (string, error)) (string, error) {
	// The seal is checked here and not only in cmdSetup, because minting first
	// and finding out afterwards leaves a live setup code on the disk of an
	// instance nobody was reopening. It is inert while the unit is disabled,
	// and it is still a secret lying somewhere nobody will look.
	if !release.Claimed(conf) {
		return "", fmt.Errorf("there is no seal at %s to remove", filepath.Join(conf, "claimed"))
	}
	code, err := mintCode()
	if err != nil {
		return "", err
	}
	if err := writeClaim(conf, code); err != nil {
		return "", err
	}
	if err := os.Remove(filepath.Join(conf, "claimed")); err != nil {
		return "", fmt.Errorf("the setup code was minted but the seal is still there, so the unit's\n"+
			"ConditionPathExists will refuse to start it: %w", err)
	}
	// enable --now, not start: the point of the seal was that it survived a
	// reboot, so its undoing has to as well.
	if out, err := systemctl("systemctl", "enable", "--now", setupUnit); err != nil {
		return "", fmt.Errorf("unclaimed, but %s did not come up: %v\n%s", setupUnit, err, out)
	}
	return code, nil
}
