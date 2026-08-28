package release

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Installed is what this machine believes it is running. Written by the
// installer and by every upgrade, read by every upgrade.
//
// The installer did not write this at first, which meant `upgrade` had nothing
// to compare against and could only ever reinstall. A version you cannot read
// back is not a version.
type Installed struct {
	Version     string    `json:"version"`
	Platform    string    `json:"platform"`
	Archive     string    `json:"archive"`
	SHA256      string    `json:"sha256"`
	InstalledAt time.Time `json:"installedAt"`
	// Binaries is what was laid down, so an upgrade knows what it may replace
	// and — more to the point — what it may not. A binary this machine did not
	// install is not ours to overwrite.
	Binaries []string `json:"binaries"`
}

const stateFile = "installed.json"

func ReadInstalled(stateDir string) (*Installed, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, stateFile))
	if err != nil {
		return nil, err
	}
	var in Installed
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("%s is not readable as a version record: %w", stateFile, err)
	}
	return &in, nil
}

func WriteInstalled(stateDir string, in *Installed) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	// Written to a sibling and renamed, so a crash mid-write leaves the previous
	// record intact rather than a truncated one. A half-written version record
	// reads as "no version", which would make the next upgrade reinstall
	// silently.
	tmp := filepath.Join(stateDir, "."+stateFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(stateDir, stateFile))
}

// Swap replaces the binaries in binDir with the ones in the unpacked release,
// keeping the displaced ones so a failure can be undone.
//
// It returns the names it replaced, and a function that puts the old ones back.
// Nothing here restarts anything: swapping files and restarting services are
// separate failures with separate recoveries, and running them as one step is
// how you end up with new binaries and dead units.
func Swap(rel *Release, binDir string) (replaced []string, undo func() error, err error) {
	srcDir := filepath.Join(rel.Dir, "holistic", "bin")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, nil, err
	}

	backupDir, err := os.MkdirTemp(filepath.Dir(binDir), ".holistic-previous-")
	if err != nil {
		return nil, nil, err
	}

	undo = func() error {
		var firstErr error
		for _, name := range replaced {
			from := filepath.Join(backupDir, name)
			if _, statErr := os.Stat(from); statErr != nil {
				continue // it was new; there is nothing to put back
			}
			if e := os.Rename(from, filepath.Join(binDir, name)); e != nil && firstErr == nil {
				firstErr = e
			}
		}
		return firstErr
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		dst := filepath.Join(binDir, name)

		// Keep the outgoing one. Rename rather than copy: on Linux a running
		// process holds its inode open, so renaming the file out from under it
		// is safe and instant, and the process keeps running the old code until
		// it is restarted — which is exactly the window we want.
		if _, statErr := os.Stat(dst); statErr == nil {
			if e := os.Rename(dst, filepath.Join(backupDir, name)); e != nil {
				_ = undo()
				return replaced, undo, fmt.Errorf("could not set aside the current %s: %w", name, e)
			}
		}

		if e := copyExecutable(filepath.Join(srcDir, name), dst); e != nil {
			_ = undo()
			return replaced, undo, fmt.Errorf("could not install %s: %w", name, e)
		}
		replaced = append(replaced, name)
	}

	sort.Strings(replaced)
	return replaced, undo, nil
}

func copyExecutable(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// Into a sibling then renamed, so a reader never sees a partial binary.
	tmp := dst + ".incoming"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// RestartUnits restarts the units that are currently active, and only those.
//
// A unit that is stopped is stopped on purpose. Starting it because an upgrade
// happened to run would turn `upgrade` into a thing that changes what is
// running on the machine, and the one unit where that would matter most is the
// setup listener: it disables itself when the instance is claimed, and bringing
// it back would reopen a root-privileged HTTP server on the local network.
func RestartUnits(units []string) ([]string, error) {
	var restarted []string
	for _, u := range units {
		if !unitIsActive(u) {
			continue
		}
		out, err := exec.Command("systemctl", "restart", u).CombinedOutput()
		if err != nil {
			return restarted, fmt.Errorf("%s did not come back: %v\n%s", u, err, strings.TrimSpace(string(out)))
		}
		restarted = append(restarted, u)
	}
	return restarted, nil
}

func unitIsActive(unit string) bool {
	// `is-active` exits non-zero for anything that is not active, which is the
	// question being asked, so the exit code is the answer.
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

// Claimed reports whether this instance has been set up. An upgrade must never
// change this: the same transaction that writes it destroys the setup code and
// disables the listener, and undoing any of that reopens the takeover window
// that the claim closed.
func Claimed(confDir string) bool {
	_, err := os.Stat(filepath.Join(confDir, "claimed"))
	return err == nil
}
