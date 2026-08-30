package steps

import (
	"path/filepath"
	"testing"
)

// Every program this package runs is named by absolute path.
//
// holistic-setup runs as a systemd unit, and a unit's PATH is not a login
// shell's: /opt/holistic/bin is not on it. A bare name therefore resolves on a
// developer's machine, in every test, and nowhere that matters. Corexctl was
// bare and WarpgateBin was not — the same kind of field in the same struct,
// and only one had been given a path. The admin step failed on the running
// machine with `exec: "corexctl": executable file not found in $PATH`.
func TestEveryProgramIsNamedByAbsolutePath(t *testing.T) {
	p := DefaultPaths()
	for name, got := range map[string]string{
		"WarpgateBin": p.WarpgateBin,
		"Corexctl":    p.Corexctl,
	} {
		if !filepath.IsAbs(got) {
			t.Errorf("%s = %q, which a systemd unit cannot resolve — its PATH does not carry /opt/holistic/bin", name, got)
		}
	}
}
