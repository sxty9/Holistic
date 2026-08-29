package steps

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sxty9/Holistic/internal/instance"
)

// edit is one configuration file being prepared. It wraps instance.File with
// the two things a multi-file write needs and a single-file write does not: the
// bytes that were there before, so a partial write can be put back, and whether
// the file existed at all, so putting it back means removing it.
type edit struct {
	path   string
	mode   os.FileMode
	file   *instance.File
	before []byte
	// tree is what was on disk, for the questions asked before anything is
	// written: is there already something here, and did we put it there.
	tree map[string]any
	// backups are the .before-<timestamp> copies that were beside this file
	// already. A rollback removes the ones that were not.
	backups map[string]bool
	// existed distinguishes "was empty" from "was not there". Restoring the
	// first writes an empty file; restoring the second must remove it, or a
	// rolled-back run leaves a file that a service will read.
	existed bool
}

func openEdit(path string, mode os.FileMode) (*edit, error) {
	tree, before, err := readTree(path)
	if err != nil {
		return nil, err
	}
	f, err := instance.Open(path)
	if err != nil {
		return nil, err
	}
	return &edit{
		path: path, mode: mode, file: f, before: before, tree: tree,
		existed: before != nil, backups: backupsBeside(path),
	}, nil
}

func backupsBeside(path string) map[string]bool {
	out := map[string]bool{}
	names, _ := filepath.Glob(path + ".before-*")
	for _, n := range names {
		out[n] = true
	}
	return out
}

// was is what the file held at the dotted path before this edit touched it.
func (ed *edit) was(path string) any { return at(ed.tree, path) }

// set records an intended value. Everything that is not a string, a number or a
// bool goes through generic first — see the comment on generic; without it
// nothing in here is idempotent.
func (ed *edit) set(path string, v any) {
	switch v.(type) {
	case string, bool, float64, int:
		ed.file.Set(path, v)
	default:
		ed.file.Set(path, generic(v))
	}
}

// changes lists what this file would gain or lose, with the file named. A diff
// across three files that does not say which file is a diff nobody can act on.
func (ed *edit) changes() []Change {
	var out []Change
	for _, c := range ed.file.Changes() {
		out = append(out, Change{Path: ed.path + "  " + c.Path, From: c.From, To: c.To})
	}
	return out
}

// restore puts the file back exactly as this edit found it — including removing
// the copy Save had just taken.
//
// That copy is worth a sentence. instance.File.Save writes a
// .before-<timestamp> beside the file BEFORE it writes, so a rollback that left
// it behind would leave a backup of a file that was never changed, in somebody's
// /etc, one per failed attempt. "Holistic has not changed anything" is either
// true of the directory or it is not a promise; the record that an attempt was
// made belongs in the ledger, which is where it goes.
func (ed *edit) restore() error {
	for _, n := range mustGlob(ed.path + ".before-*") {
		if !ed.backups[n] {
			_ = os.Remove(n)
		}
	}
	if !ed.existed {
		return os.Remove(ed.path)
	}
	tmp := ed.path + ".rollback"
	if err := os.WriteFile(tmp, ed.before, ed.mode); err != nil {
		return err
	}
	return os.Rename(tmp, ed.path)
}

func mustGlob(pattern string) []string {
	names, _ := filepath.Glob(pattern)
	return names
}

// applyAll writes a set of files as one unit, or leaves them all as it found
// them.
//
// Three files on a filesystem cannot be written in one transaction, so this
// does the two things that are available and that between them cover the
// failure worth covering. Every file is opened, parsed and set BEFORE the first
// byte is written, so a malformed file or a bad value stops the whole write
// before it starts — which is where nearly every failure actually lives. And if
// an I/O error does land partway through, the files already written are put
// back byte for byte, so the outcome is still all or none.
//
// A rollback also removes the .before-<timestamp> copy Save had just taken, so
// that the directory really is as it was — see restore. The record that a
// partial write happened goes in the ledger, which is the place a person can
// find it, rather than as litter in somebody's /etc.
func applyAll(edits []*edit) error {
	var done []*edit
	for _, ed := range edits {
		if err := ed.file.Save(ed.mode); err != nil {
			var back, stuck []string
			for _, d := range done {
				if rerr := d.restore(); rerr != nil {
					stuck = append(stuck, fmt.Sprintf("%s (%v)", d.path, rerr))
					continue
				}
				back = append(back, d.path)
			}
			msg := fmt.Sprintf("%s could not be written: %v", ed.path, err)
			if len(back) > 0 {
				msg += "\nPut back as found: " + strings.Join(back, ", ")
			}
			if len(stuck) > 0 {
				// The one case where the promise cannot be kept, said plainly
				// rather than folded into the error above.
				msg += "\nCOULD NOT be put back, and needs a person: " + strings.Join(stuck, ", ")
			}
			return fmt.Errorf("%s", msg)
		}
		done = append(done, ed)
	}
	return nil
}

// writeSecret puts a credential on disk and nowhere else.
//
// Created at its final mode rather than chmod-ed afterwards: between an open
// and a later chmod there is a window, and a secret is what gets read during
// it. The explicit Chmod after WriteFile is not that chmod — it is there
// because WriteFile's mode is masked by the process umask, and this file's
// permissions are a guarantee rather than a preference.
func writeSecret(path, value string, mode os.FileMode) error {
	if err := os.MkdirAll(dirOf(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".incoming"
	if err := os.WriteFile(tmp, []byte(value+"\n"), mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	// root:root, and only where that is meaningful. Under a test, or anywhere
	// this runs unprivileged, chown would fail and failing the write over it
	// would mean the ownership rule could only ever be exercised as root.
	if os.Geteuid() == 0 {
		if err := os.Chown(tmp, 0, 0); err != nil {
			return err
		}
	}
	return os.Rename(tmp, path)
}

func dirOf(path string) string {
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return "."
}
