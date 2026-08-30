package steps

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The two halves of the setup API are written by different hands against
// docs/setup-api.md — the Go here, the pages in web/src. That is deliberate: two
// implementations that both read the document disagree loudly, where one
// generated from the other agrees silently and both are wrong together.
//
// This is where they disagree loudly. It reads the TypeScript as text and
// compares field names and optionality against the Go struct tags.
//
// It was written after the first comparison found three real mismatches that
// nothing else would have caught until a browser did:
//
//   - the page read `since` on a step; the wire never had it. It fell back to
//     "now", so every wait would have reported having just begun, forever —
//     the six-hour lie about a nameserver change, told in a timestamp.
//   - the page rendered `refusedFrom`; the wire carried only the count. The
//     addresses would have been silently absent from the one screen that is
//     meant to tell somebody they have been probed.
//   - `unchanged` — the "Holistic has not changed anything" promise — was a
//     string hardcoded in a component on one side and a required field on the
//     other.
//
// What it cannot check: that the two agree about what a field MEANS. `at` on a
// waiting row means when the waiting began, and nothing here would notice if
// one side started reading it as when the row was last polled.

var (
	tsField = regexp.MustCompile(`(?m)^\s{2}([A-Za-z_$][\w$]*)(\?)?\s*:`)
	tsCmt   = regexp.MustCompile(`(?s)/\*.*?\*/`)
	tsLine  = regexp.MustCompile(`(?m)//.*$`)
	goTag   = regexp.MustCompile("`json:\"([^\"]+)\"`")
)

// tsFields returns field name -> is it optional.
//
// It splits on the declaration rather than matching each one with a regex. The
// regex version was wrong in a way worth keeping a note about: with a
// non-greedy body and a closing brace matched anywhere, a SINGLE-LINE interface
// — `export interface Option { value: string }` — swallowed everything up to the
// next brace on its own line, which was three declarations later. Conflict
// simply did not exist as far as the check could see, and the check said so
// rather than passing, which is the only reason it was caught in a minute.
func tsFields(src, name string) map[string]bool {
	const marker = "export interface "
	for _, chunk := range strings.Split(src, marker)[1:] {
		head, body, ok := strings.Cut(chunk, "{")
		if !ok || strings.TrimSpace(head) != name {
			continue
		}
		// The declaration ends at the first closing brace that starts a line,
		// or — for a one-liner — at the first closing brace at all.
		if i := strings.Index(body, "\n}"); i >= 0 {
			body = body[:i]
		} else if i := strings.Index(body, "}"); i >= 0 {
			body = body[:i]
		}
		body = tsLine.ReplaceAllString(tsCmt.ReplaceAllString(body, ""), "")
		out := map[string]bool{}
		for _, f := range tsField.FindAllStringSubmatch(body, -1) {
			out[f[1]] = f[2] == "?"
		}
		return out
	}
	return nil
}

func goFields(src, name string) map[string]bool {
	re := regexp.MustCompile(`(?s)type ` + name + ` struct \{(.*?)\n\}`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		return nil
	}
	out := map[string]bool{}
	for _, t := range goTag.FindAllStringSubmatch(m[1], -1) {
		parts := strings.Split(t[1], ",")
		if parts[0] == "-" {
			continue
		}
		out[parts[0]] = len(parts) > 1 && strings.Contains(t[1], "omitempty")
	}
	return out
}

func TestTheWireAndThePagesAgree(t *testing.T) {
	goSrc, err := os.ReadFile("steps.go")
	if err != nil {
		t.Fatal(err)
	}
	tsPath := filepath.Join("..", "..", "web", "src", "api.ts")
	tsSrc, err := os.ReadFile(tsPath)
	if err != nil {
		// Not skipped. The pages are part of this repository; if they are gone
		// that is the finding, not a reason to pass.
		t.Fatalf("the pages' copy of the wire is missing at %s: %v", tsPath, err)
	}

	for _, pair := range []struct{ goName, tsName string }{
		{"Envelope", "State"},
		{"Row", "Step"},
		{"Conflict", "Conflict"},
		{"Resource", "Resource"},
	} {
		g := goFields(string(goSrc), pair.goName)
		s := tsFields(string(tsSrc), pair.tsName)
		if g == nil {
			t.Errorf("no Go struct %s", pair.goName)
			continue
		}
		if s == nil {
			t.Errorf("no TypeScript interface %s", pair.tsName)
			continue
		}
		for _, k := range sorted(g) {
			if _, ok := s[k]; !ok {
				t.Errorf("%s.%s is on the wire and the pages do not know about it",
					pair.goName, k)
			}
		}
		for _, k := range sorted(s) {
			if _, ok := g[k]; !ok {
				t.Errorf("%s.%s is read by the pages and nothing sends it",
					pair.tsName, k)
			}
		}
		// A Go field without omitempty is always present, so the page may still
		// mark it optional — that is weaker than reality, not wrong. The other
		// direction is a real defect: the page requiring something the wire may
		// omit.
		for _, k := range sorted(g) {
			if opt, ok := s[k]; ok && g[k] && !opt {
				t.Errorf("%s.%s may be omitted, and the pages require it",
					pair.goName, k)
			}
		}
	}
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
