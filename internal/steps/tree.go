package steps

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Reading configuration is this package's business; editing it is
// internal/instance's. The two are kept apart deliberately — a reconciler reads
// far more than it writes, and every read here is a read of somebody else's
// file that must not disturb it.
//
// The refusal to treat an unparseable file as an empty one is repeated from
// instance.Open rather than shared, because it is the rule that matters most
// and a rule stated once and imported is a rule that gets optimised away: a
// file that exists and cannot be read is not a file that is absent, and
// treating it as absent is how an installer writes over live configuration.

// readTree parses a JSON configuration file. The bytes come back too, because
// they are what a rollback puts back.
func readTree(path string) (map[string]any, []byte, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return map[string]any{}, b, nil
	}
	var tree map[string]any
	if err := json.Unmarshal(b, &tree); err != nil {
		return nil, b, fmt.Errorf("%s exists but is not readable as JSON (%w) — fix or move it aside deliberately", path, err)
	}
	return tree, b, nil
}

// at walks a dotted path. A missing path is nil, which is the same thing a
// present null is; nothing here distinguishes them and nothing needs to.
func at(tree map[string]any, path string) any {
	var cur any = tree
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[p]
		if !ok {
			return nil
		}
	}
	return cur
}

func atString(tree map[string]any, path string) string {
	s, _ := at(tree, path).(string)
	return s
}

// generic turns a Go value into the same shape json.Unmarshal would produce for
// it: maps, slices, strings, float64.
//
// This is not tidiness, it is what makes "run it twice and the second run
// changes nothing" true. instance.File compares what is on disk with what has
// been Set by marshalling both and comparing the text. A struct marshals its
// fields in declaration order; a map[string]any marshals its keys in sorted
// order. Setting a []catalogue.WarpgateApp therefore differs textually from the
// identical value read back off disk, every single time, and the apps step
// would rewrite three files and restart two services on every run while
// reporting that it had reconciled them.
func generic(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}

// quote renders a value the way a conflict has to show it: what is actually
// there, verbatim, rather than a paraphrase of it.
func quote(v any) string {
	switch t := v.(type) {
	case nil:
		return "(nothing)"
	case string:
		return `"` + t + `"`
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
}
