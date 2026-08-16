package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/sxty9/Holistic/internal/lan"
	"github.com/sxty9/Holistic/internal/ledger"
)

// These pages are server-rendered and deliberately plain. The wizard proper is
// a separate front end built from the same component library as the Solisuite
// apps, so that setup and the thing it configures look like one product; what
// is here is the shell around it — the gate, and the page that remains once the
// gate is gone. Both have to work when no front end has been built yet, which
// is exactly the situation on a machine somebody just installed.
//
// No stylesheet is fetched and no script runs. The gate is the one page on this
// machine that takes a secret before anything has been established, and giving
// it zero moving parts costs nothing here.

const shell = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
  :root { color-scheme: light dark; --ink:#16181d; --dim:#5b6270; --line:#dfe3ea; --bg:#f6f7f9; --card:#fff; --warn:#8a4b00; --warnbg:#fff6e8; }
  @media (prefers-color-scheme: dark) {
    :root { --ink:#e8eaef; --dim:#9aa2b1; --line:#2a2f3a; --bg:#101216; --card:#171a20; --warn:#ffc98a; --warnbg:#2a1e0c; }
  }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center; padding:2rem 1rem;
         background:var(--bg); color:var(--ink);
         font:16px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  main { width:100%%; max-width:34rem; background:var(--card); border:1px solid var(--line);
         border-radius:14px; padding:2rem; }
  h1 { font-size:1.35rem; margin:0 0 .25rem; letter-spacing:-.01em; }
  p.lead { color:var(--dim); margin:0 0 1.5rem; }
  label { display:block; font-weight:600; margin-bottom:.4rem; font-size:.9rem; }
  input[type=text] { width:100%%; padding:.7rem .8rem; font:inherit; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
         letter-spacing:.06em; border:1px solid var(--line); border-radius:9px;
         background:var(--bg); color:var(--ink); }
  input[type=text]:focus { outline:2px solid #4b7bec; outline-offset:1px; }
  button { margin-top:1rem; width:100%%; padding:.7rem 1rem; font:inherit; font-weight:600;
           border:0; border-radius:9px; background:#2f6fed; color:#fff; cursor:pointer; }
  .note { margin-top:1.5rem; padding-top:1.25rem; border-top:1px solid var(--line);
          color:var(--dim); font-size:.88rem; }
  .bad { background:var(--warnbg); color:var(--warn); border:1px solid currentColor;
         border-radius:9px; padding:.7rem .8rem; margin-bottom:1.25rem; font-size:.92rem; }
  table { width:100%%; border-collapse:collapse; font-size:.92rem; }
  td { padding:.45rem 0; border-bottom:1px solid var(--line); vertical-align:top; }
  td.k { color:var(--dim); width:11rem; }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.9em; }
</style>
<main>%s</main>
`

func page(title, body string) string {
	return fmt.Sprintf(shell, template.HTMLEscapeString(title), body)
}

func pageGate(problem string) string {
	var b strings.Builder
	b.WriteString(`<h1>This machine is not claimed yet</h1>`)
	b.WriteString(`<p class="lead">The installer printed a setup code. Enter it to become this instance's administrator.</p>`)
	if problem != "" {
		fmt.Fprintf(&b, `<div class="bad">%s</div>`, template.HTMLEscapeString(problem))
	}
	b.WriteString(`<form method="post" action="/claim/">`)
	b.WriteString(`<label for="code">Setup code</label>`)
	b.WriteString(`<input id="code" name="code" type="text" autocomplete="off" autocapitalize="off" ` +
		`spellcheck="false" autofocus placeholder="xxxxx-xxxxx-xxxxx-xxxxx">`)
	b.WriteString(`<button type="submit">Claim this instance</button>`)
	b.WriteString(`</form>`)
	b.WriteString(`<p class="note">The code exists only in a root-owned file on this machine and in the
	   terminal where you ran the installer. Nobody on your network can read it. If you have lost it,
	   mint a new one on the machine rather than looking for it here.</p>`)
	return page("Claim this instance", b.String())
}

func pageClaimed(refused []string) string {
	var b strings.Builder
	b.WriteString(`<h1>Claimed</h1>`)
	b.WriteString(`<p class="lead">This browser is now the one setting this instance up.</p>`)

	// Shown on the first screen after a successful claim, and only there. If
	// somebody else on the network was trying codes, the owner should learn it
	// at the moment they can still do something about it.
	if n := len(refused); n > 0 {
		fmt.Fprintf(&b, `<div class="bad">%d wrong code(s) were offered before you claimed this instance, from: %s.
		  If that was not you, someone else on this network found it first and tried to take it.</div>`,
			n, template.HTMLEscapeString(strings.Join(unique(refused), ", ")))
	}

	b.WriteString(`<p class="note">The wizard itself is not built into this binary yet. What exists so far:
	   the claim, the ledger that records every step, and the guarantee that nothing in your DNS zone
	   or your cloud accounts is touched without being shown to you first.</p>`)
	return page("Claimed", b.String())
}

func pageStatus(led *ledger.Ledger) string {
	var b strings.Builder
	b.WriteString(`<h1>Holistic</h1>`)
	b.WriteString(`<p class="lead">This instance is set up. Sign in at your own domain.</p>`)

	b.WriteString(`<table>`)
	rows := led.Steps()
	if len(rows) == 0 {
		b.WriteString(`<tr><td colspan="2">No setup steps were recorded.</td></tr>`)
	}
	for _, s := range rows {
		fmt.Fprintf(&b, `<tr><td class="k"><code>%s</code></td><td>%s`,
			template.HTMLEscapeString(s.ID), template.HTMLEscapeString(string(s.Status)))
		if s.Detail != "" {
			fmt.Fprintf(&b, `<br><span style="color:var(--dim)">%s</span>`, template.HTMLEscapeString(s.Detail))
		}
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</table>`)

	if un := led.Unconfirmed(); len(un) > 0 {
		fmt.Fprintf(&b, `<div class="bad" style="margin-top:1.25rem">%d thing(s) were started at a provider
		  and never confirmed. They may or may not exist in your account, and only you can look:`, len(un))
		b.WriteString(`<ul>`)
		for _, r := range un {
			fmt.Fprintf(&b, `<li><code>%s</code> %s <code>%s</code></li>`,
				template.HTMLEscapeString(r.Provider), template.HTMLEscapeString(r.Kind),
				template.HTMLEscapeString(r.Ref))
		}
		b.WriteString(`</ul></div>`)
	}

	// Deliberately not a sign-in form. After the hand-off the instance's
	// session cookie is scoped to the real domain and marked Secure, so a form
	// served here over plain HTTP could never succeed. A login that cannot work
	// is worse than no login, because it is discovered in an emergency.
	fmt.Fprintf(&b, `<p class="note">%s is this machine's name on your own network. It is how you reach
	   this page when your domain, your tunnel or your provider account is unavailable — but signing in
	   happens on your domain, over HTTPS, because that is where your session belongs.</p>`,
		`<code>`+lan.SetupName+`</code>`)
	return page("Holistic", b.String())
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
