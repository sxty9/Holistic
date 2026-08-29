# The setup API

What `holistic-setup` serves and what its pages consume. Written before either
half was built, because the two are built by different hands and a contract
agreed afterwards is a contract that describes whichever half was finished
first.

Everything below is behind a session. The session is issued once, by redeeming
the setup code (`POST /claim`), and the code is destroyed the moment it is spent.

## The shape of the thing

The wizard is **a reconciler, not a form**. Every step reads what is actually
there, shows it against what it wants, and applies only the difference. That is
what makes the same code the later diagnosis and the later domain change — and
it is why the ledger, not the page, is the source of truth. A tab closed and
reopened lands in the same place because the state was never in the tab.

## The ledger is the state

`internal/ledger` already defines it. Seven statuses, and the distinction that
matters most is between `running` and `waiting_on_them`: "we are working" and
"a registrar is working" feel identical in a spinner and are completely
different facts.

## Mapping the ledger onto the Stepper

The pages render the ledger with FinesseFX's `Stepper`, whose `Observation` is a
discriminated union. The mapping is total and lossless except where noted:

| ledger `Status`   | `Observation.state` | carries |
|---|---|---|
| `pending`         | `ahead`             | `desired` — what it will do |
| `running`         | `waiting`           | `waitingOn: "this machine"`, `since` |
| `waiting_on_them` | `waiting`           | `waitingOn` — **named**, `since`, `lastLooked` |
| `passed`          | `passed`            | `at`, `actual` — the proof, verbatim |
| `failed`          | `failed`            | `at`, `output` — the machine's own words |
| `conflict`        | `held`              | `found`, `desired`, `resolution` |
| `skipped`         | `yours`             | `action` — a control to run it now |

`running` becomes a `waiting` whose clock is named as this machine rather than
inventing a state: the Stepper's rule is that an unattributed wait reads as this
being slow, and "we are working" is a wait like any other. `skipped` becomes
`yours` because a skipped step is not blocked — it is not done, and you own
whether it happens.

The Stepper has no spinner and no percentage, deliberately. A spinner is a
promise about duration, and two of these steps run on a registrar's clock.

## Steps

Ordered. `kind` says who has to act, and it is what decides whether a step can
run unattended.

| id | kind | what it does |
|---|---|---|
| `domain` | `local` | the domain as a string. Nothing is contacted. |
| `display-name` | `local` | what the instance calls itself |
| `storage` | `local` | where data lives |
| `engines` | `local` | which AI engines are configured |
| `admin` | `shell` | verifies an administrator exists. Creating one is `corexctl admin create`, on the machine, over stdin — never in a page served over plain HTTP on a LAN name. |
| `apps` | `local` | which apps are on. **One answer, three outputs.** |
| `token-verify` | `foreign` | verify the Cloudflare token **before it lands anywhere** |
| `zone-resolve` | `foreign` | resolve the zone; require `status == active`; keep the account id |
| `token-store` | `local` | write it to Warpgate's own path, `0600 root:root` |
| `zone-inventory` | `foreign` | read the zone before changing it; the export goes in the ledger |
| `tunnel-ensure` | `foreign` | the first irreversible creation at a provider |
| `warpgate-config` | `local` | write config.json; pin `configPath` and `reloadUnit` |
| `plan-show` | `local` | render the plan. The last free stop. |
| `dns-apply` | `foreign` | apply it |
| `ingress-write` | `local` | write the ingress, start **and enable** the connector |
| `connector-registered` | `theirs` | wait for `Registered tunnel connection` — not for "unit active" |
| `solisuite-write` | `local` | write and restart |
| `corex-write` | `local` | write and restart; `insecureCookies` → `false` |
| `cert-wait` | `theirs` | Cloudflare's universal certificate, on their clock |
| `nonce-probe` | `theirs` | per hostname, from the public internet; then `appOrigins` for that host |
| `corex-restart-2` | `local` | restart again; check the apex while logged out |

`nameservers` sits between `zone-resolve` and the rest when the zone is
`pending`: the registrar has no API, so it is `theirs` and it is where the
wizard stops and waits rather than pretending.

**Every step ends in a real observation.** An API returning 200 is a fast
pre-check that buys a better error message. It is never the proof. That is the
lesson of the week inbound mail was destroyed: every component reported success.

## Routes

    GET  /api/state                    the whole thing
    POST /api/step/{id}/run            run one step
    POST /api/step/{id}/skip           mark it skipped, with a reason
    POST /api/answer/{id}              give a step what it asked for

### `GET /api/state`

```json
{
  "readAt": "2026-08-30T00:41:12Z",
  "sealed": false,
  "domain": "",
  "steps": [
    {
      "id": "domain",
      "title": "The domain this instance answers on",
      "kind": "local",
      "status": "pending",
      "detail": "",
      "proof": "",
      "at": "",
      "needs": { … },
      "desired": "…"
    }
  ],
  "resources": [
    { "provider": "cloudflare", "kind": "tunnel", "ref": "…",
      "intended": "…", "confirmed": "" }
  ],
  "refused": 0
}
```

`refused` is the count of wrong setup codes offered before this one worked, with
their source addresses shown on the first screen. Someone who has been probed
should know it.

`resources` is what exists at a provider because of this machine. An entry that
stays unconfirmed is the one worth a person's attention — it is how an
interrupted apply is found rather than forgotten.

### `needs` — what a step is asking for

A step that cannot run until it is told something carries a `needs`. The page
renders it; it does not know what any particular step means.

```json
{ "kind": "text",    "label": "Domain",  "placeholder": "example.org", "value": "" }
{ "kind": "choice",  "label": "…", "options": [ { "value": "…", "label": "…" } ], "value": "" }
{ "kind": "apps",    "label": "…", "options": [ { "id": "mail", "label": "Mail", "on": true } ] }
{ "kind": "secret",  "label": "Cloudflare API token", "help": "…", "link": "https://…" }
{ "kind": "confirm", "label": "…", "changes": [ { "path": "…", "from": "…", "to": "…" } ] }
{ "kind": "manual",  "label": "…", "instructions": "…", "recheck": true }
```

`secret` is submitted and never returned. `GET /api/state` must never echo one
back, not even masked: a masked secret in a JSON response is still a secret in a
browser's memory, in a proxy log, and in whatever the page later serialises.

`manual` is the shape for everything a third party will not automate — the
registrar's nameservers, the CloudFormation upload. `recheck: true` means the
page offers "check again" and nothing else. There is never a "continue anyway".

### `POST /api/answer/{id}`

Body is `{"value": …}` shaped by the step's `needs`. The response is the same
envelope as `GET /api/state`, so a page never has to merge two representations
of the same thing.

### Conflicts

A step that finds something it did not create returns `status: "conflict"` and a
`held` row. The six fields are fixed and they are always in this order — object,
what is theirs, what was wanted, why it collides, that nothing was changed, and
what to do:

```json
{
  "status": "conflict",
  "conflict": {
    "object":   "TXT  example.org",
    "found":    "\"google-site-verification=…\"",
    "foundNote":"TTL 300, no comment — not created by Holistic",
    "desired":  "\"v=spf1 include:amazonses.com ~all\"",
    "why":      "A domain may carry only one SPF record. A second makes every
                 receiver treat SPF as permerror — worse than none.",
    "resolution": "…",
    "consequence": "outgoing mail fails SPF. Nothing else depends on it."
  }
}
```

**"Holistic has not changed anything" is on its own line in every conflict.**
That is the product promise, and a promise stated in a paragraph is a promise
nobody read.

There is never a way past a conflict from inside the page. `[Check again]`,
`[Skip this step]`, `[Copy the instructions]` — and nothing else. The point is
not to get past the obstacle; it is to leave the operator's own things alone.

## What the pages must not do

- **Never navigate to the new domain.** The tab that starts the switch finishes
  it. The two slowest links — the registrar's nameservers and Cloudflare's
  certificate — run on someone else's clock and can outlive a session.
- **Never a spinner or a percentage.** See above.
- **Never store a secret**, in `localStorage` or anywhere else. This page is
  served over plain HTTP on a name anyone on the network can claim.
- **Never assume the LAN phase needs the tunnel.** If the probes do not come
  back, `publicBaseUrl`, `cookieDomain` and `appOrigins` are not written,
  `insecureCookies` stays `true`, and the page says in words: your instance is
  running on this network, it is just not on the internet yet. A wizard that
  only knows how to finish leaves people stranded.

## Why the pages are plain HTTP, and what follows

`http://holistic.local` is not a secure context — only HTTPS and loopback are.
So `crypto.subtle` is absent, **passkeys are impossible**, `navigator.clipboard`
is undefined and `Secure` cookies do not apply.

The consequences are design constraints, not annoyances:

- A copy button needs the `execCommand` fallback, or the text is selectable and
  there is no button.
- **No secret worth stealing is ever on this page.** The administrator password
  is set through the shell the operator already has open. A password typed here
  would be saved by their manager against an origin every Holistic instance in
  the world shares, and offered back on somebody else's machine.

## After the seal

The same transaction that writes `claimed` stops and disables the unit and
**destroys** the setup code — not marks it used. The LAN listener is gone before
the tunnel goes live; never both doors open at once.

`holistic.local` keeps resolving afterwards, and serves a status page: which
services answer, the version, the time, and the sentence that signing in happens
on the domain. Not a login form — a `Secure` cookie scoped to the domain would
neither be sent nor accepted here, so a form on this page could not work, and a
form that cannot work is worse than a sentence that explains.
