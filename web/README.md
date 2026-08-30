# The setup pages

What `holistic-setup` serves on the local network before an instance is claimed,
and the status page it serves afterwards. `docs/setup-api.md` is the contract
between this and the Go half; read that first.

## The dependency that is not published yet

`package.json` pins `@finessefx/ui` at `github:sxty9/FinesseFX#v0.2.0`, and
**that tag does not exist yet.** These pages are built around `Stepper`, and
`Stepper` postdates `v0.1.2` — the newest tag there is — so nothing here can be
installed from the published package until FinesseFX is tagged and pushed.

Until then, develop against the working copy:

```sh
pnpm install
pnpm add --save-dev --config.node-linker=hoisted ../../FinesseFX   # or:
npm install --no-save ../../FinesseFX
```

That path is deliberately not written into `package.json`. A machine path in a
manifest builds on exactly one machine, and finding that out is somebody else's
afternoon.

## Why the pages are shaped the way they are

Every constraint below comes from one fact: this is plain HTTP on a name any
machine on the network can claim.

- **No secret worth stealing is ever on these pages.** The administrator
  password is set through the shell that installed this — `corexctl admin
  create`, over stdin. A password typed here would be saved by the reader's
  password manager against an origin every Holistic instance in the world
  shares, and offered back to them on somebody else's machine.
- **`navigator.clipboard` does not exist here**, because only HTTPS and loopback
  are secure contexts. `copy.ts` uses the `execCommand` path and, when even that
  fails, leaves the text selected rather than reporting a failure.
- **`crypto.subtle` is absent and passkeys are impossible** — which is the
  strongest answer to the takeover question, and it is off the table. The setup
  code is what stands in its place.
- **The tab that starts the switch finishes it.** Nothing navigates to the new
  domain. The registrar's nameservers and Cloudflare's certificate run on
  somebody else's clock and can outlive a session.
- **No spinner and no percentage, anywhere.** A spinner is a promise about
  duration. Two of these steps are waiting on a third party and one of them can
  take days. The ledger says who is being waited on and when it was last looked
  at, which is a fact rather than a guess.

## The shape

    main.tsx      chooses between three screens by asking the server, never by
                  reading its own cookie
    Gate.tsx      the setup code, before a session exists
    App.tsx       the wizard: the ledger on the left, the step being worked on
                  the right
    Needs.tsx     renders what a step asks for, without knowing what the step
                  means — so a step it has never seen renders as well as one it
                  has
    Conflict.tsx  the six fields, fixed order, "Holistic has not changed
                  anything" on its own line
    Status.tsx    what this address serves after the seal. Not a login form: a
                  Secure cookie scoped to the domain would be neither sent nor
                  accepted here
    ledger.ts     the ledger's seven statuses onto the Stepper's six
                  observations, with the two places it is not one to one
    api.ts        the wire, hand-written against the contract rather than
                  generated from the Go — two implementations that both read the
                  document disagree loudly, where one generated from the other
                  agrees silently and both are wrong
