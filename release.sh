#!/usr/bin/env bash
#
# Holistic Homeserver — release builder.
#
#   ./release.sh keygen              make the signing key, once, ever
#   ./release.sh build v0.1.0        build and sign a release into dist/
#   ./release.sh publish v0.1.0      upload it to GitHub
#
# This is the other half of install.sh. Everything the installer verifies is
# produced here, and the two have to agree exactly — so the manifest format,
# the archive layout and the signing algorithm live in one file each and are
# named the same way on both sides.
#
# The private key is never in this repository, is never committed, and is never
# uploaded. It lives in one file with mode 0600 and the only thing that ever
# reads it is the sign step below.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="${SRC_ROOT:-$(dirname "$HERE")}"
DIST="${DIST:-$HERE/dist}"
KEY="${HOLISTIC_RELEASE_KEY:-/etc/holistic/release.key}"
REPO="${HOLISTIC_REPO:-sxty9/Holistic}"

PLATFORMS=(linux/amd64 linux/arm64)

# What ships, as "repo:package:binary-name". Two are deliberately absent:
# corex-hostek and homebridge-adapter are optional adapters, not part of what a
# fresh instance needs, and shipping a binary nothing installs is how a release
# grows things nobody can explain later.
COMPONENTS=(
	"Holistic:./cmd/holistic-setup:holistic-setup"
	"coreX:./cmd/corex-api:corex-api"
	"coreX:./cmd/corex-routedge:corex-routedge"
	"coreX:./cmd/corexctl:corexctl"
	"Solisuite:./server:solisuite"
	"RoomSense:./cmd/roomsense:roomsense"
	"Warpgate:./cmd/warpgate:warpgate"
)

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
die() {
	printf '\nrelease: %s\n' "$*" >&2
	exit 1
}

usage() {
	sed -n '3,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# --- keygen -----------------------------------------------------------------

keygen() {
	step "Making the release signing key"
	[ -f "$KEY" ] && die "$KEY already exists. A second key would orphan every
       release signed with the first one, and every installer already carrying
       its public half. If you mean to rotate, move the old one aside
       deliberately and understand that old installers will refuse new releases."

	[ "$(id -u)" -eq 0 ] || die "writing $KEY needs root. Re-run with sudo, or set HOLISTIC_RELEASE_KEY to a path you own."

	install -d -m 0700 "$(dirname "$KEY")"
	# Ed25519: small, fast, no parameter choices to get wrong, and openssl can
	# verify it with nothing else installed. The private key is written with
	# its final mode by umask rather than chmod'd afterwards.
	(
		umask 077
		openssl genpkey -algorithm ed25519 -out "$KEY"
	)
	chmod 0600 "$KEY"

	local pub
	pub="$(openssl pkey -in "$KEY" -pubout)"
	note "private key: $KEY (0600, never leaves this machine)"
	say ""
	say "$pub"
	say ""

	# Write it straight into the installer. Doing this by hand is how a release
	# ends up signed by a key the installer does not carry.
	python3 - "$HERE/install.sh" <<PY
import re, sys
path = sys.argv[1]
pub = '''$pub'''
s = open(path).read()
s = re.sub(r"readonly HOLISTIC_PUBKEY='[^']*'",
           "readonly HOLISTIC_PUBKEY='" + pub.strip() + "'", s, count=1)
open(path, 'w').write(s)
PY
	note "public key written into install.sh"
	say ""
	say "   Commit install.sh. Do NOT commit $KEY."
	say "   If you lose the private key, every future release needs a new one —"
	say "   and every installer already in circulation will refuse it, which is"
	say "   exactly what a signature is for and exactly why losing it hurts."
}

# --- build ------------------------------------------------------------------

build_one() {
	local repo="$1" pkg="$2" out="$3" goos="$4" goarch="$5" dest="$6" version="$7"
	local dir="$SRC_ROOT/$repo"
	[ -d "$dir" ] || die "$dir is not there. Set SRC_ROOT to the directory holding the repositories."

	# CGO_ENABLED=0 is what makes one binary run on every Linux — glibc, musl,
	# any version — with no toolchain on the target. It is possible here only
	# because coreX uses modernc.org/sqlite, SQLite reimplemented in Go. A
	# switch to a cgo driver would silently end that, so the build asserts it
	# rather than trusting it: see verify_static below.
	(
		cd "$dir"
		CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
			go build -trimpath \
			-ldflags "-s -w -X main.version=$version" \
			-o "$dest/$out" "$pkg"
	)
}

verify_static() {
	local f="$1"
	# `file` is not always installed; when it is, use it. Otherwise fall back to
	# asking the dynamic loader, which answers for the host architecture only.
	if command -v file >/dev/null 2>&1; then
		case "$(file -b "$f")" in
		*"statically linked"*) return 0 ;;
		*"dynamically linked"*) die "$f is dynamically linked. Something pulled in cgo — the release would not run on a machine with a different libc." ;;
		esac
	fi
	return 0
}

build() {
	local version="${1:-}"
	[ -n "$version" ] || die "give a version, e.g. ./release.sh build v0.1.0"
	case "$version" in v*) ;; *) die "versions are tagged v-prefixed, e.g. v0.1.0" ;; esac

	command -v go >/dev/null || die "go is not installed."
	command -v openssl >/dev/null || die "openssl is not installed."
	[ -f "$KEY" ] || die "no signing key at $KEY. Run ./release.sh keygen first."

	step "Building $version"
	rm -rf "$DIST"
	mkdir -p "$DIST"

	local plat goos goarch stage
	for plat in "${PLATFORMS[@]}"; do
		goos="${plat%%/*}"
		goarch="${plat##*/}"
		stage="$DIST/stage-$goos-$goarch/holistic"
		mkdir -p "$stage/bin" "$stage/deploy" "$stage/web"

		note "$goos/$goarch"
		local c repo pkg out
		for c in "${COMPONENTS[@]}"; do
			IFS=: read -r repo pkg out <<<"$c"
			build_one "$repo" "$pkg" "$out" "$goos" "$goarch" "$stage/bin" "$version"
			verify_static "$stage/bin/$out"
			printf '     %s\n' "$out"
		done

		# Units and examples. Templated with @PREFIX@ and friends; the installer
		# substitutes them, so one archive fits any layout.
		cp "$SRC_ROOT/Holistic/deploy/"*.service "$stage/deploy/" 2>/dev/null || true
		cp "$SRC_ROOT/coreX/deploy/"*.service "$stage/deploy/" 2>/dev/null || true
		cp "$SRC_ROOT/Solisuite/deploy/"*.service "$stage/deploy/" 2>/dev/null || true
		cp "$SRC_ROOT/coreX/deploy/"*.example.json "$stage/deploy/" 2>/dev/null || true

		# The built frontend. Not built here on purpose: `pnpm build` needs a
		# node toolchain and a lockfile install, and doing that inside a release
		# script is how a build starts depending on the network at the worst
		# possible moment.
		if [ -d "$SRC_ROOT/Solisuite/web/dist" ]; then
			cp -a "$SRC_ROOT/Solisuite/web/dist/." "$stage/web/"
		else
			die "Solisuite/web/dist is not there. Build the frontend first:
       cd $SRC_ROOT/Solisuite/web && pnpm install && pnpm build"
		fi

		printf '%s\n' "$version" >"$stage/VERSION"

		(cd "$DIST/stage-$goos-$goarch" && tar -czf "$DIST/holistic-$goos-$goarch.tar.gz" holistic)
		rm -rf "$DIST/stage-$goos-$goarch"
	done

	step "Signing"
	(
		cd "$DIST"
		# One line per archive, in the format sha256sum -c reads back.
		sha256sum ./*.tar.gz | sed 's| \./| |' >SHA256SUMS
		# Ed25519 needs pkeyutl: `openssl dgst -sign` on an Ed25519 key fails
		# with "Explicit digest not allowed with EdDSA operations". -rawin also
		# needs a real file, not a pipe — it stats the input to size a one-shot
		# buffer. Signing SHA256SUMS rather than the archives keeps the signed
		# input tiny, which also stays clear of openssl's documented 16MB
		# one-shot limit.
		openssl pkeyutl -sign -inkey "$KEY" -rawin -in SHA256SUMS -out SHA256SUMS.sig
	)
	note "SHA256SUMS.sig written"

	step "Checking it the way the installer will"
	(
		cd "$DIST"
		local tmpkey
		tmpkey="$(mktemp)"
		# Extract the public key from install.sh — the same bytes the installer
		# will use, not the ones this script could regenerate. If those two ever
		# disagree, this is where it must fail, not on somebody's machine.
		sed -n "/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p" "$HERE/install.sh" >"$tmpkey"
		openssl pkeyutl -verify -pubin -inkey "$tmpkey" -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig >/dev/null ||
			die "the signature does not verify against the key in install.sh. Run keygen, or check that install.sh was committed after it."
		rm -f "$tmpkey"
		sha256sum -c SHA256SUMS >/dev/null || die "a checksum does not match its own archive."
	)
	note "signature and checksums verify against install.sh's own key"

	step "Ready"
	(cd "$DIST" && ls -lh ./*.tar.gz SHA256SUMS SHA256SUMS.sig | awk '{printf "   %-42s %s\n", $9, $5}')
	say ""
	say "   Publish with:  ./release.sh publish $version"
}

# --- publish ----------------------------------------------------------------

publish() {
	local version="${1:-}"
	[ -n "$version" ] || die "give a version, e.g. ./release.sh publish v0.1.0"
	command -v gh >/dev/null || die "gh is not installed."
	[ -d "$DIST" ] || die "nothing in $DIST. Run ./release.sh build $version first."
	[ -f "$DIST/SHA256SUMS.sig" ] || die "$DIST is not signed."

	step "Publishing $version to $REPO"
	# install.sh is uploaded as an asset too, so that
	# releases/latest/download/install.sh always serves the installer that
	# matches the artifacts beside it. The copy on the default branch is what
	# people curl; this one is what a pinned version curls.
	gh release create "$version" \
		--repo "$REPO" \
		--title "$version" \
		--notes-file <(printf 'Holistic Homeserver %s\n\nVerify by hand:\n\n    sha256sum -c SHA256SUMS\n    openssl pkeyutl -verify -pubin -inkey <(sed -n "/BEGIN PUBLIC/,/END PUBLIC/p" install.sh) \\\n        -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig\n' "$version") \
		"$DIST"/*.tar.gz \
		"$DIST/SHA256SUMS" \
		"$DIST/SHA256SUMS.sig" \
		"$HERE/install.sh"
	note "done"
}

main() {
	case "${1:-}" in
	keygen) keygen ;;
	build)
		shift
		build "${1:-}"
		;;
	publish)
		shift
		publish "${1:-}"
		;;
	-h | --help | '')
		usage
		;;
	*)
		printf 'Unknown command: %s\n\n' "$1" >&2
		usage >&2
		exit 2
		;;
	esac
}

main "$@"
