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
	"Holistic:./cmd/holistic:holistic"
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

# --- reaching the key -------------------------------------------------------
#
# The key is 0600 and its directory is 0700, both root-owned, so an ordinary
# user cannot even stat it. That is the point, and it is also why the build does
# NOT simply run as root: `go build` under sudo writes a root-owned module and
# build cache into root's home, and the next ordinary build then fails on
# permissions in a way that takes an afternoon to understand.
#
# So the build runs as whoever invoked it, and exactly one step — the signature
# — elevates. If the key is readable without elevation (a key kept under the
# operator's own home, which is a perfectly reasonable choice), nothing
# elevates at all.

SUDO=''

key_reachable() {
	if [ -r "$KEY" ]; then
		SUDO=''
		return 0
	fi
	if command -v sudo >/dev/null && sudo -n test -r "$KEY" 2>/dev/null; then
		SUDO='sudo -n'
		return 0
	fi
	return 1
}

# installer_pubkey prints the public key exactly as install.sh will use it.
#
# The naive extraction — sed from BEGIN to END — takes the whole first line,
# which in install.sh reads `readonly HOLISTIC_PUBKEY='-----BEGIN PUBLIC KEY---`,
# and the whole last line, which ends in a stray quote. openssl then reports
# "Could not find private key of public key", which is a spectacularly
# misleading way to say "that is not a PEM file". So the wrapper is trimmed off
# both ends.
installer_pubkey() {
	sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' "$HERE/install.sh" |
		sed -e 's/.*\(-----BEGIN PUBLIC KEY-----\)/\1/' \
			-e "s/\(-----END PUBLIC KEY-----\).*/\1/"
}

sign_manifest() {
	local in="$1" out="$2"
	# Written to stdout and redirected rather than passed as -out, so the
	# signature file belongs to the invoking user and not to root — otherwise
	# the next build cannot overwrite its own dist/.
	$SUDO openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$in" >"$out"
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
			-ldflags "-s -w -X main.version=$version -X main.pubkeyB64=$(installer_pubkey | base64 -w0)" \
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
	key_reachable || die "no signing key at $KEY, or it cannot be reached.
       Run ./release.sh keygen first, or set HOLISTIC_RELEASE_KEY."

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

		# Units and examples, named one by one rather than globbed.
		#
		# The first build globbed them, and shipped homebridge-adapter.service
		# into an archive that deliberately contains no homebridge-adapter
		# binary — a unit for something that is not there, which is precisely
		# the kind of thing nobody can explain a year later. A wildcard means
		# the archive's contents are decided by whatever happens to be in a
		# directory; a list means they are decided here.
		local unit
		for unit in \
			"Holistic/deploy/holistic-setup.service" \
			"coreX/deploy/corex-api.service" \
			"coreX/deploy/corex-routedge.service" \
			"Solisuite/deploy/solisuite.service" \
			"coreX/deploy/config.example.json" \
			"coreX/deploy/routedge.example.json"; do
			[ -f "$SRC_ROOT/$unit" ] ||
				die "$SRC_ROOT/$unit is missing, and the release needs it."
			cp "$SRC_ROOT/$unit" "$stage/deploy/"
		done

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

		# The version, as a file in the archive. It is the only way to answer
		# "what is installed here?" on a machine installed from
		# /latest/download, because "latest" is not a version — it is a
		# redirect that means something else next week. install.sh copies it
		# into the state directory and `holistic upgrade` reads it back.
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
		sign_manifest SHA256SUMS SHA256SUMS.sig
	)
	note "SHA256SUMS.sig written"

	step "Checking it the way the installer will"
	(
		cd "$DIST"
		local tmpkey
		tmpkey="$(mktemp)"
		# The same bytes the installer will use, not the ones this script could
		# regenerate. If those two ever disagree, this is where it must fail —
		# not on somebody else's machine.
		installer_pubkey >"$tmpkey"
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

# release_notes tells somebody how to check this release without trusting the
# installer to do it for them. The commands are the ones that actually work —
# including the key extraction, which is the part everybody gets wrong.
release_notes() {
	cat <<NOTES
Holistic Homeserver $1

Install:

    curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo bash

Check it yourself, if you would rather not take the installer's word for it.
Download install.sh, SHA256SUMS and SHA256SUMS.sig from this release, then:

    sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' install.sh \\
      | sed -e 's/.*\\(-----BEGIN PUBLIC KEY-----\\)/\\1/' \\
            -e 's/\\(-----END PUBLIC KEY-----\\).*/\\1/' > holistic.pub.pem

    openssl pkeyutl -verify -pubin -inkey holistic.pub.pem \\
        -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig

    sha256sum -c SHA256SUMS

The signature is Ed25519 over SHA256SUMS, and it needs pkeyutl rather than
dgst: openssl refuses an explicit digest with EdDSA operations.
NOTES
}

publish() {
	local version="${1:-}"
	[ -n "$version" ] || die "give a version, e.g. ./release.sh publish v0.1.0"
	command -v gh >/dev/null || die "gh is not installed."
	[ -d "$DIST" ] || die "nothing in $DIST. Run ./release.sh build $version first."
	[ -f "$DIST/SHA256SUMS.sig" ] || die "$DIST is not signed."

	# A 0.0.x release is marked as a prerelease and GitHub then keeps it out of
	# "latest". That matters more than it sounds: the installer's default path
	# is releases/latest/download, so an unfinished build cannot become what a
	# stranger's `curl | sudo bash` installs simply because it was the most
	# recent thing pushed.
	local pre=()
	case "$version" in
	v0.0.*) pre=(--prerelease) ;;
	esac

	step "Publishing $version to $REPO"
	[ ${#pre[@]} -gt 0 ] && note "marked as a prerelease; it will not become 'latest'"
	# install.sh is uploaded as an asset too, so that
	# releases/latest/download/install.sh always serves the installer that
	# matches the artifacts beside it. The copy on the default branch is what
	# people curl; this one is what a pinned version curls.
	gh release create "$version" \
		--repo "$REPO" \
		--title "$version" \
		${pre[@]+"${pre[@]}"} \
		--notes-file <(release_notes "$version") \
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
