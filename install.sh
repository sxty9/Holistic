#!/usr/bin/env bash
#
# Holistic Homeserver — installer.
#
#   curl -fsSL https://raw.githubusercontent.com/sxty9/Holistic/main/install.sh | sudo bash
#
# One command. What it leaves behind is a machine waiting to be configured from a
# browser on your own network, and a code that proves you are the person who
# installed it.
#
# ---------------------------------------------------------------------------
# Why every line of this file sits inside a function
#
# A pipe is not seekable, so bash cannot read this whole file, parse it, and then
# run it. It reads a line, runs it, reads the next. `curl | bash` is streaming
# execution: everything that arrived before a dropped connection has ALREADY run
# as root, and there is no download-then-run step that could fail atomically.
#
# The danger is not that a truncated command breaks. It is that it does not.
#
#     rm -rf /opt/holistic/staging-tmp     <- what the line says
#     rm -rf /opt/holistic/                <- what runs if the transfer dies here
#
# Both are syntactically perfect. Bash sees EOF, treats the partial word as a
# complete argument, and runs it. Truncation does not corrupt a command; it
# silently rebinds its argument.
#
# A function definition is a single compound command. Bash cannot execute any
# part of it before reading the matching brace, and defining a function does
# nothing on its own. So the file below contains DEFINITIONS ONLY, and one call
# on the last line. Cut this file anywhere and bash reports an unexpected
# end-of-file and does nothing at all. The whole installer collapses to one
# atomic decision made at the very end.
#
# Nothing may follow the call on the last line — not a heredoc, not a cleanup
# line. And that call carries a marker: cutting the last line leaves a bare
# `main`, which is still a valid command and would run with no arguments, so a
# truncation in the final six bytes could silently turn a --dry-run into a real
# install. Only the complete line carries the marker.
#
# ---------------------------------------------------------------------------
# The second consequence of the pipe: stdin is this script
#
# Under `curl | bash`, file descriptor 0 is the script text. Anything that reads
# stdin eats the installer's own remaining lines — silently, with no error:
#
#     read -r answer      <- consumes the NEXT LINE OF THIS FILE as the answer
#
# So questions are asked on /dev/tty, which the kernel resolves to the
# controlling terminal regardless of what fd 0 is, and every external command
# that could conceivably prompt gets </dev/null.
#
# ---------------------------------------------------------------------------
# What it will not do, on purpose
#
#   * It never installs a package without asking, and never more than one.
#   * It never puts the setup code anywhere but a root-owned file and your
#     terminal. Not in the journal — journal-readable is not root-only.
#   * It never claims the instance for you. Claiming happens in your browser.
#   * It refuses to unpack anything whose checksum does not match a signed
#     manifest, and says so rather than continuing.

set -euo pipefail

# --- what this installer trusts --------------------------------------------
#
# The public half of the key that signs each release's SHA256SUMS. The private
# half is not in this repository and never will be.
#
# Be honest about what this buys. On a first install the trust decision is made
# by TLS and by choosing to pipe an unread script into root — not by this key.
# The signature's job starts one instant later: it means the tarballs can live
# anywhere, on any mirror or CDN, and whoever hosts them cannot alter them. An
# attacker who takes the release bucket is stopped; an attacker who can rewrite
# THIS FILE is not, because they would replace the key below in the same edit.
readonly HOLISTIC_PUBKEY='-----BEGIN PUBLIC KEY-----
REPLACE_ME_WITH_THE_RELEASE_PUBLIC_KEY_SEE_release.sh_keygen
-----END PUBLIC KEY-----'

# Base URL of the release artifacts. A variable rather than a literal so that
# moving to a shorter domain later costs one line and not a rewrite.
BASE_URL="${HOLISTIC_BASE_URL:-https://github.com/sxty9/Holistic/releases}"

PREFIX="${PREFIX:-/opt/holistic}"
CONF="${CONF:-/etc/holistic}"
STATE="${STATE:-/var/lib/holistic}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
PORT="${PORT:-80}"
SETUP_NAME="holistic.local"

usage() {
	cat <<'EOF'
Holistic Homeserver installer

  curl -fsSL .../install.sh | sudo bash          install the latest release
  ./install.sh --dry-run                         say what it would do, change nothing
  ./install.sh --version v0.2.0                  install a specific release
  ./install.sh --yes                             never ask; assume yes
  ./install.sh --code                            mint a fresh setup code
  ./install.sh --insecure-skip-verify            refuse to. See below.

There is no --insecure-skip-verify. If a checksum does not match, the honest
answers are to retry the download or to distrust the source, and this installer
will not offer you a third one.
EOF
}

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
warn() { printf '   ! %s\n' "$*" >&2; }
die() {
	printf '\nholistic: %s\n' "$*" >&2
	exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

# need reports a missing command with the command that installs it, and stops.
# It never installs anything itself: this machine belongs to somebody.
need() {
	have "$1" && return 0
	die "$1 is required and not installed. Install it with:  apt-get install $2"
}

# ask reads from the controlling terminal, never from stdin — stdin is this
# script. When there is no terminal at all (cron, CI, ssh with a command), the
# answer is no, because silence is not consent.
ask() {
	[ "$ASSUME_YES" -eq 1 ] && return 0
	[ -r /dev/tty ] || {
		note "no terminal to ask on, so: no"
		return 1
	}
	printf '\n%s [y/N] ' "$1" >/dev/tty
	local reply=''
	read -r reply </dev/tty || return 1
	case "$reply" in y | Y | yes | YES) return 0 ;; *) return 1 ;; esac
}

require_root() {
	[ "$(id -u)" -eq 0 ] && return 0
	cat >&2 <<EOF

holistic: this installs a system service and needs root.

  curl -fsSL $BASE_URL/latest/download/install.sh | sudo bash

The sudo is in the command rather than inside this script on purpose: handing
root to something should be a thing you type, not a thing you discover.
EOF
	exit 1
}

# platform maps uname's answers onto the names used in the release.
# uname says x86_64 and aarch64; Go and most release conventions say amd64 and
# arm64, and getting that mapping wrong is the classic 404 in an installer.
platform() {
	local os arch
	case "$(uname -s)" in
	Linux) os=linux ;;
	*) die "Holistic is a Linux homeserver. This machine reports $(uname -s)." ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "no release is built for $(uname -m) yet." ;;
	esac
	printf '%s-%s' "$os" "$arch"
}

fetch() {
	# -f  fail on an HTTP error instead of writing the error PAGE to the output,
	#     which is how a 404 becomes a tarball that will not open
	# -sS quiet, but still print the reason when something goes wrong
	# -L  follow redirects; GitHub release assets always redirect
	# --proto/--proto-redir pin https on the first request AND across every
	# redirect. GitHub release assets redirect twice, and without the pin a
	# 302 could send this to http:// or file:// — the second of which would
	# read a local file and hand it to the checksum as though it came down
	# the wire.
	curl -fsSL --proto '=https' --proto-redir '=https' \
		--retry 3 --retry-connrefused --connect-timeout 10 --max-time 600 \
		"$1" -o "$2" </dev/null
}

# --- verification -----------------------------------------------------------
#
# Two steps, in this order, and the order is the point:
#
#   1. The signature covers SHA256SUMS — a small text file. Signing that rather
#      than the archives also sidesteps openssl's documented 16MB limit for
#      one-shot signing.
#   2. SHA256SUMS covers the archive.
#
# Ed25519 needs `pkeyutl`, not `dgst`: `openssl dgst -sha256 -sign` on an
# Ed25519 key fails outright with "Explicit digest not allowed with EdDSA
# operations". And -rawin needs a real seekable file, not a pipe, which is why
# everything is written to the staging directory before it is checked.
verify_manifest() {
	local dir="$1"
	# Two statements, not one `local a=… b="$a/…"`. A builtin's arguments are
	# expanded before it runs, so $dir in the same `local` would expand to
	# whatever dir meant OUTSIDE this function — here, nothing — and the key
	# would be written to /holistic.pub.pem.
	local keyfile="$dir/holistic.pub.pem"
	printf '%s\n' "$HOLISTIC_PUBKEY" >"$keyfile"
	case "$HOLISTIC_PUBKEY" in
	*REPLACE_ME*)
		die "this installer was built without a release key. Refusing to verify nothing and call it verified."
		;;
	esac
	openssl pkeyutl -verify -pubin -inkey "$keyfile" \
		-rawin -in "$dir/SHA256SUMS" -sigfile "$dir/SHA256SUMS.sig" \
		>/dev/null 2>&1 </dev/null && return 0

	cat >&2 <<EOF

holistic: the release manifest is not signed by the key this installer trusts.

Nothing has been unpacked and nothing has been installed.

This means one of two things. Either the download was tampered with, or you are
running an installer from a different release line than the artifacts it is
pointing at. Re-fetch the installer from the same place as the release and try
again. If it happens twice, do not work around it.
EOF
	exit 1
}

verify_archive() {
	local dir="$1" file="$2" want have_
	want="$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1; exit }' "$dir/SHA256SUMS")"
	[ -n "$want" ] || die "$file is not listed in the signed manifest."
	have_="$(sha256sum "$dir/$file" </dev/null | cut -d' ' -f1)"
	[ "$want" = "$have_" ] && return 0

	cat >&2 <<EOF

holistic: $file does not match the signed manifest.

  expected  $want
  got       $have_

Nothing has been unpacked. This is usually an interrupted or corrupted
download — run the same command again. If it matches on a second attempt, the
first one was simply cut short. If it fails twice, stop and ask where the file
came from.
EOF
	exit 1
}

resolve_version() {
	[ -n "$VERSION" ] && {
		printf '%s' "$VERSION"
		return 0
	}
	printf 'latest'
}

download_release() {
	local dir="$1" plat="$2" ver="$3" base
	if [ "$ver" = latest ]; then
		base="$BASE_URL/latest/download"
	else
		base="$BASE_URL/download/$ver"
	fi

	step "Fetching the release"
	note "$base"
	fetch "$base/SHA256SUMS" "$dir/SHA256SUMS" ||
		die "could not fetch the release manifest from $base"
	fetch "$base/SHA256SUMS.sig" "$dir/SHA256SUMS.sig" ||
		die "the release has no signature. Refusing to install it."
	verify_manifest "$dir"
	note "manifest signature: ok"

	ARCHIVE="holistic-$plat.tar.gz"
	fetch "$base/$ARCHIVE" "$dir/$ARCHIVE" ||
		die "could not fetch $ARCHIVE from $base"
	verify_archive "$dir" "$ARCHIVE"
	note "$ARCHIVE checksum: ok"
}

# --- the setup code ---------------------------------------------------------

mint_code() {
	# From the kernel, grouped for copying by eye. Never generated in a browser:
	# Synology did that with Math.random, the seed was recovered, and the
	# administrator account went with it.
	head -c 16 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z' |
		sed 's/.\{5\}/&-/g; s/-$//'
}

write_code() {
	install -d -m 0750 -o root -g root "$CONF"
	# install(1) creates the file with its final mode. Between an open and a
	# later chmod there is a window, and a secret is what gets read during it.
	printf '%s\n' "$1" | install -m 0640 -o root -g root /dev/stdin "$CONF/setup.claim"
}

# --- publishing the name ----------------------------------------------------

publish_name() {
	step "Publishing $SETUP_NAME on your network"
	if have avahi-daemon || [ -x /usr/sbin/avahi-daemon ]; then
		configure_avahi
		return 0
	fi
	say ""
	say "   $SETUP_NAME needs avahi-daemon, which is not installed."
	say "   Without it the setup page is still reachable — by address rather"
	say "   than by name, which also works on the networks where .local is"
	say "   blocked, and that is more of them than you would expect."
	if ! ask "   Install avahi-daemon?"; then
		note "not installed. The address below is how you reach setup."
		return 0
	fi
	[ "$DRY" -eq 1 ] && {
		note "would apt-get install avahi-daemon"
		return 0
	}
	have apt-get || {
		warn "this is not an apt system; install avahi-daemon yourself"
		return 0
	}
	DEBIAN_FRONTEND=noninteractive apt-get install -y avahi-daemon </dev/null ||
		warn "avahi-daemon could not be installed; the address below still works"
	configure_avahi
}

configure_avahi() {
	local conf=/etc/avahi/avahi-daemon.conf
	[ -f "$conf" ] || return 0
	if grep -qE '^[[:space:]]*host-name[[:space:]]*=[[:space:]]*holistic[[:space:]]*$' "$conf"; then
		note "already published"
		return 0
	fi
	local current
	current="$(hostname 2>/dev/null || echo this-machine)"
	say ""
	say "   Publishing $SETUP_NAME sets avahi's host-name to 'holistic'."
	say "   This machine currently answers to '${current}.local' and will stop."
	if ! ask "   Publish $SETUP_NAME?"; then
		note "left alone"
		return 0
	fi
	[ "$DRY" -eq 1 ] && {
		note "would set host-name=holistic in $conf"
		return 0
	}
	cp -a "$conf" "$conf.before-holistic"
	if grep -qE '^[[:space:]]*#?[[:space:]]*host-name[[:space:]]*=' "$conf"; then
		sed -i 's|^[[:space:]]*#\?[[:space:]]*host-name[[:space:]]*=.*|host-name=holistic|' "$conf"
	else
		sed -i 's|^\[server\]|[server]\nhost-name=holistic|' "$conf"
	fi
	systemctl restart avahi-daemon </dev/null 2>/dev/null ||
		warn "avahi could not be restarted; $SETUP_NAME may not resolve yet"
	note "published (previous configuration kept at $conf.before-holistic)"
}

# --- what to print ----------------------------------------------------------
#
# The installer verifies its own advice rather than hoping. A URL that hangs is
# worse than a plain address, because the person following it cannot tell which
# of a dozen things went wrong.

lan_address() {
	ip -4 -o route get 1.1.1.1 2>/dev/null |
		awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1
}

name_resolves_to() {
	have getent || return 1
	local got
	got="$(getent ahostsv4 "$SETUP_NAME" 2>/dev/null | awk 'NR==1{print $1}')" || return 1
	[ -n "$got" ] && [ "$got" = "$1" ]
}

print_where() {
	local code="$1" addr suffix=''
	addr="$(lan_address || true)"
	[ "$PORT" != "80" ] && suffix=":$PORT"

	step "Setup is waiting"
	say ""
	if [ -n "$addr" ] && name_resolves_to "$addr"; then
		say "   Open this from any device on your network:"
		say ""
		say "       http://${SETUP_NAME}${suffix}/"
		say ""
		say "   (the same page is at http://${addr}${suffix}/)"
	elif [ -n "$addr" ]; then
		say "   Open this from any device on your network:"
		say ""
		say "       http://${addr}${suffix}/"
		say ""
		say "   $SETUP_NAME did not resolve to $addr when checked just now, so the"
		say "   address above is the one to trust. Guest Wi-Fi and separated VLANs"
		say "   usually block the discovery protocol .local depends on."
	else
		say "   No address on a local network was found. If you reach this machine"
		say "   only over ssh, forward the port and open http://localhost${suffix}/:"
		say ""
		say "       ssh -L ${PORT}:127.0.0.1:${PORT} <you>@this-machine"
	fi

	say ""
	say "   Your setup code:"
	say ""
	say "       $code"
	say ""
	say "   Anyone on your network can reach that page. Only someone with this"
	say "   code can claim the machine. It is destroyed the moment it is used."
	say ""
	say "   Lost it?  sudo $PREFIX/bin/holistic code"
}

# --- installing -------------------------------------------------------------

install_release() {
	local dir="$1"
	step "Installing"
	if [ "$DRY" -eq 1 ]; then
		note "would unpack $ARCHIVE into $PREFIX"
		note "would install $UNIT_DIR/holistic-setup.service"
		note "would enable and start holistic-setup.service"
		return 0
	fi

	install -d -m 0755 "$PREFIX/bin"
	install -d -m 0700 "$STATE"
	tar -xzf "$dir/$ARCHIVE" -C "$dir" </dev/null

	local src="$dir/holistic"
	[ -d "$src" ] || die "the archive does not look like a Holistic release."

	local f
	for f in "$src/bin/"*; do
		[ -f "$f" ] || continue
		install -m 0755 "$f" "$PREFIX/bin/$(basename "$f")"
		note "$PREFIX/bin/$(basename "$f")"
	done

	sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@CONF@|$CONF|g" \
		-e "s|@STATE@|$STATE|g" -e "s|@PORT@|$PORT|g" \
		"$src/deploy/holistic-setup.service" >"$UNIT_DIR/holistic-setup.service"
	note "$UNIT_DIR/holistic-setup.service"

	systemctl daemon-reload </dev/null
	systemctl enable --now holistic-setup.service </dev/null >/dev/null
	note "holistic-setup.service is running"
}

# --- main -------------------------------------------------------------------

main() {
	# The marker closes the one gap the truncation test found, and its POSITION
	# is the whole trick.
	#
	# Cutting the last line turns `main "$@"` into a bare `main` — still a
	# perfectly valid command, which runs with no arguments. So a transfer that
	# dies in the final six bytes starts an install anyway, and worse, it
	# silently upgrades a `--dry-run` into a real one, because the flags were on
	# the part of the line that got cut.
	#
	# A marker at the FRONT does not fix it: `main --run "$@"` truncated to
	# `main --run` still carries the marker and still loses the flags. Measured,
	# not assumed — that version failed at exactly two cut points.
	#
	# So the marker is the LAST token on the line. It can only be present if
	# every byte before it arrived.
	[ "${!#:-}" = "--delivered-in-full" ] ||
		die "this script did not arrive complete. Nothing was changed — run the same command again."
	set -- "${@:1:$#-1}"

	ASSUME_YES=0
	DRY=0
	VERSION=''
	ARCHIVE=''
	local mode=install

	while [ $# -gt 0 ]; do
		case "$1" in
		--yes | -y) ASSUME_YES=1 ;;
		--dry-run | -n) DRY=1 ;;
		--code) mode=code ;;
		--version)
			shift
			VERSION="${1:-}"
			[ -n "$VERSION" ] || die "--version needs a release tag, e.g. v0.2.0"
			;;
		-h | --help)
			usage
			return 0
			;;
		*)
			printf 'Unknown option: %s\n\n' "$1" >&2
			usage >&2
			return 2
			;;
		esac
		shift
	done

	if [ "$mode" = code ]; then
		require_root
		[ -f "$CONF/claimed" ] &&
			die "this instance is already claimed. Re-opening setup is a separate, deliberate act."
		local fresh
		fresh="$(mint_code)"
		write_code "$fresh"
		systemctl restart holistic-setup.service </dev/null 2>/dev/null || true
		print_where "$fresh"
		return 0
	fi

	say "Holistic Homeserver installer"
	say "  binaries   $PREFIX/bin"
	say "  config     $CONF"
	say "  state      $STATE"
	say "  setup on   port $PORT, your local network only"

	step "Checking what is here"
	have systemctl || die "this expects a systemd machine."
	note "systemd: yes"
	need curl curl
	need tar tar
	need sha256sum coreutils
	# openssl is Priority: important AND ca-certificates depends on it, so any
	# machine that could fetch this file over HTTPS almost certainly has it.
	# Almost is not always — someone could have carried this over on a stick.
	need openssl openssl
	note "curl, tar, sha256sum, openssl: yes"

	if [ -f "$CONF/claimed" ]; then
		step "Already claimed"
		say "   This machine has been set up. Nothing to do."
		say "   To change its configuration, sign in at your own domain."
		say "   To start over deliberately, remove $CONF/claimed and run this again."
		return 0
	fi

	[ "$DRY" -eq 0 ] && require_root

	local plat ver dir
	plat="$(platform)"
	ver="$(resolve_version)"
	note "platform: $plat, release: $ver"

	dir="$(mktemp -d)" || die "could not make a temporary directory"
	# shellcheck disable=SC2064
	trap "rm -rf '$dir'" EXIT

	download_release "$dir" "$plat" "$ver"
	install_release "$dir"

	if [ "$DRY" -eq 1 ]; then
		step "Nothing was changed"
		say "   Re-run without --dry-run to install."
		return 0
	fi

	publish_name

	local code
	if [ -s "$CONF/setup.claim" ]; then
		step "Setup code"
		say "   One already exists and has not been used."
		code="$(cat "$CONF/setup.claim")"
	else
		code="$(mint_code)"
		write_code "$code"
	fi

	print_where "$code"
}

main "$@" --delivered-in-full
