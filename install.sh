#!/usr/bin/env bash
#
# Holistic Homeserver — installer.
#
# Two commands is the whole promise: fetch this file, run it. What it leaves
# behind is a machine waiting to be configured from a browser on your own
# network, and a code that proves you are the person who installed it.
#
# What it will not do, on purpose:
#
#   * It never installs a package without asking. This machine belongs to
#     somebody. A missing prerequisite is reported with the exact command that
#     would fix it, and you decide.
#   * It never puts the setup code anywhere but a root-owned file and your
#     terminal. Not in the journal — `getent group adm` on a normal box
#     includes more accounts than you would guess, and journal-readable is not
#     root-only.
#   * It never claims the instance for you. The code is minted here; claiming
#     happens in your browser, deliberately, once.
#
# Re-running is safe. It reconciles rather than reinstalls, and it will tell
# you if this machine has already been claimed rather than quietly re-arming
# the thing that makes it claimable.

set -euo pipefail

PREFIX="${PREFIX:-/opt/holistic}"
CONF="${CONF:-/etc/holistic}"
STATE="${STATE:-/var/lib/holistic}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
UNIT="holistic-setup.service"
PORT="${PORT:-80}"
SETUP_NAME="holistic.local"

ASSUME_YES=0
DRY=0

usage() {
	cat >&2 <<EOF
Holistic Homeserver installer

  ./install.sh              install, asking before it changes anything
  ./install.sh --yes        install without asking
  ./install.sh --dry-run    say what it would do, change nothing
  ./install.sh --code       mint a fresh setup code and print it

Environment: PREFIX=$PREFIX CONF=$CONF STATE=$STATE PORT=$PORT
EOF
}

MODE=install
while [ $# -gt 0 ]; do
	case "$1" in
	--yes | -y) ASSUME_YES=1 ;;
	--dry-run | -n) DRY=1 ;;
	--code) MODE=code ;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		printf 'Unknown option: %s\n\n' "$1" >&2
		usage
		exit 2
		;;
	esac
	shift
done

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
die() {
	printf '\nholistic: %s\n' "$*" >&2
	exit 1
}

need_root() {
	[ "$(id -u)" -eq 0 ] || die "this needs root. Re-run with sudo, or use --dry-run to see what it would do."
}

ask() {
	[ "$ASSUME_YES" -eq 1 ] && return 0
	printf '\n%s [y/N] ' "$1"
	local reply
	read -r reply </dev/tty || return 1
	case "$reply" in y | Y | yes | YES) return 0 ;; *) return 1 ;; esac
}

# --- prerequisites ---------------------------------------------------------
# Reported, never installed silently. The two-command promise is worth less
# than the rule that this installer does not reach into somebody's package
# manager behind their back.

MISSING=()
have() { command -v "$1" >/dev/null 2>&1; }

check_prerequisites() {
	step "Checking what is here"
	have systemctl || die "this expects a systemd machine."
	note "systemd: yes"

	if have avahi-daemon || [ -x /usr/sbin/avahi-daemon ]; then
		note "avahi: installed — $SETUP_NAME can be published"
	else
		MISSING+=("avahi-daemon")
		note "avahi: NOT installed — $SETUP_NAME will not resolve"
		note "  install it with:  sudo apt-get install avahi-daemon"
		note "  or skip it: the installer prints this machine's address instead,"
		note "  which works on every network including the ones where .local does not."
	fi
}

# --- the setup code --------------------------------------------------------

mint_code() {
	# Base32 from the kernel's randomness, grouped for copying by eye. Never
	# generated in a browser: Synology did that with Math.random, the seed was
	# recovered, and the administrator account went with it.
	local raw
	raw="$(head -c 16 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z')"
	printf '%s' "$raw" | sed 's/.\{5\}/&-/g; s/-$//'
}

write_code() {
	local code="$1"
	install -d -m 0750 -o root -g root "$CONF"
	# install(1) creates the file with the mode from the start. Between an open
	# and a chmod there is a window, and a secret is exactly what gets read
	# during it.
	printf '%s\n' "$code" | install -m 0640 -o root -g root /dev/stdin "$CONF/setup.claim"
}

# --- publishing the name ---------------------------------------------------

publish_name() {
	step "Publishing $SETUP_NAME on your network"
	if [ ${#MISSING[@]} -gt 0 ]; then
		note "skipped — avahi is not installed"
		return 0
	fi
	local conf=/etc/avahi/avahi-daemon.conf
	[ -f "$conf" ] || {
		note "skipped — $conf is not there"
		return 0
	}

	local current
	current="$(hostname)"
	if grep -qE '^\s*host-name\s*=\s*holistic\s*$' "$conf"; then
		note "already published"
		return 0
	fi

	say ""
	say "   Publishing $SETUP_NAME means setting avahi's host-name to 'holistic'."
	say "   This machine currently answers to '${current}.local' and will stop."
	say "   Nothing else changes, and it is one line in $conf."
	if ! ask "   Publish $SETUP_NAME?"; then
		note "left alone — the address below is how you reach setup"
		return 0
	fi
	[ "$DRY" -eq 1 ] && {
		note "would set host-name=holistic in $conf"
		return 0
	}

	cp -a "$conf" "$conf.before-holistic"
	if grep -qE '^\s*#?\s*host-name\s*=' "$conf"; then
		sed -i 's|^\s*#\?\s*host-name\s*=.*|host-name=holistic|' "$conf"
	else
		sed -i 's|^\[server\]|[server]\nhost-name=holistic|' "$conf"
	fi
	systemctl restart avahi-daemon || note "avahi could not be restarted; $SETUP_NAME may not resolve yet"
	note "published (previous configuration kept at $conf.before-holistic)"
}

# --- what to print ---------------------------------------------------------
#
# The installer verifies its own advice rather than hoping. A URL that hangs is
# worse than an address that looks less friendly, because the person following
# it has no way to tell which of a dozen things went wrong.

lan_address() {
	ip -4 -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1
}

verify_name() {
	local expect="$1" got
	have getent || return 1
	got="$(getent ahostsv4 "$SETUP_NAME" 2>/dev/null | awk 'NR==1{print $1}')" || return 1
	[ -n "$got" ] && [ "$got" = "$expect" ]
}

print_where() {
	local code="$1" addr port_suffix
	addr="$(lan_address || true)"
	port_suffix=""
	[ "$PORT" != "80" ] && port_suffix=":$PORT"

	step "Setup is waiting"
	say ""
	if [ -n "$addr" ] && verify_name "$addr"; then
		say "   Open this from any machine on your network:"
		say ""
		say "       http://${SETUP_NAME}${port_suffix}/"
		say ""
		say "   (also reachable at http://${addr}${port_suffix}/)"
	elif [ -n "$addr" ]; then
		say "   Open this from any machine on your network:"
		say ""
		say "       http://${addr}${port_suffix}/"
		say ""
		say "   $SETUP_NAME did not resolve to $addr when checked just now, so the"
		say "   address above is the one to trust. Some networks block the discovery"
		say "   protocol .local depends on — guest Wi-Fi and separated VLANs usually do."
	else
		say "   No address on a local network was found. If this machine is only"
		say "   reachable over ssh, forward the port and open http://localhost${port_suffix}/:"
		say ""
		say "       ssh -L ${PORT}:127.0.0.1:${PORT} $(id -un)@this-machine"
	fi

	say ""
	say "   Your setup code:"
	say ""
	say "       $code"
	say ""
	say "   It is written to $CONF/setup.claim, readable only by root, and it is"
	say "   destroyed the moment it is used. Anyone on your network can reach the"
	say "   page; only someone with this code can claim the machine."
	say ""
	say "   Lost it? Run:  sudo ./install.sh --code"
}

# --- install ---------------------------------------------------------------

build_or_find() {
	if [ -x "./bin/holistic-setup" ]; then
		echo "./bin/holistic-setup"
		return 0
	fi
	if have go && [ -f ./go.mod ]; then
		[ "$DRY" -eq 1 ] && {
			echo ""
			return 0
		}
		note "building from source"
		GOFLAGS=-trimpath go build -o /tmp/holistic-setup.$$ ./cmd/holistic-setup
		echo "/tmp/holistic-setup.$$"
		return 0
	fi
	die "no holistic-setup binary in ./bin and no Go toolchain to build one."
}

install_service() {
	local src="$1"
	step "Installing"
	if [ "$DRY" -eq 1 ]; then
		note "would install $src -> $PREFIX/bin/holistic-setup"
		note "would install $UNIT_DIR/$UNIT"
		note "would enable and start $UNIT"
		return 0
	fi
	install -d -m 0755 "$PREFIX/bin"
	install -d -m 0700 "$STATE"
	install -m 0755 "$src" "$PREFIX/bin/holistic-setup"
	note "$PREFIX/bin/holistic-setup"

	sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@CONF@|$CONF|g" -e "s|@STATE@|$STATE|g" -e "s|@PORT@|$PORT|g" \
		deploy/holistic-setup.service >"$UNIT_DIR/$UNIT"
	note "$UNIT_DIR/$UNIT"

	systemctl daemon-reload
	systemctl enable --now "$UNIT" >/dev/null
	note "$UNIT is running"
}

# --- main ------------------------------------------------------------------

if [ "$MODE" = code ]; then
	need_root
	[ -f "$CONF/claimed" ] && die "this instance is already claimed. Re-opening setup is a separate, deliberate act."
	CODE="$(mint_code)"
	write_code "$CODE"
	systemctl restart "$UNIT" 2>/dev/null || true
	print_where "$CODE"
	exit 0
fi

say "Holistic Homeserver installer"
say "  binaries   $PREFIX/bin"
say "  config     $CONF"
say "  state      $STATE"
say "  setup on   port $PORT, your local network only"

check_prerequisites

if [ -f "$CONF/claimed" ]; then
	step "Already claimed"
	say "   This machine has been set up. Nothing to do."
	say "   To change its configuration, sign in at your own domain."
	say "   To start over deliberately, remove $CONF/claimed and run this again."
	exit 0
fi

[ "$DRY" -eq 0 ] && need_root

BIN="$(build_or_find)"
install_service "$BIN"
# Written as an if rather than an && chain: under `set -e` a chain whose last
# test is false exits the script, so "there was nothing temporary to clean up"
# would end the install just before it printed the setup code.
if [ "$DRY" -eq 0 ] && [ "${BIN#/tmp/}" != "$BIN" ]; then
	rm -f "$BIN"
fi

if [ "$DRY" -eq 1 ]; then
	step "Nothing was changed"
	say "   Re-run without --dry-run to install."
	exit 0
fi

publish_name

if [ -s "$CONF/setup.claim" ]; then
	step "Setup code"
	say "   One already exists and has not been used. Run --code to replace it."
	CODE="$(cat "$CONF/setup.claim")"
else
	CODE="$(mint_code)"
	write_code "$CODE"
fi

print_where "$CODE"
