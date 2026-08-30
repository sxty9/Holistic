#!/usr/bin/env bash
# What install.sh must be true about before it touches a machine.
#
#   ./install_test.sh
#
# Exit code is the number of failures. Everything here runs unprivileged in a
# temporary directory: the point of the checks below is precisely that the
# installer decides what it is allowed to do BEFORE it needs any privilege.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
# The last line is `main "$@" --delivered-in-full`; drop it so the functions can
# be sourced without running an install.
head -n -1 "$HERE/install.sh" >"$T/lib.sh"

fail=0
bad() { printf '  ✗ %s\n' "$*"; fail=$((fail + 1)); }
ok() { printf '  ✓ %s\n' "$*"; }

# survey runs one verdict in a subshell with the paths overridden.
survey() { bash -c "source '$T/lib.sh' >/dev/null 2>&1; survey_dir '$1'"; }

check() { # <expected> <path> <what it is>
	local got
	got="$(survey "$2")"
	[ "$got" = "$1" ] && ok "$3 → $1" || bad "$3 → got '$got', wanted '$1'"
}

echo "== survey_dir tells the four cases apart"
check free "$T/nothing-here" "a path that does not exist"
mkdir -p "$T/empty"
check empty "$T/empty" "an empty directory"
mkdir -p "$T/ours"; touch "$T/ours/.holistic-owns-this" "$T/ours/binaries"
check ours "$T/ours" "one this installer already owns"
mkdir -p "$T/theirs"; touch "$T/theirs/jwt-secret"
check occupied "$T/theirs" "one holding somebody else's files"
: >"$T/notadir"
check notadir "$T/notadir" "a file where a directory should be"

# Unreadable must never read as empty. This is the case that was wrong first
# time: run unprivileged against a 0700 directory owned by a service account —
# which is what /etc/holistic is on a machine running the earlier landscape —
# a survey that swallowed the error answered "empty, adopt it".
echo
echo "== an unreadable directory is not an empty one"
mkdir -p "$T/locked"; touch "$T/locked/secret"; chmod 000 "$T/locked"
if [ "$(id -u)" = 0 ]; then
	ok "skipped: running as root, which can read it"
else
	check unreadable "$T/locked" "a directory this user cannot read"
fi
chmod 755 "$T/locked"

echo
echo "== check_paths refuses a collision and writes nothing first"
# The order matters: /opt free, /etc taken. The first version created /opt and
# then printed "Holistic has not changed anything", which was a lie told by the
# function whose whole job is to not change anything.
rm -rf "$T/m"; mkdir -p "$T/m/etc"; touch "$T/m/etc/jwt-secret"
out="$(bash -c "PREFIX='$T/m/opt'; CONF='$T/m/etc'; STATE='$T/m/var'; DRY=1
	source '$T/lib.sh' >/dev/null 2>&1
	PREFIX='$T/m/opt'; CONF='$T/m/etc'; STATE='$T/m/var'; DRY=1
	check_paths" 2>&1)"
rc=$?
[ "$rc" -ne 0 ] && ok "it refused" || bad "it did not refuse (exit $rc)"
printf '%s' "$out" | grep -q 'Holistic has not changed anything' &&
	ok "it says so" || bad "the refusal does not say nothing was changed"
printf '%s' "$out" | grep -q 'jwt-secret' &&
	ok "it names what it found" || bad "the refusal does not name what is in the way"
[ -e "$T/m/opt" ] && bad "it created $T/m/opt before refusing" || ok "and it created nothing"
[ -e "$T/m/var" ] && bad "it created $T/m/var before refusing" || ok "neither directory"

echo
echo "== a clear machine passes"
rm -rf "$T/c"; mkdir -p "$T/c"
bash -c "PREFIX='$T/c/opt'; CONF='$T/c/etc'; STATE='$T/c/var'; DRY=1
	source '$T/lib.sh' >/dev/null 2>&1
	PREFIX='$T/c/opt'; CONF='$T/c/etc'; STATE='$T/c/var'; DRY=1
	check_paths" >/dev/null 2>&1 &&
	ok "three free paths are accepted" || bad "three free paths were refused"

echo
echo "== the delivery marker still guards a truncated download"
# Cutting the last line turns `main "$@" --delivered-in-full` into a bare `main`,
# which is a valid command. The marker is the last token for that reason, and
# this is the check that it stayed there.
tail -1 "$HERE/install.sh" | grep -q -- '--delivered-in-full$' &&
	ok "the marker is the last token of the last line" ||
	bad "the delivery marker is not where it has to be"

echo
[ "$fail" = 0 ] && echo "clean" || echo "$fail failure(s)"
exit "$fail"
