#!/bin/sh
# Provenant installer for macOS and Linux. Run as yourself, not as an agent:
#   curl -fsSL https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.sh | sh
# Uses pipx when available, otherwise installs for the current user with pip (no sudo, no dependencies),
# then runs `provenant setup`, which shows what it will protect and asks before changing anything.
set -eu
SRC="${PROVENANT_SRC:-https://github.com/MithunSidhaarth/provenant/archive/refs/heads/main.zip}"
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    M='\033[35m'; G='\033[32m'; R='\033[31m'; D='\033[2m'; B='\033[1m'; N='\033[0m'
else
    M=''; G=''; R=''; D=''; B=''; N=''
fi
step() { printf "  ${D}[%s/4]${N} %-25s" "$1" "$2"; }
done_() { printf "${G}✓${N} ${D}%s${N}\n" "$1"; }
fail() { printf "\n  ${R}✗ %s${N}\n\n" "$1"; exit 1; }
LOG="${TMPDIR:-/tmp}/provenant-install.log"

printf "\n  ${M}◆${N} ${B}provenant${N}  ${D}· a firewall between AI agents and their tools${N}\n\n"

step 1 "Finding Python 3.10+"
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        PY="$(command -v "$c")"; break
    fi
done
[ -n "$PY" ] || fail "Python 3.10 or newer was not found. Install it (https://www.python.org/downloads/) and run this again."
done_ "Python $("$PY" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"

step 2 "Installing Provenant"
BIN="$HOME/.provenant/bin"
if command -v pipx >/dev/null 2>&1; then
    pipx install --force "$SRC" >"$LOG" 2>&1 || fail "pipx could not install Provenant. Details: $LOG"
    PV="$(command -v provenant || echo "$HOME/.local/bin/provenant")"
    HOW="with pipx"
else
    { "$PY" -m pip install --user --upgrade --quiet --disable-pip-version-check "$SRC" \
      || "$PY" -m pip install --user --upgrade --quiet --disable-pip-version-check --break-system-packages "$SRC"; } >"$LOG" 2>&1 \
      || fail "pip could not install Provenant. Details: $LOG"
    mkdir -p "$BIN"
    printf '#!/bin/sh\nexec "%s" -m agentshield.cli "$@"\n' "$PY" > "$BIN/provenant"
    chmod +x "$BIN/provenant"
    PV="$BIN/provenant"
    HOW="for $(id -un), no sudo"
fi
done_ "$("$PV" --version) $HOW"

step 3 "Adding the command"
if [ -d "$HOME/.local/bin" ] && [ "$PV" = "$BIN/provenant" ] && [ ! -e "$HOME/.local/bin/provenant" ]; then
    ln -s "$PV" "$HOME/.local/bin/provenant" && PV="$HOME/.local/bin/provenant"
fi
case ":$PATH:" in
    *":$(dirname "$PV"):"*) done_ "'provenant' is on your PATH" ;;
    *) done_ "add $(dirname "$PV") to PATH to type 'provenant' anywhere" ;;
esac

step 4 "Protecting your agents"
printf "\n"
if [ -t 1 ] && [ -r /dev/tty ]; then "$PV" setup </dev/tty; else "$PV" setup --dry-run; fi
