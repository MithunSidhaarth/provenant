#!/bin/sh
# Provenant installer for macOS and Linux. Run as yourself, not as an agent:
#   curl -fsSL https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.sh | sh
# Uses pipx when available, otherwise installs for the current user with pip (no sudo, no dependencies),
# then runs `provenant setup`, which shows what it will protect and asks before changing anything.
set -eu
SRC="${PROVENANT_SRC:-https://github.com/MithunSidhaarth/provenant/archive/refs/heads/main.zip}"
say() { printf '  \033[36m>\033[0m %s\n' "$1"; }

printf '\n  \033[35mprovenant installer\033[0m\n'
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        PY="$(command -v "$c")"; break
    fi
done

if command -v pipx >/dev/null 2>&1; then
    say "Installing with pipx"
    pipx install --force "$SRC" >/dev/null
    PV="$(command -v provenant || echo "$HOME/.local/bin/provenant")"
else
    if [ -z "$PY" ]; then
        echo "  Python 3.10 or newer was not found. Install it (https://www.python.org/downloads/) and run this again."; exit 1
    fi
    say "Installing for $(id -un) with $PY"
    "$PY" -m pip install --user --upgrade --quiet --disable-pip-version-check "$SRC" 2>/dev/null \
        || "$PY" -m pip install --user --upgrade --quiet --disable-pip-version-check --break-system-packages "$SRC"
    BIN="$HOME/.provenant/bin"
    mkdir -p "$BIN"
    printf '#!/bin/sh\nexec "%s" -m agentshield.cli "$@"\n' "$PY" > "$BIN/provenant"
    chmod +x "$BIN/provenant"
    PV="$BIN/provenant"
    if [ -d "$HOME/.local/bin" ] && [ ! -e "$HOME/.local/bin/provenant" ]; then
        ln -s "$PV" "$HOME/.local/bin/provenant" && PV="$HOME/.local/bin/provenant"
    fi
    case ":$PATH:" in *":$(dirname "$PV"):"*) ;; *) say "Add $(dirname "$PV") to your PATH to type 'provenant' anywhere";; esac
fi

say "Done. Running provenant setup"
if [ -t 1 ] && [ -r /dev/tty ]; then "$PV" setup </dev/tty; else "$PV" setup --dry-run; fi
