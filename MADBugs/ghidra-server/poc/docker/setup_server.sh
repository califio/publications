#!/bin/bash
#
# Configure and start GhidraServer in PKI mode (-a2), then immediately run
# the demo setup: create an admin-only repository so the exploit has
# something meaningful to demonstrate against.
#
# Startup sequence:
#   1. Generate PKI hierarchy if not already present
#   2. Write user registry
#   3. Start GhidraServer in the background
#   4. Wait for the RMI registry port to accept connections
#   5. Run Setup.class — admin creates 'SecretAnalysis' (admin-only ACL)
#   6. Touch .setup_done sentinel so external tooling knows we are ready
#   7. wait on the server process (keeps the container alive)
#
set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
PKI_DIR="${PKI_DIR:-/opt/pki}"
REPOS_DIR="${REPOS_DIR:-/opt/repos}"
JAVA_HOME="${JAVA_HOME:-/opt/java/openjdk}"
PORT="${PORT:-13100}"
PASSWORD="changeit"

mkdir -p "$REPOS_DIR"

# ── PKI ───────────────────────────────────────────────────────────────────────
if [ ! -f "$PKI_DIR/cacerts" ]; then
    echo "[*] PKI directory empty, generating certificates..."
    /opt/setup_pki.sh "$PKI_DIR"
fi

# ── Classpath ─────────────────────────────────────────────────────────────────
echo "[*] Building classpath..."
CP="/opt"
for jar in $(find "$GHIDRA_HOME/Ghidra" -name "*.jar" \
    \( -path "*/GhidraServer/*" \
       -o -path "*/FileSystem/*" \
       -o -path "*/DB/*" \
       -o -path "*/Generic/*" \
       -o -path "*/Utility/*" \
       -o -path "*/Docking/*" \
       -o -path "*/Help/*" \
       -o -path "*/Gui/*" \) | sort); do
    CP="$CP:$jar"
done

# ── User registry ─────────────────────────────────────────────────────────────
echo "[*] Writing user registry..."
cat > "$REPOS_DIR/users" << EOF
admin:*:*:CN=admin,O=GhidraDemo,C=US
analyst:*:*:CN=analyst,O=GhidraDemo,C=US
EOF

# ── Start GhidraServer in the background ─────────────────────────────────────
echo "[*] Starting GhidraServer on port $PORT (PKI mode)..."
"$JAVA_HOME/bin/java" \
    -Djava.rmi.server.hostname=::1 \
    -Dghidra.cacerts="$PKI_DIR/cacerts" \
    -Dghidra.keystore="$PKI_DIR/server.p12" \
    -Dghidra.password="$PASSWORD" \
    -cp "$CP" \
    ghidra.server.remote.GhidraServer \
    -a2 -p"$PORT" "$REPOS_DIR" &

SERVER_PID=$!

# ── Wait for RMI registry port ────────────────────────────────────────────────
echo "[*] Waiting for RMI registry on port $PORT..."
until nc -z localhost "$PORT" 2>/dev/null; do
    # Exit early if the server process died
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "[!] GhidraServer process exited unexpectedly."
        exit 1
    fi
    sleep 1
done
# Allow the RMI SSL object channel and block-stream ports to fully initialise
sleep 4
echo "[+] Server ports are up."

# ── Run setup: create admin-only repository ───────────────────────────────────
echo "[*] Creating admin-only repository 'SecretAnalysis'..."
"$JAVA_HOME/bin/java" \
    -Dghidra.cacerts="$PKI_DIR/cacerts" \
    -cp "$CP" \
    Setup \
    --host localhost --port "$PORT" \
    --admin-key "$PKI_DIR/admin.p12" \
    --ca-cert   "$PKI_DIR/ca.crt" \
    --repo      SecretAnalysis \
    --password  "$PASSWORD"

# ── Signal readiness ─────────────────────────────────────────────────────────
touch "$REPOS_DIR/.setup_done"
echo "[+] Setup complete. Container ready for demo."

# ── Keep container alive ─────────────────────────────────────────────────────
wait "$SERVER_PID"
