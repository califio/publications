#!/bin/bash
#
# Generate a complete PKI hierarchy for the GhidraServer exploit demo.
#
# Creates:
#   pki/ca.crt, ca.key          — Certificate Authority
#   pki/server.crt, server.p12  — GhidraServer identity (mTLS + token signing)
#   pki/admin.crt, admin.p12    — Admin user (the impersonation target)
#   pki/user.crt, user.p12      — Regular user (the attacker)
#   pki/cacerts                 — JKS truststore containing the CA cert
#
set -euo pipefail

PKI_DIR="${1:-/opt/pki}"
PASSWORD="changeit"
DAYS=365

mkdir -p "$PKI_DIR"
cd "$PKI_DIR"

echo "[*] Generating Certificate Authority..."
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days $DAYS \
    -subj "/C=US/O=GhidraDemo/CN=DemoCA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -out ca.crt 2>/dev/null

echo "[*] Generating server certificate..."
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/O=GhidraDemo/CN=localhost" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days $DAYS -sha256 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1,IP:$(hostname -I | awk '{print $1}')\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth") \
    2>/dev/null
openssl pkcs12 -export -in server.crt -inkey server.key -certfile ca.crt \
    -out server.p12 -name server -passout pass:$PASSWORD 2>/dev/null

echo "[*] Generating admin certificate (impersonation target)..."
openssl genrsa -out admin.key 2048 2>/dev/null
openssl req -new -key admin.key -out admin.csr \
    -subj "/C=US/O=GhidraDemo/CN=admin" 2>/dev/null
openssl x509 -req -in admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out admin.crt -days $DAYS -sha256 \
    -extfile <(printf "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth") \
    2>/dev/null
openssl pkcs12 -export -in admin.crt -inkey admin.key -certfile ca.crt \
    -out admin.p12 -name admin -passout pass:$PASSWORD 2>/dev/null

echo "[*] Generating user certificate (the attacker)..."
openssl genrsa -out user.key 2048 2>/dev/null
openssl req -new -key user.key -out user.csr \
    -subj "/C=US/O=GhidraDemo/CN=analyst" 2>/dev/null
openssl x509 -req -in user.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out user.crt -days $DAYS -sha256 \
    -extfile <(printf "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth") \
    2>/dev/null
openssl pkcs12 -export -in user.crt -inkey user.key -certfile ca.crt \
    -out user.p12 -name analyst -passout pass:$PASSWORD 2>/dev/null

echo "[*] Building JKS trust store (cacerts)..."
keytool -import -noprompt -alias ca -file ca.crt \
    -keystore cacerts -storepass $PASSWORD -storetype JKS 2>/dev/null

# Cleanup CSRs and serials
rm -f *.csr *.srl

echo "[+] PKI hierarchy complete in $PKI_DIR"
echo "    CA:     $(openssl x509 -in ca.crt -noout -subject 2>/dev/null)"
echo "    Server: $(openssl x509 -in server.crt -noout -subject 2>/dev/null)"
echo "    Admin:  $(openssl x509 -in admin.crt -noout -subject 2>/dev/null)"
echo "    User:   $(openssl x509 -in user.crt -noout -subject 2>/dev/null)"
