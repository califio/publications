#!/bin/sh
# Generate a self-signed cert for groove-therapy.local on first start, then
# run hitch in the foreground. The cert also covers *.groove-therapy.local
# and localhost so the attacker script can connect over TLS if it wants to.
set -e

PEM=/etc/hitch/groove-therapy.local.pem

if [ ! -f "$PEM" ]; then
    echo "[tls] generating self-signed cert for groove-therapy.local"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout /etc/hitch/key.pem \
        -out    /etc/hitch/cert.pem \
        -subj   "/CN=groove-therapy.local/O=Groove Therapy/C=US" \
        -addext "subjectAltName=DNS:groove-therapy.local,DNS:*.groove-therapy.local,DNS:localhost,IP:127.0.0.1,IP:::1" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth"
    # hitch expects cert and key concatenated in one PEM file.
    cat /etc/hitch/cert.pem /etc/hitch/key.pem > "$PEM"
    chown _hitch:_hitch "$PEM" /etc/hitch/cert.pem /etc/hitch/key.pem
    chmod 640 "$PEM" /etc/hitch/cert.pem /etc/hitch/key.pem
    echo "[tls] cert SHA-256 fingerprint:"
    openssl x509 -in /etc/hitch/cert.pem -noout -fingerprint -sha256
fi

# hitch refuses to start until its backend resolves. Give Varnish a moment.
for _ in $(seq 1 30); do
    if getent hosts varnish >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

echo "[tls] starting hitch → varnish:6086 (PROXY v2, ALPN h2/http1.1)"
exec hitch --config=/etc/hitch/hitch.conf
