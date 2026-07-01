#!/bin/sh
# Start varnishd in the foreground with feature=+http2 — the one
# non-default parameter the exploit needs. Thread pool sized so the
# demo keeps serving /reviews while some workers are blocked reading
# from backend connections poisoned by the attacker.
#
# One frontend:
#   :6086  — PROXY-protocol listener, terminated by the hitch TLS
#            sidecar. Browsers and the attacker both reach this path
#            via https://groove-therapy.local and speak HTTP/2
#            (negotiated via ALPN by hitch). No cleartext listener is
#            exposed; this mirrors the realistic production shape.
set -e
exec varnishd -F \
    -f /etc/varnish/default.vcl \
    -a proxy=:6086,PROXY \
    -p feature=+http2 \
    -p thread_pools=2 \
    -p thread_pool_min=50 \
    -p thread_pool_max=200 \
    -p first_byte_timeout=15 \
    -p between_bytes_timeout=15 \
    -p backend_idle_timeout=60 \
    -s malloc,256m
