# Hitch — the Varnish project's canonical TLS terminator. Terminates HTTPS
# and forwards cleartext HTTP/2 (or HTTP/1.1, whichever ALPN selected) to
# Varnish over a PROXY-protocol-v2 prefixed TCP connection. This is the
# setup every production Varnish deployment uses to serve HTTPS.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends hitch openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY hitch.conf /etc/hitch/hitch.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 443
ENTRYPOINT ["/entrypoint.sh"]
