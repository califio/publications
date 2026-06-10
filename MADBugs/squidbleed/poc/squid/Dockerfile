# Intentionally runs the Debian-shipped default /etc/squid/squid.conf verbatim —
# no custom squid.conf is copied into this image. The only runtime change is a
# one-line ACL uncomment (see squid_entrypoint.sh) to enable `http_access allow
# localnet`, which Debian's own default config explicitly instructs admins to
# do to make the proxy usable. All Squid security-relevant defaults
# (memory_pools=on, ftp_passive=on, Safe_ports, etc.) are untouched.
FROM debian:bookworm-slim
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        squid=5.7-2+deb12u5 curl procps \
 && rm -rf /var/lib/apt/lists/*

COPY squid_entrypoint.sh /usr/local/bin/squid_entrypoint.sh
RUN chmod +x /usr/local/bin/squid_entrypoint.sh \
 && mkdir -p /var/spool/squid /var/log/squid \
 && chown -R proxy:proxy /var/spool/squid /var/log/squid

EXPOSE 3128
CMD ["/usr/local/bin/squid_entrypoint.sh"]
