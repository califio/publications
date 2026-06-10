#!/bin/bash
set -u

# Docker writes both A and AAAA entries for host.docker.internal into
# /etc/hosts. This container has no IPv6 stack, so Squid's connect to the
# AAAA address fails immediately and ftp:// requests come back 503 before
# the bug can ever fire. Drop any IPv6 mapping for host.docker.internal so
# only the IPv4 entry remains. /etc/hosts is a docker bind-mount; `sed -i`
# fails (EBUSY on rename), so read+truncate+write in place.
grep -v ':.*host\.docker\.internal' /etc/hosts > /tmp/hosts.new
cat /tmp/hosts.new > /etc/hosts
rm -f /tmp/hosts.new

# The ONLY modification to the Debian-shipped /etc/squid/squid.conf: uncomment
# `http_access allow localnet`. Debian's own comment directly above that line
# ("A more permissive configuration which also allows access to local private
# networks via the RFC 1918 address space can be enabled by uncommenting the
# following line:") instructs admins to do exactly this. Without it the stock
# ACL denies everyone except 127.0.0.1, so our host-bridged triage traffic
# (172.x.x.x via the docker bridge) can't reach the proxy at all. This has no
# bearing on the vulnerability — the F17 parser bug fires identically no
# matter what source IP is allowed through.
sed -i 's/^#http_access allow localnet$/http_access allow localnet/' /etc/squid/squid.conf

squid -N -z >/var/log/squid/init.log 2>&1
exec squid -N -d 1
