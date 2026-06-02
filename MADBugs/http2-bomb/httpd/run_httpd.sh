#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

IMAGE="${IMAGE:-docker.io/library/httpd:latest}"
NAME="${NAME:-httpd-hpack-cookie}"
HOST_PORT="${HOST_PORT:-10080}"

if [[ ! -s certs/server.crt || ! -s certs/server.key ]]; then
  ./setup_certs.sh
fi

podman run \
  --detach \
  --replace \
  --name "$NAME" \
  --publish "127.0.0.1:${HOST_PORT}:8443" \
  --volume "$PWD/httpd.conf:/usr/local/apache2/conf/httpd.conf:ro" \
  --volume "$PWD/htdocs:/usr/local/apache2/htdocs:ro" \
  --volume "$PWD/certs:/certs:ro" \
  "$IMAGE" \
  httpd-foreground

podman ps --filter "name=${NAME}"
