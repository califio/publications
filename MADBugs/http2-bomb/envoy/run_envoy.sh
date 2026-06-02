#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

IMAGE="${IMAGE:-docker.io/envoyproxy/envoy:v1.37-latest}"
NAME="${NAME:-envoy-hpack-cookie}"
HOST_PORT="${HOST_PORT:-10000}"
ADMIN_PORT="${ADMIN_PORT:-19901}"

if [[ ! -s certs/server.crt || ! -s certs/server.key ]]; then
  ./setup_certs.sh
fi

podman run \
  --detach \
  --replace \
  --name "$NAME" \
  --publish "127.0.0.1:${HOST_PORT}:10000" \
  --publish "127.0.0.1:${ADMIN_PORT}:9901" \
  --volume "$PWD/envoy.yaml:/etc/envoy/envoy.yaml:ro" \
  --volume "$PWD/certs:/certs:ro" \
  "$IMAGE" \
  -c /etc/envoy/envoy.yaml \
  --log-level warn

podman ps --filter "name=${NAME}"
