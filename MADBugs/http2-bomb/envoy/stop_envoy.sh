#!/usr/bin/env bash
set -euo pipefail

NAME="${NAME:-envoy-hpack-cookie}"
podman rm -f "$NAME"
