#!/usr/bin/env bash
set -euo pipefail

NAME="${NAME:-httpd-hpack-cookie}"
podman rm -f "$NAME"
