#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p certs

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -sha256 \
  -days 30 \
  -subj "/CN=localhost" \
  -keyout certs/server.key \
  -out certs/server.crt
