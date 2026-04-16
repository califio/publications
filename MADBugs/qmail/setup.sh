#!/bin/bash
# Setup script for qmail v2026.04.02 vulnerability research environment
# This script builds and runs qmail in a Docker container.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Clone qmail source if not present
if [ ! -d "$SCRIPT_DIR/qmail" ]; then
    for i in 1 2 3; do
        git clone https://github.com/sagredo-dev/qmail.git "$SCRIPT_DIR/qmail" && break
        echo "Clone attempt $i failed, retrying in $((i*5))s..."
        sleep $((i*5))
    done
fi

cd "$SCRIPT_DIR/qmail"
git checkout v2026.04.02

# Build Docker image (with retry for transient failures)
cd "$SCRIPT_DIR"
for i in 1 2 3; do
    docker build -t qmail-build -f Dockerfile . && break
    echo "Docker build attempt $i failed, retrying in $((i*10))s..."
    sleep $((i*10))
done

# Run container
docker rm -f qmail-test 2>/dev/null || true
docker run -d --name qmail-test qmail-build

echo "qmail v2026.04.02 is built and running in container 'qmail-test'"
echo "Source code: /usr/src/qmail/ (inside container)"
echo "Install dir: /var/qmail/ (inside container)"
echo "Key binaries: qmail-smtpd, qmail-local, qmail-remote, qmail-inject, qmail-queue"
