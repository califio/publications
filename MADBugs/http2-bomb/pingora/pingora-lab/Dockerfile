FROM rust:1.95-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates build-essential pkg-config cmake perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pingora-lab/Cargo.toml ./pingora-lab/Cargo.toml
COPY pingora-lab/Cargo.lock ./pingora-lab/Cargo.lock
COPY pingora-lab/src ./pingora-lab/src
WORKDIR /src/pingora-lab
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates procps python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/pingora-lab/target/release/pingora-hpack-lab /usr/local/bin/pingora-hpack-lab
COPY attacker/monitor_rss.py /poc/monitor_rss.py

EXPOSE 6145
CMD ["/usr/local/bin/pingora-hpack-lab"]
