# Stage 1: Build the pyde-node binary
FROM rust:1.95-bookworm AS builder

# Install build dependencies (libclang for bindgen/RocksDB, cmake for aws-lc)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang libclang-dev cmake pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Build release binary
RUN cargo build --release -p pyde-node && \
    cp target/release/pyde /usr/local/bin/pyde

# Stage 2: Slim runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/pyde /usr/local/bin/pyde

# Copy Docker runtime files
COPY docker/entrypoint.sh /docker/entrypoint.sh
COPY docker/prometheus.yml /docker/prometheus.yml
COPY docker/grafana/ /docker/grafana/
RUN chmod +x /docker/entrypoint.sh

# Default data directory
RUN mkdir -p /data /testnet
ENV PYDE_DATADIR=/data

EXPOSE 30303/udp 8545 8546 9090
# 8545 — JSON-RPC; 8546 — WebSocket subscriptions (`rpc.port + 1`,
# bound by `crates/node/src/node.rs`); 9090 — Prometheus metrics.

ENTRYPOINT ["pyde"]
CMD ["run", "--role", "validator", "--datadir", "/data", "--log-level", "info"]
