#!/bin/bash
set -e

DATADIR="${PYDE_DATADIR:-/data}"
NODE_INDEX="${NODE_INDEX:-0}"
VALIDATORS="${VALIDATORS:-4}"
BASE_PORT="${BASE_PORT:-30303}"
BASE_RPC="${BASE_RPC:-8545}"
DEV_MODE="${DEV_MODE:-true}"
CHAIN_ID="${CHAIN_ID:-31337}"

CONFIG="$DATADIR/config.toml"

if [ "$NODE_INDEX" = "0" ] && [ ! -f "$CONFIG" ]; then
    echo "Node-0: Generating testnet with $VALIDATORS validators..."
    pyde testnet \
        --validators "$VALIDATORS" \
        --out /testnet \
        --base-port "$BASE_PORT" \
        --base-rpc-port "$BASE_RPC" \
        --chain-id "$CHAIN_ID" \
        $([ "$DEV_MODE" = "true" ] && echo "--dev")

    # Fix configs for Docker networking:
    # 1. Replace 127.0.0.1 bootstrap IPs with Docker container IPs (172.20.0.1X)
    # 2. Change RPC listen from 127.0.0.1 to 0.0.0.0 (accessible from host)
    for i in $(seq 0 $((VALIDATORS - 1))); do
        NODE_DIR="/testnet/node-${i}"
        if [ -f "$NODE_DIR/config.toml" ]; then
            # Replace bootstrap IPs: 127.0.0.1 → 172.20.0.1X
            for j in $(seq 0 $((VALIDATORS - 1))); do
                DOCKER_IP="172.20.0.1${j}"
                PORT=$((BASE_PORT + j))
                sed -i "s|/ip4/127.0.0.1/udp/${PORT}/|/ip4/${DOCKER_IP}/udp/${PORT}/|g" "$NODE_DIR/config.toml"
            done
            # RPC: bind to all interfaces
            sed -i 's|listen = "127.0.0.1"|listen = "0.0.0.0"|' "$NODE_DIR/config.toml"
        fi
    done

    cp /testnet/node-0/* "$DATADIR/"
    echo "Node-0: Testnet generated."
fi

# Wait for config (other nodes wait for node-0)
if [ "$NODE_INDEX" != "0" ]; then
    NODE_DIR="/testnet/node-${NODE_INDEX}"
    echo "Node-$NODE_INDEX: Waiting for testnet config..."
    for i in $(seq 1 30); do
        if [ -f "$NODE_DIR/config.toml" ]; then
            cp "$NODE_DIR"/* "$DATADIR/"
            echo "Node-$NODE_INDEX: Config loaded."
            break
        fi
        sleep 1
    done
    if [ ! -f "$DATADIR/config.toml" ]; then
        echo "Node-$NODE_INDEX: ERROR — config not found after 30s"
        exit 1
    fi
    # Fix RPC listen and bootstrap IPs in our own copy
    sed -i 's|listen = "127.0.0.1"|listen = "0.0.0.0"|' "$DATADIR/config.toml"
    for j in $(seq 0 $((${VALIDATORS:-4} - 1))); do
        DOCKER_IP="172.20.0.1${j}"
        PORT=$((BASE_PORT + j))
        sed -i "s|/ip4/127.0.0.1/udp/${PORT}/|/ip4/${DOCKER_IP}/udp/${PORT}/|g" "$DATADIR/config.toml"
    done
fi

# Override datadir in config
sed -i "s|datadir = .*|datadir = \"$DATADIR\"|" "$DATADIR/config.toml"

# Build args
ARGS="run --role validator --config $DATADIR/config.toml --datadir $DATADIR"
if [ "$DEV_MODE" = "true" ]; then
    ARGS="$ARGS --dev"
fi

echo "Node-$NODE_INDEX: Starting pyde..."
exec pyde $ARGS
