.PHONY: build run-full run-validator test check clean default-config help

# Build the pyde binary (release mode)
build:
	cargo build -p pyde-node --release

# Build in debug mode (faster compilation)
build-debug:
	cargo build -p pyde-node

# Run a full node
run-full:
	cargo run -p pyde-node -- run --role full

# Run a validator node
run-validator:
	cargo run -p pyde-node -- run --role validator

# Run a full node on a custom port
run-full-port:
	cargo run -p pyde-node -- run --role full --port $(PORT)

# Run with debug logging
run-debug:
	cargo run -p pyde-node -- run --role full --log-level debug

# Run with JSON logs
run-json:
	cargo run -p pyde-node -- run --role full --log-json

# Run from a config file
run-config:
	cargo run -p pyde-node -- run --config $(CONFIG)

# Print default configuration
default-config:
	cargo run -p pyde-node -- default-config

# Print default devnet genesis
default-genesis:
	cargo run -p pyde-node -- default-genesis

# Generate a genesis file
gen-genesis:
	cargo run -p pyde-node -- default-genesis > genesis.toml
	@echo "Genesis written to genesis.toml"

# Generate a config file
gen-config:
	cargo run -p pyde-node -- default-config > pyde.toml
	@echo "Config written to pyde.toml"

# Run all workspace tests
test:
	cargo test --workspace

# Run tests for a specific crate
test-crate:
	cargo test -p $(CRATE)

# Check compilation (no build artifacts)
check:
	cargo check --workspace --all-targets

# Format code
fmt:
	cargo fmt --all

# Benchmark RPC (requires running node: make run-full)
bench-rpc:
	cargo bench -p pyde-node

# Lint
clippy:
	cargo clippy --workspace --all-targets

# Clean build artifacts
clean:
	cargo clean

help:
	@echo "Pyde Blockchain Node"
	@echo ""
	@echo "Usage:"
	@echo "  make build            Build release binary"
	@echo "  make build-debug      Build debug binary"
	@echo "  make run-full         Run a full node (port 30303)"
	@echo "  make run-validator    Run a validator node (port 30303)"
	@echo "  make run-full-port PORT=31337  Run full node on custom port"
	@echo "  make run-debug        Run with debug logging"
	@echo "  make run-json         Run with JSON log output"
	@echo "  make run-config CONFIG=pyde.toml  Run from config file"
	@echo "  make default-config   Print default config to stdout"
	@echo "  make default-genesis  Print default devnet genesis to stdout"
	@echo "  make gen-config       Write default config to pyde.toml"
	@echo "  make gen-genesis      Write default genesis to genesis.toml"
	@echo "  make test             Run all tests"
	@echo "  make test-crate CRATE=pyde-vm  Run tests for one crate"
	@echo "  make bench-rpc        Benchmark RPC (requires running node)"
	@echo "  make check            Check compilation"
	@echo "  make fmt              Format code"
	@echo "  make clippy           Run linter"
	@echo "  make clean            Clean build artifacts"
