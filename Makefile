.PHONY: all ebpf daemon ui test run-daemon run-ui simulate-attack clean

SHELL := /bin/bash
CARGO := cargo

all: ebpf daemon test

## Build release eBPF bytecode targeting bpfel-unknown-none
ebpf:
	@echo "==> Compiling Ring-0 eBPF Probes (bpfel-unknown-none)..."
	cargo +nightly build --manifest-path crates/soc-ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core --release

## Build Ring-3 Userspace Daemon
daemon: ebpf
	@echo "==> Compiling Userspace Daemon (soc-daemon)..."
	cargo build --workspace

## Run all automated unit and integration tests
test:
	@echo "==> Running Automated Rust Test Suite..."
	cargo test --workspace
	@echo "==> Running Flutter UI Analysis..."
	cd apps/soc_dashboard && flutter analyze

## Run the daemon with simulation fallback (unprivileged)
run-daemon:
	cargo run --bin soc-daemon -- --simulate-kernel-if-unprivileged

## Run the daemon in live mode (requires sudo / CAP_BPF)
run-daemon-live:
	sudo ./target/debug/soc-daemon --socket-path /tmp/dirtysocs.sock

## Run the Flutter Linux Desktop GUI
run-ui:
	cd apps/soc_dashboard && flutter run -d linux

## Run the attack simulation script
simulate-attack:
	./scripts/simulate_attack.sh

## Clean build artifacts and test outputs
clean:
	cargo clean
	rm -rf output/dossiers/*
