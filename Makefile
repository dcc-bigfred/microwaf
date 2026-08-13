.PHONY: all build release release-musl check test test-release-assertions fmt clippy clean ebpf ebpf-setup

CARGO ?= cargo
TARGET_MUSL ?= aarch64-unknown-linux-musl
DIST ?= dist
BIN ?= microwaf
NIGHTLY ?= nightly
# Ensure cargo-installed tools (bpf-linker) are visible.
export PATH := $(HOME)/.cargo/bin:$(PATH)

all: build

# Host binary includes the `ebpf` feature by default (aya XDP loader).
build: ebpf
	$(CARGO) build --workspace

# One-time deps for the BPF object: nightly + rust-src + bpf-linker.
# bpf-linker is the official musl binary (cargo install needs system LLVM).
ebpf-setup:
	rustup toolchain install $(NIGHTLY) --profile minimal
	rustup component add rust-src --toolchain $(NIGHTLY)
	./scripts/install-bpf-linker.sh

# Build the XDP object into workspace `target/bpfel-unknown-none/release/libmw_ebpf.so`.
# Must run inside crates/mw-ebpf so its `.cargo/config.toml` applies (panic=abort, build-std).
ebpf:
	@command -v rustup >/dev/null || (echo "error: rustup required"; exit 1)
	@rustup run $(NIGHTLY) rustc --version >/dev/null 2>&1 || \
		(echo "error: nightly toolchain missing — run: make ebpf-setup"; exit 1)
	@rustup component list --toolchain $(NIGHTLY) --installed 2>/dev/null | grep -qx 'rust-src' || \
		(echo "error: nightly rust-src missing — run: make ebpf-setup"; exit 1)
	@command -v bpf-linker >/dev/null || \
		(echo "error: bpf-linker not on PATH — run: make ebpf-setup (and ensure ~/.cargo/bin is on PATH)"; exit 1)
	cd crates/mw-ebpf && $(CARGO) +$(NIGHTLY) build --target-dir ../../target --release
	@test -f target/bpfel-unknown-none/release/libmw_ebpf.so || \
		(echo "error: BPF object not produced at target/bpfel-unknown-none/release/libmw_ebpf.so"; exit 1)
	@echo "BPF object: target/bpfel-unknown-none/release/libmw_ebpf.so"

release: ebpf
	$(CARGO) build --workspace --release
	mkdir -p $(DIST)
	cp target/release/$(BIN) $(DIST)/$(BIN)
	@echo "BPF object is embedded in $(DIST)/$(BIN) (override/extract via MICROWAF_BPF_OBJECT / MICROWAF_BPF_EXTRACT)"

release-musl: ebpf
	RUSTFLAGS='-C target-feature=+crt-static' \
	  $(CARGO) build -p microwaf --release --target $(TARGET_MUSL)
	mkdir -p $(DIST)
	cp target/$(TARGET_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-$(shell echo $(TARGET_MUSL) | cut -d- -f1 | sed 's/aarch64/arm64/;s/x86_64/amd64/')
	@echo "BPF object is embedded in the musl binary"

check:
	$(CARGO) check --workspace

test:
	$(CARGO) test --workspace

test-release-assertions:
	$(CARGO) test --workspace --profile release-assertions

fmt:
	$(CARGO) fmt --all

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

clean:
	$(CARGO) clean
	rm -rf $(DIST)
