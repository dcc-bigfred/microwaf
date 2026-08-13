# MicroWAF

Lightweight host-side WAF for Linux (Raspberry Pi / arm64). Counts L7 traffic
(HTTP, WebSocket, Z21, WiThrottle) and generic UDP/TCP per client MAC+IP, then
throttles or blocks offenders via XDP drop rates.

## Layout

```
crates/
  mw-proto     # Unix-socket wire protocol
  mw-core      # rules engine, CEL, policy, windows
  mw-sniffer   # pure L7 detectors
  mw-store     # Redis persistence (write-only at runtime)
  mw-client    # Rust SDK
  mw-ebpf      # XDP program (built via `make ebpf` / nightly)
  microwaf     # daemon + CLI (ebpf/XDP loader enabled by default)
go/client      # Go SDK
docs/          # api, cli, rules, architecture, go-client
```

## Build

```bash
# one-time eBPF toolchain
make ebpf-setup     # nightly + rust-src + bpf-linker

make build          # BPF object + host crates (XDP bytes embedded in microwaf)
make test
make release-musl   # static musl binary → dist/ (BPF embedded; single artifact)

# userspace-only (no aya / no embedded BPF):
cargo build -p microwaf --no-default-features
```

At runtime the daemon loads the embedded XDP object from memory. Optional env:

| Env | Notes |
|-----|-------|
| `MICROWAF_BPF_OBJECT` | Load this file instead of the embedded object |
| `MICROWAF_BPF_EXTRACT` | Write the embedded object to this path (debug) |

## Run

```bash
# config
mkdir -p /data/etc/microwaf/rules.d
cp config/daemon.yaml /data/etc/microwaf/
cp config/rules.d/*.yaml /data/etc/microwaf/rules.d/

# daemon (permissive first)
sudo microwaf --mode permissive --config-dir /data/etc/microwaf
# default interface is `any` (all NICs); override with -i eth0 if needed

# CLI
microwaf info
microwaf top -n 10 --protocol z21
microwaf block aa:bb:cc:dd:ee:ff@10.0.0.5 -d 5m
```

## Docs

- [Architecture](docs/architecture.md)
- [Unix socket API](docs/api.md)
- [CLI](docs/cli.md)
- [Rules (YAML + CEL)](docs/rules.md)
- [Go client](docs/go-client.md)

## License

MIT
