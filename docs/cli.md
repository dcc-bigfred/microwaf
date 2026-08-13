# MicroWAF CLI

Single binary: daemon + client subcommands.

```bash
microwaf [--socket PATH] [--verbose] [COMMAND]
```

With no subcommand (or `daemon`), the process runs the daemon.

## Global flags

| Flag | Env | Notes |
|------|-----|-------|
| `--socket` | `MICROWAF_SOCKET` | Unix socket path |
| `-v` / `--verbose` | | debug logging |

## Daemon flags

| Flag | Env | Notes |
|------|-----|-------|
| `-i` / `--interface` | `MICROWAF_INTERFACE` | NIC for XDP / AF_PACKET. Use `any` to sniff on all interfaces (daemon refuses to start if a named NIC does not exist). |
| `--redis-url` | `MICROWAF_REDIS_URL` | default `redis://127.0.0.1:6379/0` |
| `--config-dir` | `MICROWAF_CONFIG_DIR` | default `$BIGFRED_DATA_DIR/etc/microwaf` |
| `--mode` | `MICROWAF_MODE` | `enforce` (default) \| `permissive` (startup only) |

## Client subcommands

```bash
microwaf info [--json]
microwaf top -n 10 [--rule-id ID] [--protocol P] [--metric M] [--interval 500ms] [--once] [--json]
microwaf clients [--json]
microwaf rules [--json]
microwaf throttle MAC[@IP] [-d DURATION] [--rate 50]
microwaf unthrottle MAC[@IP]
microwaf block MAC[@IP] [-d DURATION]
microwaf unblock MAC[@IP]
```

Client identity: `aa:bb:cc:dd:ee:ff` or `aa:bb:cc:dd:ee:ff@10.0.0.1`.

`--duration` / `-d` accepts humantime values (`30s`, `5m`). Omit for permanent.

### `top`

On a TTY, `top` shows a live table refreshed every `--interval` (default `500ms`), like htop. Press `q` or Ctrl+C to quit. Use `--once` for a single snapshot, or `--json` for machine-readable output (also one-shot). Non-TTY stdout always prints one snapshot.

Rows are ranked **hot first** (any matching rule ≥ `minThreshold`, marked `*`), then the rest of known clients. `-n 0` (default) shows everyone; set `-n N` to cap the list.

## Examples

```bash
# permissive dry-run
microwaf --mode permissive --interface eth0 --config-dir ./config

# top HTTP offenders (live table; q to quit)
microwaf top -n 20 --protocol http --metric requests
# single snapshot
microwaf top -n 20 --once --protocol http

# temporary block
microwaf block aa:bb:cc:dd:ee:ff@192.168.1.10 -d 5m
```
