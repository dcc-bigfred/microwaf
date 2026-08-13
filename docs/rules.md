# MicroWAF rules (YAML + CEL)

Rules live in `<config-dir>/rules.d/*.yaml`, hot-reloaded via inotify / `SIGHUP`.

On first start the daemon creates `<config-dir>/`, `rules.d/`, seeds missing
`daemon.yaml` / `sets.yaml` / `rules.d/00-baseline.yaml`, and always rewrites the
sibling `*.example` files (documentation only — not loaded).

## Rule schema

```yaml
- id: http-rps-100
  protocol: http          # http | websocket | z21 | withrottle | udp | tcp
  ports: [80, 443]        # mandatory for parsed protocols; optional for udp/tcp
  metric: requests        # requests | bytes | connections
  window: per-second      # per-second | per-minute
  limit: 100
  action: { kind: throttle, dropRate: 50 }   # or { kind: block }
  minThreshold: 50
  match: 'request.method == "POST"'          # optional CEL
```

### Metric validity

| Protocol | Allowed metrics |
|----------|-----------------|
| `http`, `websocket`, `z21`, `withrottle` | `requests`, `bytes` |
| `udp`, `tcp` | `connections`, `bytes` |

Rules may **overlap** (same protocol+ports); each is counted independently per `(client, rule)`.

## CEL context

Common: `client.mac`, `client.ip`, `time.epoch`, `time.hour`, `time.dow`, `port`, `sets`.

| Protocol | Bindings |
|----------|----------|
| http | `request.method`, `request.path`, `request.headers`, `request.query` |
| websocket | `frame.fin`, `frame.opcode`, `frame.payloadLen` |
| z21 | `z21.header`, `z21.xheader`, `z21.dataLen`, `z21.data` |
| withrottle | `withrottle.prefix`, `withrottle.throttle`, `withrottle.command` |
| udp/tcp | common only |

## `sets.yaml`

```yaml
allowlist:
  - 10.0.0.0/8
blocked:
  - 203.0.113.0/24
```

Referenced as `client.ip in sets.allowlist`.

## `daemon.yaml`

```yaml
mode: enforce
interface: any    # default; or a specific NIC name (e.g. eth0)
cooldownSecs: 30
statsSnapshotSecs: 5
allowUsers: [root, bigfred, bigfred-wizard]
```

`mode` is **not** hot-reloadable (restart required). `interface` is validated at
startup: a missing NIC aborts the daemon; `any` binds AF_PACKET to all
interfaces (and, in enforce mode with eBPF enabled, attaches XDP to every
non-loopback NIC).
