# MicroWAF Unix socket API

Canonical wire protocol for the MicroWAF daemon. Consumed by the Rust `mw-client`, the Go SDK (`go/client`), and third-party integrators.

## Transport

- **Socket:** Unix domain socket
- **Default path:** `$BIGFRED_DATA_DIR/run/microwaf/microwaf.sock` (fallback `/data/run/microwaf/microwaf.sock`)
- **Mode:** `0660`, owned by the daemon's group
- **Auth:** `SO_PEERCRED` + username allowlist (`daemon.yaml` `allowUsers`, default `root,bigfred,bigfred-wizard`). UID 0 (`root`) is always allowed regardless of the allowlist.

## Framing

Each message is:

```
[4-byte little-endian u32 length][UTF-8 JSON body]
```

- `MAX_FRAME_BYTES = 1 MiB`
- Oversized frames are rejected
- One request → one response per round-trip (clients may pipeline; the daemon answers in order)

## Envelope

```json
{
  "type": "info",
  "params": { }
}
```

```json
{
  "type": "info",
  "result": { ... },
  "error": null
}
```

On failure:

```json
{
  "type": "info",
  "error": { "code": "forbidden", "message": "..." }
}
```

Error codes: `forbidden`, `notFound`, `invalid`, `busy`.

Field names are **camelCase**.

## Methods

### `info`

Returns daemon version and run mode.

**Response `result`:**

| Field | Type | Notes |
|-------|------|-------|
| `version` | string | `dev` or release tag |
| `commit` | string | build git SHA |
| `buildTime` | string | ISO-8601 when set |
| `mode` | string | `enforce` \| `permissive` |
| `interface` | string | NIC name |

### `top`

Ranked clients for a live/htop-style view: hot band (any matching rule ≥
`minThreshold`) first, then the rest, both sorted by windowed value descending.
`limit` 0 = unlimited.

**Params:**

| Field | Type | Notes |
|-------|------|-------|
| `limit` | number | max rows (`0` = all) |
| `ruleId` | string? | filter |
| `protocol` | string? | `http`/`websocket`/`z21`/`withrottle`/`udp`/`tcp` |
| `metric` | string? | `requests`/`bytes`/`connections` |

**Result:** `{ "clients": [ ClientEntry, ... ], "columns": [ TopColumn, ... ] }`

`columns` lists matching rules (header order). Each client's `violations` aligns
with `columns` and includes zeros. Display rates as `N/s` (`per-second`) or
`N/m` (`per-minute`).

### `listClients`

Lists known clients with effective / would-be actions and diagnostic stats.

### `listRules`

Read-only list of loaded rules (from YAML config).

### `throttle` / `unthrottle`

Manual throttle overlay.

**Params (`throttle`):** `{ "client": { "mac": "aa:..", "ip": "1.2.3.4" }, "rate": 50, "durationSecs": 60 }`

Omit `durationSecs` for a permanent policy.

### `block` / `unblock`

Manual block overlay. Same client shape; `block` accepts optional `durationSecs`.

## ClientEntry

| Field | Type | Notes |
|-------|------|-------|
| `client` | `{mac, ip?}` | identity |
| `action` | ActionWire? | effective action in enforce mode |
| `wouldBeAction` | ActionWire? | set in permissive mode |
| `violations` | array | `top`: non-zero rule observations |
| `hot` | bool | `top`: above `minThreshold` band |
| `stats` | object? | cumulative diagnostics |

## ActionWire

```json
{ "kind": "throttle", "dropRate": 50 }
{ "kind": "block" }
{ "kind": "none" }
```

## Versioning

`info` carries `version` / `commit` / `buildTime` / `mode`. Breaking wire changes bump the daemon major and are documented here.
