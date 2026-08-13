# MicroWAF Go client

```bash
go get github.com/dcc-bigfred/microwaf/go/client
```

```go
package main

import (
    "fmt"
    "github.com/dcc-bigfred/microwaf/go/client"
)

func main() {
    c := &client.Client{Socket: client.DefaultSocket}
    info, err := c.Info()
    if err != nil {
        panic(err)
    }
    fmt.Println(info.Version, info.Mode)
}
```

## Methods

| Method | Wire type |
|--------|-----------|
| `Info()` | `info` |
| `Top(TopParams)` | `top` |
| `ListClients()` | `listClients` |
| `ListRules()` | `listRules` |
| `Throttle(ThrottleParams)` | `throttle` |
| `Unthrottle(ClientRef)` | `unthrottle` |
| `Block(BlockParams)` | `block` |
| `Unblock(ClientRef)` | `unblock` |

Sentinel errors: `ErrForbidden`, `ErrNotFound`, `ErrInvalid`, `ErrBusy`.

Framing and schema are documented in [api.md](api.md).
