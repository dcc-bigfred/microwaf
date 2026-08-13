package client

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// DefaultSocket is the daemon socket when DATA_DIR is /data.
	DefaultSocket  = "/data/run/microwaf/microwaf.sock"
	maxFrameBytes  = 1024 * 1024
	defaultTimeout = 10 * time.Second
)

var (
	// ErrForbidden is returned when SO_PEERCRED auth rejects the caller.
	ErrForbidden = errors.New("forbidden")
	// ErrNotFound is returned when a referenced object does not exist.
	ErrNotFound = errors.New("not found")
	// ErrInvalid is returned for malformed requests.
	ErrInvalid = errors.New("invalid")
	// ErrBusy is returned under contention.
	ErrBusy = errors.New("busy")
)

// Client talks to a microwaf daemon over a Unix socket.
type Client struct {
	Socket  string
	Timeout time.Duration
	// Dial is a test hook; nil uses net.DialTimeout.
	Dial func(network, address string, timeout time.Duration) (net.Conn, error)
}

func (c *Client) dial() (net.Conn, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	socket := c.Socket
	if socket == "" {
		socket = DefaultSocket
	}
	dial := c.Dial
	if dial == nil {
		dial = net.DialTimeout
	}
	return dial("unix", socket, timeout)
}

func (c *Client) roundTrip(req any, resp any) error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := writeFrame(conn, req); err != nil {
		return err
	}
	return readFrame(conn, resp)
}

func writeFrame(w io.Writer, msg any) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(payload) > maxFrameBytes {
		return fmt.Errorf("frame too large: %d > %d", len(payload), maxFrameBytes)
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

func readFrame(r io.Reader, out any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if int(n) > maxFrameBytes {
		return fmt.Errorf("frame too large: %d > %d", n, maxFrameBytes)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, out)
}

// Request mirrors mw_proto::Request.
type Request struct {
	Type   string `json:"type"`
	Params any    `json:"params,omitempty"`
}

// Response mirrors mw_proto::Response.
type Response struct {
	Type   string          `json:"type"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *ErrorBody      `json:"error,omitempty"`
}

// ErrorBody mirrors mw_proto::ErrorBody.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func mapError(e *ErrorBody) error {
	if e == nil {
		return nil
	}
	switch e.Code {
	case "forbidden":
		return fmt.Errorf("%w: %s", ErrForbidden, e.Message)
	case "notFound":
		return fmt.Errorf("%w: %s", ErrNotFound, e.Message)
	case "invalid":
		return fmt.Errorf("%w: %s", ErrInvalid, e.Message)
	case "busy":
		return fmt.Errorf("%w: %s", ErrBusy, e.Message)
	default:
		return fmt.Errorf("%s: %s", e.Code, e.Message)
	}
}

// InfoResult mirrors mw_proto::InfoResult.
type InfoResult struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildTime string `json:"buildTime,omitempty"`
	Mode      string `json:"mode"`
	Interface string `json:"interface,omitempty"`
}

// ClientRef mirrors mw_proto::ClientRef.
type ClientRef struct {
	MAC string  `json:"mac"`
	IP  *string `json:"ip,omitempty"`
}

// TopParams mirrors mw_proto::TopParams.
type TopParams struct {
	Limit    int     `json:"limit"`
	RuleID   *string `json:"ruleId,omitempty"`
	Protocol *string `json:"protocol,omitempty"`
	Metric   *string `json:"metric,omitempty"`
}

// ActionWire mirrors mw_proto::ActionWire.
type ActionWire struct {
	Kind     string `json:"kind"`
	DropRate *uint8 `json:"dropRate,omitempty"`
}

// ViolationWire mirrors mw_proto::ViolationWire.
type ViolationWire struct {
	RuleID string     `json:"ruleId"`
	Value  uint64     `json:"value"`
	Limit  uint64     `json:"limit"`
	Action ActionWire `json:"action"`
}

// ClientStats mirrors mw_proto::ClientStatsWire.
type ClientStats struct {
	Requests      uint64 `json:"requests"`
	Bytes         uint64 `json:"bytes"`
	Connections   uint64 `json:"connections"`
	WSConnections uint64 `json:"wsConnections"`
}

// ClientEntry mirrors mw_proto::ClientEntry.
type ClientEntry struct {
	Client        ClientRef       `json:"client"`
	Action        *ActionWire     `json:"action,omitempty"`
	WouldBeAction *ActionWire     `json:"wouldBeAction,omitempty"`
	Violations    []ViolationWire `json:"violations,omitempty"`
	Hot           bool            `json:"hot,omitempty"`
	Stats         *ClientStats    `json:"stats,omitempty"`
}

// TopResult / ClientsResult mirrors mw_proto::ClientsResult.
type TopResult struct {
	Clients []ClientEntry `json:"clients"`
	Columns []TopColumn   `json:"columns,omitempty"`
}

// ClientsResult mirrors mw_proto::ClientsResult.
type ClientsResult struct {
	Clients []ClientEntry `json:"clients"`
	Columns []TopColumn   `json:"columns,omitempty"`
}

// TopColumn mirrors mw_proto::TopColumn.
type TopColumn struct {
	RuleID        string `json:"ruleId"`
	Window        string `json:"window"`
	Limit         uint64 `json:"limit"`
	MinThreshold  uint64 `json:"minThreshold"`
}

// RuleWire mirrors mw_proto::RuleWire.
type RuleWire struct {
	ID           string     `json:"id"`
	Protocol     string     `json:"protocol"`
	Ports        []uint16   `json:"ports,omitempty"`
	Metric       string     `json:"metric"`
	Window       string     `json:"window"`
	Limit        uint64     `json:"limit"`
	Action       ActionWire `json:"action"`
	MinThreshold uint64     `json:"minThreshold"`
	Match        *string    `json:"match,omitempty"`
}

// RulesResult mirrors mw_proto::RulesResult.
type RulesResult struct {
	Rules []RuleWire `json:"rules"`
}

func (c *Client) call(kind string, params any, result any) error {
	var resp Response
	if err := c.roundTrip(Request{Type: kind, Params: params}, &resp); err != nil {
		return err
	}
	if err := mapError(resp.Error); err != nil {
		return err
	}
	if result == nil {
		return nil
	}
	if len(resp.Result) == 0 {
		return fmt.Errorf("missing result")
	}
	return json.Unmarshal(resp.Result, result)
}

// Info returns daemon version and mode.
func (c *Client) Info() (*InfoResult, error) {
	var out InfoResult
	if err := c.call("info", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Top returns ranked clients (hot band first, then the rest).
func (c *Client) Top(p TopParams) (*TopResult, error) {
	var out TopResult
	if err := c.call("top", p, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListClients lists known clients.
func (c *Client) ListClients() (*ClientsResult, error) {
	var out ClientsResult
	if err := c.call("listClients", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListRules lists loaded rules.
func (c *Client) ListRules() (*RulesResult, error) {
	var out RulesResult
	if err := c.call("listRules", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ThrottleParams mirrors mw_proto::ThrottleParams.
type ThrottleParams struct {
	Client       ClientRef `json:"client"`
	Rate         *uint8    `json:"rate,omitempty"`
	DurationSecs *uint64   `json:"durationSecs,omitempty"`
}

// BlockParams mirrors mw_proto::BlockParams.
type BlockParams struct {
	Client       ClientRef `json:"client"`
	DurationSecs *uint64   `json:"durationSecs,omitempty"`
}

// Throttle sets a manual throttle.
func (c *Client) Throttle(p ThrottleParams) error {
	return c.call("throttle", p, &map[string]any{})
}

// Unthrottle clears a manual throttle.
func (c *Client) Unthrottle(client ClientRef) error {
	return c.call("unthrottle", map[string]any{"client": client}, &map[string]any{})
}

// Block sets a manual block.
func (c *Client) Block(p BlockParams) error {
	return c.call("block", p, &map[string]any{})
}

// Unblock clears a manual block.
func (c *Client) Unblock(client ClientRef) error {
	return c.call("unblock", map[string]any{"client": client}, &map[string]any{})
}
