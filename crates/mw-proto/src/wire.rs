//! Request/response envelope and typed wire bodies for MicroWAF IPC.

use serde::{Deserialize, Serialize};

/// Top-level request envelope. `type` selects the method; `params` carries arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// Method selector.
    #[serde(rename = "type")]
    pub kind: RequestKind,
    /// Method parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Params>,
}

impl Request {
    /// Construct a request with no params.
    #[must_use]
    pub fn new(kind: RequestKind) -> Self {
        Self { kind, params: None }
    }

    /// Construct a request with params.
    #[must_use]
    pub fn with_params(kind: RequestKind, params: Params) -> Self {
        Self {
            kind,
            params: Some(params),
        }
    }
}

/// Top-level response envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    /// Method selector mirrored from the request.
    #[serde(rename = "type")]
    pub kind: RequestKind,
    /// Result on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultBody>,
    /// Error on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    /// Successful response.
    #[must_use]
    pub fn ok(kind: RequestKind, result: ResultBody) -> Self {
        Self {
            kind,
            result: Some(result),
            error: None,
        }
    }

    /// Error response.
    #[must_use]
    pub fn err(kind: RequestKind, error: ErrorBody) -> Self {
        Self {
            kind,
            result: None,
            error: Some(error),
        }
    }
}

/// A typed error returned over the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    /// Machine-readable error code (`forbidden`, `notFound`, `invalid`, `busy`).
    pub code: String,
    /// Human-readable message.
    pub message: String,
}

impl ErrorBody {
    /// Construct an error body.
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    /// Forbidden (auth failure).
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new("forbidden", message)
    }

    /// Not found.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("notFound", message)
    }

    /// Invalid request.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid", message)
    }

    /// Busy / contention.
    pub fn busy(message: impl Into<String>) -> Self {
        Self::new("busy", message)
    }
}

/// Supported request methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RequestKind {
    /// `info`: daemon version + mode.
    Info,
    /// `top`: top-N clients exceeding min thresholds.
    Top,
    /// `listClients`: list known clients and their policies/stats.
    ListClients,
    /// `throttle`: set manual throttle for a client.
    Throttle,
    /// `unthrottle`: clear manual throttle.
    Unthrottle,
    /// `block`: set manual block for a client.
    Block,
    /// `unblock`: clear manual block.
    Unblock,
    /// `listRules`: list loaded rules (read-only).
    ListRules,
}

/// Method parameters (tagged by request kind).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Params {
    /// Arguments for [`RequestKind::Top`].
    Top(TopParams),
    /// Arguments for [`RequestKind::Throttle`].
    Throttle(ThrottleParams),
    /// Arguments for [`RequestKind::Unthrottle`] / [`RequestKind::Unblock`].
    Client(ClientParams),
    /// Arguments for [`RequestKind::Block`].
    Block(BlockParams),
}

/// `top` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopParams {
    /// Max clients to return.
    pub limit: usize,
    /// Optional rule id filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Optional protocol filter (`http`, `websocket`, `z21`, `withrottle`, `udp`, `tcp`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Optional metric filter (`requests`, `bytes`, `connections`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<String>,
}

/// Client identity on the wire: `aa:bb:cc:dd:ee:ff` or `aa:bb:cc:dd:ee:ff@1.2.3.4`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientRef {
    /// MAC address string (`aa:bb:cc:dd:ee:ff`).
    pub mac: String,
    /// Optional IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

/// Parameters that only carry a client ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientParams {
    /// Target client.
    pub client: ClientRef,
}

/// `throttle` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThrottleParams {
    /// Target client.
    pub client: ClientRef,
    /// Drop rate 0..=100. Default 50 when omitted by the daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<u8>,
    /// Duration in seconds; omitted = permanent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
}

/// `block` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockParams {
    /// Target client.
    pub client: ClientRef,
    /// Duration in seconds; omitted = permanent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
}

/// Successful result body (tagged by request kind via outer envelope).
///
/// Note: `top` and `listClients` share the same JSON shape (`{ "clients": [...] }`),
/// so they use a single untagged variant [`ResultBody::Clients`]. Discriminating by
/// request `type` is the caller's job (see `mw-client`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResultBody {
    /// `info` result.
    Info(InfoResult),
    /// `top` / `listClients` result (identical wire shape).
    Clients(ClientsResult),
    /// `listRules` result.
    Rules(RulesResult),
    /// Empty success (`throttle`/`unthrottle`/`block`/`unblock`).
    Empty(EmptyResult),
}

/// Empty success payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EmptyResult {}

/// `info` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResult {
    /// Release version (`dev` when unset).
    pub version: String,
    /// Build git commit.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub commit: String,
    /// Build time (ISO-8601) when available.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build_time: String,
    /// Run mode: `enforce` or `permissive`.
    pub mode: String,
    /// Network interface the daemon is attached to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub interface: String,
}

/// Shared payload for `top` and `listClients`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientsResult {
    /// Clients.
    pub clients: Vec<ClientEntry>,
    /// `top` only: one column per matching rule (order matches `violations`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<TopColumn>,
}

/// `top` result (same wire shape as [`ClientsResult`]).
pub type TopResult = ClientsResult;

/// Column metadata for a `top` rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopColumn {
    /// Rule id (column header).
    pub rule_id: String,
    /// Window (`per-second` / `per-minute`) — display as `/s` or `/m`.
    pub window: String,
    /// Rule limit.
    pub limit: u64,
    /// Hot-band floor.
    pub min_threshold: u64,
}

/// A client row in `top` / `listClients`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientEntry {
    /// Client identity.
    pub client: ClientRef,
    /// Effective action currently applied (`throttle`/`block`/`none`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionWire>,
    /// In permissive mode: the action that *would* have been applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub would_be_action: Option<ActionWire>,
    /// Per-rule windowed values aligned with [`ClientsResult::columns`] for `top`
    /// (includes zeros).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<ViolationWire>,
    /// `top` only: client is in the hot band (some rule ≥ `minThreshold`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hot: bool,
    /// Optional diagnostic counters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<ClientStatsWire>,
}

/// Wire representation of an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ActionWire {
    /// Throttle with drop rate.
    #[serde(rename = "throttle")]
    Throttle {
        /// Drop percentage 0..=100.
        #[serde(rename = "dropRate")]
        drop_rate: u8,
    },
    /// Full block.
    #[serde(rename = "block")]
    Block,
    /// No action.
    #[serde(rename = "none")]
    None,
}

/// A rule violation snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViolationWire {
    /// Rule id.
    pub rule_id: String,
    /// Observed windowed value.
    pub value: u64,
    /// Rule limit.
    pub limit: u64,
    /// Action prescribed by the rule.
    pub action: ActionWire,
}

/// Diagnostic client stats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClientStatsWire {
    /// Cumulative requests across rules (diagnostic).
    #[serde(default)]
    pub requests: u64,
    /// Cumulative bytes across rules (diagnostic).
    #[serde(default)]
    pub bytes: u64,
    /// Cumulative connections across rules (diagnostic).
    #[serde(default)]
    pub connections: u64,
    /// WebSocket handshakes (diagnostic).
    #[serde(default)]
    pub ws_connections: u64,
}

/// `listRules` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RulesResult {
    /// Loaded rules.
    pub rules: Vec<RuleWire>,
}

/// A rule as returned by `listRules`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleWire {
    /// Rule id.
    pub id: String,
    /// Protocol.
    pub protocol: String,
    /// Ports (empty = all for udp/tcp).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Metric.
    pub metric: String,
    /// Window.
    pub window: String,
    /// Limit.
    pub limit: u64,
    /// Action.
    pub action: ActionWire,
    /// Min threshold for `top`.
    pub min_threshold: u64,
    /// Optional CEL match expression (source text).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#match: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_request_round_trips() {
        let req = Request::new(RequestKind::Info);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""type":"info""#));
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn top_params_camel_case() {
        let params = TopParams {
            limit: 10,
            rule_id: Some("http-rps-100".into()),
            protocol: Some("http".into()),
            metric: Some("requests".into()),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains("ruleId"));
        assert!(json.contains("protocol"));
        let back: TopParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, params);
    }

    #[test]
    fn action_wire_tagged() {
        let a = ActionWire::Throttle { drop_rate: 50 };
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains(r#""kind":"throttle""#));
        assert!(json.contains(r#""dropRate":50"#));
        let back: ActionWire = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn clients_and_top_share_result_body_variant() {
        let payload = r#"{"clients":[{"client":{"mac":"aa:bb:cc:dd:ee:ff"}}]}"#;
        let body: ResultBody = serde_json::from_str(payload).unwrap();
        match body {
            ResultBody::Clients(r) => assert_eq!(r.clients.len(), 1),
            other => panic!("expected Clients, got {other:?}"),
        }
    }

    #[test]
    fn error_codes() {
        assert_eq!(ErrorBody::forbidden("no").code, "forbidden");
        assert_eq!(ErrorBody::not_found("x").code, "notFound");
        assert_eq!(ErrorBody::invalid("y").code, "invalid");
        assert_eq!(ErrorBody::busy("z").code, "busy");
    }
}
