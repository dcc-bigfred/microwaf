//! Unix-socket client.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mw_proto::{
    read_frame, write_frame, BlockParams, ClientParams, ClientRef, ClientsResult, InfoResult,
    Params, Request, RequestKind, Response, ResultBody, RulesResult, ThrottleParams, TopParams,
    TopResult,
};

use crate::error::ClientError;

/// Default socket when DATA_DIR is `/data`.
pub const DEFAULT_SOCKET: &str = "/data/run/microwaf/microwaf.sock";
/// Default round-trip timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve socket path from env / override.
#[must_use]
pub fn resolve_socket(override_path: Option<&Path>) -> PathBuf {
    if let Some(p) = override_path {
        return p.to_path_buf();
    }
    if let Ok(p) = std::env::var("MICROWAF_SOCKET") {
        return PathBuf::from(p);
    }
    let data = dcc_daemon::datadir::DataDir::resolve(
        dcc_daemon::EnvPolicy::BigfredThenDataDir,
        dcc_daemon::PathRule::AcceptAny,
    );
    data.run_nested_socket("microwaf")
}

/// Sync MicroWAF client.
#[derive(Debug, Clone)]
pub struct Client {
    /// Socket path.
    pub socket: PathBuf,
    /// IO timeout.
    pub timeout: Duration,
}

impl Client {
    /// Construct with resolved default socket.
    #[must_use]
    pub fn new() -> Self {
        Self {
            socket: resolve_socket(None),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Construct with explicit socket.
    #[must_use]
    pub fn with_socket(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    fn connect(&self) -> Result<UnixStream, ClientError> {
        let stream = UnixStream::connect(&self.socket).map_err(ClientError::Connect)?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();
        Ok(stream)
    }

    fn round_trip(&self, req: Request) -> Result<ResultBody, ClientError> {
        let mut stream = self.connect()?;
        write_frame(&mut stream, &req)?;
        let resp: Response = read_frame(&mut stream)?;
        if let Some(err) = resp.error {
            return Err(ClientError::from_body(err));
        }
        resp.result
            .ok_or_else(|| ClientError::Unexpected("missing result".into()))
    }

    /// `info`.
    pub fn info(&self) -> Result<InfoResult, ClientError> {
        match self.round_trip(Request::new(RequestKind::Info))? {
            ResultBody::Info(r) => Ok(r),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `top`.
    pub fn top(&self, params: TopParams) -> Result<TopResult, ClientError> {
        match self.round_trip(Request::with_params(RequestKind::Top, Params::Top(params)))? {
            ResultBody::Clients(r) => Ok(r),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `listClients`.
    pub fn list_clients(&self) -> Result<ClientsResult, ClientError> {
        match self.round_trip(Request::new(RequestKind::ListClients))? {
            ResultBody::Clients(r) => Ok(r),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `listRules`.
    pub fn list_rules(&self) -> Result<RulesResult, ClientError> {
        match self.round_trip(Request::new(RequestKind::ListRules))? {
            ResultBody::Rules(r) => Ok(r),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `throttle`.
    pub fn throttle(&self, params: ThrottleParams) -> Result<(), ClientError> {
        match self.round_trip(Request::with_params(
            RequestKind::Throttle,
            Params::Throttle(params),
        ))? {
            ResultBody::Empty(_) => Ok(()),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `unthrottle`.
    pub fn unthrottle(&self, client: ClientRef) -> Result<(), ClientError> {
        match self.round_trip(Request::with_params(
            RequestKind::Unthrottle,
            Params::Client(ClientParams { client }),
        ))? {
            ResultBody::Empty(_) => Ok(()),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `block`.
    pub fn block(&self, params: BlockParams) -> Result<(), ClientError> {
        match self.round_trip(Request::with_params(
            RequestKind::Block,
            Params::Block(params),
        ))? {
            ResultBody::Empty(_) => Ok(()),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `unblock`.
    pub fn unblock(&self, client: ClientRef) -> Result<(), ClientError> {
        match self.round_trip(Request::with_params(
            RequestKind::Unblock,
            Params::Client(ClientParams { client }),
        ))? {
            ResultBody::Empty(_) => Ok(()),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}
