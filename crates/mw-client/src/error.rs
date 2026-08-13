//! Client errors.

use thiserror::Error;

use mw_proto::{ErrorBody, FrameError};

/// Client-side errors.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Framing / IO.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Wire error from daemon.
    #[error("{code}: {message}")]
    Server {
        /// Error code.
        code: String,
        /// Message.
        message: String,
    },
    /// Unexpected response shape.
    #[error("unexpected response: {0}")]
    Unexpected(String),
    /// Connect failure.
    #[error("connect: {0}")]
    Connect(#[source] std::io::Error),
}

impl ClientError {
    /// From wire error body.
    #[must_use]
    pub fn from_body(e: ErrorBody) -> Self {
        Self::Server {
            code: e.code,
            message: e.message,
        }
    }
}
