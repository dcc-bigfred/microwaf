//! Sync MicroWAF Unix-socket client.

#![forbid(unsafe_code)]

mod client;
mod error;

pub use client::{resolve_socket, Client, DEFAULT_SOCKET, DEFAULT_TIMEOUT};
pub use error::ClientError;
pub use mw_proto::*;
