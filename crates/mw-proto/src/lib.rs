//! MicroWAF wire protocol: length-prefixed JSON over a Unix socket.

#![forbid(unsafe_code)]

pub mod framing;
pub mod wire;

pub use framing::{read_frame, write_frame, FrameError, MAX_FRAME_BYTES};
pub use wire::*;
