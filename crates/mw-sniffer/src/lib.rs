//! Pure L7 detectors (no I/O). Host-testable with golden payloads.

#![forbid(unsafe_code)]

pub mod http;
pub mod ws;
pub mod z21;
pub mod withrottle;

pub use http::{detect_http_request, HttpRequestLine};
pub use ws::{detect_ws_frame, WsFrameHeader};
pub use z21::{detect_z21_records, Z21Record};
pub use withrottle::{detect_withrottle_lines, WithrottleLine};
