//! CLI definition.

pub mod client;
pub mod daemon;
pub mod top;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use mw_core::enforcer::Mode;

/// MicroWAF — lightweight host WAF for Linux.
#[derive(Debug, Parser)]
#[command(name = "microwaf", version, about)]
pub struct Cli {
    /// Subcommand; omitted → run daemon.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Unix socket path.
    #[arg(long, global = true, env = "MICROWAF_SOCKET")]
    pub socket: Option<PathBuf>,

    /// Verbose logging.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Network interface (daemon). `any` = sniff on all NICs.
    #[arg(short = 'i', long = "interface", env = "MICROWAF_INTERFACE")]
    pub interface: Option<String>,

    /// Redis URL (daemon).
    #[arg(long, env = "MICROWAF_REDIS_URL")]
    pub redis_url: Option<String>,

    /// Config directory (daemon).
    #[arg(long, env = "MICROWAF_CONFIG_DIR")]
    pub config_dir: Option<PathBuf>,

    /// Run mode (daemon, startup only).
    #[arg(long, env = "MICROWAF_MODE")]
    pub mode: Option<Mode>,
}

/// CLI subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the daemon (same as bare invocation).
    Daemon(DaemonArgs),
    /// Show daemon version and mode.
    Info {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Timeout.
        #[arg(long, default_value = "10s")]
        timeout: humantime::Duration,
    },
    /// Top-N clients (live table; refresh like htop).
    Top {
        /// Max rows (`0` = all known clients).
        #[arg(short = 'n', long, default_value_t = 0)]
        limit: usize,
        /// Filter by rule id.
        #[arg(long)]
        rule_id: Option<String>,
        /// Filter by protocol.
        #[arg(long)]
        protocol: Option<String>,
        /// Filter by metric.
        #[arg(long)]
        metric: Option<String>,
        /// Refresh interval for the live view.
        #[arg(long, default_value = "500ms")]
        interval: humantime::Duration,
        /// Print one snapshot and exit (also implied by `--json` or a non-TTY).
        #[arg(long)]
        once: bool,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Timeout.
        #[arg(long, default_value = "10s")]
        timeout: humantime::Duration,
    },
    /// List known clients.
    Clients {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Timeout.
        #[arg(long, default_value = "10s")]
        timeout: humantime::Duration,
    },
    /// Set manual throttle.
    Throttle {
        /// Client `mac` or `mac@ip`.
        client: String,
        /// Duration (omit = permanent).
        #[arg(short = 'd', long)]
        duration: Option<humantime::Duration>,
        /// Drop rate 0..=100.
        #[arg(long, default_value_t = 50)]
        rate: u8,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Timeout.
        #[arg(long, default_value = "10s")]
        timeout: humantime::Duration,
    },
    /// Clear manual throttle.
    Unthrottle {
        /// Client.
        client: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Timeout.
        #[arg(long, default_value = "10s")]
        timeout: humantime::Duration,
    },
    /// Block a client.
    Block {
        /// Client.
        client: String,
        /// Duration (omit = permanent).
        #[arg(short = 'd', long)]
        duration: Option<humantime::Duration>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Timeout.
        #[arg(long, default_value = "10s")]
        timeout: humantime::Duration,
    },
    /// Unblock a client.
    Unblock {
        /// Client.
        client: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Timeout.
        #[arg(long, default_value = "10s")]
        timeout: humantime::Duration,
    },
    /// List loaded rules.
    Rules {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Timeout.
        #[arg(long, default_value = "10s")]
        timeout: humantime::Duration,
    },
}

/// Extra daemon flags (subcommand form).
#[derive(Debug, clap::Args)]
pub struct DaemonArgs {
    /// Network interface. Use `any` to sniff on all NICs.
    #[arg(short = 'i', long = "interface")]
    pub interface: Option<String>,
    /// Redis URL.
    #[arg(long)]
    pub redis_url: Option<String>,
    /// Config directory.
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
    /// Run mode.
    #[arg(long)]
    pub mode: Option<Mode>,
}
