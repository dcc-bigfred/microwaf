//! Daemon runner.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::info;

use crate::cli::{Cli, Command, DaemonArgs};
use crate::config::{self, LiveConfig};
use crate::decision;
use crate::ebpf::{self, BpfEnforcer};
use crate::ipc;
use crate::sniffer;
use crate::state::DaemonState;
use crate::store;
use mw_core::enforcer::{Enforcer, Mode, PermissiveEnforcer};
use mw_store::MemoryStore;

/// Run the daemon.
pub fn run(cli: &Cli) -> Result<()> {
    let (iface_cli, redis_cli, config_cli, mode_cli) = match &cli.command {
        Some(Command::Daemon(DaemonArgs {
            interface,
            redis_url,
            config_dir,
            mode,
        })) => (
            interface.clone().or_else(|| cli.interface.clone()),
            redis_url.clone().or_else(|| cli.redis_url.clone()),
            config_dir.clone().or_else(|| cli.config_dir.clone()),
            mode.or(cli.mode),
        ),
        _ => (
            cli.interface.clone(),
            cli.redis_url.clone(),
            cli.config_dir.clone(),
            cli.mode,
        ),
    };

    let config_dir = config::resolve_config_dir(config_cli.as_deref());
    let live = LiveConfig::load(&config_dir).context("load config")?;
    let mode = mode_cli.unwrap_or(live.daemon.mode);
    let interface = iface_cli
        .or(live.daemon.interface.clone())
        .unwrap_or_else(|| "any".into());
    crate::iface::ensure_exists(&interface).with_context(|| {
        format!("interface `{interface}` (set via --interface / MICROWAF_INTERFACE / daemon.yaml)")
    })?;
    let redis_url = redis_cli.unwrap_or_else(|| "redis://127.0.0.1:6379/0".into());
    let socket = crate::config::resolve_socket_path(cli.socket.as_deref());

    if crate::iface::is_any(&interface) {
        match crate::iface::list_attachable() {
            Ok(ifaces) => info!(?ifaces, "interface=any — sniffing on all network interfaces"),
            Err(e) => {
                tracing::warn!(error = %e, "interface=any — could not enumerate NICs");
                info!("interface=any — sniffing on all network interfaces");
            }
        }
    }

    info!(
        %mode,
        %interface,
        config_dir = %config_dir.display(),
        socket = %socket.display(),
        "starting microwaf daemon"
    );

    // Claim the IPC socket before spawning workers — refuse if another daemon
    // is already live on this path.
    let listener = ipc::bind_listener(&socket).context("bind IPC socket")?;

    let state = Arc::new(DaemonState::new(mode, interface.clone(), live));

    // Persistence: prefer Redis; fall back to memory with a warning (dev/test).
    let store_backend = match store::open_redis(&redis_url) {
        Ok(s) => {
            store::hydrate(&state, &s)?;
            StoreBackend::Redis(Arc::new(s))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Redis unavailable — using in-memory store");
            StoreBackend::Memory(Arc::new(MemoryStore::default()))
        }
    };

    let enforcer: Arc<dyn Enforcer> = match mode {
        Mode::Enforce => {
            match ebpf::load_and_attach(&interface) {
                Ok(bpf) => Arc::new(BpfEnforcer::new(bpf)),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "eBPF load failed — falling back to permissive enforcer (no packet drops)"
                    );
                    Arc::new(PermissiveEnforcer::default())
                }
            }
        }
        Mode::Permissive => Arc::new(PermissiveEnforcer::default()),
    };
    state.set_enforcer(enforcer);

    // Hot-reload watcher
    let state_cfg = Arc::clone(&state);
    let config_dir_watch = config_dir.clone();
    std::thread::Builder::new()
        .name("mw-config".into())
        .spawn(move || config::watch_loop(config_dir_watch, state_cfg))
        .context("spawn config watcher")?;

    // Sniffer
    let state_sniff = Arc::clone(&state);
    let iface_sniff = interface.clone();
    std::thread::Builder::new()
        .name("mw-sniffer".into())
        .spawn(move || {
            if let Err(e) = sniffer::run(&iface_sniff, state_sniff) {
                tracing::error!(error = %e, "sniffer exited");
            }
        })
        .context("spawn sniffer")?;

    // Decision loop
    let state_dec = Arc::clone(&state);
    let store_dec = store_backend.clone();
    std::thread::Builder::new()
        .name("mw-decision".into())
        .spawn(move || decision::run(state_dec, store_dec))
        .context("spawn decision")?;

    // IPC server (blocking) on the already-claimed listener
    let state_ipc = Arc::clone(&state);
    let store_ipc = store_backend;
    let allow = state.allow_users();
    ipc::serve_listener(listener, state_ipc, store_ipc, allow)?;

    Ok(())
}

/// Shared store handle for decision + IPC.
#[derive(Clone)]
pub enum StoreBackend {
    /// Redis.
    Redis(Arc<mw_store::RedisStore>),
    /// Memory.
    Memory(Arc<MemoryStore>),
}

impl StoreBackend {
    /// As manual policy store.
    pub fn as_manual(&self) -> &dyn mw_core::store::ManualPolicyStore {
        match self {
            Self::Redis(s) => s.as_ref(),
            Self::Memory(s) => s.as_ref(),
        }
    }

    /// As stats store.
    pub fn as_stats(&self) -> &dyn mw_core::store::ClientStatsStore {
        match self {
            Self::Redis(s) => s.as_ref(),
            Self::Memory(s) => s.as_ref(),
        }
    }
}

/// Unused helper kept for type visibility.
#[allow(dead_code)]
fn _cooldown_default() -> Duration {
    Duration::from_secs(30)
}

/// Resolve helper re-export path type.
#[allow(dead_code)]
type _P = PathBuf;
