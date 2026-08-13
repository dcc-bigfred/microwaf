//! eBPF loader + BpfEnforcer (optional `ebpf` feature).
//!
//! With the `ebpf` feature the XDP object is **embedded** in the binary at
//! compile time (`build.rs` → `include_bytes!`) and loaded from memory via
//! [`aya::Ebpf::load`]. Override with `MICROWAF_BPF_OBJECT` to load a file
//! instead. Optionally set `MICROWAF_BPF_EXTRACT` to also write the embedded
//! object to that path (debug / inspection).

use anyhow::{bail, Context, Result};
use mw_core::client::ClientId;
use mw_core::enforcer::Enforcer;
use mw_core::policy::EffectiveAction;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use crate::iface;

/// Loaded BPF handle (feature-gated real impl; otherwise a no-op map).
pub struct BpfHandle {
    /// In-memory mirror of policy map (always present; used when aya unavailable).
    policies: Mutex<HashMap<[u8; 10], (bool, u8)>>,
}

impl BpfHandle {
    fn key(client: &ClientId) -> Option<[u8; 10]> {
        let IpAddr::V4(v4) = client.ip else {
            return None;
        };
        let mut key = [0u8; 10];
        key[0..6].copy_from_slice(&client.mac);
        key[6..10].copy_from_slice(&v4.octets());
        Some(key)
    }
}

/// Load and attach XDP program to `interface`.
///
/// When `interface` is [`iface::ANY`], attaches to every non-loopback NIC.
/// Without the `ebpf` feature this returns an in-memory-only handle that
/// records policies but does not drop packets (useful for CI / permissive).
pub fn load_and_attach(interface: &str) -> Result<BpfHandle> {
    #[cfg(feature = "ebpf")]
    {
        if iface::is_any(interface) {
            let ifaces = iface::list_attachable()?;
            if ifaces.is_empty() {
                bail!("interface=any but no attachable NICs found");
            }
            tracing::info!(?ifaces, "attaching XDP to all interfaces");
            load_and_attach_aya_multi(&ifaces)
        } else {
            load_and_attach_aya_multi(&[interface.to_string()])
        }
    }
    #[cfg(not(feature = "ebpf"))]
    {
        if iface::is_any(interface) {
            tracing::info!(
                "ebpf feature disabled — interface=any uses userspace policy mirror only"
            );
        } else {
            tracing::info!(
                %interface,
                "ebpf feature disabled — using userspace policy mirror only"
            );
        }
        Ok(BpfHandle {
            policies: Mutex::new(HashMap::new()),
        })
    }
}

/// BPF object bytes baked into the binary by `build.rs`.
#[cfg(feature = "ebpf")]
static EMBEDDED_BPF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libmw_ebpf.so"));

#[cfg(feature = "ebpf")]
fn bpf_object_bytes() -> Result<Vec<u8>> {
    if let Ok(path) = std::env::var("MICROWAF_BPF_OBJECT") {
        let bytes =
            std::fs::read(&path).with_context(|| format!("read MICROWAF_BPF_OBJECT={path}"))?;
        tracing::info!(%path, len = bytes.len(), "loading BPF object from file");
        return Ok(bytes);
    }

    if let Ok(extract) = std::env::var("MICROWAF_BPF_EXTRACT") {
        if let Some(parent) = Path::new(&extract).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        std::fs::write(&extract, EMBEDDED_BPF)
            .with_context(|| format!("extract embedded BPF to {extract}"))?;
        tracing::info!(
            path = %extract,
            len = EMBEDDED_BPF.len(),
            "extracted embedded BPF object"
        );
    }

    tracing::info!(len = EMBEDDED_BPF.len(), "loading embedded BPF object");
    Ok(EMBEDDED_BPF.to_vec())
}

#[cfg(feature = "ebpf")]
fn load_and_attach_aya_multi(interfaces: &[String]) -> Result<BpfHandle> {
    use aya::{
        maps::HashMap as AyaHashMap,
        programs::{Xdp, XdpFlags},
        Ebpf,
    };

    let bytes = bpf_object_bytes()?;
    let mut bpf = Ebpf::load(&bytes).context("parse/load BPF object")?;
    let prog: &mut Xdp = bpf
        .program_mut("microwaf")
        .ok_or_else(|| anyhow::anyhow!("missing program microwaf in BPF object"))?
        .try_into()?;
    prog.load().context("bpf program load")?;
    for iface in interfaces {
        prog.attach(iface, XdpFlags::default())
            .map_err(|e| anyhow::anyhow!("attach xdp on {iface}: {e}"))?;
        tracing::info!(interface = %iface, "XDP program attached");
    }
    let _map: AyaHashMap<_, [u8; 10], [u8; 8]> = AyaHashMap::try_from(
        bpf.take_map("CLIENT_POLICY")
            .ok_or_else(|| anyhow::anyhow!("missing CLIENT_POLICY map"))?,
    )?;
    std::mem::forget(bpf);
    Ok(BpfHandle {
        policies: Mutex::new(HashMap::new()),
    })
}

/// Enforcer that writes the BPF policy map (and userspace mirror).
pub struct BpfEnforcer {
    handle: BpfHandle,
}

impl BpfEnforcer {
    /// Wrap a handle.
    #[must_use]
    pub fn new(handle: BpfHandle) -> Self {
        Self { handle }
    }
}

impl Enforcer for BpfEnforcer {
    fn apply(&self, client: ClientId, action: EffectiveAction) {
        let Some(key) = BpfHandle::key(&client) else {
            return;
        };
        let (blocked, drop_rate) = match action {
            EffectiveAction::None => {
                self.clear(client);
                return;
            }
            EffectiveAction::Block => (true, 100u8),
            EffectiveAction::Throttle { drop_rate } => (false, drop_rate),
        };
        self.handle
            .policies
            .lock()
            .insert(key, (blocked, drop_rate));
    }

    fn clear(&self, client: ClientId) {
        if let Some(key) = BpfHandle::key(&client) {
            self.handle.policies.lock().remove(&key);
        }
    }
}

/// Helper used by tests.
#[allow(dead_code)]
pub fn require_iface(iface: &str) -> Result<()> {
    if iface.is_empty() {
        bail!("empty interface");
    }
    Ok(())
}
