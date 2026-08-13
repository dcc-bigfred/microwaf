//! Network interface helpers (existence check + `any` = all NICs).

use std::ffi::CStr;
use std::io;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// Sentinel interface name: sniff / observe on all NICs.
pub const ANY: &str = "any";

/// True when `name` means “all interfaces” (`any`, case-insensitive).
#[must_use]
pub fn is_any(name: &str) -> bool {
    name.eq_ignore_ascii_case(ANY)
}

/// Resolve an interface name to an ifindex (`0` for [`ANY`]).
///
/// # Errors
/// Returns an error when the named interface does not exist.
pub fn ifindex(name: &str) -> Result<u32> {
    if is_any(name) {
        return Ok(0);
    }
    let cname = std::ffi::CString::new(name).context("interface name")?;
    // SAFETY: if_nametoindex with a valid C string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        let err = io::Error::last_os_error();
        bail!("interface `{name}` does not exist ({err})");
    }
    Ok(idx)
}

/// Fail fast at daemon start unless `name` is [`ANY`] or a real NIC.
///
/// # Errors
/// Missing / empty name, or unknown interface.
pub fn ensure_exists(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("interface name is empty (use a NIC name or `any`)");
    }
    let _ = ifindex(name)?;
    Ok(())
}

/// List host interfaces suitable for XDP attach when sniffing on [`ANY`].
///
/// Skips `lo` and interfaces that are not present under `/sys/class/net`.
///
/// # Errors
/// Propagates `/sys/class/net` read failures.
pub fn list_attachable() -> Result<Vec<String>> {
    // Prefer if_nameindex when available; fall back to /sys/class/net.
    if let Ok(list) = list_via_if_nameindex() {
        return Ok(list);
    }
    list_via_sysfs()
}

fn list_via_if_nameindex() -> Result<Vec<String>> {
    // SAFETY: if_nameindex / if_freenameindex pair.
    unsafe {
        let ptr = libc::if_nameindex();
        if ptr.is_null() {
            return Err(io::Error::last_os_error()).context("if_nameindex");
        }
        let mut out = Vec::new();
        let mut p = ptr;
        loop {
            if (*p).if_index == 0 || (*p).if_name.is_null() {
                break;
            }
            let name = CStr::from_ptr((*p).if_name).to_string_lossy().into_owned();
            if name != "lo" && !is_any(&name) {
                out.push(name);
            }
            p = p.add(1);
        }
        libc::if_freenameindex(ptr);
        Ok(out)
    }
}

fn list_via_sysfs() -> Result<Vec<String>> {
    let root = Path::new("/sys/class/net");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "lo" {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_is_case_insensitive() {
        assert!(is_any("any"));
        assert!(is_any("ANY"));
        assert!(is_any("Any"));
        assert!(!is_any("eth0"));
    }

    #[test]
    fn any_resolves_to_zero() {
        assert_eq!(ifindex("any").unwrap(), 0);
    }

    #[test]
    fn lo_exists_on_linux() {
        // `lo` is always present on Linux hosts used for CI/dev.
        assert!(ensure_exists("lo").is_ok());
    }

    #[test]
    fn missing_iface_errors() {
        let err = ensure_exists("microwaf-no-such-iface-xyz").unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }
}
