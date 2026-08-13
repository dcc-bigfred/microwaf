//! MicroWAF XDP program: enforce `client_policy` only (no counting).
//!
//! Build via `make ebpf` (or from this crate directory with nightly):
//! `cargo +nightly build --release`
//!
//! Requires: `make ebpf-setup` (nightly rust-src + official bpf-linker binary).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_get_prandom_u32,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;

/// Max clients in the policy map.
const MAX_CLIENTS: u32 = 8192;

/// Policy entry written by userspace.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClientPolicyEntry {
    /// 1 = block all packets.
    pub blocked: u8,
    /// Drop percentage 0..=100.
    pub drop_rate: u8,
    /// Padding / reserved.
    pub _pad: [u8; 2],
    /// Expiry as unix seconds (0 = never).
    pub until_unix: u32,
}

/// Client key: 6-byte MAC + 4-byte IPv4.
pub type ClientKey = [u8; 10];

#[map]
static CLIENT_POLICY: HashMap<ClientKey, ClientPolicyEntry> =
    HashMap::<ClientKey, ClientPolicyEntry>::with_max_entries(MAX_CLIENTS, 0);

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = 14;
const IP_HDR_MIN: usize = 20;

#[xdp]
pub fn microwaf(ctx: XdpContext) -> u32 {
    match try_microwaf(ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

fn try_microwaf(ctx: XdpContext) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    if u16::from_be(unsafe { (*eth).h_proto }) != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip = ptr_at::<Ipv4Hdr>(&ctx, ETH_HDR_LEN)?;
    let ihl = (unsafe { (*ip).ihl_version } & 0x0f) as usize * 4;
    if ihl < IP_HDR_MIN {
        return Ok(xdp_action::XDP_PASS);
    }

    let mut key = [0u8; 10];
    unsafe {
        key[0..6].copy_from_slice(&(*eth).h_source);
        key[6..10].copy_from_slice(&(*ip).saddr.to_ne_bytes());
    }

    let Some(policy) = (unsafe { CLIENT_POLICY.get(&key) }) else {
        return Ok(xdp_action::XDP_PASS);
    };

    if policy.blocked != 0 {
        return Ok(xdp_action::XDP_DROP);
    }
    if policy.drop_rate > 0 {
        let r = unsafe { bpf_get_prandom_u32() } % 100;
        if r < u32::from(policy.drop_rate) {
            return Ok(xdp_action::XDP_DROP);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
