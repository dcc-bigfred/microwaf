//! AF_PACKET sniffer: dispatch by L4+port → parsers → per-(client,rule) counters.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::{debug, warn};

use mw_core::cel_match::{eval_match, MatchContext};
use mw_core::client::ClientId;
use mw_core::rule::{Metric, Protocol};
use mw_sniffer::{
    detect_http_request, detect_withrottle_lines, detect_ws_frame, detect_z21_records,
};

use crate::state::DaemonState;

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Flow table for connection counting.
struct FlowTable {
    flows: HashMap<FlowKey, Instant>,
    max: usize,
    idle: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    proto: u8,
}

impl FlowTable {
    fn new() -> Self {
        Self {
            flows: HashMap::new(),
            max: 8192,
            idle: Duration::from_secs(60),
        }
    }

    /// Returns true if this is a new flow.
    fn observe(&mut self, key: FlowKey, now: Instant) -> bool {
        self.flows.retain(|_, t| now.duration_since(*t) < self.idle);
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.flows.entry(key) {
            e.insert(now);
            return false;
        }
        if self.flows.len() >= self.max {
            // Drop oldest
            if let Some((&old, _)) = self.flows.iter().min_by_key(|(_, t)| *t) {
                self.flows.remove(&old);
            }
        }
        self.flows.insert(key, now);
        true
    }
}

/// Marked WS connections (TCP 4-tuple).
type WsConns = HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), ()>;

/// Run sniffer loop.
pub fn run(interface: &str, state: Arc<DaemonState>) -> Result<()> {
    // Prefer AF_PACKET via libc raw socket; fall back to idle loop in unsupported envs.
    match open_af_packet(interface) {
        Ok(fd) => {
            debug!(%interface, "AF_PACKET socket open");
            sniff_loop(fd, state)
        }
        Err(e) => {
            warn!(error = %e, %interface, "AF_PACKET unavailable — sniffer idle");
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
    }
}

fn open_af_packet(interface: &str) -> Result<i32> {
    use crate::iface;
    // SAFETY: raw socket setup for AF_PACKET.
    unsafe {
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        );
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("socket AF_PACKET");
        }
        let ifindex = match iface::ifindex(interface) {
            Ok(i) => i,
            Err(e) => {
                libc::close(fd);
                return Err(e);
            }
        };
        // ifindex 0 (`any`) receives from all interfaces.
        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifindex as i32;
        let rc = libc::bind(
            fd,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&sll) as u32,
        );
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(err).context("bind AF_PACKET");
        }
        Ok(fd)
    }
}

fn sniff_loop(fd: i32, state: Arc<DaemonState>) -> Result<()> {
    let mut buf = vec![0u8; 65536];
    let mut flows = FlowTable::new();
    let mut ws_conns = WsConns::new();
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err).context("recv");
        }
        let frame = &buf[..n as usize];
        if let Err(e) = handle_frame(frame, &state, &mut flows, &mut ws_conns) {
            debug!(error = %e, "frame handle");
        }
    }
}

fn handle_frame(
    frame: &[u8],
    state: &DaemonState,
    flows: &mut FlowTable,
    ws_conns: &mut WsConns,
) -> Result<()> {
    if frame.len() < 14 {
        return Ok(());
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETH_P_IP {
        return Ok(());
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[6..12]); // src MAC
    let ip = &frame[14..];
    if ip.len() < 20 {
        return Ok(());
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ip.len() < ihl {
        return Ok(());
    }
    let proto = ip[9];
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let l4 = &ip[ihl..];
    let client = ClientId::new(mac, IpAddr::V4(src));
    let now = Instant::now();

    match proto {
        IPPROTO_TCP if l4.len() >= 20 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let flags = l4[13];
            let data_off = ((l4[12] >> 4) as usize) * 4;
            let payload = if l4.len() > data_off {
                &l4[data_off..]
            } else {
                &[]
            };
            let syn = flags & 0x02 != 0 && flags & 0x10 == 0;
            dispatch_tcp(
                state, client, src, sport, dst, dport, syn, payload, flows, ws_conns, now,
            );
        }
        IPPROTO_UDP if l4.len() >= 8 => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let payload = &l4[8..];
            dispatch_udp(state, client, src, sport, dst, dport, payload, flows, now);
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn dispatch_tcp(
    state: &DaemonState,
    client: ClientId,
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    syn: bool,
    payload: &[u8],
    flows: &mut FlowTable,
    ws_conns: &mut WsConns,
    now: Instant,
) {
    let rules = state.rules();
    let sets = state.sets();
    let byte_len = payload.len() as u64;

    // Generic TCP rules
    for rule in rules.matching(Protocol::Tcp, dport) {
        if rule.metric == Metric::Connections && syn {
            let key = FlowKey {
                src,
                sport,
                dst,
                dport,
                proto: IPPROTO_TCP,
            };
            if flows.observe(key, now)
                && match_ok(rule.as_ref(), &common_ctx(&client, dport, &sets))
            {
                state.counters.add_connections(client, &rule.id, 1);
            }
        }
        if rule.metric == Metric::Bytes
            && byte_len > 0
            && match_ok(rule.as_ref(), &common_ctx(&client, dport, &sets))
        {
            state.counters.add_bytes(client, &rule.id, byte_len);
        }
    }

    let ws_key = (src, sport, dst, dport);
    if ws_conns.contains_key(&ws_key) {
        if let Some(frame) = detect_ws_frame(payload) {
            for rule in rules.matching(Protocol::WebSocket, dport) {
                let mut ctx = common_ctx(&client, dport, &sets);
                ctx.set_bool("frame.fin", frame.fin);
                ctx.set_int("frame.opcode", i64::from(frame.opcode));
                ctx.set_int("frame.payloadLen", frame.payload_len as i64);
                if match_ok(rule.as_ref(), &ctx) {
                    if rule.metric == Metric::Requests {
                        state.counters.add_requests(client, &rule.id, 1);
                    }
                    if rule.metric == Metric::Bytes {
                        state.counters.add_bytes(client, &rule.id, byte_len);
                    }
                }
            }
        }
        return;
    }

    if let Some(http) = detect_http_request(payload) {
        if http.upgrade_ws {
            ws_conns.insert(ws_key, ());
            state.counters.add_ws_connection(client);
            return;
        }
        for rule in rules.matching(Protocol::Http, dport) {
            let mut ctx = common_ctx(&client, dport, &sets);
            ctx.set_str("request.method", &http.method);
            ctx.set_str("request.path", &http.path);
            if match_ok(rule.as_ref(), &ctx) {
                if rule.metric == Metric::Requests {
                    state.counters.add_requests(client, &rule.id, 1);
                }
                if rule.metric == Metric::Bytes {
                    state.counters.add_bytes(client, &rule.id, byte_len);
                }
            }
        }
        return;
    }

    // WiThrottle
    let lines = detect_withrottle_lines(payload);
    if !lines.is_empty() {
        for rule in rules.matching(Protocol::Withrottle, dport) {
            for line in &lines {
                let mut ctx = common_ctx(&client, dport, &sets);
                ctx.set_str("withrottle.prefix", &line.prefix);
                ctx.set_str("withrottle.throttle", &line.throttle);
                ctx.set_str("withrottle.command", &line.command);
                if match_ok(rule.as_ref(), &ctx) {
                    if rule.metric == Metric::Requests {
                        state.counters.add_requests(client, &rule.id, 1);
                    }
                    if rule.metric == Metric::Bytes {
                        state
                            .counters
                            .add_bytes(client, &rule.id, line.command.len() as u64);
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_udp(
    state: &DaemonState,
    client: ClientId,
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    payload: &[u8],
    flows: &mut FlowTable,
    now: Instant,
) {
    let rules = state.rules();
    let sets = state.sets();
    let byte_len = payload.len() as u64;

    for rule in rules.matching(Protocol::Udp, dport) {
        if rule.metric == Metric::Connections {
            let key = FlowKey {
                src,
                sport,
                dst,
                dport,
                proto: IPPROTO_UDP,
            };
            if flows.observe(key, now)
                && match_ok(rule.as_ref(), &common_ctx(&client, dport, &sets))
            {
                state.counters.add_connections(client, &rule.id, 1);
            }
        }
        if rule.metric == Metric::Bytes
            && byte_len > 0
            && match_ok(rule.as_ref(), &common_ctx(&client, dport, &sets))
        {
            state.counters.add_bytes(client, &rule.id, byte_len);
        }
    }

    let records = detect_z21_records(payload);
    if !records.is_empty() {
        for rule in rules.matching(Protocol::Z21, dport) {
            for rec in &records {
                let mut ctx = common_ctx(&client, dport, &sets);
                ctx.set_int("z21.header", i64::from(rec.header));
                ctx.set_int("z21.xheader", i64::from(rec.xheader));
                ctx.set_int("z21.dataLen", i64::from(rec.data_len));
                if match_ok(rule.as_ref(), &ctx) {
                    if rule.metric == Metric::Requests {
                        state.counters.add_requests(client, &rule.id, 1);
                    }
                    if rule.metric == Metric::Bytes {
                        state
                            .counters
                            .add_bytes(client, &rule.id, u64::from(rec.data_len));
                    }
                }
            }
        }
    }
}

fn common_ctx(client: &ClientId, port: u16, sets: &mw_core::config::SetsConfig) -> MatchContext {
    let mut ctx = MatchContext::default();
    ctx.set_str("client.mac", client.mac_string());
    ctx.set_str("client.ip", client.ip.to_string());
    ctx.set_int("port", i64::from(port));
    let now = chrono::Utc::now();
    ctx.set_int("time.epoch", now.timestamp());
    ctx.set_int("time.hour", i64::from(now.hour()));
    ctx.set_int("time.dow", i64::from(now.weekday().num_days_from_sunday()));
    ctx.sets = sets.sets.clone().into_iter().collect();
    ctx
}

fn match_ok(rule: &mw_core::rule::Rule, ctx: &MatchContext) -> bool {
    match &rule.r#match {
        None => true,
        Some(prog) => eval_match(prog, ctx),
    }
}

// chrono helpers
use chrono::Datelike;
use chrono::Timelike;
