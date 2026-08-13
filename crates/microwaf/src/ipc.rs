//! Unix socket IPC server with SO_PEERCRED auth.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use mw_core::client::ClientId;
use mw_core::enforcer::Mode;
use mw_core::policy::{merge_policy, ManualPolicy, StoredManualPolicy};
use mw_core::rule::{Action, Rule};
use mw_core::window::RuleWindows;
use mw_proto::{
    read_frame, write_frame, ActionWire, BlockParams, ClientEntry, ClientParams, ClientRef,
    ClientsResult, EmptyResult, ErrorBody, InfoResult, Params, Request, RequestKind, Response,
    ResultBody, RuleWire, RulesResult, ThrottleParams, TopParams, TopResult, ViolationWire,
};

use crate::cli::daemon::StoreBackend;
use crate::state::DaemonState;
use crate::store;
use crate::version;

/// Bind the Unix socket, refusing to start if another daemon is already live.
///
/// - Missing path → bind.
/// - Path exists and `connect` succeeds → another daemon is running → error.
/// - Path exists and `connect` fails → treat as stale file, remove, bind.
pub fn bind_listener(socket: &Path) -> Result<UnixListener> {
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }
    claim_socket_path(socket)?;
    let listener =
        UnixListener::bind(socket).with_context(|| format!("bind {}", socket.display()))?;
    let mut perms = fs::metadata(socket)
        .with_context(|| format!("stat {}", socket.display()))?
        .permissions();
    perms.set_mode(0o660);
    fs::set_permissions(socket, perms)
        .with_context(|| format!("chmod {}", socket.display()))?;
    info!(path = %socket.display(), "IPC listening");
    Ok(listener)
}

/// Serve on an already-bound listener.
pub fn serve_listener(
    listener: UnixListener,
    state: Arc<DaemonState>,
    store: StoreBackend,
    allow_users: Vec<String>,
) -> Result<()> {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let state = Arc::clone(&state);
                let store = store.clone();
                let allow = allow_users.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, state, store, &allow) {
                        debug!(error = %e, "ipc conn");
                    }
                });
            }
            Err(e) => warn!(error = %e, "accept"),
        }
    }
    Ok(())
}

fn claim_socket_path(socket: &Path) -> Result<()> {
    if !socket.exists() {
        return Ok(());
    }
    match UnixStream::connect(socket) {
        Ok(_alive) => {
            anyhow::bail!(
                "another microwaf daemon is already running (socket {} is live)",
                socket.display()
            );
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %socket.display(),
                "removing stale Unix socket"
            );
            fs::remove_file(socket)
                .with_context(|| format!("remove stale socket {}", socket.display()))?;
            Ok(())
        }
    }
}

fn handle_conn(
    mut stream: UnixStream,
    state: Arc<DaemonState>,
    store: StoreBackend,
    allow: &[String],
) -> Result<()> {
    if !peer_allowed(&stream, allow) {
        let resp = Response::err(
            RequestKind::Info,
            ErrorBody::forbidden("peer user not in allowlist"),
        );
        let _ = write_frame(&mut stream, &resp);
        return Ok(());
    }
    loop {
        let req: Request = match read_frame(&mut stream) {
            Ok(r) => r,
            Err(mw_proto::FrameError::UnexpectedEof { .. }) => break,
            Err(mw_proto::FrameError::Io(e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        };
        let resp = dispatch(&req, &state, &store);
        write_frame(&mut stream, &resp)?;
    }
    Ok(())
}

fn peer_allowed(stream: &UnixStream, allow: &[String]) -> bool {
    if allow.is_empty() {
        return true;
    }
    // SAFETY: SO_PEERCRED getsockopt
    unsafe {
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        let rc = libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            return false;
        }
        // UID 0 (root) is always allowed — operators run the CLI as root on the Pi.
        if cred.uid == 0 {
            return true;
        }
        let uid = cred.uid;
        if let Some(name) = uid_to_name(uid) {
            return allow.iter().any(|u| u == &name);
        }
        false
    }
}

fn uid_to_name(uid: u32) -> Option<String> {
    use nix::unistd::{Uid, User};
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
}

fn dispatch(req: &Request, state: &DaemonState, store: &StoreBackend) -> Response {
    match req.kind {
        RequestKind::Info => Response::ok(req.kind, ResultBody::Info(info_result(state))),
        RequestKind::ListRules => Response::ok(req.kind, ResultBody::Rules(list_rules(state))),
        RequestKind::ListClients => {
            Response::ok(req.kind, ResultBody::Clients(list_clients(state)))
        }
        RequestKind::Top => {
            let params = match &req.params {
                Some(Params::Top(p)) => p.clone(),
                _ => TopParams {
                    limit: 10,
                    rule_id: None,
                    protocol: None,
                    metric: None,
                },
            };
            Response::ok(req.kind, ResultBody::Clients(top(state, &params)))
        }
        RequestKind::Throttle => match &req.params {
            Some(Params::Throttle(p)) => match throttle(state, store, p) {
                Ok(()) => Response::ok(req.kind, ResultBody::Empty(EmptyResult {})),
                Err(e) => Response::err(req.kind, ErrorBody::invalid(e)),
            },
            _ => Response::err(req.kind, ErrorBody::invalid("missing throttle params")),
        },
        RequestKind::Unthrottle => match &req.params {
            Some(Params::Client(ClientParams { client })) => {
                match clear_manual_throttle(state, store, client) {
                    Ok(()) => Response::ok(req.kind, ResultBody::Empty(EmptyResult {})),
                    Err(e) => Response::err(req.kind, ErrorBody::invalid(e)),
                }
            }
            _ => Response::err(req.kind, ErrorBody::invalid("missing client")),
        },
        RequestKind::Block => match &req.params {
            Some(Params::Block(p)) => match block(state, store, p) {
                Ok(()) => Response::ok(req.kind, ResultBody::Empty(EmptyResult {})),
                Err(e) => Response::err(req.kind, ErrorBody::invalid(e)),
            },
            _ => Response::err(req.kind, ErrorBody::invalid("missing block params")),
        },
        RequestKind::Unblock => match &req.params {
            Some(Params::Client(ClientParams { client })) => {
                match clear_manual_block(state, store, client) {
                    Ok(()) => Response::ok(req.kind, ResultBody::Empty(EmptyResult {})),
                    Err(e) => Response::err(req.kind, ErrorBody::invalid(e)),
                }
            }
            _ => Response::err(req.kind, ErrorBody::invalid("missing client")),
        },
    }
}

fn info_result(state: &DaemonState) -> InfoResult {
    let v = version::info();
    InfoResult {
        version: v.version,
        commit: v.commit,
        build_time: v.build_time,
        mode: state.mode.as_str().into(),
        interface: state.interface.clone(),
    }
}

fn list_rules(state: &DaemonState) -> RulesResult {
    let rules = state.rules();
    RulesResult {
        rules: rules
            .rules
            .iter()
            .map(|r| RuleWire {
                id: r.id.clone(),
                protocol: r.protocol.as_str().into(),
                ports: r.ports.clone().unwrap_or_default(),
                metric: r.metric.as_str().into(),
                window: r.window.as_str().into(),
                limit: r.limit,
                action: action_to_wire(r.action),
                min_threshold: r.min_threshold,
                r#match: r.match_src.clone(),
            })
            .collect(),
    }
}

fn action_to_wire(a: Action) -> ActionWire {
    match a {
        Action::Throttle { drop_rate } => ActionWire::Throttle { drop_rate },
        Action::Block => ActionWire::Block,
    }
}

fn effective_to_wire(a: mw_core::policy::EffectiveAction) -> ActionWire {
    match a {
        mw_core::policy::EffectiveAction::None => ActionWire::None,
        mw_core::policy::EffectiveAction::Throttle { drop_rate } => {
            ActionWire::Throttle { drop_rate }
        }
        mw_core::policy::EffectiveAction::Block => ActionWire::Block,
    }
}

fn client_to_ref(c: ClientId) -> ClientRef {
    ClientRef {
        mac: c.mac_string(),
        ip: Some(c.ip.to_string()),
    }
}

fn parse_ref(r: &ClientRef) -> Result<ClientId, String> {
    let s = match &r.ip {
        Some(ip) => format!("{}@{}", r.mac, ip),
        None => r.mac.clone(),
    };
    s.parse()
        .map_err(|e: mw_core::client::ClientRefParseError| e.to_string())
}

fn list_clients(state: &DaemonState) -> ClientsResult {
    let now = Instant::now();
    let policies = state.policies.lock();
    let would = state.would_be.lock();
    let stats = state.counters.snapshot_clients();
    let mut clients = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (&client, policy) in policies.iter() {
        seen.insert(client);
        let eff = merge_policy(policy, now);
        clients.push(ClientEntry {
            client: client_to_ref(client),
            action: Some(effective_to_wire(eff)),
            would_be_action: would.get(&client).map(|a| effective_to_wire(*a)).or_else(
                || {
                    if state.mode == Mode::Permissive {
                        Some(effective_to_wire(eff))
                    } else {
                        None
                    }
                },
            ),
            violations: vec![],
            hot: false,
            stats: stats.get(&client).map(|s| mw_proto::ClientStatsWire {
                requests: s.requests,
                bytes: s.bytes,
                connections: s.connections,
                ws_connections: s.ws_connections,
            }),
        });
    }
    for (&client, s) in &stats {
        if seen.contains(&client) {
            continue;
        }
        clients.push(ClientEntry {
            client: client_to_ref(client),
            action: Some(ActionWire::None),
            would_be_action: None,
            violations: vec![],
            hot: false,
            stats: Some(mw_proto::ClientStatsWire {
                requests: s.requests,
                bytes: s.bytes,
                connections: s.connections,
                ws_connections: s.ws_connections,
            }),
        });
    }
    ClientsResult {
        clients,
        columns: Vec::new(),
    }
}

fn top(state: &DaemonState, params: &TopParams) -> TopResult {
    let now = Instant::now();
    let rules = state.rules();
    let windows = state.windows.lock();
    let would = state.would_be.lock();
    let policies = state.policies.lock();
    let stats = state.counters.snapshot_clients();

    let matching_rules: Vec<_> = rules
        .rules
        .iter()
        .filter(|rule| {
            if let Some(id) = &params.rule_id {
                if &rule.id != id {
                    return false;
                }
            }
            if let Some(p) = &params.protocol {
                if rule.protocol.as_str() != p.as_str() {
                    return false;
                }
            }
            if let Some(m) = &params.metric {
                if rule.metric.as_str() != m.as_str() {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    let columns: Vec<mw_proto::TopColumn> = matching_rules
        .iter()
        .map(|r| mw_proto::TopColumn {
            rule_id: r.id.clone(),
            window: r.window.as_str().to_string(),
            limit: r.limit,
            min_threshold: r.min_threshold,
        })
        .collect();

    let zero_obs = zero_observations(&matching_rules);

    let mut seen = std::collections::HashSet::new();
    let mut scored: Vec<(ClientId, u64, bool, Vec<ViolationWire>)> = Vec::new();

    for (client, win) in windows.iter() {
        seen.insert(*client);
        let (best, hot, observations) = score_client(win, &matching_rules);
        scored.push((*client, best, hot, observations));
    }
    for &client in policies.keys() {
        if seen.insert(client) {
            scored.push((client, 0, false, zero_obs.clone()));
        }
    }
    for &client in stats.keys() {
        if seen.insert(client) {
            scored.push((client, 0, false, zero_obs.clone()));
        }
    }

    // Hot (above min_threshold on any matching rule) first, then by score desc.
    scored.sort_by(|a, b| {
        b.2.cmp(&a.2)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.0.mac.cmp(&b.0.mac))
            .then_with(|| a.0.ip.cmp(&b.0.ip))
    });
    if params.limit > 0 {
        scored.truncate(params.limit);
    }

    let clients = scored
        .into_iter()
        .map(|(client, _, hot, observations)| {
            let eff = policies
                .get(&client)
                .map(|p| merge_policy(p, now))
                .unwrap_or(mw_core::policy::EffectiveAction::None);
            ClientEntry {
                client: client_to_ref(client),
                action: Some(effective_to_wire(eff)),
                would_be_action: would.get(&client).map(|a| effective_to_wire(*a)).or_else(
                    || {
                        if state.mode == Mode::Permissive {
                            Some(effective_to_wire(eff))
                        } else {
                            None
                        }
                    },
                ),
                violations: observations,
                hot,
                stats: stats.get(&client).map(|s| mw_proto::ClientStatsWire {
                    requests: s.requests,
                    bytes: s.bytes,
                    connections: s.connections,
                    ws_connections: s.ws_connections,
                }),
            }
        })
        .collect();
    TopResult { clients, columns }
}

fn zero_observations(matching_rules: &[Arc<Rule>]) -> Vec<ViolationWire> {
    matching_rules
        .iter()
        .map(|rule| ViolationWire {
            rule_id: rule.id.clone(),
            value: 0,
            limit: rule.limit,
            action: action_to_wire(rule.action),
        })
        .collect()
}

/// Score a client against matching rules.
///
/// Returns `(best_value, is_hot, observations)`. Observations are aligned with
/// matching rules (including zeros). `is_hot` means any value ≥ `min_threshold`.
fn score_client(
    win: &RuleWindows,
    matching_rules: &[Arc<Rule>],
) -> (u64, bool, Vec<ViolationWire>) {
    let mut best = 0u64;
    let mut hot = false;
    let mut observations = Vec::with_capacity(matching_rules.len());
    for rule in matching_rules {
        let value = win.sum(&rule.id, rule.metric, rule.window.secs());
        best = best.max(value);
        if value >= rule.min_threshold && value > 0 {
            hot = true;
        }
        observations.push(ViolationWire {
            rule_id: rule.id.clone(),
            value,
            limit: rule.limit,
            action: action_to_wire(rule.action),
        });
    }
    (best, hot, observations)
}

fn throttle(state: &DaemonState, store: &StoreBackend, p: &ThrottleParams) -> Result<(), String> {
    let client = parse_ref(&p.client)?;
    let now = Instant::now();
    let until = p
        .duration_secs
        .map(|s| now + Duration::from_secs(s));
    let rate = p.rate.unwrap_or(50);
    {
        let mut policies = state.policies.lock();
        let entry = policies.entry(client).or_default();
        let mut manual = entry.manual.clone().unwrap_or(ManualPolicy {
            throttle: None,
            blocked: false,
            until: None,
        });
        manual.throttle = Some(rate);
        manual.until = until;
        entry.manual = Some(manual.clone());
        let stored = StoredManualPolicy::from_runtime(&manual, now);
        store::persist_manual(store.as_manual(), &client, Some(&stored)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn block(state: &DaemonState, store: &StoreBackend, p: &BlockParams) -> Result<(), String> {
    let client = parse_ref(&p.client)?;
    let now = Instant::now();
    let until = p
        .duration_secs
        .map(|s| now + Duration::from_secs(s));
    {
        let mut policies = state.policies.lock();
        let entry = policies.entry(client).or_default();
        let mut manual = entry.manual.clone().unwrap_or(ManualPolicy {
            throttle: None,
            blocked: false,
            until: None,
        });
        manual.blocked = true;
        manual.until = until;
        entry.manual = Some(manual.clone());
        let stored = StoredManualPolicy::from_runtime(&manual, now);
        store::persist_manual(store.as_manual(), &client, Some(&stored)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn clear_manual_throttle(
    state: &DaemonState,
    store: &StoreBackend,
    cref: &ClientRef,
) -> Result<(), String> {
    let client = parse_ref(cref)?;
    let now = Instant::now();
    let mut policies = state.policies.lock();
    if let Some(entry) = policies.get_mut(&client) {
        if let Some(m) = entry.manual.as_mut() {
            m.throttle = None;
            if !m.blocked {
                entry.manual = None;
                store::persist_manual(store.as_manual(), &client, None).map_err(|e| e.to_string())?;
            } else {
                let stored = StoredManualPolicy::from_runtime(m, now);
                store::persist_manual(store.as_manual(), &client, Some(&stored))
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

fn clear_manual_block(
    state: &DaemonState,
    store: &StoreBackend,
    cref: &ClientRef,
) -> Result<(), String> {
    let client = parse_ref(cref)?;
    let now = Instant::now();
    let mut policies = state.policies.lock();
    if let Some(entry) = policies.get_mut(&client) {
        if let Some(m) = entry.manual.as_mut() {
            m.blocked = false;
            if m.throttle.is_none() {
                entry.manual = None;
                store::persist_manual(store.as_manual(), &client, None).map_err(|e| e.to_string())?;
            } else {
                let stored = StoredManualPolicy::from_runtime(m, now);
                store::persist_manual(store.as_manual(), &client, Some(&stored))
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn claim_removes_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("microwaf.sock");
        // Create a dangling socket file (bind then drop without keeping the listener).
        {
            let _listener = UnixListener::bind(&sock).unwrap();
        }
        // After drop, the path still exists but nothing accepts — connect fails → stale.
        assert!(sock.exists());
        claim_socket_path(&sock).expect("stale should be removed");
        assert!(!sock.exists());
    }

    #[test]
    fn claim_refuses_live_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("microwaf.sock");
        let _listener = UnixListener::bind(&sock).unwrap();
        let err = claim_socket_path(&sock).unwrap_err();
        assert!(
            err.to_string().contains("already running"),
            "got: {err}"
        );
    }

    #[test]
    fn bind_listener_twice_fails_second() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("microwaf.sock");
        let _first = bind_listener(&sock).expect("first bind");
        let err = bind_listener(&sock).unwrap_err();
        assert!(
            err.to_string().contains("already running"),
            "got: {err}"
        );
    }
}
