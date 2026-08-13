//! CLI client subcommands.

use anyhow::{bail, Result};
use mw_client::Client;
use mw_proto::{BlockParams, ClientRef, ThrottleParams, TopParams};

use crate::cli::{Cli, Command};
use crate::cli::top;

/// Run a client subcommand.
pub fn run(cli: &Cli) -> Result<()> {
    let socket = crate::config::resolve_socket_path(cli.socket.as_deref());
    let mut client = Client::with_socket(&socket);

    match &cli.command {
        Some(Command::Info { json, timeout }) => {
            client.timeout = (*timeout).into();
            let r = client.info()?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                println!(
                    "microwaf {} commit={} mode={} interface={}",
                    r.version, r.commit, r.mode, r.interface
                );
            }
        }
        Some(Command::Top {
            limit,
            rule_id,
            protocol,
            metric,
            interval,
            once,
            json,
            timeout,
        }) => {
            client.timeout = (*timeout).into();
            top::run(
                &client,
                TopParams {
                    limit: *limit,
                    rule_id: rule_id.clone(),
                    protocol: protocol.clone(),
                    metric: metric.clone(),
                },
                (*interval).into(),
                *once,
                *json,
            )?;
        }
        Some(Command::Clients { json, timeout }) => {
            client.timeout = (*timeout).into();
            let r = client.list_clients()?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                for c in &r.clients {
                    println!(
                        "{} action={:?} wouldBe={:?}",
                        format_client(&c.client),
                        c.action,
                        c.would_be_action
                    );
                }
            }
        }
        Some(Command::Throttle {
            client: cref,
            duration,
            rate,
            json,
            timeout,
        }) => {
            client.timeout = (*timeout).into();
            client.throttle(ThrottleParams {
                client: parse_client(cref)?,
                rate: Some(*rate),
                duration_secs: duration.map(|d| d.as_secs()),
            })?;
            if *json {
                println!("{{\"ok\":true}}");
            } else {
                println!("throttled {}", cref);
            }
        }
        Some(Command::Unthrottle {
            client: cref,
            json,
            timeout,
        }) => {
            client.timeout = (*timeout).into();
            client.unthrottle(parse_client(cref)?)?;
            if *json {
                println!("{{\"ok\":true}}");
            } else {
                println!("unthrottled {}", cref);
            }
        }
        Some(Command::Block {
            client: cref,
            duration,
            json,
            timeout,
        }) => {
            client.timeout = (*timeout).into();
            client.block(BlockParams {
                client: parse_client(cref)?,
                duration_secs: duration.map(|d| d.as_secs()),
            })?;
            if *json {
                println!("{{\"ok\":true}}");
            } else {
                println!("blocked {}", cref);
            }
        }
        Some(Command::Unblock {
            client: cref,
            json,
            timeout,
        }) => {
            client.timeout = (*timeout).into();
            client.unblock(parse_client(cref)?)?;
            if *json {
                println!("{{\"ok\":true}}");
            } else {
                println!("unblocked {}", cref);
            }
        }
        Some(Command::Rules { json, timeout }) => {
            client.timeout = (*timeout).into();
            let r = client.list_rules()?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                for rule in &r.rules {
                    println!(
                        "{} proto={} metric={} window={} limit={} action={:?}",
                        rule.id, rule.protocol, rule.metric, rule.window, rule.limit, rule.action
                    );
                }
            }
        }
        Some(Command::Daemon(_)) | None => bail!("internal: daemon command in client runner"),
    }
    Ok(())
}

fn parse_client(s: &str) -> Result<ClientRef> {
    let id: mw_core::ClientId = s.parse().map_err(|e: mw_core::client::ClientRefParseError| {
        anyhow::anyhow!(e.to_string())
    })?;
    Ok(ClientRef {
        mac: id.mac_string(),
        ip: Some(id.ip.to_string()),
    })
}

fn format_client(c: &ClientRef) -> String {
    match &c.ip {
        Some(ip) => format!("{}@{}", c.mac, ip),
        None => c.mac.clone(),
    }
}
