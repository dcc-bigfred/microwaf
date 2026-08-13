//! Live `top` view (htop-style refresh).

use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mw_client::Client;
use mw_proto::{ActionWire, ClientEntry, TopColumn, TopParams, TopResult, ViolationWire};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::termios::{
    tcgetattr, tcsetattr, InputFlags, LocalFlags, SetArg, Termios,
};
use nix::unistd::isatty;

/// Run `top`: live table on a TTY, otherwise one snapshot.
pub fn run(
    client: &Client,
    params: TopParams,
    interval: Duration,
    once: bool,
    json: bool,
) -> Result<()> {
    if json {
        let r = client.top(params)?;
        println!("{}", serde_json::to_string_pretty(&r)?);
        return Ok(());
    }

    let live = !once && io::stdout().is_terminal() && isatty_stdin();
    if !live {
        let limit = params.limit;
        let r = client.top(params)?;
        print!("{}", render_frame(&r, limit, interval, false));
        return Ok(());
    }

    run_live(client, params, interval)
}

fn isatty_stdin() -> bool {
    isatty(io::stdin().as_raw_fd()).unwrap_or(false)
}

fn run_live(client: &Client, params: TopParams, interval: Duration) -> Result<()> {
    let interval = interval.max(Duration::from_millis(50));
    let limit = params.limit;
    let mut out = io::stdout();
    let _raw = RawMode::enter().context("enable terminal raw mode")?;
    let _alt = AlternateScreen::enter(&mut out)?;

    loop {
        let frame = match client.top(params.clone()) {
            Ok(r) => render_frame(&r, limit, interval, true),
            Err(e) => format!(
                "microwaf top  -n {limit}  interval={}  q/Ctrl+C quit\n\nerror: {e:#}\n",
                humantime::format_duration(interval)
            ),
        };

        write!(out, "\x1b[H{frame}\x1b[J")?;
        out.flush()?;

        if wait_quit_or_timeout(interval)? {
            break;
        }
    }
    Ok(())
}

fn render_frame(result: &TopResult, limit: usize, interval: Duration, live: bool) -> String {
    let mut buf = String::with_capacity(2048);
    let hot_n = result.clients.iter().filter(|c| c.hot).count();
    if live {
        buf.push_str(&format!(
            "microwaf top  -n {limit}  hot={hot_n}  interval={}  q/Ctrl+C quit\n",
            humantime::format_duration(interval)
        ));
    } else {
        buf.push_str(&format!("microwaf top  hot={hot_n}\n"));
    }

    let client_w = result
        .clients
        .iter()
        .map(|c| format_client(&c.client).len())
        .max()
        .unwrap_or(6)
        .max(6);
    let action_w = 10usize;
    let would_w = 10usize;
    let col_widths = column_widths(&result.columns, &result.clients);

    // Header
    buf.push_str(&format!(
        " {:>3}  {:<client_w$}  {:<action_w$}  {:<would_w$}",
        "#",
        "CLIENT",
        "ACTION",
        "WOULD",
        client_w = client_w,
        action_w = action_w,
        would_w = would_w,
    ));
    for (col, w) in result.columns.iter().zip(col_widths.iter()) {
        buf.push_str(&format!("  {:^w$}", col.rule_id, w = w));
    }
    buf.push('\n');

    // Separator
    buf.push_str(&format!(
        " {:-<3}  {:-<client_w$}  {:-<action_w$}  {:-<would_w$}",
        "",
        "",
        "",
        "",
        client_w = client_w,
        action_w = action_w,
        would_w = would_w,
    ));
    for w in &col_widths {
        buf.push_str(&format!("  {:-<w$}", "", w = w));
    }
    buf.push('\n');

    if result.clients.is_empty() {
        buf.push_str(" (no known clients)\n");
    } else {
        let mut saw_rest = false;
        for (i, entry) in result.clients.iter().enumerate() {
            if !entry.hot && !saw_rest {
                if i > 0 {
                    buf.push_str(&format!(
                        " {:·<3}  {:·<client_w$}  {:·<action_w$}  {:·<would_w$}",
                        "",
                        "",
                        "",
                        "",
                        client_w = client_w,
                        action_w = action_w,
                        would_w = would_w,
                    ));
                    for w in &col_widths {
                        buf.push_str(&format!("  {:·<w$}", "", w = w));
                    }
                    buf.push('\n');
                }
                saw_rest = true;
            }
            buf.push_str(&format_row(
                i + 1,
                entry,
                &result.columns,
                &col_widths,
                client_w,
                action_w,
                would_w,
            ));
            buf.push('\n');
        }
    }
    buf
}

fn column_widths(columns: &[TopColumn], clients: &[ClientEntry]) -> Vec<usize> {
    columns
        .iter()
        .enumerate()
        .map(|(i, col)| {
            let unit = window_unit(&col.window);
            let mut w = col.rule_id.len();
            for entry in clients {
                let value = value_for_column(entry, col, i);
                w = w.max(format_rate(value, unit).len());
            }
            // at least room for "0/s"
            w.max(3)
        })
        .collect()
}

fn format_row(
    rank: usize,
    entry: &ClientEntry,
    columns: &[TopColumn],
    col_widths: &[usize],
    client_w: usize,
    action_w: usize,
    would_w: usize,
) -> String {
    let mark = if entry.hot { '*' } else { ' ' };
    let mut row = format!(
        "{mark}{:>3}  {:<client_w$}  {:<action_w$}  {:<would_w$}",
        rank,
        format_client(&entry.client),
        format_action(entry.action.as_ref()),
        format_action(entry.would_be_action.as_ref()),
        client_w = client_w,
        action_w = action_w,
        would_w = would_w,
    );
    for (i, (col, w)) in columns.iter().zip(col_widths.iter()).enumerate() {
        let value = value_for_column(entry, col, i);
        let cell = format_rate(value, window_unit(&col.window));
        row.push_str(&format!("  {:>w$}", cell, w = w));
    }
    row
}

fn value_for_column(entry: &ClientEntry, col: &TopColumn, index: usize) -> u64 {
    if let Some(v) = entry.violations.get(index) {
        if v.rule_id == col.rule_id {
            return v.value;
        }
    }
    entry
        .violations
        .iter()
        .find(|v| v.rule_id == col.rule_id)
        .map(|v: &ViolationWire| v.value)
        .unwrap_or(0)
}

fn window_unit(window: &str) -> &'static str {
    match window {
        "per-second" | "per_second" | "second" | "1s" => "/s",
        "per-minute" | "per_minute" | "minute" | "60s" => "/m",
        _ => "",
    }
}

fn format_rate(value: u64, unit: &str) -> String {
    format!("{value}{unit}")
}

fn format_client(c: &mw_proto::ClientRef) -> String {
    match &c.ip {
        Some(ip) => format!("{}@{}", c.mac, ip),
        None => c.mac.clone(),
    }
}

fn format_action(a: Option<&ActionWire>) -> String {
    match a {
        None | Some(ActionWire::None) => "-".into(),
        Some(ActionWire::Block) => "block".into(),
        Some(ActionWire::Throttle { drop_rate }) => format!("thr {drop_rate}%"),
    }
}

/// Wait until `interval` elapses or the user presses q / Ctrl+C.
/// Returns `true` if the user asked to quit.
fn wait_quit_or_timeout(interval: Duration) -> Result<bool> {
    let deadline = Instant::now() + interval;
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut buf = [0u8; 32];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }

        let mut fds = [PollFd::new(stdin.as_fd(), PollFlags::POLLIN)];
        let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
        let n = poll(&mut fds, timeout).context("poll stdin")?;
        if n == 0 {
            return Ok(false);
        }

        let nread = stdin.read(&mut buf).context("read stdin")?;
        if nread == 0 {
            return Ok(true);
        }
        for &b in &buf[..nread] {
            if b == b'q' || b == b'Q' || b == 0x03 {
                return Ok(true);
            }
        }
    }
}

struct AlternateScreen;

impl AlternateScreen {
    fn enter(out: &mut impl Write) -> Result<Self> {
        write!(out, "\x1b[?1049h\x1b[?25l")?;
        out.flush()?;
        Ok(Self)
    }
}

impl Drop for AlternateScreen {
    fn drop(&mut self) {
        let mut out = io::stdout();
        let _ = write!(out, "\x1b[?25h\x1b[?1049l");
        let _ = out.flush();
    }
}

struct RawMode {
    orig: Termios,
}

impl RawMode {
    fn enter() -> Result<Self> {
        let stdin = io::stdin();
        let orig = tcgetattr(stdin.as_fd()).context("tcgetattr")?;
        let mut raw = orig.clone();
        raw.local_flags.remove(LocalFlags::ECHO | LocalFlags::ICANON);
        raw.input_flags
            .remove(InputFlags::IXON | InputFlags::ICRNL | InputFlags::INLCR);
        tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &raw).context("tcsetattr")?;
        Ok(Self { orig })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let stdin = io::stdin();
        let _ = tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &self.orig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mw_proto::{ClientRef, TopColumn};

    #[test]
    fn rate_units() {
        assert_eq!(format_rate(0, window_unit("per-second")), "0/s");
        assert_eq!(format_rate(12, window_unit("per-minute")), "12/m");
    }

    #[test]
    fn render_has_rule_columns() {
        let result = TopResult {
            columns: vec![
                TopColumn {
                    rule_id: "http-rps".into(),
                    window: "per-second".into(),
                    limit: 100,
                    min_threshold: 50,
                },
                TopColumn {
                    rule_id: "z21-rpm".into(),
                    window: "per-minute".into(),
                    limit: 500,
                    min_threshold: 200,
                },
            ],
            clients: vec![ClientEntry {
                client: ClientRef {
                    mac: "aa:bb:cc:dd:ee:ff".into(),
                    ip: Some("10.0.0.1".into()),
                },
                action: Some(ActionWire::None),
                would_be_action: None,
                violations: vec![
                    ViolationWire {
                        rule_id: "http-rps".into(),
                        value: 3,
                        limit: 100,
                        action: ActionWire::None,
                    },
                    ViolationWire {
                        rule_id: "z21-rpm".into(),
                        value: 0,
                        limit: 500,
                        action: ActionWire::None,
                    },
                ],
                hot: false,
                stats: None,
            }],
        };
        let frame = render_frame(&result, 0, Duration::from_millis(500), false);
        assert!(frame.contains("http-rps"), "{frame}");
        assert!(frame.contains("z21-rpm"), "{frame}");
        assert!(frame.contains("3/s"), "{frame}");
        assert!(frame.contains("0/m"), "{frame}");
    }
}
