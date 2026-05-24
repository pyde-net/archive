//! Terminal dashboard (--tui flag). Renders a 4-pane summary of the
//! local validator's view of the network: chain head & finality,
//! peers + committee + proposer, mempool depth, throughput. Refresh
//! 1 Hz from `metrics::snapshot()`, which the existing
//! `metrics::record_*` callers feed in lock-step with the Prometheus
//! exporter — so the dashboard never drifts from what `/metrics`
//! would scrape.
//!
//! Press `q` (or Ctrl-C) to exit cleanly: the terminal is restored
//! to its prior state via the leave_alternate_screen + disable_raw
//! cleanup in `run`.

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::metrics::{snapshot, Snapshot};

/// Throughput rates measured over the most recent
/// `THROUGHPUT_WINDOW_MS` window. Computed lazily on each tick by
/// diffing cumulative counters against a previous snapshot.
struct ThroughputState {
    last_at: Instant,
    last_blocks: u64,
    last_txs: u64,
    last_accepts: u64,
    last_rejects: u64,
}

impl ThroughputState {
    fn new(snap: &Snapshot) -> Self {
        Self {
            last_at: Instant::now(),
            last_blocks: snap.blocks_processed_total.load(Ordering::Relaxed),
            last_txs: snap.txs_committed_total.load(Ordering::Relaxed),
            last_accepts: snap.rpc_accepts_total.load(Ordering::Relaxed),
            last_rejects: snap.rpc_rejects_total.load(Ordering::Relaxed),
        }
    }

    fn tick(&mut self, snap: &Snapshot) -> Rates {
        let now = Instant::now();
        let dt = now.duration_since(self.last_at).as_secs_f64().max(0.001);
        let blocks = snap.blocks_processed_total.load(Ordering::Relaxed);
        let txs = snap.txs_committed_total.load(Ordering::Relaxed);
        let accepts = snap.rpc_accepts_total.load(Ordering::Relaxed);
        let rejects = snap.rpc_rejects_total.load(Ordering::Relaxed);
        let rates = Rates {
            blocks_per_s: (blocks.saturating_sub(self.last_blocks)) as f64 / dt,
            txs_per_s: (txs.saturating_sub(self.last_txs)) as f64 / dt,
            rpc_accepts_per_s: (accepts.saturating_sub(self.last_accepts)) as f64 / dt,
            rpc_rejects_per_s: (rejects.saturating_sub(self.last_rejects)) as f64 / dt,
        };
        self.last_at = now;
        self.last_blocks = blocks;
        self.last_txs = txs;
        self.last_accepts = accepts;
        self.last_rejects = rejects;
        rates
    }
}

struct Rates {
    blocks_per_s: f64,
    txs_per_s: f64,
    rpc_accepts_per_s: f64,
    rpc_rejects_per_s: f64,
}

/// Run the TUI render loop until the user presses `q`, Ctrl-C, or
/// `quit_flag` is set externally. Designed to run on its own
/// blocking thread; the metrics it reads are lock-free.
///
/// The TUI flips `quit_flag` itself on `q`/Ctrl-C so the caller can
/// observe and propagate to the rest of the process (which
/// otherwise relies on `ShutdownSignal` over tokio broadcast — that
/// API is async and awkward to poll from this sync loop).
pub fn run(quit_flag: Arc<AtomicBool>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let snap = snapshot();
    let mut throughput = ThroughputState::new(&snap);
    let result = render_loop(&mut terminal, &snap, &mut throughput, &quit_flag);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    result
}

fn render_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    snap: &Snapshot,
    throughput: &mut ThroughputState,
    quit_flag: &AtomicBool,
) -> io::Result<()> {
    let tick = Duration::from_millis(1000);
    let mut last_tick = Instant::now();
    let mut rates = throughput.tick(snap);
    loop {
        if quit_flag.load(Ordering::Relaxed) {
            break;
        }
        terminal.draw(|f| draw_ui(f, snap, &rates))?;
        // Poll for the remaining time in the current tick window so
        // keystrokes feel responsive without burning CPU on a hot loop.
        let timeout = tick
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_millis(0));
        if event::poll(timeout)? {
            if let Event::Key(k) = event::read()? {
                let ctrl_c =
                    k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c');
                if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) || ctrl_c {
                    quit_flag.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
        if last_tick.elapsed() >= tick {
            rates = throughput.tick(snap);
            last_tick = Instant::now();
        }
    }
    Ok(())
}

fn draw_ui(f: &mut ratatui::Frame, snap: &Snapshot, rates: &Rates) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(f.area());

    render_header(f, outer[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[1]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body[1]);

    render_chain(f, left[0], snap);
    render_mempool(f, left[1], snap);
    render_peers(f, right[0], snap);
    render_throughput(f, right[1], snap, rates);
}

fn render_header(f: &mut ratatui::Frame, area: Rect) {
    let role = if snapshot().is_validator.load(Ordering::Relaxed) {
        "validator"
    } else {
        "full"
    };
    let local = *snapshot().local_address.read().unwrap();
    let text = Line::from(vec![
        Span::styled(
            " pyde ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("· role={} ", role)),
        Span::raw(format!("· addr=0x{}", &hex::encode(&local[..6]))),
        Span::raw("   "),
        Span::styled("(q to quit)", Style::default().fg(Color::DarkGray)),
    ]);
    let p = Paragraph::new(text).block(Block::default().borders(Borders::ALL));
    f.render_widget(p, area);
}

fn render_chain(f: &mut ratatui::Frame, area: Rect, snap: &Snapshot) {
    let head = snap.chain_head_slot.load(Ordering::Relaxed);
    let finalized = snap.chain_finalized_slot.load(Ordering::Relaxed);
    let epoch = snap.epoch.load(Ordering::Relaxed);
    let base_fee = snap.chain_base_fee.load(Ordering::Relaxed);
    let last_slot = snap.last_block_slot.load(Ordering::Relaxed);
    let last_txs = snap.last_block_txs.load(Ordering::Relaxed);
    let last_gas = snap.last_block_gas.load(Ordering::Relaxed);
    let last_ms = snap.last_block_ms.load(Ordering::Relaxed);
    let last_at = snap.last_block_at_unix_ms.load(Ordering::Relaxed);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let since_last_block = now_ms.saturating_sub(last_at);

    let lines = vec![
        kv("head_slot", head.to_string()),
        kv("finalized", finalized.to_string()),
        kv("finality_lag", head.saturating_sub(finalized).to_string()),
        kv("epoch", epoch.to_string()),
        kv("base_fee", base_fee.to_string()),
        kv(
            "last_block",
            format!(
                "slot={} txs={} gas={} elapsed_ms={}",
                last_slot, last_txs, last_gas, last_ms
            ),
        ),
        kv("since_last", format!("{} ms", since_last_block)),
    ];
    let p = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" chain "));
    f.render_widget(p, area);
}

fn render_peers(f: &mut ratatui::Frame, area: Rect, snap: &Snapshot) {
    let peers = snap.peers.load(Ordering::Relaxed);
    let committee = snap.committee_size.load(Ordering::Relaxed);
    let proposer = *snap.current_proposer.read().unwrap();
    let proposer_str = if proposer == [0u8; 32] {
        "—".to_string()
    } else {
        format!("0x{}", &hex::encode(&proposer[..8]))
    };
    let lines = vec![
        kv("peers", peers.to_string()),
        kv("committee_size", committee.to_string()),
        kv("current_proposer", proposer_str),
    ];
    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" peers & committee "),
    );
    f.render_widget(p, area);
}

fn render_mempool(f: &mut ratatui::Frame, area: Rect, snap: &Snapshot) {
    let plain = snap.mempool_plain.load(Ordering::Relaxed);
    let enc = snap.mempool_encrypted.load(Ordering::Relaxed);
    let lines = vec![
        kv("plaintext", plain.to_string()),
        kv("encrypted", enc.to_string()),
    ];
    let p = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" mempool "));
    f.render_widget(p, area);
}

fn render_throughput(f: &mut ratatui::Frame, area: Rect, snap: &Snapshot, rates: &Rates) {
    let blocks_total = snap.blocks_processed_total.load(Ordering::Relaxed);
    let txs_total = snap.txs_committed_total.load(Ordering::Relaxed);
    let accepts = snap.rpc_accepts_total.load(Ordering::Relaxed);
    let rejects = snap.rpc_rejects_total.load(Ordering::Relaxed);
    let lines = vec![
        kv("blocks/s", format!("{:.2}", rates.blocks_per_s)),
        kv("txs/s (committed)", format!("{:.1}", rates.txs_per_s)),
        kv("rpc accepts/s", format!("{:.1}", rates.rpc_accepts_per_s)),
        kv("rpc rejects/s", format!("{:.1}", rates.rpc_rejects_per_s)),
        Line::from(""),
        kv("blocks_total", blocks_total.to_string()),
        kv("txs_total", txs_total.to_string()),
        kv("rpc_total", format!("{} ok / {} err", accepts, rejects)),
    ];
    let p =
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" throughput "));
    f.render_widget(p, area);
}

fn kv(k: &str, v: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {:<18}", k), Style::default().fg(Color::DarkGray)),
        Span::raw(v),
    ])
}
