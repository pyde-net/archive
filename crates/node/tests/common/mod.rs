//! Multi-node test harness (slice 6.1, plan task 063+).
//!
//! Spawns N `pyde` subprocesses via the existing `pyde testnet` config
//! generator, then exposes RPC polling helpers so tests can assert
//! consensus invariants against real live processes.
//!
//! These tests are slow (FALCON keygen + RocksDB init + libp2p
//! bootstrap per node) — mark them `#[ignore]` and run on-demand via
//! `cargo test -p pyde-node -- --ignored`.
//!
//! Network state lives in a single `tempfile::tempdir()` kept alive
//! for the entire test; the `Drop` impl kills any still-running
//! children and reaps their stdout/stderr.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// A single spawned node in the harness.
pub struct TestNode {
    pub index: usize,
    pub role: &'static str,
    pub rpc_port: u16,
    pub p2p_port: u16,
    pub datadir: PathBuf,
    process: Option<Child>,
    output: Arc<Mutex<Vec<String>>>,
}

impl TestNode {
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    pub fn kill(&mut self) {
        if let Some(mut c) = self.process.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn output_snapshot(&self) -> String {
        self.output
            .lock()
            .map(|o| o.join("\n"))
            .unwrap_or_else(|_| String::from("<poisoned>"))
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.kill();
    }
}

pub struct TestNetwork {
    pub nodes: Vec<TestNode>,
    pub chain_id: u64,
    _tempdir: TempDir,
}

impl TestNetwork {
    /// Spawn an N-validator testnet. `dev=true` uses `chain_id=31337`
    /// and skips signature validation (required for ad-hoc devnets).
    pub fn spawn(validators: usize, dev: bool) -> Result<Self, String> {
        if !(2..=8).contains(&validators) {
            return Err(format!(
                "validators must be 2..=8 for the harness; got {}",
                validators
            ));
        }

        let tempdir = tempfile::tempdir().map_err(|e| format!("create tempdir: {}", e))?;
        let net_dir = tempdir.path().join("net");
        let chain_id = if dev { 31337 } else { rand_chain_id() };
        let pyde_bin = pyde_binary_path();

        // Find contiguous free port ranges for p2p (UDP — used by QUIC)
        // and rpc (TCP). `pyde testnet` computes bootstrap multiaddrs as
        // `base_port + i`, so the range must be contiguous + free at
        // startup. We probe by binding then immediately releasing.
        let (p2p_base, _p2p_holders) = allocate_contiguous_udp_ports(validators)?;
        let (rpc_base, _rpc_holders) = allocate_contiguous_tcp_ports(validators)?;

        // Run `pyde testnet` to set up genesis + per-node configs.
        run_testnet_cli(
            &pyde_bin, validators, &net_dir, dev, chain_id, p2p_base, rpc_base,
        )?;

        // Drop the port-holder sockets just before spawning. There's
        // a tiny race window here where another process could grab
        // one, but on a CI runner (and local dev) the window is
        // microseconds and the collision probability is negligible.
        drop(_p2p_holders);
        drop(_rpc_holders);

        // Spawn all validators.
        let mut nodes: Vec<TestNode> = Vec::with_capacity(validators);
        for i in 0..validators {
            let node_dir = net_dir.join(format!("node-{}", i));
            let rpc_port = rpc_base + i as u16;
            let p2p_port = p2p_base + i as u16;
            let mut n = TestNode {
                index: i,
                role: "validator",
                rpc_port,
                p2p_port,
                datadir: node_dir,
                process: None,
                output: Arc::new(Mutex::new(Vec::new())),
            };
            start_node(&mut n, &pyde_bin, dev)?;
            nodes.push(n);
        }

        // Wait for RPC up on every node. Generous deadline — first
        // boot includes RocksDB init + libp2p bootstrap.
        let deadline = Instant::now() + Duration::from_secs(45);
        for node in &nodes {
            wait_rpc_up(&node.rpc_url(), deadline).map_err(|e| {
                format!(
                    "{}\n--- node-{} output ---\n{}",
                    e,
                    node.index,
                    node.output_snapshot()
                )
            })?;
        }

        Ok(Self {
            nodes,
            chain_id,
            _tempdir: tempdir,
        })
    }

    /// Poll each node's `pyde_blockNumber` until all ≥ `target_slot`
    /// or time out.
    pub fn wait_for_slot(&self, target_slot: u64, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            let slots = self.current_slots();
            if slots
                .iter()
                .all(|(_, s)| s.map(|v| v >= target_slot).unwrap_or(false))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "wait_for_slot({}) timed out — per-node slots: {:?}",
                    target_slot, slots
                ));
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn current_slots(&self) -> Vec<(usize, Option<u64>)> {
        self.nodes
            .iter()
            .map(|n| (n.index, rpc_block_number(&n.rpc_url()).ok()))
            .collect()
    }

    pub fn state_root(&self, node_idx: usize) -> Result<String, String> {
        rpc_state_root(&self.nodes[node_idx].rpc_url())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn pyde_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pyde"))
}

fn rand_chain_id() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    (now % 1_000_000) + 1000
}

/// Find `count` contiguous free UDP ports starting at some base.
/// Returns `(base, holders)` where `holders` must be kept alive
/// until just before the ports are needed to prevent a second
/// allocator from stealing them.
fn allocate_contiguous_udp_ports(count: usize) -> Result<(u16, Vec<UdpSocket>), String> {
    // Try random bases in the 40000..=60000 range (avoid common
    // dev ports like 30303, 8545, 9090, 3000, 8080).
    for attempt in 0..32 {
        let seed = rand_port_seed(attempt);
        let base = 40000 + (seed % 15000) as u16;
        if let Some(holders) = try_bind_udp_range(base, count) {
            return Ok((base, holders));
        }
    }
    Err(format!("no free {}-port UDP range found", count))
}

fn allocate_contiguous_tcp_ports(count: usize) -> Result<(u16, Vec<TcpListener>), String> {
    for attempt in 0..32 {
        let seed = rand_port_seed(attempt);
        let base = 40000 + (seed % 15000) as u16;
        if let Some(holders) = try_bind_tcp_range(base, count) {
            return Ok((base, holders));
        }
    }
    Err(format!("no free {}-port TCP range found", count))
}

fn try_bind_udp_range(base: u16, count: usize) -> Option<Vec<UdpSocket>> {
    let mut holders = Vec::with_capacity(count);
    for i in 0..count {
        match UdpSocket::bind(("127.0.0.1", base + i as u16)) {
            Ok(s) => holders.push(s),
            Err(_) => return None,
        }
    }
    Some(holders)
}

fn try_bind_tcp_range(base: u16, count: usize) -> Option<Vec<TcpListener>> {
    let mut holders = Vec::with_capacity(count);
    for i in 0..count {
        match TcpListener::bind(("127.0.0.1", base + i as u16)) {
            Ok(s) => holders.push(s),
            Err(_) => return None,
        }
    }
    Some(holders)
}

fn rand_port_seed(attempt: u32) -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u32;
    now.wrapping_mul(attempt + 1).wrapping_add(0x9E3779B9)
}

fn run_testnet_cli(
    pyde: &Path,
    validators: usize,
    out: &Path,
    dev: bool,
    chain_id: u64,
    base_port: u16,
    base_rpc_port: u16,
) -> Result<(), String> {
    let mut cmd = Command::new(pyde);
    cmd.arg("testnet")
        .arg("--validators")
        .arg(validators.to_string())
        .arg("--out")
        .arg(out)
        .arg("--base-port")
        .arg(base_port.to_string())
        .arg("--base-rpc-port")
        .arg(base_rpc_port.to_string())
        .arg("--chain-id")
        .arg(chain_id.to_string());
    if dev {
        cmd.arg("--dev");
    }
    let out = cmd
        .output()
        .map_err(|e| format!("run `pyde testnet`: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "`pyde testnet` exited {}:\nstdout: {}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn start_node(node: &mut TestNode, pyde: &Path, dev: bool) -> Result<(), String> {
    let config_path = node.datadir.join("config.toml");
    let mut cmd = Command::new(pyde);
    cmd.arg("run")
        .arg("--role")
        .arg(node.role)
        .arg("--config")
        .arg(&config_path)
        .arg("--datadir")
        .arg(&node.datadir)
        .arg("--log-level")
        .arg("info");
    if dev {
        cmd.arg("--dev");
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn node-{}: {}", node.index, e))?;

    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let output = node.output.clone();
    thread::spawn(move || drain_stream(stdout, output));
    let output2 = node.output.clone();
    thread::spawn(move || drain_stream(stderr, output2));

    node.process = Some(child);
    Ok(())
}

fn drain_stream<R: Read + Send + 'static>(r: R, output: Arc<Mutex<Vec<String>>>) {
    let reader = BufReader::new(r);
    for line in reader.lines().map_while(Result::ok) {
        if let Ok(mut buf) = output.lock() {
            buf.push(line);
        }
    }
}

fn wait_rpc_up(rpc_url: &str, deadline: Instant) -> Result<(), String> {
    loop {
        match rpc_block_number(rpc_url) {
            Ok(_) => return Ok(()),
            Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(250));
            }
            Err(e) => return Err(format!("RPC at {} never came up: {}", rpc_url, e)),
        }
    }
}

/// Dependency-free JSON-RPC client. Talks raw HTTP to localhost.
fn rpc_call(rpc_url: &str, method: &str, params: &str) -> Result<String, String> {
    let url = rpc_url.trim_start_matches("http://");
    let addr = url
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {}", url, e))?
        .next()
        .ok_or_else(|| format!("no address for {}", url))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map_err(|e| format!("connect: {}", e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;

    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{}}}"#,
        method, params
    );
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {}", e))?;

    let mut resp = Vec::new();
    stream
        .read_to_end(&mut resp)
        .map_err(|e| format!("read: {}", e))?;
    let s = String::from_utf8_lossy(&resp).to_string();
    let body_start = s
        .find("\r\n\r\n")
        .ok_or_else(|| format!("no HTTP body separator: {:?}", s))?
        + 4;
    Ok(s[body_start..].to_string())
}

fn rpc_block_number(rpc_url: &str) -> Result<u64, String> {
    let resp = rpc_call(rpc_url, "pyde_blockNumber", "[]")?;
    let hex = parse_hex_result(&resp)?;
    u64::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map_err(|e| format!("parse slot {:?}: {}", hex, e))
}

fn rpc_state_root(rpc_url: &str) -> Result<String, String> {
    let resp = rpc_call(rpc_url, "pyde_stateRoot", "[]")?;
    parse_hex_result(&resp)
}

fn parse_hex_result(resp: &str) -> Result<String, String> {
    let key = r#""result":""#;
    let start = resp
        .find(key)
        .ok_or_else(|| format!("no result in {:?}", resp))?;
    let tail = &resp[start + key.len()..];
    let end = tail
        .find('"')
        .ok_or_else(|| format!("unterminated result in {:?}", resp))?;
    Ok(tail[..end].to_string())
}
