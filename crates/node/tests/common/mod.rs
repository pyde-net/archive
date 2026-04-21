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

use std::collections::HashMap;
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

    /// True if a child process is attached — i.e. the node has been
    /// started and not yet explicitly killed.
    pub fn is_running(&self) -> bool {
        self.process.is_some()
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
    pyde_bin: PathBuf,
    dev: bool,
    /// Port reservations for deferred nodes. Dropped just before that
    /// node is started so the child process can bind the same ports.
    /// Keeps random OS processes from snatching the port during the
    /// gap between testnet generation and `start_deferred()`.
    deferred_port_holders: HashMap<usize, DeferredPortHolder>,
    _tempdir: TempDir,
}

struct DeferredPortHolder {
    _udp: UdpSocket,
    _tcp: TcpListener,
}

impl TestNetwork {
    /// Default block time (400 ms/slot) — mainnet target.
    const DEFAULT_BLOCK_TIME_MS: u64 = 400;

    /// Spawn an N-validator testnet. `dev=true` uses `chain_id=31337`
    /// and skips signature validation (required for ad-hoc devnets).
    pub fn spawn(validators: usize, dev: bool) -> Result<Self, String> {
        Self::spawn_mixed(validators, 0, dev)
    }

    /// Spawn V validators + F full nodes. Full nodes bootstrap to every
    /// validator and relay txs but don't participate in consensus.
    pub fn spawn_mixed(
        validators: usize,
        full_nodes: usize,
        dev: bool,
    ) -> Result<Self, String> {
        Self::spawn_mixed_inner(validators, full_nodes, 0, dev, Self::DEFAULT_BLOCK_TIME_MS)
    }

    /// Same as `spawn_mixed`, but the last `deferred` full nodes have
    /// their dirs + configs created and kept NOT running. Call
    /// `start_deferred(idx)` later to bring each one online. Used to
    /// test sync: let the live nodes build a chain, then start a cold
    /// node and watch it catch up.
    pub fn spawn_with_deferred_full_nodes(
        validators: usize,
        full_nodes: usize,
        deferred: usize,
        dev: bool,
    ) -> Result<Self, String> {
        if deferred > full_nodes {
            return Err(format!(
                "deferred ({}) must be <= full_nodes ({})",
                deferred, full_nodes
            ));
        }
        Self::spawn_mixed_inner(
            validators,
            full_nodes,
            deferred,
            dev,
            Self::DEFAULT_BLOCK_TIME_MS,
        )
    }

    /// Spawn V validators at a custom block time (ms/slot). 400 is the
    /// production default; 50-100 is useful for tests that need to
    /// cross epoch boundaries (1000 slots) quickly. Block times < 50
    /// tend to destabilize consensus on laptops under 4-subprocess load.
    pub fn spawn_with_block_time(
        validators: usize,
        dev: bool,
        block_time_ms: u64,
    ) -> Result<Self, String> {
        Self::spawn_mixed_inner(validators, 0, 0, dev, block_time_ms)
    }

    fn spawn_mixed_inner(
        validators: usize,
        full_nodes: usize,
        deferred: usize,
        dev: bool,
        block_time_ms: u64,
    ) -> Result<Self, String> {
        if !(2..=8).contains(&validators) {
            return Err(format!(
                "validators must be 2..=8 for the harness; got {}",
                validators
            ));
        }
        if full_nodes > 4 {
            return Err(format!(
                "full_nodes must be 0..=4 for the harness; got {}",
                full_nodes
            ));
        }
        let total = validators + full_nodes;
        // The last `deferred` nodes stay cold; the rest start eagerly.
        let first_deferred_idx = total - deferred;

        let tempdir = tempfile::tempdir().map_err(|e| format!("create tempdir: {}", e))?;
        let net_dir = tempdir.path().join("net");
        let chain_id = if dev { 31337 } else { rand_chain_id() };
        let pyde_bin = pyde_binary_path();

        // Find contiguous free port ranges for p2p (UDP — used by QUIC)
        // and rpc (TCP). `pyde testnet` computes bootstrap multiaddrs as
        // `base_port + i`, so the range must be contiguous + free at
        // startup for EVERY node (validators + full nodes). We probe by
        // binding then immediately releasing.
        let (p2p_base, mut p2p_holders) = allocate_contiguous_udp_ports(total)?;
        let (rpc_base, mut rpc_holders) = allocate_contiguous_tcp_ports(total)?;

        // Run `pyde testnet` to set up genesis + per-node configs.
        run_testnet_cli(
            &pyde_bin,
            validators,
            full_nodes,
            &net_dir,
            dev,
            chain_id,
            p2p_base,
            rpc_base,
            block_time_ms,
        )?;

        // Port-holder strategy:
        //   - For every node that starts NOW, drop its holders just
        //     before spawn() — there's a tiny race window where another
        //     process could snatch the port, but in practice the window
        //     is microseconds.
        //   - For deferred nodes, KEEP their holders alive in
        //     `deferred_port_holders` so a 30s-later `start_deferred()`
        //     doesn't race with system processes for that exact port.
        let mut deferred_port_holders: HashMap<usize, DeferredPortHolder> = HashMap::new();

        // Build all TestNode entries; start only the non-deferred ones.
        let mut nodes: Vec<TestNode> = Vec::with_capacity(total);
        for i in 0..total {
            let role: &'static str = if i < validators { "validator" } else { "full" };
            let node_dir = net_dir.join(format!("node-{}", i));
            let rpc_port = rpc_base + i as u16;
            let p2p_port = p2p_base + i as u16;
            let mut n = TestNode {
                index: i,
                role,
                rpc_port,
                p2p_port,
                datadir: node_dir,
                process: None,
                output: Arc::new(Mutex::new(Vec::new())),
            };
            // Take this node's holders out of the shared vec.
            let udp = p2p_holders.remove(0);
            let tcp = rpc_holders.remove(0);
            if i < first_deferred_idx {
                // Drop holders, then spawn — the OS releases the ports
                // immediately and the child grabs them on startup.
                drop(udp);
                drop(tcp);
                start_node(&mut n, &pyde_bin, dev)?;
            } else {
                // Keep them reserved until start_deferred() is called.
                deferred_port_holders.insert(i, DeferredPortHolder { _udp: udp, _tcp: tcp });
            }
            nodes.push(n);
        }

        // Wait for RPC up only on started nodes. Deferred nodes have
        // no process; their RPC port is still held by the OS at this
        // point? No — the holders were dropped. Leave them alone.
        let deadline = Instant::now() + Duration::from_secs(45);
        for node in &nodes {
            if node.process.is_none() {
                continue;
            }
            wait_rpc_up(&node.rpc_url(), deadline).map_err(|e| {
                format!(
                    "{}\n--- node-{} ({}) output ---\n{}",
                    e,
                    node.index,
                    node.role,
                    node.output_snapshot()
                )
            })?;
        }

        Ok(Self {
            nodes,
            chain_id,
            pyde_bin,
            dev,
            deferred_port_holders,
            _tempdir: tempdir,
        })
    }

    /// Start a previously-deferred node. Returns once its RPC is up.
    pub fn start_deferred(&mut self, idx: usize) -> Result<(), String> {
        if !self.deferred_port_holders.contains_key(&idx) {
            return Err(format!(
                "node-{} is not a deferred node (either never deferred or already started)",
                idx
            ));
        }
        let node = self
            .nodes
            .get_mut(idx)
            .ok_or_else(|| format!("no node at index {}", idx))?;
        if node.process.is_some() {
            return Err(format!("node-{} is already running", idx));
        }
        // Release the port reservation AT THE MOMENT we spawn — gap
        // between drop and child bind is microseconds, which closes
        // the race window that caused EADDRINUSE in earlier runs.
        drop(self.deferred_port_holders.remove(&idx));
        start_node(node, &self.pyde_bin, self.dev)?;
        let url = node.rpc_url();
        let deadline = Instant::now() + Duration::from_secs(45);
        if let Err(e) = wait_rpc_up(&url, deadline) {
            thread::sleep(Duration::from_millis(200));
            let snapshot = self.nodes[idx].output_snapshot();
            return Err(format!("{}\n--- node-{} output ---\n{}", e, idx, snapshot));
        }
        Ok(())
    }

    /// Kill a running node by index. Returns error if the node is
    /// not running. Used by fault-tolerance tests that take a
    /// validator offline mid-run and watch the rest of the network
    /// continue.
    pub fn kill_node(&mut self, idx: usize) -> Result<(), String> {
        let node = self
            .nodes
            .get_mut(idx)
            .ok_or_else(|| format!("no node at index {}", idx))?;
        if node.process.is_none() {
            return Err(format!("node-{} is not running", idx));
        }
        node.kill();
        Ok(())
    }

    /// Restart a previously-killed node. The datadir is preserved
    /// across kill/restart, so the child picks up from persisted
    /// RocksDB state (chain head, validator key, etc.) instead of
    /// re-applying genesis. Returns once the node's RPC is up again.
    pub fn restart_node(&mut self, idx: usize) -> Result<(), String> {
        let node = self
            .nodes
            .get_mut(idx)
            .ok_or_else(|| format!("no node at index {}", idx))?;
        if node.process.is_some() {
            return Err(format!("node-{} is already running", idx));
        }
        start_node(node, &self.pyde_bin, self.dev)?;
        let url = node.rpc_url();
        let deadline = Instant::now() + Duration::from_secs(45);
        if let Err(e) = wait_rpc_up(&url, deadline) {
            thread::sleep(Duration::from_millis(200));
            let snapshot = self.nodes[idx].output_snapshot();
            return Err(format!("{}\n--- node-{} output ---\n{}", e, idx, snapshot));
        }
        Ok(())
    }

    /// Read the `epoch` field from a committed block. Returns
    /// `Ok(None)` if the node hasn't committed that slot yet.
    pub fn epoch_of(&self, node_idx: usize, slot: u64) -> Result<Option<u64>, String> {
        let params = format!("[{}]", slot);
        let resp = rpc_call(
            &self.nodes[node_idx].rpc_url(),
            "pyde_getBlockByNumber",
            &params,
        )?;
        if resp.contains(r#""result":null"#) {
            return Ok(None);
        }
        let key = r#""epoch":"#;
        let start = resp
            .find(key)
            .ok_or_else(|| format!("no epoch field in response: {}", resp))?
            + key.len();
        let tail = &resp[start..];
        let end = tail
            .bytes()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if end == 0 {
            return Err(format!("couldn't parse epoch from {}", tail));
        }
        let v: u64 = tail[..end]
            .parse()
            .map_err(|e| format!("parse epoch {}: {}", &tail[..end], e))?;
        Ok(Some(v))
    }

    /// Read the proposer address for a block at `slot` from `node_idx`'s
    /// `pyde_getBlockByNumber`. Returns `Ok(None)` if the node has not
    /// committed that slot yet (gap or pre-produced).
    pub fn proposer_of(
        &self,
        node_idx: usize,
        slot: u64,
    ) -> Result<Option<[u8; 32]>, String> {
        let params = format!("[{}]", slot);
        let resp = rpc_call(
            &self.nodes[node_idx].rpc_url(),
            "pyde_getBlockByNumber",
            &params,
        )?;
        if resp.contains(r#""result":null"#) {
            return Ok(None);
        }
        // Response has `"proposer":"0x<64 hex>"`. Extract it.
        let key = r#""proposer":"0x"#;
        let start = resp.find(key).ok_or_else(|| {
            format!("no proposer in getBlockByNumber({}) response: {}", slot, resp)
        })?;
        let tail = &resp[start + key.len()..];
        let end = tail
            .find('"')
            .ok_or_else(|| format!("unterminated proposer: {}", resp))?;
        let hex = &tail[..end];
        let bytes = hex::decode(hex)
            .map_err(|e| format!("decode proposer {}: {}", hex, e))?;
        if bytes.len() != 32 {
            return Err(format!("proposer address is {} bytes, expected 32", bytes.len()));
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        Ok(Some(addr))
    }

    /// Indices of every validator node.
    pub fn validator_indices(&self) -> Vec<usize> {
        self.nodes
            .iter()
            .filter(|n| n.role == "validator")
            .map(|n| n.index)
            .collect()
    }

    /// Indices of every full-node.
    pub fn full_node_indices(&self) -> Vec<usize> {
        self.nodes
            .iter()
            .filter(|n| n.role == "full")
            .map(|n| n.index)
            .collect()
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

    // --------------------------------------------------------------
    // Slashing helpers (slice 6.6)
    // --------------------------------------------------------------

    /// Read a validator's FALCON keypair from its datadir. Layout is
    /// the one `generate_testnet` writes: `pk_len u32 LE || pk || sk`.
    /// Returns `(pk_bytes, sk_bytes)`.
    pub fn load_validator_key(
        &self,
        node_idx: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let path = self.nodes[node_idx].datadir.join("validator.key");
        let raw = std::fs::read(&path)
            .map_err(|e| format!("read {}: {}", path.display(), e))?;
        if raw.len() < 4 {
            return Err(format!("validator.key too short: {}", raw.len()));
        }
        let pk_len = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
        if raw.len() < 4 + pk_len {
            return Err(format!(
                "validator.key truncated: expected >= {} bytes, got {}",
                4 + pk_len,
                raw.len()
            ));
        }
        let pk = raw[4..4 + pk_len].to_vec();
        let sk = raw[4 + pk_len..].to_vec();
        Ok((pk, sk))
    }

    /// Read the on-chain validator set via `pyde_getValidators`. Returns
    /// a vec of (address, stake, status) tuples. `status` is "active",
    /// "unbonding", or "exited".
    pub fn get_validator_set(
        &self,
        node_idx: usize,
    ) -> Result<Vec<(String, u128, String)>, String> {
        let resp = rpc_call(
            &self.nodes[node_idx].rpc_url(),
            "pyde_getValidators",
            "[]",
        )?;
        parse_validator_set(&resp)
    }

    /// Build the wire-format bytes for a `DoubleSignEvidence`.
    /// Mirrors `pyde_node::wire::encode_double_sign_evidence` — kept
    /// here rather than imported because `pyde_node` is a binary-only
    /// crate (no `[lib]` target) and integration tests can't reach
    /// into its modules.
    ///
    /// Layout (EVIDENCE_VERSION = 1):
    ///   u8 version | u64 slot | [u8;32] hash1 | u32 len | sig1 bytes
    ///             | [u8;32] hash2 | u32 len | sig2 bytes
    ///             | [u8;32] signer | [u8;32] submitter
    pub fn encode_double_sign_evidence_bytes(
        slot: u64,
        hash_1: &[u8; 32],
        signature_1: &[u8],
        hash_2: &[u8; 32],
        signature_2: &[u8],
        signer: &[u8; 32],
        submitter: &[u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + 8 + 32 + 4 + signature_1.len() + 32 + 4 + signature_2.len() + 32 + 32,
        );
        out.push(1u8); // version
        out.extend_from_slice(&slot.to_le_bytes());
        out.extend_from_slice(hash_1);
        out.extend_from_slice(&(signature_1.len() as u32).to_le_bytes());
        out.extend_from_slice(signature_1);
        out.extend_from_slice(hash_2);
        out.extend_from_slice(&(signature_2.len() as u32).to_le_bytes());
        out.extend_from_slice(signature_2);
        out.extend_from_slice(signer);
        out.extend_from_slice(submitter);
        out
    }

    /// Submit a double-sign Slash tx via `pyde_sendTransaction`.
    /// `evidence_hex` is the output of `encode_double_sign_evidence`,
    /// hex-encoded without the `0x` prefix. `submitter` is the address
    /// that pays gas and receives the finder's fee.
    pub fn submit_slash_tx(
        &self,
        node_idx: usize,
        submitter: &[u8; 32],
        evidence_hex: &str,
    ) -> Result<String, String> {
        // to = zero address; slash txs have no recipient. tx_type =
        // "slash" triggers the TransactionType::Slash path added to
        // the RPC handler for this slice.
        let params = format!(
            r#"[{{"from":"0x{}","to":"0x{}","value":"0","gas":500000,"data":"0x{}","txType":"slash"}}]"#,
            hex::encode(submitter),
            hex::encode([0u8; 32]),
            evidence_hex,
        );
        let resp = rpc_call(
            &self.nodes[node_idx].rpc_url(),
            "pyde_sendTransaction",
            &params,
        )?;
        parse_escaped_tx_hash(&resp).map_err(|e| {
            format!(
                "pyde_sendTransaction(slash) parse failed: {}; raw response:\n{}",
                e, resp
            )
        })
    }

    // --------------------------------------------------------------
    // Tx lifecycle helpers (slice 6.2)
    // --------------------------------------------------------------

    /// Pre-funded addresses from `node-0`'s `genesis.toml`. Includes
    /// every validator (staked account), 5 extra non-validator accounts,
    /// and the faucet. Useful sources for test transfers.
    pub fn funded_addresses(&self) -> Result<Vec<[u8; 32]>, String> {
        let path = self.nodes[0].datadir.join("genesis.toml");
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("read {}: {}", path.display(), e))?;
        // Lightweight scrape of `address = "hex..."` lines. A full TOML
        // decoder would pull in another dep; this is plenty for the
        // harness's needs.
        let mut out = Vec::new();
        for line in content.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("address = \"") {
                if let Some(hex) = rest.strip_suffix('"') {
                    if let Ok(bytes) = hex::decode(hex) {
                        if bytes.len() == 32 {
                            let mut a = [0u8; 32];
                            a.copy_from_slice(&bytes);
                            // genesis.toml lists validators twice (once
                            // in `[[allocations]]`, once in
                            // `[[validators]]`) — dedupe.
                            if !out.contains(&a) {
                                out.push(a);
                            }
                        }
                    }
                }
            }
        }
        if out.is_empty() {
            return Err(format!("no addresses found in {}", path.display()));
        }
        Ok(out)
    }

    /// Submit a dev-mode transfer from `from` to `to` for `value`
    /// quanta via node `node_idx`. Returns the tx hash.
    ///
    /// No signature is constructed — devnet's `chain_id == 31337`
    /// path in the RPC handler skips signature verification, and the
    /// network was spawned with `dev = true` specifically to unlock
    /// this path.
    pub fn submit_transfer(
        &self,
        node_idx: usize,
        from: &[u8; 32],
        to: &[u8; 32],
        value: u128,
    ) -> Result<String, String> {
        let params = format!(
            r#"[{{"from":"0x{}","to":"0x{}","value":"{}","gas":100000}}]"#,
            hex::encode(from),
            hex::encode(to),
            value
        );
        let resp = rpc_call(
            &self.nodes[node_idx].rpc_url(),
            "pyde_sendTransaction",
            &params,
        )?;
        // `pyde_sendTransaction` returns a JSON-stringified object as
        // its `result` field, so the raw wire format is:
        //   {"jsonrpc":"2.0","id":1,"result":"{\"txHash\":\"0x...\"}"}
        // The inner quotes are escaped. Scan for the escaped
        // `txHash` pattern directly rather than trying to unescape
        // the string first.
        parse_escaped_tx_hash(&resp).map_err(|e| {
            format!(
                "pyde_sendTransaction parse failed: {}; raw response:\n{}",
                e, resp
            )
        })
    }

    /// Balance in quanta. Returns `0` if the account is unknown.
    pub fn get_balance(&self, node_idx: usize, address: &[u8; 32]) -> Result<u128, String> {
        let params = format!(r#"["0x{}"]"#, hex::encode(address));
        let resp = rpc_call(
            &self.nodes[node_idx].rpc_url(),
            "pyde_getBalance",
            &params,
        )?;
        // `pyde_getBalance` returns the balance as a decimal string
        // (see `balance.to_string()` in `rpc.rs::get_balance`). Not
        // hex, despite the `0x`-ish feel of the sibling RPCs.
        let raw = parse_hex_result(&resp)?;
        raw.parse::<u128>()
            .map_err(|e| format!("parse balance {:?}: {}", raw, e))
    }

    /// Get the receipt for a tx. Returns `Ok(None)` if the node has
    /// not yet indexed the tx (e.g. it hasn't been included yet).
    pub fn get_receipt(
        &self,
        node_idx: usize,
        tx_hash: &str,
    ) -> Result<Option<ReceiptView>, String> {
        let params = format!(r#"["{}"]"#, tx_hash);
        let resp = rpc_call(
            &self.nodes[node_idx].rpc_url(),
            "pyde_getTransactionReceipt",
            &params,
        )?;
        // Response: `"result":null` or `"result":{...}`.
        let body = resp.trim();
        if body.contains(r#""result":null"#) {
            return Ok(None);
        }
        // Extract success flag + block slot from JSON. Use simple
        // string matching to avoid pulling serde into the harness.
        let success = extract_bool_field(body, "status")
            .or_else(|| extract_bool_field(body, "success"))
            .unwrap_or(false);
        let block_slot = extract_u64_field(body, "blockNumber")
            .or_else(|| extract_u64_field(body, "slot"));
        Ok(Some(ReceiptView {
            raw: body.to_string(),
            success,
            block_slot,
        }))
    }

    /// Poll every node until each reports a receipt for `tx_hash` or
    /// the deadline elapses. Returns the per-node receipt snapshots.
    pub fn wait_for_receipt_on_all(
        &self,
        tx_hash: &str,
        timeout: Duration,
    ) -> Result<Vec<ReceiptView>, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut all: Vec<Option<ReceiptView>> = Vec::with_capacity(self.nodes.len());
            for n in &self.nodes {
                all.push(self.get_receipt(n.index, tx_hash).ok().flatten());
            }
            if all.iter().all(|r| r.is_some()) {
                return Ok(all.into_iter().map(Option::unwrap).collect());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "receipt for {} never appeared on all nodes within {:?}; per-node: {:?}",
                    tx_hash,
                    timeout,
                    all.iter().map(|r| r.is_some()).collect::<Vec<_>>()
                ));
            }
            thread::sleep(Duration::from_millis(250));
        }
    }
}

/// Lightweight receipt representation. Full receipt JSON is kept as
/// `raw` so tests can drill into fields the harness doesn't expose.
#[derive(Clone, Debug)]
pub struct ReceiptView {
    pub raw: String,
    pub success: bool,
    pub block_slot: Option<u64>,
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
    full_nodes: usize,
    out: &Path,
    dev: bool,
    chain_id: u64,
    base_port: u16,
    base_rpc_port: u16,
    block_time_ms: u64,
) -> Result<(), String> {
    let mut cmd = Command::new(pyde);
    cmd.arg("testnet")
        .arg("--validators")
        .arg(validators.to_string())
        .arg("--full-nodes")
        .arg(full_nodes.to_string())
        .arg("--out")
        .arg(out)
        .arg("--base-port")
        .arg(base_port.to_string())
        .arg("--base-rpc-port")
        .arg(base_rpc_port.to_string())
        .arg("--chain-id")
        .arg(chain_id.to_string())
        .arg("--block-time-ms")
        .arg(block_time_ms.to_string());
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

/// Extract every validator (address, stake, status) from a
/// `pyde_getValidators` response. Handler returns a real JSON object
/// (not a stringified one), so the wire layout is
///   `"result":{"count":N,"validators":[{"address":"0x..","stake":"N","status":"..","index":i},...]}`
/// Uses simple string scanning to avoid pulling serde into the harness.
fn parse_validator_set(resp: &str) -> Result<Vec<(String, u128, String)>, String> {
    // Leave the `0x` prefix in the captured address so callers can
    // compare against `format!("0x{}", hex::encode(addr))` directly.
    let key_addr = r#""address":""#;
    let key_stake = r#""stake":""#;
    let key_status = r#""status":""#;
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(addr_start_rel) = resp[cursor..].find(key_addr) {
        let addr_start = cursor + addr_start_rel + key_addr.len();
        let addr_end_rel = resp[addr_start..]
            .find('"')
            .ok_or_else(|| format!("unterminated address in {:?}", &resp[addr_start..]))?;
        let addr = resp[addr_start..addr_start + addr_end_rel].to_string();

        // stake and status follow the address for the same validator object.
        let after_addr = addr_start + addr_end_rel;
        let stake_start_rel = resp[after_addr..]
            .find(key_stake)
            .ok_or("no stake field after address")?;
        let stake_start = after_addr + stake_start_rel + key_stake.len();
        let stake_end_rel = resp[stake_start..]
            .find('"')
            .ok_or("unterminated stake")?;
        let stake: u128 = resp[stake_start..stake_start + stake_end_rel]
            .parse()
            .map_err(|e| format!("parse stake {}: {}", &resp[stake_start..stake_start + stake_end_rel], e))?;

        let after_stake = stake_start + stake_end_rel;
        let status_start_rel = resp[after_stake..]
            .find(key_status)
            .ok_or("no status field after stake")?;
        let status_start = after_stake + status_start_rel + key_status.len();
        let status_end_rel = resp[status_start..]
            .find('"')
            .ok_or("unterminated status")?;
        let status = resp[status_start..status_start + status_end_rel].to_string();

        out.push((addr, stake, status));
        cursor = status_start + status_end_rel;
    }
    Ok(out)
}

/// Extract the `txHash` from a `pyde_sendTransaction` response.
///
/// The handler in `crates/node/src/rpc.rs` wraps the hash in a
/// JSON-stringified object (`Result<String, _>` where the string is
/// itself a serialized JSON object). On the wire, that produces
/// `"result":"{\"txHash\":\"0x...\"}"` — so we scan for the escaped
/// `\"txHash\":\"` pattern directly.
fn parse_escaped_tx_hash(resp: &str) -> Result<String, String> {
    let needle = r#"\"txHash\":\""#;
    let idx = resp
        .find(needle)
        .ok_or_else(|| format!("no txHash in {:?}", resp))?;
    let tail = &resp[idx + needle.len()..];
    let end = tail
        .find(r#"\""#)
        .ok_or_else(|| format!("unterminated txHash in {:?}", resp))?;
    Ok(tail[..end].to_string())
}

/// Extract `"<field>": true|false` from a JSON blob. Returns `None`
/// if the field isn't present. Tolerant of whitespace but assumes
/// no nested object shares the key name.
fn extract_bool_field(body: &str, field: &str) -> Option<bool> {
    let needle = format!(r#""{}""#, field);
    let start = body.find(&needle)? + needle.len();
    let tail = &body[start..];
    let colon = tail.find(':')? + 1;
    let rest = tail[colon..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Extract `"<field>": 123` or `"<field>": "0x..."` as a u64.
fn extract_u64_field(body: &str, field: &str) -> Option<u64> {
    let needle = format!(r#""{}""#, field);
    let start = body.find(&needle)? + needle.len();
    let tail = &body[start..];
    let colon = tail.find(':')? + 1;
    let rest = tail[colon..].trim_start();
    if rest.starts_with('"') {
        // Quoted string — look for closing quote.
        let inner = &rest[1..];
        let end = inner.find('"')?;
        let s = &inner[..end];
        if let Some(hex) = s.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()
        } else {
            s.parse().ok()
        }
    } else {
        // Bare number — read until a non-digit.
        let end = rest
            .bytes()
            .take_while(|b| b.is_ascii_digit())
            .count();
        rest[..end].parse().ok()
    }
}
