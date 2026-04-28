//! Persistent peer book for warm-restart connection restoration.
//!
//! Audit 234 follow-up: when a validator restarts, libp2p's
//! Kademlia discovery + bootstrap-list dial don't always re-
//! establish a connection to *every* peer the node had before. A
//! small N=4 committee that survives one restart can end up with
//! one missing edge (e.g. node-0 ↔ node-3) — invisible while all
//! 4 are alive because messages still route through the central
//! peer, but the moment a different node dies the network drops
//! below quorum and consensus stalls.
//!
//! Persisting the observed `(PeerId, Multiaddr)` set on a coarse
//! cadence and re-dialing on startup closes the gap. The saved
//! set is treated as a hint, not a source of truth: addresses can
//! drift between runs (cloud restart with a new IP), so a dial
//! failure falls back to the existing bootstrap + Kademlia DHT
//! discovery path.
//!
//! Storage shape: a small JSON file at
//! `<datadir>/peer_book.json`. Atomic-write via temp + rename so
//! a `kill -9` mid-write doesn't corrupt the on-disk file. Size is
//! ~80 bytes per peer; 128 mainnet validators ≈ 10 KB.

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use tracing::{info, warn};

const PEER_BOOK_FILENAME: &str = "peer_book.json";

/// In-memory + persisted view of recently-connected peers.
#[derive(Debug, Default)]
pub struct PeerBook {
    /// Latest known multiaddr per peer. Replaced on subsequent
    /// observations of the same `PeerId` — when a peer comes back
    /// on a new address, we want the new one.
    peers: HashMap<PeerId, Multiaddr>,
}

#[derive(Serialize, Deserialize)]
struct PeerEntry {
    peer_id: String,
    multiaddr: String,
}

#[derive(Serialize, Deserialize, Default)]
struct PeerBookFile {
    peers: Vec<PeerEntry>,
}

impl PeerBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the persisted set from disk. Missing file, parse
    /// errors, and unparseable entries all fall through to an
    /// empty book — corruption isn't fatal, we re-discover via
    /// bootstrap + DHT.
    pub fn load(datadir: &Path) -> Self {
        let path = datadir.join(PEER_BOOK_FILENAME);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => return Self::new(),
        };
        let parsed: PeerBookFile = match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "failed to parse peer book; starting fresh"
                );
                return Self::new();
            }
        };
        let mut book = Self::new();
        for entry in parsed.peers {
            match (
                PeerId::from_str(&entry.peer_id),
                Multiaddr::from_str(&entry.multiaddr),
            ) {
                (Ok(peer_id), Ok(addr)) => {
                    book.peers.insert(peer_id, addr);
                }
                _ => {
                    // Skip malformed entries silently — file may
                    // be from a future version or hand-edited.
                }
            }
        }
        info!(count = book.peers.len(), "loaded peer book");
        book
    }

    /// Atomically persist the current set. Writes to
    /// `peer_book.json.tmp` then `rename`s into place so a
    /// `kill -9` mid-write either lands the new file or leaves the
    /// old one untouched.
    pub fn save(&self, datadir: &Path) -> Result<(), String> {
        let entries: Vec<PeerEntry> = self
            .peers
            .iter()
            .map(|(p, a)| PeerEntry {
                peer_id: p.to_string(),
                multiaddr: a.to_string(),
            })
            .collect();
        let file = PeerBookFile { peers: entries };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
        let final_path = datadir.join(PEER_BOOK_FILENAME);
        let tmp_path = datadir.join(format!("{}.tmp", PEER_BOOK_FILENAME));
        std::fs::write(&tmp_path, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp_path, &final_path).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Record an observed `(peer, addr)` pair. Idempotent —
    /// duplicate observations just refresh the address.
    pub fn record(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.peers.insert(peer_id, addr);
    }

    /// Iterate over saved peers. Used at swarm startup to
    /// supplement the bootstrap dial list.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &Multiaddr)> {
        self.peers.iter()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity;

    fn random_peer_addr() -> (PeerId, Multiaddr) {
        let kp = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(kp.public());
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/30000".parse().unwrap();
        (peer_id, addr)
    }

    #[test]
    fn roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut book = PeerBook::new();
        let (p1, a1) = random_peer_addr();
        let (p2, a2) = random_peer_addr();
        book.record(p1, a1.clone());
        book.record(p2, a2.clone());
        book.save(dir.path()).unwrap();

        let loaded = PeerBook::load(dir.path());
        assert_eq!(loaded.len(), 2);
        let map: HashMap<_, _> = loaded.iter().map(|(p, a)| (*p, a.clone())).collect();
        assert_eq!(map.get(&p1), Some(&a1));
        assert_eq!(map.get(&p2), Some(&a2));
    }

    #[test]
    fn record_is_idempotent_and_refreshes_address() {
        let mut book = PeerBook::new();
        let (p1, a1) = random_peer_addr();
        let a2: Multiaddr = "/ip4/127.0.0.1/tcp/40000".parse().unwrap();
        book.record(p1, a1);
        book.record(p1, a2.clone());
        assert_eq!(book.len(), 1);
        let loaded: HashMap<_, _> = book.iter().map(|(p, a)| (*p, a.clone())).collect();
        assert_eq!(loaded.get(&p1), Some(&a2));
    }

    #[test]
    fn missing_file_is_empty_book() {
        let dir = tempfile::tempdir().unwrap();
        let book = PeerBook::load(dir.path());
        assert!(book.is_empty());
    }

    #[test]
    fn corrupt_file_is_empty_book() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("peer_book.json"), b"not-json").unwrap();
        let book = PeerBook::load(dir.path());
        assert!(book.is_empty());
    }
}
