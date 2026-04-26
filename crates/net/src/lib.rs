//! Pyde Networking: P2P transport layer with libp2p.
//!
//! ## Transport Crypto
//!
//! Transport uses Ed25519/X25519 (libp2p default). This is NOT a security
//! gap because all consensus-critical messages (votes, blocks, transactions)
//! are signed with FALCON-512 at the application layer, and encrypted mempool
//! uses Kyber-768. A quantum attacker who breaks Ed25519 P2P identity cannot
//! forge FALCON signatures, manipulate consensus, or decrypt threshold-encrypted
//! transactions. The Ed25519 layer only handles libp2p routing.
//!
//! Post-launch hardening: add FALCON peer authentication handshake on connect
//! to reject impersonators faster (defense-in-depth, not a security fix).

pub mod auth;
pub mod channels;
pub mod config;
pub mod consensus_protocol;
pub mod ddos;
pub mod discovery;
pub mod node;
pub mod peer;
pub mod propagation;
pub mod sync;
pub mod sync_protocol;
