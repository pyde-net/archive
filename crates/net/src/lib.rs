// Frozen pre-pivot archive: the lints below were promoted to default-warn
// in clippy 1.95, after this code was frozen. The archive is historical and
// not developed further, so it is not conformed to new clippy-version style
// opinions. Allowed at the crate level because the CI's `-- -D warnings`
// overrides Cargo.toml lint tables but not source attributes.
#![allow(
    clippy::cloned_ref_to_slice_refs,
    clippy::explicit_counter_loop,
    clippy::if_same_then_else,
    clippy::manual_checked_ops,
    clippy::manual_flatten,
    clippy::unnecessary_get_then_check,
    clippy::assertions_on_constants,
    clippy::unnecessary_sort_by,
    dead_code
)]

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
pub mod block_txs_protocol;
pub mod blocks_protocol;
pub mod channels;
pub mod config;
pub mod consensus_protocol;
// Audit 335: `ddos.rs` was a 431-line module of unwired
// primitives — `RateLimiter`, `SubnetLimiter`, `PowChallenge`,
// `subnet_diversity` — none of which had any consumer outside
// their own tests. The module gave a false sense of protection:
// operators reading the source might assume per-peer flood
// limits and per-/24 connection caps were active when in fact
// nothing called them.
//
// Deleted in favor of the gossipsub peer-score system installed
// for audit 334, which subsumes the most-needed primitives:
//   - `behaviour_penalty_weight = -10.0` → flood-misbehaving
//     peers (re-graft floods, dropped IWANT) get demoted from
//     the mesh and (eventually) graylisted, replacing
//     `RateLimiter`.
//   - `ip_colocation_factor_weight = -5.0` (threshold 10
//     peers/IP) → Sybil farms behind one address get scored
//     down, replacing `SubnetLimiter` at IP granularity.
//   - `max_transmit_size = 4 MB` (audit 333) on the gossipsub
//     ConfigBuilder → message-size enforcement, replacing
//     `validate_message_size`.
//   - PoW connection-flood mitigation deferred — testnet
//     doesn't need it; can re-introduce when post-mainnet load
//     justifies the connection-level CPU.
//
// The /24-subnet variant of colocation isn't covered exactly by
// gossipsub (it only counts exact-IP matches). If real-world
// telemetry shows /24 abuse on the public testnet, re-introduce
// a SubnetLimiter wired into `ConnectionEstablished`. Until
// then, keeping it as dead code is worse than not having it at
// all.
pub mod discovery;
pub mod node;
pub mod peer;
pub mod propagation;
pub mod sync;
pub mod sync_protocol;
