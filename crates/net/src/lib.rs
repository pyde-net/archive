//! Pyde Networking: P2P transport layer with libp2p.
//!
//! ## Transport Crypto (TODO: Pre-Mainnet)
//!
//! Currently uses Ed25519 (libp2p default) for peer identity and Noise
//! transport encryption. Before mainnet, swap to:
//! - Peer identity: FALCON-512 (post-quantum signatures)
//! - Transport encryption: Kyber-768 (post-quantum key exchange)
//!
//! The swap is isolated to the transport layer — all application-layer
//! messages are already signed with FALCON-512 and encrypted with
//! threshold Kyber. See ROADMAP tasks for upgrade path.

pub mod channels;
pub mod config;
pub mod discovery;
pub mod node;
pub mod peer;
