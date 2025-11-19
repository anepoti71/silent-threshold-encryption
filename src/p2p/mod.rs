//! Peer-to-peer coordination module for decentralized threshold encryption
//!
//! This module provides a truly decentralized alternative to the coordinator-based
//! architecture. Parties can discover each other and coordinate through gossip
//! protocols without any central authority.
//!
//! # Architecture
//!
//! ```text
//! ┌─────┐     ┌─────┐
//! │Party├─────┤Party│
//! │  0  │     │  1  │
//! └──┬──┘     └──┬──┘
//!    │    ┌──────┘
//!    │    │
//! ┌──▼────▼─┐
//! │ Party   │
//! │   2     │
//! └──┬──────┘
//!    │
//! ┌──▼───┐
//! │Party │
//! │  3   │
//! └──────┘
//! ```
//!
//! # Protocol Phases
//!
//! 1. **Discovery Phase**: Parties discover peers via mDNS or bootstrap nodes
//! 2. **Setup Phase**: Distributed KZG parameter generation via VSS
//! 3. **Key Generation**: Each party generates keys and gossips public keys
//! 4. **Encryption**: Any party can encrypt using gossiped aggregate key
//! 5. **Decryption**: Selected parties collaborate via gossip to decrypt

pub mod discovery;
pub mod gossip;
#[cfg(feature = "distributed")]
pub mod libp2p_network;
pub mod messages;
pub mod network;
#[cfg(feature = "distributed")]
pub mod protocol;
pub mod transport;
pub mod vss;
#[cfg(feature = "distributed")]
pub mod crypto_utils;

pub use discovery::PeerDiscovery;
pub use gossip::{GossipMessage, GossipProtocol};
#[cfg(feature = "distributed")]
pub use libp2p_network::{
    Libp2pConfig, Libp2pEvent, Libp2pNetwork, Libp2pNetworkError, Libp2pResult,
};
pub use messages::{MessageType, P2PMessage, PeerInfo};
pub use network::{NetworkConfig, P2PNetwork};
#[cfg(feature = "distributed")]
pub use protocol::{PeerConfig, PeerNode, PeerRuntimeMode};
pub use transport::P2PTransport;
