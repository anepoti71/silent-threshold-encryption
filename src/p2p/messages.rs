//! P2P message types for decentralized coordination

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Unique message identifier
pub type MessageId = [u8; 32];

/// Peer identifier (derived from public key or network address)
pub type PeerId = String;

/// Message type for P2P communication
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2PMessage {
    /// Discovery: Announce presence to network
    PeerAnnouncement {
        peer_id: PeerId,
        party_id: Option<usize>,
        listen_addr: String,
        capabilities: Vec<String>,
    },

    /// Discovery: Request peer list
    PeerListRequest { from_peer: PeerId },

    /// Discovery: Response with known peers
    PeerListResponse { peers: Vec<PeerInfo> },

    /// Setup: Propose VSS parameters for distributed setup
    VSSProposal {
        proposer_id: PeerId,
        n: usize,
        t: usize,
        commitment_bytes: Vec<u8>,
    },

    /// Setup: VSS share for distributed KZG parameter generation
    VSSShare {
        from_peer: PeerId,
        to_peer: PeerId,
        share_bytes: Vec<u8>, // Encrypted share
        proof_bytes: Vec<u8>,
    },

    /// Setup: Verify and acknowledge VSS contribution
    VSSAck {
        from_peer: PeerId,
        proposal_id: MessageId,
        valid: bool,
    },

    /// Key Generation: Broadcast public key
    PublicKeyBroadcast {
        party_id: usize,
        peer_id: PeerId,
        pk_bytes: Vec<u8>,
        signature: Vec<u8>, // Sign with peer identity key
    },

    /// Key Generation: Request missing public keys
    PublicKeyRequest {
        from_peer: PeerId,
        requested_parties: Vec<usize>,
    },

    /// Aggregate Key: Broadcast computed aggregate key
    AggregateKeyBroadcast {
        from_peer: PeerId,
        agg_key_bytes: Vec<u8>,
        contributing_parties: Vec<usize>,
        signature: Vec<u8>,
    },

    /// Encryption: Broadcast ciphertext
    CiphertextBroadcast {
        from_peer: PeerId,
        ct_bytes: Vec<u8>,
        threshold: usize,
        timestamp: u64,
    },

    /// Decryption: Request partial decryption
    PartialDecryptionRequest {
        request_id: MessageId,
        from_peer: PeerId,
        ct_bytes: Vec<u8>,
        requesting_parties: Vec<usize>,
    },

    /// Decryption: Provide partial decryption
    PartialDecryptionResponse {
        request_id: MessageId,
        party_id: usize,
        peer_id: PeerId,
        pd_bytes: Vec<u8>,
        signature: Vec<u8>,
    },

    /// Consensus: Propose party selection for decryption
    PartySelectionProposal {
        proposal_id: MessageId,
        from_peer: PeerId,
        selected_parties: Vec<usize>,
        threshold: usize,
    },

    /// Consensus: Vote on party selection
    PartySelectionVote {
        proposal_id: MessageId,
        from_peer: PeerId,
        approve: bool,
        reason: Option<String>,
    },

    /// Generic: Forward message to other peers (gossip)
    Gossip {
        message_id: MessageId,
        ttl: u8,
        seen_by: HashSet<PeerId>,
        payload: Box<P2PMessage>,
    },

    /// Health: Ping for liveness check
    Ping { from_peer: PeerId, timestamp: u64 },

    /// Health: Pong response
    Pong { from_peer: PeerId, timestamp: u64 },

    /// Error: Report protocol error
    Error {
        from_peer: PeerId,
        error_type: String,
        message: String,
    },
}

/// Peer information for discovery
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub party_id: Option<usize>,
    pub address: String,
    pub last_seen: u64,
    pub capabilities: Vec<String>,
}

impl P2PMessage {
    /// Get the sender peer ID
    pub fn sender(&self) -> Option<&PeerId> {
        match self {
            P2PMessage::PeerAnnouncement { peer_id, .. } => Some(peer_id),
            P2PMessage::PeerListRequest { from_peer } => Some(from_peer),
            P2PMessage::VSSProposal { proposer_id, .. } => Some(proposer_id),
            P2PMessage::VSSShare { from_peer, .. } => Some(from_peer),
            P2PMessage::VSSAck { from_peer, .. } => Some(from_peer),
            P2PMessage::PublicKeyBroadcast { peer_id, .. } => Some(peer_id),
            P2PMessage::PublicKeyRequest { from_peer, .. } => Some(from_peer),
            P2PMessage::AggregateKeyBroadcast { from_peer, .. } => Some(from_peer),
            P2PMessage::CiphertextBroadcast { from_peer, .. } => Some(from_peer),
            P2PMessage::PartialDecryptionRequest { from_peer, .. } => Some(from_peer),
            P2PMessage::PartialDecryptionResponse { peer_id, .. } => Some(peer_id),
            P2PMessage::PartySelectionProposal { from_peer, .. } => Some(from_peer),
            P2PMessage::PartySelectionVote { from_peer, .. } => Some(from_peer),
            P2PMessage::Ping { from_peer, .. } => Some(from_peer),
            P2PMessage::Pong { from_peer, .. } => Some(from_peer),
            P2PMessage::Error { from_peer, .. } => Some(from_peer),
            P2PMessage::Gossip { payload, .. } => payload.sender(),
            P2PMessage::PeerListResponse { .. } => None,
        }
    }

    /// Get message type as string
    pub fn message_type(&self) -> MessageType {
        match self {
            P2PMessage::PeerAnnouncement { .. } => MessageType::Discovery,
            P2PMessage::PeerListRequest { .. } => MessageType::Discovery,
            P2PMessage::PeerListResponse { .. } => MessageType::Discovery,
            P2PMessage::VSSProposal { .. } => MessageType::Setup,
            P2PMessage::VSSShare { .. } => MessageType::Setup,
            P2PMessage::VSSAck { .. } => MessageType::Setup,
            P2PMessage::PublicKeyBroadcast { .. } => MessageType::KeyGeneration,
            P2PMessage::PublicKeyRequest { .. } => MessageType::KeyGeneration,
            P2PMessage::AggregateKeyBroadcast { .. } => MessageType::KeyGeneration,
            P2PMessage::CiphertextBroadcast { .. } => MessageType::Encryption,
            P2PMessage::PartialDecryptionRequest { .. } => MessageType::Decryption,
            P2PMessage::PartialDecryptionResponse { .. } => MessageType::Decryption,
            P2PMessage::PartySelectionProposal { .. } => MessageType::Consensus,
            P2PMessage::PartySelectionVote { .. } => MessageType::Consensus,
            P2PMessage::Gossip { payload, .. } => payload.message_type(),
            P2PMessage::Ping { .. } => MessageType::Health,
            P2PMessage::Pong { .. } => MessageType::Health,
            P2PMessage::Error { .. } => MessageType::Error,
        }
    }
}

/// Message classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Discovery,
    Setup,
    KeyGeneration,
    Encryption,
    Decryption,
    Consensus,
    Health,
    Error,
}
