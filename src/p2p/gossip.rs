//! Gossip protocol for efficient message propagation in P2P network

use super::messages::{MessageId, P2PMessage, PeerId};
use blake2::{Blake2b512, Digest};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default Time-To-Live for gossip messages
const DEFAULT_TTL: u8 = 5;

/// Default fanout (number of peers to forward to)
const DEFAULT_FANOUT: usize = 3;

/// Message cache timeout in seconds
const CACHE_TIMEOUT: u64 = 300; // 5 minutes

/// Gossip protocol handler
pub struct GossipProtocol {
    /// Local peer ID
    local_peer_id: PeerId,

    /// Seen messages cache (message_id -> timestamp)
    seen_messages: Arc<RwLock<HashMap<MessageId, u64>>>,

    /// Message handlers
    handlers: Arc<RwLock<HashMap<String, Box<dyn MessageHandler + Send + Sync>>>>,

    /// Gossip fanout
    fanout: usize,

    /// Default TTL
    default_ttl: u8,
}

/// Message handler trait
pub trait MessageHandler {
    fn handle(&self, msg: &P2PMessage) -> Result<(), String>;
}

impl GossipProtocol {
    /// Create new gossip protocol handler
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            local_peer_id,
            seen_messages: Arc::new(RwLock::new(HashMap::new())),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            fanout: DEFAULT_FANOUT,
            default_ttl: DEFAULT_TTL,
        }
    }

    /// Create with custom parameters
    pub fn with_params(local_peer_id: PeerId, fanout: usize, default_ttl: u8) -> Self {
        Self {
            local_peer_id,
            seen_messages: Arc::new(RwLock::new(HashMap::new())),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            fanout,
            default_ttl,
        }
    }

    /// Register a message handler
    pub fn register_handler<H>(&self, message_type: String, handler: H)
    where
        H: MessageHandler + Send + Sync + 'static,
    {
        let mut handlers = self.handlers.write().unwrap();
        handlers.insert(message_type, Box::new(handler));
    }

    /// Broadcast a message to the network
    pub fn broadcast(&self, msg: P2PMessage) -> GossipMessage {
        let message_id = self.compute_message_id(&msg);
        let mut seen_by = HashSet::new();
        seen_by.insert(self.local_peer_id.clone());

        self.mark_as_seen(&message_id);

        GossipMessage {
            message_id,
            ttl: self.default_ttl,
            seen_by,
            payload: msg,
        }
    }

    /// Handle incoming gossip message
    pub fn handle_gossip(&self, gossip: &GossipMessage) -> GossipResult {
        // Check if we've seen this message before
        if self.has_seen(&gossip.message_id) {
            return GossipResult::AlreadySeen;
        }

        // Check TTL
        if gossip.ttl == 0 {
            return GossipResult::Expired;
        }

        // Mark as seen
        self.mark_as_seen(&gossip.message_id);

        // Process the message locally
        let message_type = format!("{:?}", gossip.payload.message_type());
        if let Some(handler) = self.handlers.read().unwrap().get(&message_type) {
            if let Err(e) = handler.handle(&gossip.payload) {
                return GossipResult::HandlerError(e);
            }
        }

        // Determine if we should forward
        if gossip.ttl > 1 && !gossip.seen_by.contains(&self.local_peer_id) {
            let mut new_gossip = gossip.clone();
            new_gossip.ttl -= 1;
            new_gossip.seen_by.insert(self.local_peer_id.clone());

            GossipResult::ShouldForward(new_gossip)
        } else {
            GossipResult::Processed
        }
    }

    /// Check if message has been seen
    pub fn has_seen(&self, message_id: &MessageId) -> bool {
        let seen = self.seen_messages.read().unwrap();
        seen.contains_key(message_id)
    }

    /// Mark message as seen
    fn mark_as_seen(&self, message_id: &MessageId) {
        let mut seen = self.seen_messages.write().unwrap();
        let timestamp = current_timestamp();
        seen.insert(*message_id, timestamp);
    }

    /// Compute message ID from message content
    fn compute_message_id(&self, msg: &P2PMessage) -> MessageId {
        let mut hasher = Blake2b512::new();

        // Hash message content
        let msg_bytes = bincode::serialize(msg).unwrap_or_default();
        hasher.update(&msg_bytes);

        // Add timestamp for uniqueness
        let timestamp = current_timestamp();
        hasher.update(&timestamp.to_le_bytes());

        let result = hasher.finalize();
        let mut message_id = [0u8; 32];
        message_id.copy_from_slice(&result[..32]);
        message_id
    }

    /// Clean up old seen messages
    pub fn cleanup_old_messages(&self) {
        let mut seen = self.seen_messages.write().unwrap();
        let now = current_timestamp();

        seen.retain(|_, timestamp| now - *timestamp < CACHE_TIMEOUT);
    }

    /// Get fanout value
    pub fn fanout(&self) -> usize {
        self.fanout
    }

    /// Get number of seen messages
    pub fn seen_count(&self) -> usize {
        let seen = self.seen_messages.read().unwrap();
        seen.len()
    }
}

/// Gossip message wrapper
#[derive(Clone, Debug)]
pub struct GossipMessage {
    pub message_id: MessageId,
    pub ttl: u8,
    pub seen_by: HashSet<PeerId>,
    pub payload: P2PMessage,
}

/// Result of gossip handling
pub enum GossipResult {
    /// Message already seen, ignore
    AlreadySeen,

    /// Message TTL expired
    Expired,

    /// Message processed successfully
    Processed,

    /// Message should be forwarded to other peers
    ShouldForward(GossipMessage),

    /// Handler error
    HandlerError(String),
}

/// Get current timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::messages::P2PMessage;

    struct TestHandler;
    impl MessageHandler for TestHandler {
        fn handle(&self, _msg: &P2PMessage) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn test_gossip_broadcast() {
        let gossip = GossipProtocol::new("peer1".to_string());

        let msg = P2PMessage::Ping {
            from_peer: "peer1".to_string(),
            timestamp: current_timestamp(),
        };

        let gossip_msg = gossip.broadcast(msg);
        assert_eq!(gossip_msg.ttl, DEFAULT_TTL);
        assert!(gossip_msg.seen_by.contains("peer1"));
    }

    #[test]
    fn test_has_seen() {
        let gossip = GossipProtocol::new("peer1".to_string());

        let msg = P2PMessage::Ping {
            from_peer: "peer1".to_string(),
            timestamp: current_timestamp(),
        };

        let gossip_msg = gossip.broadcast(msg);
        assert!(gossip.has_seen(&gossip_msg.message_id));
    }

    #[test]
    fn test_ttl_decrement() {
        let gossip = GossipProtocol::new("peer1".to_string());

        let msg = P2PMessage::Ping {
            from_peer: "peer2".to_string(),
            timestamp: current_timestamp(),
        };

        let gossip_msg = GossipMessage {
            message_id: [1u8; 32],
            ttl: 3,
            seen_by: HashSet::new(),
            payload: msg,
        };

        match gossip.handle_gossip(&gossip_msg) {
            GossipResult::ShouldForward(new_msg) => {
                assert_eq!(new_msg.ttl, 2);
            }
            _ => panic!("Expected ShouldForward"),
        }
    }
}
