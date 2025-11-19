//! Peer discovery mechanisms for P2P network

use super::messages::{PeerId, PeerInfo};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Peer discovery service
pub struct PeerDiscovery {
    /// Our peer ID
    local_peer_id: PeerId,

    /// Known peers
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,

    /// Bootstrap nodes (seed peers to connect to)
    bootstrap_nodes: Vec<String>,

    /// Discovery mode
    mode: DiscoveryMode,
}

/// Discovery mode
#[derive(Debug, Clone)]
pub enum DiscoveryMode {
    /// Use bootstrap nodes only
    Bootstrap,

    /// Local network discovery (mDNS-like)
    Local,

    /// Both bootstrap and local
    Hybrid,
}

impl PeerDiscovery {
    /// Create new peer discovery service
    pub fn new(local_peer_id: PeerId, bootstrap_nodes: Vec<String>, mode: DiscoveryMode) -> Self {
        Self {
            local_peer_id,
            peers: Arc::new(RwLock::new(HashMap::new())),
            bootstrap_nodes,
            mode,
        }
    }

    /// Add a known peer
    pub fn add_peer(&self, peer: PeerInfo) {
        match self.peers.write() {
            Ok(mut peers) => {
                peers.insert(peer.peer_id.clone(), peer);
            }
            Err(poisoned) => {
                // Recover from poisoned lock by clearing the poison and using the guard
                let mut peers = poisoned.into_inner();
                peers.insert(peer.peer_id.clone(), peer);
            }
        }
    }

    /// Remove a peer
    pub fn remove_peer(&self, peer_id: &PeerId) {
        match self.peers.write() {
            Ok(mut peers) => {
                peers.remove(peer_id);
            }
            Err(poisoned) => {
                let mut peers = poisoned.into_inner();
                peers.remove(peer_id);
            }
        }
    }

    /// Get all known peers
    pub fn get_peers(&self) -> Vec<PeerInfo> {
        match self.peers.read() {
            Ok(peers) => peers.values().cloned().collect(),
            Err(poisoned) => {
                let peers = poisoned.into_inner();
                peers.values().cloned().collect()
            }
        }
    }

    /// Get a specific peer
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        match self.peers.read() {
            Ok(peers) => peers.get(peer_id).cloned(),
            Err(poisoned) => {
                let peers = poisoned.into_inner();
                peers.get(peer_id).cloned()
            }
        }
    }

    /// Update peer last seen timestamp
    pub fn update_peer_seen(&self, peer_id: &PeerId) {
        match self.peers.write() {
            Ok(mut peers) => {
                if let Some(peer) = peers.get_mut(peer_id) {
                    peer.last_seen = current_timestamp();
                }
            }
            Err(poisoned) => {
                let mut peers = poisoned.into_inner();
                if let Some(peer) = peers.get_mut(peer_id) {
                    peer.last_seen = current_timestamp();
                }
            }
        }
    }

    /// Get bootstrap nodes
    pub fn bootstrap_nodes(&self) -> &[String] {
        &self.bootstrap_nodes
    }

    /// Check if peer already known
    pub fn is_known(&self, peer_id: &PeerId) -> bool {
        match self.peers.read() {
            Ok(peers) => peers.contains_key(peer_id),
            Err(poisoned) => {
                let peers = poisoned.into_inner();
                peers.contains_key(peer_id)
            }
        }
    }

    /// Get our peer ID
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Clean up stale peers (not seen for timeout period)
    pub fn cleanup_stale_peers(&self, timeout_secs: u64) {
        let now = current_timestamp();
        match self.peers.write() {
            Ok(mut peers) => {
                peers.retain(|_, peer| now - peer.last_seen < timeout_secs);
            }
            Err(poisoned) => {
                let mut peers = poisoned.into_inner();
                peers.retain(|_, peer| now - peer.last_seen < timeout_secs);
            }
        }
    }

    /// Get number of active peers
    pub fn peer_count(&self) -> usize {
        match self.peers.read() {
            Ok(peers) => peers.len(),
            Err(poisoned) => {
                let peers = poisoned.into_inner();
                peers.len()
            }
        }
    }

    /// Check if we have enough peers for threshold operation
    pub fn has_sufficient_peers(&self, required: usize) -> bool {
        self.peer_count() >= required
    }

    /// Get peers by party ID
    pub fn get_peers_by_party(&self) -> HashMap<usize, PeerInfo> {
        match self.peers.read() {
            Ok(peers) => peers
                .values()
                .filter_map(|peer| peer.party_id.map(|id| (id, peer.clone())))
                .collect(),
            Err(poisoned) => {
                let peers = poisoned.into_inner();
                peers
                    .values()
                    .filter_map(|peer| peer.party_id.map(|id| (id, peer.clone())))
                    .collect()
            }
        }
    }

    /// Find a peer by party ID
    pub fn find_peer_by_party(&self, party_id: usize) -> Option<PeerInfo> {
        match self.peers.read() {
            Ok(peers) => peers
                .values()
                .find(|peer| peer.party_id == Some(party_id))
                .cloned(),
            Err(poisoned) => {
                let peers = poisoned.into_inner();
                peers
                    .values()
                    .find(|peer| peer.party_id == Some(party_id))
                    .cloned()
            }
        }
    }
}

/// Get current timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_discovery() {
        let discovery = PeerDiscovery::new(
            "peer1".to_string(),
            vec!["127.0.0.1:8080".to_string()],
            DiscoveryMode::Bootstrap,
        );

        let peer = PeerInfo {
            peer_id: "peer2".to_string(),
            party_id: Some(0),
            address: "127.0.0.1:8081".to_string(),
            last_seen: current_timestamp(),
            capabilities: vec!["encrypt".to_string()],
        };

        discovery.add_peer(peer.clone());
        assert_eq!(discovery.peer_count(), 1);

        let retrieved = discovery.get_peer("peer2");
        assert!(retrieved.is_some());

        discovery.remove_peer("peer2");
        assert_eq!(discovery.peer_count(), 0);
    }

    #[test]
    fn test_find_peer_by_party() {
        let discovery = PeerDiscovery::new("peer1".to_string(), vec![], DiscoveryMode::Local);

        let peer = PeerInfo {
            peer_id: "peer2".to_string(),
            party_id: Some(5),
            address: "127.0.0.1:8081".to_string(),
            last_seen: current_timestamp(),
            capabilities: vec![],
        };

        discovery.add_peer(peer);

        let found = discovery.find_peer_by_party(5);
        assert!(found.is_some());
        assert_eq!(found.unwrap().peer_id, "peer2");

        let not_found = discovery.find_peer_by_party(99);
        assert!(not_found.is_none());
    }
}
