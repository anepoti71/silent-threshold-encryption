//! P2P network layer for managing connections and message routing
//!
//! This module provides a real working P2P network built on TCP transport.

use super::discovery::PeerDiscovery;
use super::gossip::{GossipMessage, GossipProtocol, GossipResult};
use super::messages::{P2PMessage, PeerId, PeerInfo};
use super::transport::P2PTransport;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

/// Network configuration
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    /// Our peer ID
    pub peer_id: PeerId,

    /// Our party ID (optional)
    pub party_id: Option<usize>,

    /// Listen address
    pub listen_addr: String,

    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,

    /// Enable TLS
    pub enable_tls: bool,

    /// Maximum peers
    pub max_peers: usize,

    /// Gossip fanout
    pub gossip_fanout: usize,

    /// Message TTL
    pub message_ttl: u8,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            peer_id: generate_peer_id(),
            party_id: None,
            listen_addr: "0.0.0.0:0".to_string(),
            bootstrap_nodes: vec![],
            enable_tls: false, // Disabled for now
            max_peers: 50,
            gossip_fanout: 3,
            message_ttl: 5,
        }
    }
}

/// P2P Network manager
pub struct P2PNetwork {
    /// Network configuration
    config: NetworkConfig,

    /// Peer discovery service
    discovery: Arc<PeerDiscovery>,

    /// Gossip protocol handler
    gossip: Arc<GossipProtocol>,

    /// Transport layer
    transport: Arc<P2PTransport>,

    /// Message handler task
    handler_task: Arc<RwLock<Option<JoinHandle<()>>>>,

    /// Outgoing message queue
    outgoing_tx: mpsc::UnboundedSender<(Option<PeerId>, P2PMessage)>,
    outgoing_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<(Option<PeerId>, P2PMessage)>>>,

    /// Message handlers (by message type)
    message_handlers: Arc<RwLock<Vec<mpsc::UnboundedSender<P2PMessage>>>>,
}

impl P2PNetwork {
    /// Create new P2P network
    pub fn new(config: NetworkConfig) -> Self {
        let discovery = Arc::new(PeerDiscovery::new(
            config.peer_id.clone(),
            config.bootstrap_nodes.clone(),
            super::discovery::DiscoveryMode::Hybrid,
        ));

        let gossip = Arc::new(GossipProtocol::with_params(
            config.peer_id.clone(),
            config.gossip_fanout,
            config.message_ttl,
        ));

        // Parse listen address
        let listen_addr: SocketAddr = config.listen_addr.parse()
            .unwrap_or_else(|_| {
                eprintln!("Invalid listen address '{}', using 0.0.0.0:0", config.listen_addr);
                "0.0.0.0:0".parse().unwrap()
            });

        let transport = Arc::new(P2PTransport::new(config.peer_id.clone(), listen_addr));

        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();

        Self {
            config,
            discovery,
            gossip,
            transport,
            handler_task: Arc::new(RwLock::new(None)),
            outgoing_tx,
            outgoing_rx: Arc::new(tokio::sync::Mutex::new(outgoing_rx)),
            message_handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Start the network (listening and message processing)
    pub async fn start(&self) -> Result<(), String> {
        // Start listening for connections
        self.transport.start_listening().await?;

        // Spawn message handler task
        let transport = Arc::clone(&self.transport);
        let discovery = Arc::clone(&self.discovery);
        let gossip = Arc::clone(&self.gossip);
        let config = self.config.clone();
        let outgoing_rx = Arc::clone(&self.outgoing_rx);
        let message_handlers = Arc::clone(&self.message_handlers);

        let handle = tokio::spawn(async move {
            Self::message_loop(
                transport,
                discovery,
                gossip,
                config,
                outgoing_rx,
                message_handlers,
            )
            .await;
        });

        *self.handler_task.write().await = Some(handle);

        Ok(())
    }

    /// Connect to bootstrap nodes
    pub async fn connect_to_bootstrap(&self) -> Result<(), String> {
        for bootstrap_addr in &self.config.bootstrap_nodes {
            // Parse address - use tokio's DNS resolution for hostnames
            let addrs: Vec<SocketAddr> = if bootstrap_addr.contains(':') {
                // Try direct parse first
                match bootstrap_addr.parse::<SocketAddr>() {
                    Ok(addr) => vec![addr],
                    Err(_) => {
                        // If that fails, use DNS resolution and collect all addresses
                        tokio::net::lookup_host(bootstrap_addr)
                            .await
                            .map_err(|e| {
                                format!(
                                    "Failed to resolve bootstrap address {}: {}",
                                    bootstrap_addr, e
                                )
                            })?
                            .collect()
                    }
                }
            } else {
                return Err(format!(
                    "Invalid bootstrap address {} (must include port)",
                    bootstrap_addr
                ));
            };

            if addrs.is_empty() {
                eprintln!("No addresses found for bootstrap {}", bootstrap_addr);
                continue;
            }

            // Generate peer ID for bootstrap node
            let peer_id = format!("bootstrap-{}", bootstrap_addr);

            // Try connecting to each resolved address
            let mut connected = false;
            for addr in addrs {
                println!(
                    "[{}] Connecting to {} at {}",
                    self.config.peer_id, peer_id, addr
                );
                if let Err(e) = self.transport.connect_to_peer(peer_id.clone(), addr).await {
                    eprintln!("Failed to connect to {} at {}: {}", bootstrap_addr, addr, e);
                    continue;
                }
                connected = true;
                break;
            }

            if !connected {
                eprintln!(
                    "Failed to connect to bootstrap {} at any address",
                    bootstrap_addr
                );
                continue;
            }

            // Add to discovery
            let peer_info = PeerInfo {
                peer_id: peer_id.clone(),
                party_id: None,
                address: bootstrap_addr.clone(),
                last_seen: current_timestamp(),
                capabilities: vec!["ste".to_string()],
            };
            self.discovery.add_peer(peer_info);

            println!(
                "[{}] Connected to bootstrap node at {}",
                self.config.peer_id, bootstrap_addr
            );
        }

        Ok(())
    }

    /// Get our peer ID
    pub fn peer_id(&self) -> &PeerId {
        &self.config.peer_id
    }

    /// Get our party ID
    pub fn party_id(&self) -> Option<usize> {
        self.config.party_id
    }

    /// Set party ID
    pub fn set_party_id(&mut self, party_id: usize) {
        self.config.party_id = Some(party_id);
    }

    /// Get peer discovery service
    pub fn discovery(&self) -> &Arc<PeerDiscovery> {
        &self.discovery
    }

    /// Get gossip protocol handler
    pub fn gossip(&self) -> &Arc<GossipProtocol> {
        &self.gossip
    }

    /// Broadcast message to all peers
    pub fn broadcast(&self, msg: P2PMessage) -> Result<(), String> {
        // Queue for broadcast
        self.outgoing_tx
            .send((None, msg))
            .map_err(|e| format!("Failed to queue broadcast: {}", e))
    }

    /// Send message to specific peer
    pub fn send_to_peer(&self, peer_id: &PeerId, msg: P2PMessage) -> Result<(), String> {
        // Queue for sending
        self.outgoing_tx
            .send((Some(peer_id.clone()), msg))
            .map_err(|e| format!("Failed to queue send: {}", e))
    }

    /// Add a peer to the network
    pub fn add_peer(&self, peer: PeerInfo) {
        self.discovery.add_peer(peer);
    }

    /// Remove a peer
    pub fn remove_peer(&self, peer_id: &PeerId) {
        self.discovery.remove_peer(peer_id);
    }

    /// Get number of connected peers
    pub fn peer_count(&self) -> usize {
        self.discovery.peer_count()
    }

    /// Get all peers
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.discovery.get_peers()
    }

    /// Announce our presence to the network
    pub fn announce(&self) -> Result<(), String> {
        let announcement = P2PMessage::PeerAnnouncement {
            peer_id: self.config.peer_id.clone(),
            party_id: self.config.party_id,
            listen_addr: self.config.listen_addr.clone(),
            capabilities: vec!["ste".to_string()],
        };

        self.broadcast(announcement)
    }

    /// Request peer list from a peer
    pub fn request_peers(&self, from_peer: &PeerId) -> Result<(), String> {
        let request = P2PMessage::PeerListRequest {
            from_peer: self.config.peer_id.clone(),
        };

        self.send_to_peer(from_peer, request)
    }

    /// Register a message handler
    pub async fn register_handler(&self, tx: mpsc::UnboundedSender<P2PMessage>) {
        let mut handlers = self.message_handlers.write().await;
        handlers.push(tx);
    }

    /// Cleanup stale peers and messages
    pub fn cleanup(&self) {
        const PEER_TIMEOUT: u64 = 300; // 5 minutes
        self.discovery.cleanup_stale_peers(PEER_TIMEOUT);
        self.gossip.cleanup_old_messages();
    }

    /// Shutdown the network
    pub async fn shutdown(&self) {
        // Abort handler task
        if let Some(handle) = self.handler_task.write().await.take() {
            handle.abort();
        }

        // Shutdown transport
        self.transport.shutdown().await;
    }

    /// Get transport for advanced operations
    pub fn transport(&self) -> &Arc<P2PTransport> {
        &self.transport
    }

    // Internal message processing loop
    async fn message_loop(
        transport: Arc<P2PTransport>,
        discovery: Arc<PeerDiscovery>,
        gossip: Arc<GossipProtocol>,
        config: NetworkConfig,
        outgoing_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<(Option<PeerId>, P2PMessage)>>>,
        message_handlers: Arc<RwLock<Vec<mpsc::UnboundedSender<P2PMessage>>>>,
    ) {
        loop {
            tokio::select! {
                // Handle incoming messages
                Some((sender_id, msg)) = transport.recv() => {
                    if let Err(e) = Self::handle_incoming_message(
                        &msg,
                        &sender_id,
                        &discovery,
                        &gossip,
                        &config,
                        &transport,
                        &message_handlers,
                    ).await {
                        eprintln!("[{}] Error handling message from {}: {}", config.peer_id, sender_id, e);
                    }
                }

                // Handle outgoing messages
                result = async {
                    let mut rx = outgoing_rx.lock().await;
                    rx.recv().await
                } => {
                    if let Some((target, msg)) = result {
                        if let Some(peer_id) = target {
                            // Send to specific peer
                            if let Err(e) = transport.send_to_peer(&peer_id, &msg).await {
                                eprintln!("[{}] Failed to send to {}: {}", config.peer_id, peer_id, e);
                            }
                        } else {
                            // Broadcast to all
                            if let Err(e) = transport.broadcast(&msg).await {
                                eprintln!("[{}] Failed to broadcast: {}", config.peer_id, e);
                            }
                        }
                    }
                }
            }
        }
    }

    async fn handle_incoming_message(
        msg: &P2PMessage,
        sender_id: &PeerId,
        discovery: &Arc<PeerDiscovery>,
        gossip: &Arc<GossipProtocol>,
        config: &NetworkConfig,
        transport: &Arc<P2PTransport>,
        message_handlers: &Arc<RwLock<Vec<mpsc::UnboundedSender<P2PMessage>>>>,
    ) -> Result<(), String> {
        // Update peer last seen
        discovery.update_peer_seen(sender_id);

        // Handle specific message types
        match msg {
            P2PMessage::PeerAnnouncement {
                peer_id,
                party_id,
                listen_addr,
                capabilities,
            } => {
                let is_new_peer = !discovery.is_known(peer_id);

                // Add peer to discovery
                let peer_info = PeerInfo {
                    peer_id: peer_id.clone(),
                    party_id: *party_id,
                    address: listen_addr.clone(),
                    last_seen: current_timestamp(),
                    capabilities: capabilities.clone(),
                };
                discovery.add_peer(peer_info.clone());

                println!(
                    "[{}] Discovered peer: {} (party {:?}) at {}",
                    config.peer_id, peer_id, party_id, listen_addr
                );

                // Try to connect if not already connected (when learning via relay)
                if peer_id != &config.peer_id
                    && sender_id != peer_id
                    && !config.listen_addr.eq(listen_addr)
                {
                    let connected_peers = transport.connected_peers().await;
                    if !connected_peers.contains(peer_id) {
                        if let Ok(addr) = listen_addr.parse::<SocketAddr>() {
                            if let Err(e) = transport.connect_to_peer(peer_id.clone(), addr).await {
                                eprintln!(
                                    "[{}] Failed to connect to announced peer {}: {}",
                                    config.peer_id, peer_id, e
                                );
                            } else {
                                println!(
                                    "[{}] Connected to announced peer {} at {}",
                                    config.peer_id, peer_id, listen_addr
                                );
                            }
                        }
                    }
                }

                if is_new_peer {
                    if let Err(e) =
                        Self::relay_peer_announcement(transport, sender_id, peer_id, msg).await
                    {
                        eprintln!(
                            "[{}] Failed to relay announcement for {}: {}",
                            config.peer_id, peer_id, e
                        );
                    }
                }
            }

            P2PMessage::PeerListRequest { from_peer } => {
                // Respond with our known peers
                let peers = discovery.get_peers();
                let response = P2PMessage::PeerListResponse { peers };
                transport.send_to_peer(from_peer, &response).await?;
            }

            P2PMessage::PeerListResponse { peers } => {
                // Add all peers to discovery
                for peer in peers {
                    discovery.add_peer(peer.clone());
                }
            }

            P2PMessage::Gossip {
                message_id,
                ttl,
                seen_by,
                payload,
            } => {
                let gossip_msg = GossipMessage {
                    message_id: *message_id,
                    ttl: *ttl,
                    seen_by: seen_by.clone(),
                    payload: (**payload).clone(),
                };

                match gossip.handle_gossip(&gossip_msg) {
                    GossipResult::ShouldForward(new_gossip) => {
                        // Forward to other peers
                        Self::propagate_gossip(&new_gossip, discovery, config, transport).await?;
                    }
                    GossipResult::HandlerError(e) => {
                        return Err(e);
                    }
                    _ => {}
                }

                // Also deliver the payload to handlers
                Self::deliver_to_handlers(&payload, message_handlers).await;
            }

            _ => {
                // Deliver to registered handlers
                Self::deliver_to_handlers(msg, message_handlers).await;
            }
        }

        Ok(())
    }

    async fn propagate_gossip(
        gossip: &GossipMessage,
        discovery: &Arc<PeerDiscovery>,
        config: &NetworkConfig,
        transport: &Arc<P2PTransport>,
    ) -> Result<(), String> {
        let peers = discovery.get_peers();
        let fanout = config.gossip_fanout.min(peers.len());

        // Select peers that haven't seen this message
        let mut candidates: Vec<_> = peers
            .iter()
            .filter(|p| !gossip.seen_by.contains(&p.peer_id))
            .collect();

        candidates.truncate(fanout);

        // Create gossip message
        let gossip_msg = P2PMessage::Gossip {
            message_id: gossip.message_id,
            ttl: gossip.ttl,
            seen_by: gossip.seen_by.clone(),
            payload: Box::new(gossip.payload.clone()),
        };

        // Send to selected peers
        for peer in candidates {
            if let Err(e) = transport.send_to_peer(&peer.peer_id, &gossip_msg).await {
                eprintln!(
                    "[{}] Failed to gossip to {}: {}",
                    config.peer_id, peer.peer_id, e
                );
            }
        }

        Ok(())
    }

    async fn deliver_to_handlers(
        msg: &P2PMessage,
        message_handlers: &Arc<RwLock<Vec<mpsc::UnboundedSender<P2PMessage>>>>,
    ) {
        let handlers = message_handlers.read().await;
        for handler in handlers.iter() {
            let _ = handler.send(msg.clone());
        }
    }

    async fn relay_peer_announcement(
        transport: &Arc<P2PTransport>,
        sender_id: &PeerId,
        announced_peer: &PeerId,
        msg: &P2PMessage,
    ) -> Result<(), String> {
        let peers = transport.connected_peers().await;
        for peer in peers {
            if &peer == sender_id || &peer == announced_peer {
                continue;
            }

            if let Err(e) = transport.send_to_peer(&peer, msg).await {
                eprintln!("[relay] Failed to forward announcement to {}: {}", peer, e);
            }
        }

        Ok(())
    }
}

/// Generate a random peer ID
fn generate_peer_id() -> PeerId {
    use blake2::{Blake2b512, Digest};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();

    let mut hasher = Blake2b512::new();
    hasher.update(&timestamp.to_le_bytes());

    let result = hasher.finalize();
    hex::encode(&result[..16])
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_creation() {
        let config = NetworkConfig::default();
        let network = P2PNetwork::new(config);

        assert_eq!(network.peer_count(), 0);
    }
}
