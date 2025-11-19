//! TCP transport layer for P2P networking
//!
//! Provides actual network connectivity with message framing and routing

use super::messages::{P2PMessage, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;

/// Maximum message size (10MB)
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Transport layer for P2P communication
pub struct P2PTransport {
    /// Our peer ID
    peer_id: PeerId,

    /// Listen address
    listen_addr: SocketAddr,

    /// Active connections (peer_id -> connection)
    connections: Arc<RwLock<HashMap<PeerId, Arc<Mutex<TcpStream>>>>>,

    /// Incoming message channel
    incoming_tx: mpsc::UnboundedSender<(PeerId, P2PMessage)>,
    incoming_rx: Arc<Mutex<mpsc::UnboundedReceiver<(PeerId, P2PMessage)>>>,

    /// Listener task handle
    listener_handle: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// Connection tasks
    connection_handles: Arc<RwLock<HashMap<PeerId, JoinHandle<()>>>>,
}

impl P2PTransport {
    /// Create a new transport layer
    pub fn new(peer_id: PeerId, listen_addr: SocketAddr) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();

        Self {
            peer_id,
            listen_addr,
            connections: Arc::new(RwLock::new(HashMap::new())),
            incoming_tx,
            incoming_rx: Arc::new(Mutex::new(incoming_rx)),
            listener_handle: Arc::new(Mutex::new(None)),
            connection_handles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get listen address as string
    fn listen_addr_string(&self) -> String {
        self.listen_addr.to_string()
    }

    /// Start listening for incoming connections
    pub async fn start_listening(&self) -> Result<(), String> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(|e| format!("Failed to bind to {}: {}", self.listen_addr, e))?;

        let peer_id = self.peer_id.clone();
        let listen_addr = self.listen_addr;
        let connections = Arc::clone(&self.connections);
        let incoming_tx = self.incoming_tx.clone();
        let connection_handles = Arc::clone(&self.connection_handles);

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        println!("[{}] Accepted connection from {}", peer_id, addr);

                        let connections = Arc::clone(&connections);
                        let incoming_tx = incoming_tx.clone();
                        let peer_id = peer_id.clone();
                        let connection_handles = Arc::clone(&connection_handles);

                        // Spawn task to handle this connection
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(
                                stream,
                                peer_id,
                                listen_addr,
                                connections,
                                incoming_tx,
                                connection_handles,
                            )
                            .await
                            {
                                eprintln!("Connection handler error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[{}] Failed to accept connection: {}", peer_id, e);
                    }
                }
            }
        });

        *self.listener_handle.lock().await = Some(handle);

        println!("[{}] Listening on {}", self.peer_id, self.listen_addr);
        Ok(())
    }

    /// Connect to a remote peer
    pub async fn connect_to_peer(&self, peer_id: PeerId, addr: SocketAddr) -> Result<(), String> {
        // Check if already connected
        {
            let connections = self.connections.read().await;
            if connections.contains_key(&peer_id) {
                return Ok(());
            }
        }

        println!("[{}] Connecting to {} at {}", self.peer_id, peer_id, addr);

        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        println!("[{}] Connected to {} at {}", self.peer_id, peer_id, addr);

        // Send handshake with our peer ID and listen address
        let handshake = Handshake {
            peer_id: self.peer_id.clone(),
            listen_addr: self.listen_addr_string(),
        };

        // Send and receive handshake
        let (actual_remote_peer_id, remote_listen_addr) = {
            Self::send_message(&mut stream, &handshake).await?;

            // Receive handshake response to get actual peer ID and listen address
            let response: Handshake = Self::receive_typed_message(&mut stream).await?;
            (response.peer_id, response.listen_addr)
        };

        println!(
            "[{}] Handshake complete with {} (actual: {} at {})",
            self.peer_id, peer_id, actual_remote_peer_id, remote_listen_addr
        );

        let stream = Arc::new(Mutex::new(stream));

        // Store connection using actual peer ID
        {
            let mut connections = self.connections.write().await;
            connections.insert(actual_remote_peer_id.clone(), Arc::clone(&stream));
        }

        // Send synthetic announcement to local discovery with real listen address
        let announcement = P2PMessage::PeerAnnouncement {
            peer_id: actual_remote_peer_id.clone(),
            party_id: None,
            listen_addr: remote_listen_addr,
            capabilities: vec!["ste".to_string()],
        };
        let _ = self
            .incoming_tx
            .send((actual_remote_peer_id.clone(), announcement));

        // Spawn task to receive messages from this peer
        let connections = Arc::clone(&self.connections);
        let incoming_tx = self.incoming_tx.clone();
        let our_peer_id = self.peer_id.clone();
        let remote_peer_id = actual_remote_peer_id.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) =
                Self::receive_messages(stream, remote_peer_id.clone(), our_peer_id, incoming_tx)
                    .await
            {
                eprintln!("Receive messages error from {}: {}", remote_peer_id, e);

                // Remove connection on error
                let mut conns = connections.write().await;
                conns.remove(&remote_peer_id);
            }
        });

        // Store handle
        {
            let mut handles = self.connection_handles.write().await;
            handles.insert(actual_remote_peer_id.clone(), handle);
        }

        Ok(())
    }

    /// Send a message to a specific peer
    pub async fn send_to_peer(&self, peer_id: &PeerId, msg: &P2PMessage) -> Result<(), String> {
        let connections = self.connections.read().await;
        let stream = connections
            .get(peer_id)
            .ok_or_else(|| format!("Not connected to peer {}", peer_id))?;

        let mut stream_lock = stream.lock().await;
        Self::send_message(&mut *stream_lock, msg).await
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast(&self, msg: &P2PMessage) -> Result<(), String> {
        let connections = self.connections.read().await;
        let peer_ids: Vec<_> = connections.keys().cloned().collect();
        drop(connections);

        for peer_id in peer_ids {
            if let Err(e) = self.send_to_peer(&peer_id, msg).await {
                eprintln!("[{}] Failed to send to {}: {}", self.peer_id, peer_id, e);
            }
        }

        Ok(())
    }

    /// Receive next incoming message
    pub async fn recv(&self) -> Option<(PeerId, P2PMessage)> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }

    /// Get number of connected peers
    pub async fn peer_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Get list of connected peer IDs
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.connections.read().await.keys().cloned().collect()
    }

    /// Disconnect from a peer
    pub async fn disconnect_peer(&self, peer_id: &PeerId) {
        let mut connections = self.connections.write().await;
        connections.remove(peer_id);

        // Abort the connection task
        let mut handles = self.connection_handles.write().await;
        if let Some(handle) = handles.remove(peer_id) {
            handle.abort();
        }
    }

    /// Shutdown the transport
    pub async fn shutdown(&self) {
        // Abort listener
        if let Some(handle) = self.listener_handle.lock().await.take() {
            handle.abort();
        }

        // Abort all connection tasks
        let handles = self.connection_handles.write().await;
        for (_, handle) in handles.iter() {
            handle.abort();
        }
    }

    // Internal helper methods

    async fn handle_connection(
        mut stream: TcpStream,
        peer_id: PeerId,
        listen_addr: SocketAddr,
        connections: Arc<RwLock<HashMap<PeerId, Arc<Mutex<TcpStream>>>>>,
        incoming_tx: mpsc::UnboundedSender<(PeerId, P2PMessage)>,
        _connection_handles: Arc<RwLock<HashMap<PeerId, JoinHandle<()>>>>,
    ) -> Result<(), String> {
        // Receive handshake from remote peer
        let handshake: Handshake = Self::receive_typed_message(&mut stream).await?;
        let remote_peer_id = handshake.peer_id.clone();
        let remote_listen_addr = handshake.listen_addr.clone();

        println!(
            "[{}] Received handshake from {} at {}",
            peer_id, remote_peer_id, remote_listen_addr
        );

        // Send our handshake back
        let our_handshake = Handshake {
            peer_id: peer_id.clone(),
            listen_addr: listen_addr.to_string(),
        };
        Self::send_message(&mut stream, &our_handshake).await?;

        // Store connection
        let stream_arc = Arc::new(Mutex::new(stream));
        {
            let mut conns = connections.write().await;
            conns.insert(remote_peer_id.clone(), Arc::clone(&stream_arc));
        }

        // Send a synthetic PeerAnnouncement to trigger peer discovery
        // This ensures peers get added to discovery when they connect
        let announcement = P2PMessage::PeerAnnouncement {
            peer_id: remote_peer_id.clone(),
            party_id: None, // Will be updated when real announcement arrives
            listen_addr: remote_listen_addr,
            capabilities: vec!["ste".to_string()],
        };
        let _ = incoming_tx.send((remote_peer_id.clone(), announcement));

        // Receive messages from this peer
        Self::receive_messages(stream_arc, remote_peer_id.clone(), peer_id, incoming_tx).await?;

        // Cleanup
        let mut conns = connections.write().await;
        conns.remove(&remote_peer_id);

        Ok(())
    }

    async fn receive_messages(
        stream: Arc<Mutex<TcpStream>>,
        remote_peer_id: PeerId,
        our_peer_id: PeerId,
        incoming_tx: mpsc::UnboundedSender<(PeerId, P2PMessage)>,
    ) -> Result<(), String> {
        loop {
            let msg: P2PMessage = {
                let mut stream = stream.lock().await;
                match Self::receive_typed_message(&mut *stream).await {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!(
                            "[{}] Error receiving from {}: {}",
                            our_peer_id, remote_peer_id, e
                        );
                        return Err(e);
                    }
                }
            };

            // Forward to incoming channel
            incoming_tx
                .send((remote_peer_id.clone(), msg))
                .map_err(|e| format!("Failed to send to incoming channel: {}", e))?;
        }
    }

    async fn send_message<T: Serialize>(stream: &mut TcpStream, msg: &T) -> Result<(), String> {
        // Serialize message
        let data =
            bincode::serialize(msg).map_err(|e| format!("Failed to serialize message: {}", e))?;

        // Check size
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(format!("Message too large: {} bytes", data.len()));
        }

        // Send length prefix (4 bytes)
        let len = data.len() as u32;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| format!("Failed to write length: {}", e))?;

        // Send data
        stream
            .write_all(&data)
            .await
            .map_err(|e| format!("Failed to write data: {}", e))?;

        stream
            .flush()
            .await
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(())
    }

    async fn receive_typed_message<T: for<'de> Deserialize<'de>>(
        stream: &mut TcpStream,
    ) -> Result<T, String> {
        // Read length prefix (4 bytes)
        let mut len_bytes = [0u8; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| format!("Failed to read length: {}", e))?;

        let len = u32::from_be_bytes(len_bytes) as usize;

        // Check size
        if len > MAX_MESSAGE_SIZE {
            return Err(format!("Message too large: {} bytes", len));
        }

        // Read data
        let mut data = vec![0u8; len];
        stream
            .read_exact(&mut data)
            .await
            .map_err(|e| format!("Failed to read data: {}", e))?;

        // Deserialize
        bincode::deserialize(&data).map_err(|e| format!("Failed to deserialize message: {}", e))
    }
}

/// Handshake message sent at connection establishment
#[derive(Serialize, Deserialize, Debug)]
struct Handshake {
    peer_id: PeerId,
    listen_addr: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_creation() {
        let addr = "127.0.0.1:0".parse().unwrap();
        let transport = P2PTransport::new("test-peer".to_string(), addr);
        assert_eq!(transport.peer_count().await, 0);
    }
}
