//! Peer protocol that drives the fully peer-to-peer threshold workflow.
//!
//! This module glues the libp2p transport with the cryptographic primitives so that
//! each peer can:
//!   * Announce itself and learn about other parties
//!   * Exchange public keys and construct the aggregate key
//!   * Broadcast ciphertexts and request partial decryptions
//!   * Respond to decryption requests from other peers
//!   * Aggregate partial decryptions to recover plaintext
//!
//! The implementation intentionally keeps the networking generic enough so that
//! higher-level binaries can drive the protocol (e.g. automatically encrypt once
//! ready, or expose an interactive shell for manual commands).

use ark_bls12_381::Bls12_381 as Curve;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::Zero;
use blake2::{Blake2b512, Digest};
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::{debug, error, info, warn};

use crate::decryption::agg_dec;
use crate::encryption::{encrypt, Ciphertext};
use crate::error::SteError;
use crate::kzg::PowersOfTau;
use crate::p2p::crypto_utils::{
    peer_id_to_public_key, sign_crypto_message, verify_crypto_signature, SignatureError,
};
use crate::p2p::{Libp2pConfig, Libp2pEvent, Libp2pNetwork, P2PMessage, PeerInfo};
use crate::setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey};

use super::messages::MessageId;

type G2 = <Curve as Pairing>::G2;

/// Runtime configuration for a peer.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub party_id: usize,
    pub n: usize,
    pub threshold: usize,
    pub listen_addresses: Vec<String>,
    pub bootstrap_nodes: Vec<String>,
    pub gossip_topic: String,
    pub kzg_params_path: PathBuf,
    pub lagrange_params_path: PathBuf,
    pub mode: PeerRuntimeMode,
    pub auto_decrypt: bool,
    pub enable_mdns: bool,
}

/// Determines whether the peer should initiate an example encryption run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRuntimeMode {
    Passive,
    Initiator,
}

/// Errors surfaced while running the peer protocol.
#[derive(thiserror::Error, Debug)]
pub enum PeerError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] SteError),
    #[error("network error: {0}")]
    Network(String),
    #[error("signature error: {0}")]
    Signature(#[from] SignatureError),
}

/// Public facade for running a peer node.
pub struct PeerNode {
    config: PeerConfig,
}

impl PeerNode {
    pub fn new(config: PeerConfig) -> Self {
        Self { config }
    }

    /// Bootstraps the libp2p network and drives the message loop.
    pub async fn run(&self) -> Result<(), PeerError> {
        validate_config(&self.config)?;

        let params = Arc::new(load_powers(&self.config.kzg_params_path)?);
        let lagrange = Arc::new(load_lagrange(&self.config.lagrange_params_path)?);

        let mut rng = StdRng::from_entropy();
        let mut secret_key = SecretKey::<Curve>::new(&mut rng);

        if self.config.party_id == 0 {
            secret_key.nullify();
        }

        let public_key =
            secret_key.lagrange_get_pk(self.config.party_id, &lagrange, self.config.n)?;

        let state = Arc::new(RwLock::new(ProtocolState::new(
            self.config.clone(),
            params.clone(),
            lagrange,
            secret_key,
            public_key.clone(),
        )));

        // Start libp2p
        let libp2p_config = Libp2pConfig {
            listen_addresses: self.config.listen_addresses.clone(),
            bootstrap_nodes: self.config.bootstrap_nodes.clone(),
            gossip_topic: self.config.gossip_topic.clone(),
            enable_mdns: self.config.enable_mdns,
        };

        let network = Arc::new(
            Libp2pNetwork::new(libp2p_config)
                .await
                .map_err(|e| PeerError::Network(format!("{:?}", e)))?,
        );

        {
            let mut guard = state.write().await;
            guard.insert_local_peer(
                network.peer_id().to_string(),
                network.public_key(),
                self.config.listen_addresses.first().cloned(),
            );
            guard
                .party_keys
                .insert(self.config.party_id, public_key.clone());
        }

        // Wait for peer connections, then announce and broadcast our PK.
        {
            let state = state.clone();
            let network = network.clone();
            let min_peers = (self.config.n - 1).max(1);
            tokio::spawn(async move {
                if let Err(e) = announce_and_share_with_retry(state, network, min_peers).await {
                    error!("Failed to broadcast peer info: {e}");
                }
            });
        }

        // Event loop for incoming libp2p events.
        {
            let state = state.clone();
            let network = network.clone();
            tokio::spawn(async move {
                while let Some(event) = network.next_event().await {
                    if let Err(e) =
                        handle_network_event(state.clone(), network.clone(), event).await
                    {
                        warn!("Protocol event handling error: {e}");
                    }
                }
            });
        }

        // Initiator peers will encrypt & decrypt once the aggregate key is ready.
        if self.config.mode == PeerRuntimeMode::Initiator {
            let state = state.clone();
            let network = network.clone();
            tokio::spawn(async move {
                if let Err(e) = run_initiator_flow(state, network).await {
                    error!("Initiator flow failed: {e}");
                }
            });
        }

        // Keep running until interrupted.
        info!(
            "Peer {} running as {:?}. Press Ctrl+C to stop.",
            self.config.party_id, self.config.mode
        );
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| PeerError::Network(format!("signal error: {e}")))?;
        Ok(())
    }
}

async fn announce_and_share(
    state: Arc<RwLock<ProtocolState>>,
    network: Arc<Libp2pNetwork>,
) -> Result<(), PeerError> {
    let (announcement, pk_broadcast) = {
        let guard = state.read().await;
        (
            guard.build_peer_announcement(network.peer_id()),
            guard.build_public_key_message(network.peer_id(), network.keypair())?,
        )
    };

    debug!("Publishing PeerAnnouncement...");
    network
        .publish(&announcement)
        .await
        .map_err(|e| PeerError::Network(format!("PeerAnnouncement failed: {:?}", e)))?;
    debug!("Publishing PublicKeyBroadcast...");
    network
        .publish(&pk_broadcast)
        .await
        .map_err(|e| PeerError::Network(format!("PublicKeyBroadcast failed: {:?}", e)))?;

    Ok(())
}

async fn announce_and_share_with_retry(
    state: Arc<RwLock<ProtocolState>>,
    network: Arc<Libp2pNetwork>,
    _min_peers: usize,
) -> Result<(), PeerError> {
    // Wait for mDNS discovery and gossipsub mesh formation.
    // In a P2P network, we need to give time for:
    // 1. mDNS to discover peers (1-2 seconds)
    // 2. Libp2p to establish connections (0-1 second)
    // 3. Gossipsub mesh to form (2-5 seconds with default config, faster with our tuned config)
    info!("Waiting for peer discovery and gossipsub mesh formation...");

    // Add jitter to prevent all peers from broadcasting at exactly the same time
    let party_id = {
        let guard = state.read().await;
        guard.config.party_id
    };
    let jitter_ms = party_id as u64 * 500; // 0ms, 500ms, 1000ms, 1500ms for parties 0-3
    tokio::time::sleep(Duration::from_millis(8000 + jitter_ms)).await;

    // Now attempt to broadcast with retries
    const BROADCAST_RETRIES: usize = 10;
    for attempt in 0..BROADCAST_RETRIES {
        match announce_and_share(state.clone(), network.clone()).await {
            Ok(()) => {
                info!("Successfully broadcast peer info and public key");
                return Ok(());
            }
            Err(e) => {
                if attempt < BROADCAST_RETRIES - 1 {
                    debug!(
                        "Broadcast attempt {} failed ({}), retrying in 1s... (gossipsub mesh may still be forming)",
                        attempt + 1,
                        e
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    error!("All broadcast attempts failed: {}", e);
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}

async fn run_initiator_flow(
    state: Arc<RwLock<ProtocolState>>,
    network: Arc<Libp2pNetwork>,
) -> Result<(), PeerError> {
    wait_for_aggregate(state.clone()).await?;
    info!("Aggregate key ready; initiating encryption run.");
    let ciphertext = {
        let guard = state.write().await;
        guard.encrypt_message()?
    };

    broadcast_ciphertext(network.clone(), &ciphertext).await?;

    // Initiator immediately requests partial decryptions if auto decrypt is enabled.
    {
        let mut guard = state.write().await;
        if guard.config.auto_decrypt {
            guard
                .start_decryption_session(network.clone(), ciphertext)
                .await?;
        }
    }

    Ok(())
}

async fn broadcast_ciphertext(
    network: Arc<Libp2pNetwork>,
    ciphertext: &Ciphertext<Curve>,
) -> Result<(), PeerError> {
    let mut ct_bytes = Vec::new();
    ciphertext
        .serialize_compressed(&mut ct_bytes)
        .map_err(|e| PeerError::Serialization(e.to_string()))?;

    let message = P2PMessage::CiphertextBroadcast {
        from_peer: network.peer_id().to_string(),
        ct_bytes,
        threshold: ciphertext.t,
        timestamp: current_timestamp(),
    };

    network
        .publish(&message)
        .await
        .map_err(|e| PeerError::Network(format!("{:?}", e)))
}

async fn wait_for_aggregate(state: Arc<RwLock<ProtocolState>>) -> Result<(), PeerError> {
    loop {
        let notify = {
            let guard = state.read().await;
            if guard.aggregate_key.is_some() {
                return Ok(());
            }
            guard.aggregate_ready.clone()
        };
        notify.notified().await;
    }
}

async fn handle_network_event(
    state: Arc<RwLock<ProtocolState>>,
    network: Arc<Libp2pNetwork>,
    event: Libp2pEvent,
) -> Result<(), PeerError> {
    match event {
        Libp2pEvent::Message { message, .. } => {
            let mut guard = state.write().await;
            guard.handle_message(network.clone(), message).await
        }
        Libp2pEvent::PeerConnected(peer) => {
            info!("Connected to peer {peer}");
            Ok(())
        }
        Libp2pEvent::PeerDisconnected(peer) => {
            warn!("Peer {peer} disconnected");
            Ok(())
        }
    }
}

/// Tracks the cryptographic and peer state.
struct ProtocolState {
    config: PeerConfig,
    params: Arc<PowersOfTau<Curve>>,
    lagrange: Arc<LagrangePowers<Curve>>,
    secret_key: Arc<Mutex<SecretKey<Curve>>>,
    public_key: PublicKey<Curve>,
    aggregate_key: Option<AggregateKey<Curve>>,
    aggregate_ready: Arc<Notify>,
    aggregate_parties: HashSet<usize>,
    known_peers: HashMap<usize, PeerSummary>,
    peer_infos: HashMap<String, PeerInfo>,
    party_keys: HashMap<usize, PublicKey<Curve>>,
    /// Maps peer_id -> libp2p public key for signature verification
    peer_public_keys: HashMap<String, libp2p::identity::PublicKey>,
    ciphertexts: HashMap<MessageId, Ciphertext<Curve>>,
    decrypt_sessions: HashMap<MessageId, DecryptSession>,
}

#[derive(Clone)]
struct PeerSummary {
    peer_id: String,
    listen_addr: Option<String>,
}

struct DecryptSession {
    ciphertext: Ciphertext<Curve>,
    selector: Vec<bool>,
    responses: HashMap<usize, G2>,
    requested_parties: Vec<usize>,
    created_at: Instant,
}

impl ProtocolState {
    fn new(
        config: PeerConfig,
        params: Arc<PowersOfTau<Curve>>,
        lagrange: Arc<LagrangePowers<Curve>>,
        secret_key: SecretKey<Curve>,
        public_key: PublicKey<Curve>,
    ) -> Self {
        Self {
            config,
            params,
            lagrange,
            secret_key: Arc::new(Mutex::new(secret_key)),
            public_key,
            aggregate_key: None,
            aggregate_ready: Arc::new(Notify::new()),
            aggregate_parties: HashSet::new(),
            known_peers: HashMap::new(),
            peer_infos: HashMap::new(),
            party_keys: HashMap::new(),
            peer_public_keys: HashMap::new(),
            ciphertexts: HashMap::new(),
            decrypt_sessions: HashMap::new(),
        }
    }

    fn insert_local_peer(
        &mut self,
        peer_id: String,
        public_key: libp2p::identity::PublicKey,
        listen: Option<String>,
    ) {
        let listen_clone = listen.clone();
        let address = listen.unwrap_or_else(|| "/ip4/127.0.0.1/tcp/0".into());
        self.peer_infos.insert(
            peer_id.clone(),
            PeerInfo {
                peer_id: peer_id.clone(),
                party_id: Some(self.config.party_id),
                address,
                last_seen: current_timestamp(),
                capabilities: vec!["ste".into()],
            },
        );
        self.known_peers.insert(
            self.config.party_id,
            PeerSummary {
                peer_id: peer_id.clone(),
                listen_addr: listen_clone,
            },
        );
        // Store our own public key for consistency
        self.peer_public_keys.insert(peer_id, public_key);
    }

    fn build_peer_announcement(&self, peer_id: &str) -> P2PMessage {
        P2PMessage::PeerAnnouncement {
            peer_id: peer_id.to_string(),
            party_id: Some(self.config.party_id),
            listen_addr: self
                .config
                .listen_addresses
                .first()
                .cloned()
                .unwrap_or_else(|| "/ip4/0.0.0.0/tcp/0".into()),
            capabilities: vec!["ste".into()],
        }
    }

    fn build_public_key_message(
        &self,
        peer_id: &str,
        keypair: &libp2p::identity::Keypair,
    ) -> Result<P2PMessage, PeerError> {
        let mut pk_bytes = Vec::new();
        self.public_key
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| PeerError::Serialization(e.to_string()))?;

        // Sign the message: sign(peer_id || party_id || pk_bytes)
        let signature = sign_crypto_message(keypair, peer_id, self.config.party_id, &pk_bytes)?;

        Ok(P2PMessage::PublicKeyBroadcast {
            party_id: self.config.party_id,
            peer_id: peer_id.to_string(),
            pk_bytes,
            signature,
        })
    }

    async fn handle_message(
        &mut self,
        network: Arc<Libp2pNetwork>,
        message: P2PMessage,
    ) -> Result<(), PeerError> {
        match message {
            P2PMessage::PeerAnnouncement {
                peer_id,
                party_id,
                listen_addr,
                capabilities: _,
            } => {
                // Store the peer's libp2p public key for future signature verification
                if let Ok(public_key) = peer_id_to_public_key(&peer_id) {
                    self.peer_public_keys.insert(peer_id.clone(), public_key);
                } else {
                    warn!("Failed to extract public key from peer_id {}", peer_id);
                }

                if let Some(pid) = party_id {
                    self.known_peers.insert(
                        pid,
                        PeerSummary {
                            peer_id: peer_id.clone(),
                            listen_addr: Some(listen_addr.clone()),
                        },
                    );
                    self.peer_infos.insert(
                        peer_id.clone(),
                        PeerInfo {
                            peer_id,
                            party_id,
                            address: listen_addr,
                            last_seen: current_timestamp(),
                            capabilities: vec!["ste".into()],
                        },
                    );
                }
                Ok(())
            }
            P2PMessage::PeerListRequest { from_peer: _ } => {
                let peers: Vec<PeerInfo> = self.peer_infos.values().cloned().collect();
                let response = P2PMessage::PeerListResponse { peers };
                network
                    .publish(&response)
                    .await
                    .map_err(|e| PeerError::Network(format!("{:?}", e)))
            }
            P2PMessage::PeerListResponse { peers } => {
                for peer in peers {
                    if let Some(pid) = peer.party_id {
                        self.known_peers.insert(
                            pid,
                            PeerSummary {
                                peer_id: peer.peer_id.clone(),
                                listen_addr: Some(peer.address.clone()),
                            },
                        );
                    }
                    self.peer_infos.insert(peer.peer_id.clone(), peer);
                }
                Ok(())
            }
            P2PMessage::PublicKeyBroadcast {
                party_id,
                peer_id,
                pk_bytes,
                signature,
            } => {
                // Verify the signature before accepting the public key
                if let Some(public_key) = self.peer_public_keys.get(&peer_id) {
                    verify_crypto_signature(public_key, &peer_id, party_id, &pk_bytes, &signature)
                        .map_err(|e| {
                            PeerError::Signature(e)
                        })?;
                    info!(
                        "✓ Verified signature for public key from party {} (peer {})",
                        party_id, peer_id
                    );
                } else {
                    // Try to extract public key from peer_id
                    match peer_id_to_public_key(&peer_id) {
                        Ok(public_key) => {
                            verify_crypto_signature(&public_key, &peer_id, party_id, &pk_bytes, &signature)?;
                            self.peer_public_keys.insert(peer_id.clone(), public_key);
                            info!(
                                "✓ Verified signature for public key from party {} (peer {}, first time)",
                                party_id, peer_id
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Cannot verify public key from party {}: no public key available and extraction failed: {:?}",
                                party_id, e
                            );
                            return Err(PeerError::Signature(e));
                        }
                    }
                }

                let pk = PublicKey::<Curve>::deserialize_compressed(&pk_bytes[..])
                    .map_err(|e| PeerError::Serialization(e.to_string()))?;
                if self.party_keys.insert(party_id, pk).is_some() {
                    debug!("Updated public key for party {}", party_id);
                } else {
                    info!("Registered public key for party {}", party_id);
                }
                self.try_build_aggregate_key()?;
                Ok(())
            }
            P2PMessage::CiphertextBroadcast {
                from_peer,
                ct_bytes,
                ..
            } => {
                let ct = Ciphertext::<Curve>::deserialize_compressed(&ct_bytes[..])
                    .map_err(|e| PeerError::Serialization(e.to_string()))?;
                let id = hash_ciphertext(&ct_bytes);
                self.ciphertexts.insert(id, ct.clone());
                info!("Received ciphertext broadcast from {}", from_peer);
                // Only passive peers should NOT start their own decryption session.
                // They should only respond to incoming PartialDecryptionRequest messages.
                // The initiator handles decryption requests in run_initiator_flow().
                Ok(())
            }
            P2PMessage::PartialDecryptionRequest {
                request_id,
                from_peer: _,
                ct_bytes,
                requesting_parties,
            } => {
                if !requesting_parties.contains(&self.config.party_id) {
                    return Ok(());
                }
                let ciphertext = Ciphertext::<Curve>::deserialize_compressed(&ct_bytes[..])
                    .map_err(|e| PeerError::Serialization(e.to_string()))?;
                let pd = {
                    let sk = self.secret_key.lock().await;
                    sk.partial_decryption(&ciphertext)
                };
                let mut pd_bytes = Vec::new();
                pd.serialize_compressed(&mut pd_bytes)
                    .map_err(|e| PeerError::Serialization(e.to_string()))?;

                // Sign the partial decryption response
                // Signature covers: peer_id || party_id || (request_id || pd_bytes)
                let mut message_to_sign = Vec::new();
                message_to_sign.extend_from_slice(&request_id);
                message_to_sign.extend_from_slice(&pd_bytes);

                let signature = sign_crypto_message(
                    network.keypair(),
                    network.peer_id(),
                    self.config.party_id,
                    &message_to_sign,
                )?;

                let response = P2PMessage::PartialDecryptionResponse {
                    request_id,
                    party_id: self.config.party_id,
                    peer_id: network.peer_id().to_string(),
                    pd_bytes,
                    signature,
                };
                info!(
                    "Responding to partial decryption request {} as party {}",
                    hex::encode(request_id),
                    self.config.party_id
                );
                network
                    .publish(&response)
                    .await
                    .map_err(|e| PeerError::Network(format!("{:?}", e)))
            }
            P2PMessage::PartialDecryptionResponse {
                request_id,
                party_id,
                peer_id,
                pd_bytes,
                signature,
            } => {
                // Verify the signature before accepting the partial decryption
                let mut message_to_verify = Vec::new();
                message_to_verify.extend_from_slice(&request_id);
                message_to_verify.extend_from_slice(&pd_bytes);

                if let Some(public_key) = self.peer_public_keys.get(&peer_id) {
                    verify_crypto_signature(
                        public_key,
                        &peer_id,
                        party_id,
                        &message_to_verify,
                        &signature,
                    )?;
                    info!(
                        "✓ Verified signature for partial decryption from party {} (peer {})",
                        party_id, peer_id
                    );
                } else {
                    // Try to extract public key from peer_id
                    match peer_id_to_public_key(&peer_id) {
                        Ok(public_key) => {
                            verify_crypto_signature(
                                &public_key,
                                &peer_id,
                                party_id,
                                &message_to_verify,
                                &signature,
                            )?;
                            self.peer_public_keys.insert(peer_id.clone(), public_key);
                            info!(
                                "✓ Verified signature for partial decryption from party {} (peer {}, first time)",
                                party_id, peer_id
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Cannot verify partial decryption from party {}: no public key available: {:?}",
                                party_id, e
                            );
                            return Err(PeerError::Signature(e));
                        }
                    }
                }

                let pd = G2::deserialize_compressed(&pd_bytes[..])
                    .map_err(|e| PeerError::Serialization(e.to_string()))?;
                if let Some(session) = self.decrypt_sessions.get_mut(&request_id) {
                    session.responses.insert(party_id, pd);
                    info!(
                        "Received partial decryption from party {} ({} / {})",
                        party_id,
                        session.responses.len(),
                        session.requested_parties.len()
                    );
                    if session.responses.len() == session.requested_parties.len() {
                        self.finalize_decryption(request_id)?;
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn try_build_aggregate_key(&mut self) -> Result<(), PeerError> {
        let min_quorum = self.config.threshold + 1;
        let available_parties: HashSet<usize> = self.party_keys.keys().copied().collect();

        if available_parties.len() < min_quorum {
            debug!(
                "Waiting for minimum quorum: have {} parties, need at least {}",
                available_parties.len(),
                min_quorum
            );
            return Ok(());
        }

        let already_synced = self.aggregate_key.is_some()
            && available_parties.len() == self.aggregate_parties.len()
            && available_parties
                .iter()
                .all(|id| self.aggregate_parties.contains(id));
        if already_synced {
            return Ok(());
        }

        let mut ordered = Vec::with_capacity(self.config.n);
        for id in 0..self.config.n {
            if let Some(pk) = self.party_keys.get(&id) {
                ordered.push(pk.clone());
            } else {
                ordered.push(PublicKey::zero_for_domain(id, self.config.n));
            }
        }

        let agg = AggregateKey::new(ordered, &self.params)?;
        let available_count = available_parties.len();
        self.aggregate_key = Some(agg);
        self.aggregate_parties = available_parties;

        if available_count == self.config.n {
            info!(
                "Aggregate key constructed for all {} parties.",
                self.config.n
            );
        } else {
            info!(
                "Aggregate key constructed with {} parties (minimum quorum: {}).",
                available_count, min_quorum
            );
        }
        self.aggregate_ready.notify_waiters();
        Ok(())
    }

    fn encrypt_message(&self) -> Result<Ciphertext<Curve>, PeerError> {
        let agg = self
            .aggregate_key
            .as_ref()
            .ok_or_else(|| PeerError::Config("Aggregate key not ready".into()))?;
        let mut rng = StdRng::from_entropy();
        let ct = encrypt(agg, self.config.threshold, &self.params, &mut rng)?;
        Ok(ct)
    }

    async fn start_decryption_session(
        &mut self,
        network: Arc<Libp2pNetwork>,
        ciphertext: Ciphertext<Curve>,
    ) -> Result<(), PeerError> {
        let mut parties = self.select_parties_for_decryption();
        parties.sort_unstable();
        parties.dedup();

        if parties.len() != self.config.threshold + 1 {
            return Err(PeerError::Config(format!(
                "Need {} parties for threshold {}, only have {}",
                self.config.threshold + 1,
                self.config.threshold,
                parties.len()
            )));
        }

        let selector = build_selector(self.config.n, &parties);
        let request_id = random_message_id();

        let session = DecryptSession {
            ciphertext: ciphertext.clone(),
            selector,
            responses: HashMap::new(),
            requested_parties: parties.clone(),
            created_at: Instant::now(),
        };

        self.decrypt_sessions.insert(request_id, session);

        // If we are included in the request set, generate partial locally.
        if parties.contains(&self.config.party_id) {
            let pd = {
                let sk = self.secret_key.lock().await;
                sk.partial_decryption(&ciphertext)
            };
            self.decrypt_sessions
                .get_mut(&request_id)
                .expect("Session must exist since we just created it")
                .responses
                .insert(self.config.party_id, pd);
        }

        let mut ct_bytes = Vec::new();
        ciphertext
            .serialize_compressed(&mut ct_bytes)
            .map_err(|e| PeerError::Serialization(e.to_string()))?;

        let message = P2PMessage::PartialDecryptionRequest {
            request_id,
            from_peer: network.peer_id().to_string(),
            ct_bytes,
            requesting_parties: parties.clone(),
        };

        info!(
            "Requesting partial decryptions from parties {:?} (request {})",
            parties,
            hex::encode(request_id)
        );
        network
            .publish(&message)
            .await
            .map_err(|e| PeerError::Network(format!("{:?}", e)))
    }

    fn finalize_decryption(&mut self, request_id: MessageId) -> Result<(), PeerError> {
        let session = match self.decrypt_sessions.remove(&request_id) {
            Some(session) => session,
            None => return Ok(()),
        };
        let agg = self
            .aggregate_key
            .as_ref()
            .ok_or_else(|| PeerError::Config("Aggregate key missing".into()))?;

        let mut partials = vec![G2::zero(); self.config.n];
        for (party_id, pd) in &session.responses {
            if *party_id < partials.len() {
                partials[*party_id] = *pd;
            }
        }

        let result = agg_dec(
            &partials,
            &session.ciphertext,
            &session.selector,
            agg,
            &self.params,
        )?;
        info!(
            "Recovered encrypted key for request {}: {:?}",
            hex::encode(request_id),
            result
        );
        Ok(())
    }

    fn select_parties_for_decryption(&self) -> Vec<usize> {
        let mut parties: Vec<usize> = self
            .party_keys
            .keys()
            .copied()
            .filter(|id| *id < self.config.n)
            .collect();
        parties.sort_unstable();

        let mut selected = HashSet::new();
        if parties.contains(&0) {
            selected.insert(0);
        }
        for id in parties {
            if selected.len() >= self.config.threshold + 1 {
                break;
            }
            selected.insert(id);
        }

        selected.into_iter().collect()
    }
}

fn build_selector(n: usize, parties: &[usize]) -> Vec<bool> {
    let mut selector = vec![false; n];
    for &id in parties {
        if id < selector.len() {
            selector[id] = true;
        }
    }
    selector
}

fn random_message_id() -> MessageId {
    let mut rng = rand::rng();
    let mut id = [0u8; 32];
    rng.fill_bytes(&mut id);
    id
}

fn hash_ciphertext(data: &[u8]) -> MessageId {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&digest[..32]);
    id
}

fn validate_config(config: &PeerConfig) -> Result<(), PeerError> {
    // Minimum peer count validation (need at least 2 parties for meaningful threshold encryption)
    if config.n < 2 {
        return Err(PeerError::Config(
            "n must be at least 2".to_string(),
        ));
    }
    if config.threshold == 0 || config.threshold >= config.n {
        return Err(PeerError::Config(
            "threshold must be between 1 and n-1".to_string(),
        ));
    }
    if config.party_id >= config.n {
        return Err(PeerError::Config(format!(
            "party_id {} must be < n ({})",
            config.party_id, config.n
        )));
    }
    if config.listen_addresses.is_empty() {
        return Err(PeerError::Config(
            "at least one listen address is required".to_string(),
        ));
    }
    Ok(())
}

fn load_powers(path: &Path) -> Result<PowersOfTau<Curve>, PeerError> {
    let bytes = std::fs::read(path)?;
    PowersOfTau::<Curve>::deserialize_compressed(&bytes[..])
        .map_err(|e| PeerError::Serialization(e.to_string()))
}

fn load_lagrange(path: &Path) -> Result<LagrangePowers<Curve>, PeerError> {
    let bytes = std::fs::read(path)?;
    LagrangePowers::<Curve>::deserialize_compressed(&bytes[..])
        .map_err(|e| PeerError::Serialization(e.to_string()))
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}
