use crate::p2p::messages::P2PMessage;
use bincode;
use libp2p::core::{multiaddr::Error as MultiaddrError, upgrade, Multiaddr};
use libp2p::futures::StreamExt;
use libp2p::gossipsub::{
    self, Behaviour as Gossipsub, ConfigBuilder as GossipsubConfigBuilder, IdentTopic,
    MessageAuthenticity, ValidationMode,
};
use libp2p::identity;
use libp2p::mdns;
use libp2p::noise;
use libp2p::ping;
use libp2p::swarm::{Config as SwarmConfig, NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{identify, tcp, yamux, PeerId, Transport};
use tokio::sync::{mpsc, Mutex};

const DEFAULT_TOPIC: &str = "silent-threshold-encryption";
const IDENTIFY_PROTOCOL: &str = "/silent-threshold/1.0.0";

#[derive(Debug, Clone)]
pub struct Libp2pConfig {
    pub listen_addresses: Vec<String>,
    pub bootstrap_nodes: Vec<String>,
    pub gossip_topic: String,
}

impl Default for Libp2pConfig {
    fn default() -> Self {
        Self {
            listen_addresses: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
            bootstrap_nodes: Vec::new(),
            gossip_topic: DEFAULT_TOPIC.to_string(),
        }
    }
}

#[derive(Debug)]
pub enum Libp2pNetworkError {
    ChannelClosed,
    Serialization(String),
    InvalidAddress(String),
    Transport(String),
    Io(std::io::Error),
}

impl From<std::io::Error> for Libp2pNetworkError {
    fn from(value: std::io::Error) -> Self {
        Libp2pNetworkError::Io(value)
    }
}

pub type Libp2pResult<T> = Result<T, Libp2pNetworkError>;

pub struct Libp2pNetwork {
    local_peer_id: String,
    keypair: identity::Keypair,
    command_tx: mpsc::Sender<NetworkCommand>,
    event_rx: Mutex<mpsc::Receiver<Libp2pEvent>>,
}

impl Libp2pNetwork {
    pub async fn new(config: Libp2pConfig) -> Libp2pResult<Self> {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(upgrade::Version::V1)
            .authenticate(noise_config(&keypair)?)
            .multiplex(yamux::Config::default())
            .boxed();

        let gossipsub = build_gossipsub(&keypair)?;
        let mdns_behaviour = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
            .map_err(|e| Libp2pNetworkError::Io(e))?;
        let identify = identify::Behaviour::new(identify::Config::new(
            IDENTIFY_PROTOCOL.into(),
            keypair.public(),
        ));
        let ping = ping::Behaviour::default();

        let behaviour = SteBehaviour {
            gossipsub,
            mdns: mdns_behaviour,
            identify,
            ping,
        };

        let swarm_config = SwarmConfig::with_tokio_executor()
            .with_idle_connection_timeout(std::time::Duration::from_secs(60));

        let mut swarm =
            Swarm::new(transport, behaviour, peer_id, swarm_config);

        let topic = IdentTopic::new(config.gossip_topic.clone());
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e: gossipsub::SubscriptionError| {
                Libp2pNetworkError::Transport(e.to_string())
            })?;

        let listen_addrs = parse_multiaddrs(config.listen_addresses)?;
        if listen_addrs.is_empty() {
            return Err(Libp2pNetworkError::InvalidAddress(
                "At least one listen address is required".to_string(),
            ));
        }

        for addr in listen_addrs {
            if let Err(e) = Swarm::listen_on(&mut swarm, addr.clone()) {
                eprintln!("Failed to listen on {addr}: {e}");
            }
        }

        let bootstrap_nodes = parse_multiaddrs(config.bootstrap_nodes)?;

        let (command_tx, command_rx) = mpsc::channel(64);
        let (event_tx, event_rx) = mpsc::channel(128);

        tokio::spawn(run_swarm(
            swarm,
            topic,
            bootstrap_nodes,
            command_rx,
            event_tx,
        ));

        Ok(Self {
            local_peer_id: peer_id.to_string(),
            keypair,
            command_tx,
            event_rx: Mutex::new(event_rx),
        })
    }

    pub fn peer_id(&self) -> &str {
        &self.local_peer_id
    }

    /// Get a reference to the libp2p keypair for signing messages
    pub fn keypair(&self) -> &identity::Keypair {
        &self.keypair
    }

    /// Get the public key for this peer
    pub fn public_key(&self) -> identity::PublicKey {
        self.keypair.public()
    }

    pub async fn publish(&self, message: &P2PMessage) -> Libp2pResult<()> {
        let payload = bincode::serialize(message)
            .map_err(|e| Libp2pNetworkError::Serialization(e.to_string()))?;
        self.command_tx
            .send(NetworkCommand::Publish(payload))
            .await
            .map_err(|_| Libp2pNetworkError::ChannelClosed)
    }

    pub async fn dial(&self, addr: &str) -> Libp2pResult<()> {
        let addr: Multiaddr = addr
            .parse()
            .map_err(|e: MultiaddrError| Libp2pNetworkError::InvalidAddress(e.to_string()))?;
        self.command_tx
            .send(NetworkCommand::Dial(addr))
            .await
            .map_err(|_| Libp2pNetworkError::ChannelClosed)
    }

    pub async fn next_event(&self) -> Option<Libp2pEvent> {
        let mut rx = self.event_rx.lock().await;
        rx.recv().await
    }
}

#[derive(Debug)]
enum NetworkCommand {
    Publish(Vec<u8>),
    Dial(Multiaddr),
    Shutdown,
}

#[derive(Debug)]
pub enum Libp2pEvent {
    Message { source: String, message: P2PMessage },
    PeerConnected(String),
    PeerDisconnected(String),
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "SteEvent")]
struct SteBehaviour {
    gossipsub: Gossipsub,
    mdns: mdns::tokio::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

#[allow(clippy::large_enum_variant)]
enum SteEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
    Identify(identify::Event),
    Ping(ping::Event),
}

impl From<gossipsub::Event> for SteEvent {
    fn from(event: gossipsub::Event) -> Self {
        SteEvent::Gossipsub(event)
    }
}

impl From<mdns::Event> for SteEvent {
    fn from(event: mdns::Event) -> Self {
        SteEvent::Mdns(event)
    }
}

impl From<identify::Event> for SteEvent {
    fn from(event: identify::Event) -> Self {
        SteEvent::Identify(event)
    }
}

impl From<ping::Event> for SteEvent {
    fn from(event: ping::Event) -> Self {
        SteEvent::Ping(event)
    }
}

fn noise_config(keypair: &identity::Keypair) -> Libp2pResult<noise::Config> {
    noise::Config::new(keypair).map_err(|e| Libp2pNetworkError::Transport(e.to_string()))
}

fn build_gossipsub(keypair: &identity::Keypair) -> Libp2pResult<Gossipsub> {
    let message_authenticity = MessageAuthenticity::Signed(keypair.clone());
    let config = GossipsubConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        // Configure for small networks (threshold encryption typically uses 3-10 peers)
        // Constraint: mesh_outbound_min <= mesh_n_low <= mesh_n <= mesh_n_high
        .mesh_outbound_min(1) // Min outbound connections (default: 2)
        .mesh_n_low(1) // Allow mesh with just 1 peer (default: 4)
        .mesh_n(3) // Target 3 peers in mesh (default: 6)
        .mesh_n_high(5) // Max 5 peers in mesh (default: 12)
        .heartbeat_interval(std::time::Duration::from_secs(1)) // Faster mesh maintenance
        .build()
        .map_err(|e: gossipsub::ConfigBuilderError| {
            Libp2pNetworkError::Transport(e.to_string())
        })?;
    Gossipsub::new(message_authenticity, config)
        .map_err(|e: &'static str| Libp2pNetworkError::Transport(e.to_string()))
}

fn parse_multiaddrs(addrs: Vec<String>) -> Libp2pResult<Vec<Multiaddr>> {
    addrs
        .into_iter()
        .map(|addr| {
            addr.parse::<Multiaddr>()
                .map_err(|e: MultiaddrError| Libp2pNetworkError::InvalidAddress(e.to_string()))
        })
        .collect()
}

async fn run_swarm(
    mut swarm: Swarm<SteBehaviour>,
    topic: IdentTopic,
    bootstrap: Vec<Multiaddr>,
    mut command_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<Libp2pEvent>,
) {
    for addr in bootstrap {
        if let Err(e) = Swarm::dial(&mut swarm, addr.clone()) {
            eprintln!("Bootstrap dial failed for {addr}: {e}");
        }
    }

    loop {
        tokio::select! {
            Some(command) = command_rx.recv() => {
                match command {
                    NetworkCommand::Publish(payload) => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), payload) {
                            eprintln!("Failed to publish message: {e}");
                        }
                    }
                    NetworkCommand::Dial(addr) => {
                        if let Err(e) = Swarm::dial(&mut swarm, addr.clone()) {
                            eprintln!("Manual dial failed for {addr}: {e}");
                        }
                    }
                    NetworkCommand::Shutdown => break,
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(SteEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                        match bincode::deserialize::<P2PMessage>(&message.data) {
                            Ok(decoded) => {
                                eprintln!("Received gossip message from {}: {:?}", propagation_source, std::mem::discriminant(&decoded));
                                let _ = event_tx.send(Libp2pEvent::Message {
                                    source: propagation_source.to_string(),
                                    message: decoded,
                                }).await;
                            }
                            Err(e) => {
                                eprintln!("Failed to deserialize gossip message: {}", e);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(SteEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                        eprintln!("Peer {} subscribed to topic {}", peer_id, topic);
                    }
                    SwarmEvent::Behaviour(SteEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic })) => {
                        eprintln!("Peer {} unsubscribed from topic {}", peer_id, topic);
                    }
                    SwarmEvent::Behaviour(SteEvent::Mdns(event)) => handle_mdns_event(&mut swarm, event),
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Listening on {address}");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        eprintln!("Connection established with peer {}", peer_id);
                        let _ = event_tx.send(Libp2pEvent::PeerConnected(peer_id.to_string())).await;
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        eprintln!("Connection closed with peer {}", peer_id);
                        let _ = event_tx.send(Libp2pEvent::PeerDisconnected(peer_id.to_string())).await;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn handle_mdns_event(swarm: &mut Swarm<SteBehaviour>, event: mdns::Event) {
    match event {
        mdns::Event::Discovered(list) => {
            for (peer, addr) in list {
                eprintln!("mDNS discovered {} at {}", peer, addr);
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);

                // Only dial if we're not already connected or connecting
                if !swarm.is_connected(&peer) {
                    // Avoid simultaneous dial conflicts by only dialing if our peer_id is lower
                    let local_peer_id = *swarm.local_peer_id();
                    if local_peer_id < peer {
                        eprintln!("Dialing {} (our peer ID is lower)...", peer);
                        match Swarm::dial(swarm, addr.clone()) {
                            Ok(_) => eprintln!("Successfully initiated dial to {}", peer),
                            Err(e) => eprintln!("Dial failed for {}: {}", addr, e),
                        }
                    } else {
                        eprintln!("Not dialing {} (waiting for them to dial us)", peer);
                    }
                }
            }
        }
        mdns::Event::Expired(list) => {
            for (peer, _addr) in list {
                eprintln!("mDNS expired for {}", peer);
                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
            }
        }
    }
}
