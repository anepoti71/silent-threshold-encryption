use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use silent_threshold_encryption::p2p::{PeerConfig, PeerNode, PeerRuntimeMode};

#[derive(Parser, Debug)]
#[command(
    about = "Fully peer-to-peer Silent Threshold Encryption node",
    author,
    version
)]
struct Cli {
    /// Party identifier (0-indexed)
    #[arg(long = "party-id")]
    party_id: usize,

    /// Total number of parties (must be at least 2)
    #[arg(long = "parties")]
    parties: usize,

    /// Decryption threshold (must be between 1 and parties-1)
    #[arg(long = "threshold")]
    threshold: usize,

    /// Multiaddresses to listen on (repeat flag for multiple)
    #[arg(
        long = "listen",
        default_values_t = [String::from("/ip4/0.0.0.0/tcp/0")]
    )]
    listen: Vec<String>,

    /// Bootstrap peers to dial (repeat flag for multiple)
    #[arg(long = "bootstrap", default_values_t = Vec::<String>::new())]
    bootstrap: Vec<String>,

    /// Gossip topic to join
    #[arg(long = "gossip-topic", default_value = "silent-threshold-encryption")]
    gossip_topic: String,

    /// Path to serialized KZG Powers of Tau parameters
    #[arg(
        long = "kzg-params",
        value_name = "FILE",
        default_value = "artifacts/p2p/kzg_params.bin"
    )]
    kzg_params: PathBuf,

    /// Path to serialized preprocessed Lagrange powers
    #[arg(
        long = "lagrange-params",
        value_name = "FILE",
        default_value = "artifacts/p2p/lagrange_params.bin"
    )]
    lagrange_params: PathBuf,

    /// Operating mode (passive or initiator)
    #[arg(long = "mode", value_enum, default_value = "passive")]
    mode: ModeArg,

    /// Automatically request partial decryptions for every ciphertext
    #[arg(long = "auto-decrypt", default_value_t = false)]
    auto_decrypt: bool,

    /// Disable mDNS peer discovery (useful in sandboxed environments)
    #[arg(long = "disable-mdns", default_value_t = false)]
    disable_mdns: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ModeArg {
    Passive,
    Initiator,
}

impl From<ModeArg> for PeerRuntimeMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Passive => PeerRuntimeMode::Passive,
            ModeArg::Initiator => PeerRuntimeMode::Initiator,
        }
    }
}

#[tokio::main]
async fn main() {
    init_tracing();
    let cli = Cli::parse();

    let config = PeerConfig {
        party_id: cli.party_id,
        n: cli.parties,
        threshold: cli.threshold,
        listen_addresses: cli.listen,
        bootstrap_nodes: cli.bootstrap,
        gossip_topic: cli.gossip_topic,
        kzg_params_path: cli.kzg_params,
        lagrange_params_path: cli.lagrange_params,
        mode: cli.mode.into(),
        auto_decrypt: cli.auto_decrypt,
        enable_mdns: !cli.disable_mdns,
    };

    let node = PeerNode::new(config);
    if let Err(e) = node.run().await {
        eprintln!("Peer node failed: {e}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .try_init();
    });
}
