//! Distributed Silent Threshold Encryption Protocol
//!
//! This example demonstrates a realistic distributed threshold encryption system
//! with a coordinator server and multiple party clients communicating over TCP.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────┐
//! │ Coordinator│ (Server)
//! │  - Setup   │
//! │  - Encrypt │
//! │  - Decrypt │
//! └─────┬──────┘
//!       │
//!   ┌───┴───┬───────┬───────┐
//!   │       │       │       │
//! ┌─▼──┐ ┌──▼─┐ ┌──▼─┐ ┌───▼┐
//! │Party│ │Party│ │Party│ │Party│ (Clients)
//! │  0  │ │  1 │ │  2 │ │ ... │
//! └─────┘ └────┘ └────┘ └────┘
//! ```
//!
//! # Protocol Flow
//!
//! 1. **Setup Phase**:
//!    - Coordinator generates KZG parameters
//!    - Each party generates their secret/public key pair
//!    - Parties send public keys to coordinator
//!    - Coordinator computes aggregate key
//!
//! 2. **Encryption Phase**:
//!    - Coordinator encrypts a message using the aggregate key
//!    - Ciphertext is broadcast to all parties
//!
//! 3. **Decryption Phase**:
//!    - Coordinator selects t+1 parties for decryption
//!    - Selected parties compute partial decryptions
//!    - Parties send partial decryptions to coordinator
//!    - Coordinator aggregates and recovers the message
//!
//! # Usage
//!
//! Build with distributed feature:
//! ```bash
//! cargo build --bin distributed_protocol --features distributed --release
//! ```
//!
//! Run the coordinator (in one terminal):
//! ```bash
//! cargo run --bin distributed_protocol --features distributed --release -- coordinator --port 8080 --parties 4 --threshold 2
//! ```
//!
//! Run each party (in separate terminals):
//! ```bash
//! cargo run --bin distributed_protocol --features distributed --release -- party --id 0 --coordinator localhost:8080
//! cargo run --bin distributed_protocol --features distributed --release -- party --id 1 --coordinator localhost:8080
//! cargo run --bin distributed_protocol --features distributed --release -- party --id 2 --coordinator localhost:8080
//! cargo run --bin distributed_protocol --features distributed --release -- party --id 3 --coordinator localhost:8080
//! ```

#[cfg(feature = "distributed")]
mod distributed {
    use ark_ec::pairing::Pairing;
    use ark_poly::univariate::DensePolynomial;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{rand::RngCore, UniformRand, Zero};
    use bincode::{deserialize, serialize};
    use clap::{Parser, Subcommand};
    use rand::{rngs::StdRng, SeedableRng};
    use serde::{Deserialize, Serialize};
    use silent_threshold_encryption::{
        decryption::agg_dec,
        encryption::{encrypt, Ciphertext},
        kzg::{KZG10, PowersOfTau},
        setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey},
    };
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    type E = ark_bls12_381::Bls12_381;
    type G2 = <E as Pairing>::G2;
    type Fr = <E as Pairing>::ScalarField;
    type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

    // ============================================================================
    // Protocol Messages
    // ============================================================================

    /// Messages sent from coordinator to parties
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub enum CoordinatorMessage {
        /// Request party to generate and send their public key
        RequestPublicKey {
            party_id: usize,
            tau_bytes: Vec<u8>,  // Serialized tau parameter
            n: usize,
        },
        /// Broadcast ciphertext to all parties
        Ciphertext {
            ct_bytes: Vec<u8>,  // Serialized ciphertext
        },
        /// Request partial decryption from selected parties
        RequestPartialDecryption {
            party_id: usize,
            ct_bytes: Vec<u8>,
        },
        /// Notify party of successful completion
        Success {
            message: String,
        },
        /// Notify party of error
        Error {
            message: String,
        },
    }

    /// Messages sent from parties to coordinator
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub enum PartyMessage {
        /// Party sends their public key
        PublicKey {
            party_id: usize,
            pk_bytes: Vec<u8>,  // Serialized public key
        },
        /// Party sends partial decryption
        PartialDecryption {
            party_id: usize,
            pd_bytes: Vec<u8>,  // Serialized G2 element
        },
        /// Party ready and waiting for commands
        Ready {
            party_id: usize,
        },
        /// Party encountered an error
        Error {
            party_id: usize,
            message: String,
        },
    }

    // ============================================================================
    // Secure RNG (same as client demo)
    // ============================================================================

    struct SecureRng {
        inner: StdRng,
    }

    impl SecureRng {
        fn new() -> Self {
            use rand::RngCore;
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            SecureRng {
                inner: StdRng::from_seed(seed),
            }
        }
    }

    impl RngCore for SecureRng {
        fn next_u32(&mut self) -> u32 {
            <StdRng as rand::RngCore>::next_u32(&mut self.inner)
        }

        fn next_u64(&mut self) -> u64 {
            <StdRng as rand::RngCore>::next_u64(&mut self.inner)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            <StdRng as rand::RngCore>::fill_bytes(&mut self.inner, dest)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    // ============================================================================
    // Coordinator Server
    // ============================================================================

    pub struct Coordinator {
        n: usize,
        t: usize,
        port: u16,
        tau: Fr,
        kzg_params: PowersOfTau<E>,
        lagrange_params: LagrangePowers<E>,
        public_keys: HashMap<usize, PublicKey<E>>,
        partial_decryptions: HashMap<usize, G2>,
        party_connections: HashMap<usize, TcpStream>,
    }

    impl Coordinator {
        pub fn new(port: u16, n: usize, t: usize) -> Result<Self, Box<dyn std::error::Error>> {
            println!("🔧 Coordinator: Initializing with n={}, t={}", n, t);

            let mut rng = SecureRng::new();
            let tau = Fr::rand(&mut rng);

            println!("🔧 Coordinator: Setting up KZG parameters...");
            let kzg_params = KZG10::<E, UniPoly381>::setup(n, tau)?;

            println!("🔧 Coordinator: Preprocessing Lagrange powers...");
            let lagrange_params = LagrangePowers::<E>::new(tau, n)?;

            println!("✓ Coordinator: Setup complete");

            Ok(Self {
                n,
                t,
                port,
                tau,
                kzg_params,
                lagrange_params,
                public_keys: HashMap::new(),
                partial_decryptions: HashMap::new(),
                party_connections: HashMap::new(),
            })
        }

        pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            let addr = format!("127.0.0.1:{}", self.port);
            let listener = TcpListener::bind(&addr).await?;
            println!("🌐 Coordinator: Listening on {}", addr);
            println!("⏳ Coordinator: Waiting for {} parties to connect...", self.n);

            // Accept connections from all n parties
            for i in 0..self.n {
                let (stream, peer_addr) = listener.accept().await?;
                println!("✓ Coordinator: Party {} connected from {}", i, peer_addr);
                self.party_connections.insert(i, stream);
            }

            println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Phase 1: Key Generation");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Request public keys from all parties
            self.request_public_keys().await?;

            // Compute aggregate key
            println!("\n🔧 Coordinator: Computing aggregate key...");
            let pk_vec: Vec<PublicKey<E>> = (0..self.n)
                .map(|i| self.public_keys[&i].clone())
                .collect();
            let agg_key = AggregateKey::<E>::new(pk_vec, &self.kzg_params)?;
            println!("✓ Coordinator: Aggregate key computed");

            println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Phase 2: Encryption");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Encrypt a message
            let mut rng = SecureRng::new();
            println!("🔐 Coordinator: Encrypting message with threshold t={}...", self.t);
            let ct = encrypt::<E, _>(&agg_key, self.t, &self.kzg_params, &mut rng)?;
            println!("✓ Coordinator: Ciphertext generated");
            println!("  Encrypted key: {:?}", ct.enc_key);

            println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Phase 3: Decryption");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Select t+1 parties for decryption (always include party 0)
            let mut selected_parties: Vec<usize> = vec![0];
            for i in 1..=self.t.min(self.n - 1) {
                selected_parties.push(i);
            }

            println!("🎯 Coordinator: Selected {} parties for decryption: {:?}",
                     selected_parties.len(), selected_parties);

            // Request partial decryptions
            self.request_partial_decryptions(&ct, &selected_parties).await?;

            // Aggregate and decrypt
            println!("\n🔓 Coordinator: Aggregating partial decryptions...");
            let mut selector = vec![false; self.n];
            for &party_id in &selected_parties {
                selector[party_id] = true;
            }

            let mut pd_vec = vec![G2::zero(); self.n];
            for (party_id, pd) in &self.partial_decryptions {
                pd_vec[*party_id] = *pd;
            }

            let dec_key = agg_dec(&pd_vec, &ct, &selector, &agg_key, &self.kzg_params)?;

            println!("✓ Coordinator: Decryption complete");
            println!("  Decrypted key: {:?}", dec_key);

            // Verify correctness
            if dec_key == ct.enc_key {
                println!("\n✅ SUCCESS: Decryption successful! Keys match.");
            } else {
                println!("\n❌ ERROR: Decryption failed! Keys do not match.");
            }

            // Notify all parties of success
            self.notify_all_parties().await?;

            Ok(())
        }

        async fn request_public_keys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            // Serialize tau
            let mut tau_bytes = Vec::new();
            self.tau.serialize_compressed(&mut tau_bytes)?;

            // Send requests to all parties
            for party_id in 0..self.n {
                let msg = CoordinatorMessage::RequestPublicKey {
                    party_id,
                    tau_bytes: tau_bytes.clone(),
                    n: self.n,
                };
                self.send_to_party(party_id, &msg).await?;
            }

            // Receive public keys from all parties
            let mut received = 0;
            while received < self.n {
                let (party_id, msg) = self.receive_from_any_party().await?;

                match msg {
                    PartyMessage::PublicKey { party_id, pk_bytes } => {
                        let pk = PublicKey::<E>::deserialize_compressed(&pk_bytes[..])?;
                        self.public_keys.insert(party_id, pk);
                        println!("✓ Coordinator: Received public key from party {}", party_id);
                        received += 1;
                    }
                    PartyMessage::Ready { party_id } => {
                        // Ignore ready messages during key collection
                        println!("  Party {} ready", party_id);
                    }
                    _ => {
                        return Err(format!("Unexpected message from party {}: {:?}", party_id, msg).into());
                    }
                }
            }

            Ok(())
        }

        async fn request_partial_decryptions(
            &mut self,
            ct: &Ciphertext<E>,
            selected_parties: &[usize],
        ) -> Result<(), Box<dyn std::error::Error>> {
            // Serialize ciphertext
            let mut ct_bytes = Vec::new();
            ct.serialize_compressed(&mut ct_bytes)?;

            // Send requests to selected parties
            for &party_id in selected_parties {
                let msg = CoordinatorMessage::RequestPartialDecryption {
                    party_id,
                    ct_bytes: ct_bytes.clone(),
                };
                self.send_to_party(party_id, &msg).await?;
            }

            // Receive partial decryptions
            for _ in 0..selected_parties.len() {
                let (party_id, msg) = self.receive_from_any_party().await?;

                if let PartyMessage::PartialDecryption { party_id, pd_bytes } = msg {
                    let pd = G2::deserialize_compressed(&pd_bytes[..])?;
                    self.partial_decryptions.insert(party_id, pd);
                    println!("✓ Coordinator: Received partial decryption from party {}", party_id);
                } else {
                    return Err(format!("Unexpected message from party {}: {:?}", party_id, msg).into());
                }
            }

            Ok(())
        }

        async fn send_to_party(
            &mut self,
            party_id: usize,
            msg: &CoordinatorMessage,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let stream = self.party_connections.get_mut(&party_id)
                .ok_or(format!("Party {} not connected", party_id))?;

            let data = serialize(msg)?;
            let len = data.len() as u32;

            stream.write_u32(len).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;

            Ok(())
        }

        async fn receive_from_any_party(&mut self) -> Result<(usize, PartyMessage), Box<dyn std::error::Error>> {
            // Simple round-robin polling (in production, use select! or similar)
            loop {
                for party_id in 0..self.n {
                    if let Some(stream) = self.party_connections.get_mut(&party_id) {
                        // Try to read with a small timeout
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(10),
                            stream.read_u32()
                        ).await {
                            Ok(Ok(len)) => {
                                let mut data = vec![0u8; len as usize];
                                stream.read_exact(&mut data).await?;
                                let msg: PartyMessage = deserialize(&data)?;
                                return Ok((party_id, msg));
                            }
                            Ok(Err(e)) => return Err(e.into()),
                            Err(_) => continue, // Timeout, try next party
                        }
                    }
                }
            }
        }

        async fn notify_all_parties(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            let msg = CoordinatorMessage::Success {
                message: "Protocol completed successfully".to_string(),
            };

            for party_id in 0..self.n {
                self.send_to_party(party_id, &msg).await?;
            }

            Ok(())
        }
    }

    // ============================================================================
    // Party Client
    // ============================================================================

    pub struct Party {
        id: usize,
        coordinator_addr: String,
        secret_key: Option<SecretKey<E>>,
    }

    impl Party {
        pub fn new(id: usize, coordinator_addr: String) -> Self {
            println!("🎭 Party {}: Initializing", id);
            Self {
                id,
                coordinator_addr,
                secret_key: None,
            }
        }

        pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            println!("🌐 Party {}: Connecting to coordinator at {}", self.id, self.coordinator_addr);
            let mut stream = TcpStream::connect(&self.coordinator_addr).await?;
            println!("✓ Party {}: Connected to coordinator", self.id);

            // Send ready message
            let ready_msg = PartyMessage::Ready { party_id: self.id };
            self.send_message(&mut stream, &ready_msg).await?;

            // Main message loop
            loop {
                let msg = self.receive_message(&mut stream).await?;

                match msg {
                    CoordinatorMessage::RequestPublicKey { party_id, tau_bytes, n } => {
                        if party_id != self.id {
                            continue;
                        }
                        println!("\n📨 Party {}: Received request for public key", self.id);
                        self.handle_public_key_request(&mut stream, &tau_bytes, n).await?;
                    }
                    CoordinatorMessage::RequestPartialDecryption { party_id, ct_bytes } => {
                        if party_id != self.id {
                            continue;
                        }
                        println!("\n📨 Party {}: Received request for partial decryption", self.id);
                        self.handle_partial_decryption_request(&mut stream, &ct_bytes).await?;
                    }
                    CoordinatorMessage::Success { message } => {
                        println!("\n✅ Party {}: {}", self.id, message);
                        break;
                    }
                    CoordinatorMessage::Error { message } => {
                        println!("\n❌ Party {}: Error - {}", self.id, message);
                        break;
                    }
                    _ => {}
                }
            }

            Ok(())
        }

        async fn handle_public_key_request(
            &mut self,
            stream: &mut TcpStream,
            tau_bytes: &[u8],
            n: usize,
        ) -> Result<(), Box<dyn std::error::Error>> {
            // Deserialize tau
            let tau = Fr::deserialize_compressed(tau_bytes)?;

            // Generate secret key
            let mut rng = SecureRng::new();
            let mut sk = SecretKey::<E>::new(&mut rng);

            // Party 0 is the dummy party
            if self.id == 0 {
                sk.nullify();
                println!("🔑 Party {}: Generated nullified secret key (dummy party)", self.id);
            } else {
                println!("🔑 Party {}: Generated secret key", self.id);
            }

            // Compute public key using Lagrange method
            let lagrange_params = LagrangePowers::<E>::new(tau, n)?;
            let pk = sk.lagrange_get_pk(self.id, &lagrange_params, n)?;

            // Store secret key for later
            self.secret_key = Some(sk);

            // Serialize and send public key
            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes)?;

            let response = PartyMessage::PublicKey {
                party_id: self.id,
                pk_bytes,
            };

            self.send_message(stream, &response).await?;
            println!("✓ Party {}: Sent public key to coordinator", self.id);

            Ok(())
        }

        async fn handle_partial_decryption_request(
            &mut self,
            stream: &mut TcpStream,
            ct_bytes: &[u8],
        ) -> Result<(), Box<dyn std::error::Error>> {
            // Deserialize ciphertext
            let ct = Ciphertext::<E>::deserialize_compressed(ct_bytes)?;

            // Compute partial decryption
            let sk = self.secret_key.as_ref()
                .ok_or("Secret key not initialized")?;
            let pd = sk.partial_decryption(&ct);

            // Serialize and send partial decryption
            let mut pd_bytes = Vec::new();
            pd.serialize_compressed(&mut pd_bytes)?;

            let response = PartyMessage::PartialDecryption {
                party_id: self.id,
                pd_bytes,
            };

            self.send_message(stream, &response).await?;
            println!("✓ Party {}: Sent partial decryption to coordinator", self.id);

            Ok(())
        }

        async fn send_message(
            &self,
            stream: &mut TcpStream,
            msg: &PartyMessage,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let data = serialize(msg)?;
            let len = data.len() as u32;

            stream.write_u32(len).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;

            Ok(())
        }

        async fn receive_message(
            &self,
            stream: &mut TcpStream,
        ) -> Result<CoordinatorMessage, Box<dyn std::error::Error>> {
            let len = stream.read_u32().await?;
            let mut data = vec![0u8; len as usize];
            stream.read_exact(&mut data).await?;
            let msg: CoordinatorMessage = deserialize(&data)?;
            Ok(msg)
        }
    }

    // ============================================================================
    // CLI
    // ============================================================================

    #[derive(Parser)]
    #[command(name = "distributed-ste")]
    #[command(about = "Distributed Silent Threshold Encryption Protocol", long_about = None)]
    struct Cli {
        #[command(subcommand)]
        command: Commands,
    }

    #[derive(Subcommand)]
    enum Commands {
        /// Run as coordinator server
        Coordinator {
            /// Port to listen on
            #[arg(short, long, default_value = "8080")]
            port: u16,
            /// Number of parties
            #[arg(short = 'n', long, default_value = "4")]
            parties: usize,
            /// Threshold value
            #[arg(short, long, default_value = "2")]
            threshold: usize,
        },
        /// Run as party client
        Party {
            /// Party ID (0 to n-1)
            #[arg(short, long)]
            id: usize,
            /// Coordinator address (e.g., localhost:8080)
            #[arg(short, long)]
            coordinator: String,
        },
    }

    pub async fn main_async() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::parse();

        match cli.command {
            Commands::Coordinator { port, parties, threshold } => {
                let mut coordinator = Coordinator::new(port, parties, threshold)?;
                coordinator.run().await?;
            }
            Commands::Party { id, coordinator } => {
                let mut party = Party::new(id, coordinator);
                party.run().await?;
            }
        }

        Ok(())
    }
}

#[cfg(feature = "distributed")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    distributed::main_async().await
}

#[cfg(not(feature = "distributed"))]
fn main() {
    eprintln!("This binary requires the 'distributed' feature.");
    eprintln!("Run with: cargo run --bin distributed_protocol --features distributed");
    std::process::exit(1);
}
