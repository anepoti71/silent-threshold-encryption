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
    use ark_ec::PrimeGroup;
    use ark_ff::PrimeField;
    use ark_poly::univariate::DensePolynomial;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{rand::RngCore, UniformRand, Zero};
    use bincode::{deserialize, serialize};
    use blake2::{Blake2b512, Digest};
    use clap::{Parser, Subcommand};
    use rand::{rngs::StdRng, SeedableRng};
    use serde::{Deserialize, Serialize};
    use silent_threshold_encryption::{
        decryption::agg_dec,
        encryption::{encrypt, Ciphertext},
        kzg::{PowersOfTau, KZG10},
        security::SensitiveScalar,
        setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey},
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::TlsConnector;
    use tokio::sync::mpsc;

    mod tls_config;

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
            lagrange_bytes: Vec<u8>, // Serialized Lagrange powers
            lagrange_hash: [u8; 32],
            n: usize,
            challenge: [u8; 32],
        },
        /// Broadcast ciphertext to all parties
        Ciphertext {
            ct_bytes: Vec<u8>, // Serialized ciphertext
        },
        /// Request partial decryption from selected parties
        RequestPartialDecryption {
            party_id: usize,
            ct_bytes: Vec<u8>,
            request_id: [u8; 32],
        },
        /// Notify party of successful completion
        Success { message: String },
        /// Notify party of error
        Error { message: String },
    }

    /// Messages sent from parties to coordinator
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub enum PartyMessage {
        /// Party sends their public key
        PublicKey {
            party_id: usize,
            pk_bytes: Vec<u8>, // Serialized public key
            pop_sig: Vec<u8>,
        },
        /// Party sends partial decryption
        PartialDecryption {
            party_id: usize,
            pd_bytes: Vec<u8>, // Serialized G2 element
            request_id: [u8; 32],
            signature: Vec<u8>,
        },
        /// Party ready and waiting for commands
        Ready { party_id: usize },
        /// Party encountered an error
        Error { party_id: usize, message: String },
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

    fn hash_bytes(data: &[u8]) -> [u8; 32] {
        let digest = Blake2b512::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..32]);
        out
    }

    fn bls_message_from_payload(payload: &[u8]) -> G2 {
        let digest = Blake2b512::digest(payload);
        let scalar = Fr::from_le_bytes_mod_order(digest.as_slice());
        G2::generator() * scalar
    }

    fn verify_bls_signature(pk: &<E as Pairing>::G1, message: &G2, signature: &G2) -> bool {
        E::pairing(<E as Pairing>::G1::generator(), *signature) == E::pairing(*pk, *message)
    }

    // ============================================================================
    // Coordinator Server
    // ============================================================================

    pub struct Coordinator {
        n: usize,
        t: usize,
        port: u16,
        kzg_params: PowersOfTau<E>,
        lagrange_bytes: Vec<u8>,
        lagrange_hash: [u8; 32],
        public_keys: HashMap<usize, PublicKey<E>>,
        partial_decryptions: HashMap<usize, G2>,
        party_connections: HashMap<usize, tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>>,
        cert_path: Option<String>,
        key_path: Option<String>,
        public_key_challenges: HashMap<usize, [u8; 32]>,
        message_rx: Option<mpsc::Receiver<(usize, PartyMessage)>>,
    }

    impl Coordinator {
        pub fn new(
            port: u16,
            n: usize,
            t: usize,
            cert_path: Option<String>,
            key_path: Option<String>,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            println!("🔧 Coordinator: Initializing with n={}, t={}", n, t);

            let mut rng = SecureRng::new();
            let tau_raw = Fr::rand(&mut rng);
            let tau = SensitiveScalar::new(tau_raw);

            println!("🔧 Coordinator: Setting up KZG parameters...");
            let kzg_params = KZG10::<E, UniPoly381>::setup(n, *tau.expose_secret())?;

            println!("🔧 Coordinator: Preprocessing Lagrange powers...");
            let lagrange_params = LagrangePowers::<E>::new(*tau.expose_secret(), n)?;
            let mut lagrange_bytes = Vec::new();
            lagrange_params.serialize_compressed(&mut lagrange_bytes)?;
            let lagrange_hash_vec = Blake2b512::digest(&lagrange_bytes);
            let mut lagrange_hash = [0u8; 32];
            lagrange_hash.copy_from_slice(&lagrange_hash_vec[..32]);

            println!("✓ Coordinator: Setup complete");

            Ok(Self {
                n,
                t,
                port,
                kzg_params,
                lagrange_bytes,
                lagrange_hash,
                public_keys: HashMap::new(),
                partial_decryptions: HashMap::new(),
                party_connections: HashMap::new(),
                cert_path,
                key_path,
                public_key_challenges: HashMap::new(),
                message_rx: None,
            })
        }

        pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            // Load or generate certificate for TLS
            println!("🔐 Coordinator: Preparing TLS certificate...");
            let (certs, key) = match (&self.cert_path, &self.key_path) {
                (Some(cert_path), Some(key_path)) => {
                    println!("🔐 Coordinator: Loading certificate from {}", cert_path);
                    tls_config::load_cert_and_key(cert_path, key_path)?
                }
                (None, None) => {
                    println!("⚠️ Coordinator: No certificate/key provided. Generating self-signed certificate (share its PEM with parties for pinning).");
                    tls_config::generate_self_signed_cert()?
                }
                _ => {
                    return Err("Both certificate and key paths must be provided together".into());
                }
            };
            let tls_config = tls_config::create_server_config(certs, key)?;
            let acceptor = TlsAcceptor::from(tls_config);
            println!("✓ Coordinator: TLS certificate ready");

            let addr = format!("127.0.0.1:{}", self.port);
            let listener = TcpListener::bind(&addr).await?;
            println!("🌐 Coordinator: Listening on {} (TLS 1.3)", addr);
            println!(
                "⏳ Coordinator: Waiting for {} parties to connect...",
                self.n
            );

            let (msg_tx, msg_rx) = mpsc::channel(64);
            self.message_rx = Some(msg_rx);

            // Accept connections from all n parties
            for i in 0..self.n {
                let (tcp_stream, peer_addr) = listener.accept().await?;
                println!(
                    "🔌 Coordinator: TCP connection from {} (party {})",
                    peer_addr, i
                );

                // Perform TLS handshake
                let tls_stream = acceptor.accept(tcp_stream).await?;
                println!(
                    "✓ Coordinator: Party {} connected with TLS from {}",
                    i, peer_addr
                );
                let (read_half, write_half) = tokio::io::split(tls_stream);
                self.party_connections.insert(i, write_half);

                let tx = msg_tx.clone();
                tokio::spawn(async move {
                    let mut reader = read_half;
                    loop {
                        let len = match reader.read_u32().await {
                            Ok(len) => len,
                            Err(_) => break,
                        };
                        let mut data = vec![0u8; len as usize];
                        if reader.read_exact(&mut data).await.is_err() {
                            break;
                        }
                        let msg: PartyMessage = match deserialize(&data) {
                            Ok(msg) => msg,
                            Err(_) => break,
                        };
                        if tx.send((i, msg)).await.is_err() {
                            break;
                        }
                    }
                });
            }

            println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Phase 1: Key Generation");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Request public keys from all parties
            self.request_public_keys().await?;

            // Compute aggregate key
            println!("\n🔧 Coordinator: Computing aggregate key...");
            let pk_vec: Vec<PublicKey<E>> =
                (0..self.n).map(|i| self.public_keys[&i].clone()).collect();
            let agg_key = AggregateKey::<E>::new(pk_vec, &self.kzg_params)?;
            println!("✓ Coordinator: Aggregate key computed");

            println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Phase 2: Encryption");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            // Encrypt a message
            let mut rng = SecureRng::new();
            println!(
                "🔐 Coordinator: Encrypting message with threshold t={}...",
                self.t
            );
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

            println!(
                "🎯 Coordinator: Selected {} parties for decryption: {:?}",
                selected_parties.len(),
                selected_parties
            );

            // Request partial decryptions
            self.request_partial_decryptions(&ct, &selected_parties)
                .await?;

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
            // Send requests to all parties
            for party_id in 0..self.n {
                let mut rng = SecureRng::new();
                let mut challenge = [0u8; 32];
                rng.fill_bytes(&mut challenge);
                self.public_key_challenges.insert(party_id, challenge);
                let msg = CoordinatorMessage::RequestPublicKey {
                    party_id,
                    lagrange_bytes: self.lagrange_bytes.clone(),
                    lagrange_hash: self.lagrange_hash,
                    n: self.n,
                    challenge,
                };
                self.send_to_party(party_id, &msg).await?;
            }

            // Receive public keys from all parties
            let mut received = 0;
            while received < self.n {
                let (conn_party_id, msg) = self.receive_from_any_party().await?;

                match msg {
                    PartyMessage::PublicKey {
                        party_id,
                        pk_bytes,
                        pop_sig,
                    } => {
                        if party_id != conn_party_id {
                            return Err(format!(
                                "Party id mismatch: connection {} reported {}",
                                conn_party_id, party_id
                            )
                            .into());
                        }
                        let pk = PublicKey::<E>::deserialize_compressed(&pk_bytes[..])?;
                        let challenge = self.public_key_challenges.get(&party_id).ok_or_else(|| {
                            format!("Missing public key challenge for party {}", party_id)
                        })?;
                        let mut payload = Vec::with_capacity(64);
                        payload.extend_from_slice(b"ste-pk-pop-v1");
                        payload.extend_from_slice(&party_id.to_le_bytes());
                        payload.extend_from_slice(challenge);
                        let message = bls_message_from_payload(&payload);
                        let sig = G2::deserialize_compressed(&pop_sig[..])?;
                        if !verify_bls_signature(&pk.bls_pk, &message, &sig) {
                            return Err(format!(
                                "Invalid public key proof-of-possession from party {}",
                                party_id
                            )
                            .into());
                        }
                        self.public_keys.insert(party_id, pk);
                        println!("✓ Coordinator: Received public key from party {}", party_id);
                        received += 1;
                    }
                    PartyMessage::Ready { party_id } => {
                        // Ignore ready messages during key collection
                        println!("  Party {} ready", party_id);
                    }
                    _ => {
                        return Err(format!(
                            "Unexpected message from party {}: {:?}",
                            conn_party_id, msg
                        )
                        .into());
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
            let ct_hash = hash_bytes(&ct_bytes);
            let mut rng = SecureRng::new();
            let mut request_id = [0u8; 32];
            rng.fill_bytes(&mut request_id);

            // Send requests to selected parties
            for &party_id in selected_parties {
                let msg = CoordinatorMessage::RequestPartialDecryption {
                    party_id,
                    ct_bytes: ct_bytes.clone(),
                    request_id,
                };
                self.send_to_party(party_id, &msg).await?;
            }

            // Receive partial decryptions
            for _ in 0..selected_parties.len() {
                let (conn_party_id, msg) = self.receive_from_any_party().await?;

                if let PartyMessage::PartialDecryption {
                    party_id,
                    pd_bytes,
                    request_id: resp_request_id,
                    signature,
                } = msg
                {
                    if party_id != conn_party_id {
                        return Err(format!(
                            "Party id mismatch: connection {} reported {}",
                            conn_party_id, party_id
                        )
                        .into());
                    }
                    if resp_request_id != request_id {
                        return Err(format!(
                            "Unexpected request_id from party {}",
                            party_id
                        )
                        .into());
                    }
                    let pk = self.public_keys.get(&party_id).ok_or_else(|| {
                        format!("Missing public key for party {}", party_id)
                    })?;
                    let mut payload = Vec::with_capacity(96);
                    payload.extend_from_slice(b"ste-pd-v1");
                    payload.extend_from_slice(&party_id.to_le_bytes());
                    payload.extend_from_slice(&request_id);
                    payload.extend_from_slice(&ct_hash);
                    let message = bls_message_from_payload(&payload);
                    let sig = G2::deserialize_compressed(&signature[..])?;
                    if !verify_bls_signature(&pk.bls_pk, &message, &sig) {
                        return Err(format!(
                            "Invalid partial decryption signature from party {}",
                            party_id
                        )
                        .into());
                    }
                    let pd = G2::deserialize_compressed(&pd_bytes[..])?;
                    self.partial_decryptions.insert(party_id, pd);
                    println!(
                        "✓ Coordinator: Received partial decryption from party {}",
                        party_id
                    );
                } else {
                    return Err(
                        format!(
                            "Unexpected message from party {}: {:?}",
                            conn_party_id, msg
                        )
                        .into(),
                    );
                }
            }

            Ok(())
        }

        async fn send_to_party(
            &mut self,
            party_id: usize,
            msg: &CoordinatorMessage,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let stream = self
                .party_connections
                .get_mut(&party_id)
                .ok_or(format!("Party {} not connected", party_id))?;

            let data = serialize(msg)?;
            let len = data.len() as u32;

            stream.write_u32(len).await?;
            stream.write_all(&data).await?;
            stream.flush().await?;

            Ok(())
        }

        async fn receive_from_any_party(
            &mut self,
        ) -> Result<(usize, PartyMessage), Box<dyn std::error::Error>> {
            let rx = self
                .message_rx
                .as_mut()
                .ok_or("message channel not initialized")?;
            rx.recv()
                .await
                .ok_or_else(|| "message channel closed".into())
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
        server_cert_path: Option<String>,
        allow_insecure: bool,
        lagrange_cache: Option<([u8; 32], Arc<LagrangePowers<E>>)>,
        bad_lagrange_digest: Option<[u8; 32]>,
        secret_key: Option<SecretKey<E>>,
    }

    impl Party {
        pub fn new(
            id: usize,
            coordinator_addr: String,
            server_cert_path: Option<String>,
            allow_insecure: bool,
        ) -> Self {
            println!("🎭 Party {}: Initializing", id);
            Self {
                id,
                coordinator_addr,
                server_cert_path,
                allow_insecure,
                lagrange_cache: None,
                bad_lagrange_digest: None,
                secret_key: None,
            }
        }

        pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            println!(
                "🌐 Party {}: Connecting to coordinator at {}",
                self.id, self.coordinator_addr
            );

            // Create TLS client configuration with optional certificate pinning
            let tls_config = if let Some(cert_path) = &self.server_cert_path {
                println!(
                    "🔐 Party {}: Using pinned server certificate {}",
                    self.id, cert_path
                );
                let certs = tls_config::load_certs(cert_path)?;
                tls_config::create_client_config_with_roots(certs).map_err(|e| {
                    format!(
                        "Failed to initialize pinned certificate store ({}). \
Use the CA certificate that signed the coordinator's TLS certificate.",
                        e
                    )
                })?
            } else {
                if !self.allow_insecure {
                    return Err("Server certificate path missing. Provide --server-cert or use --allow-insecure for development".into());
                }
                println!(
                    "⚠️ Party {}: WARNING - running without server certificate verification",
                    self.id
                );
                tls_config::create_client_config_dev()?
            };
            let connector = TlsConnector::from(tls_config);

            // Connect via TCP
            let tcp_stream = TcpStream::connect(&self.coordinator_addr).await?;
            println!("🔌 Party {}: TCP connected to coordinator", self.id);

            // Perform TLS handshake
            let server_name = rustls::pki_types::ServerName::try_from("localhost")
                .map_err(|_| "Invalid DNS name")?;
            let mut stream = connector.connect(server_name, tcp_stream).await?;
            println!("✓ Party {}: TLS connection established", self.id);

            // Send ready message
            let ready_msg = PartyMessage::Ready { party_id: self.id };
            self.send_message(&mut stream, &ready_msg).await?;

            // Main message loop
            loop {
                let msg = self.receive_message(&mut stream).await?;

                match msg {
                    CoordinatorMessage::RequestPublicKey {
                        party_id,
                        lagrange_bytes,
                        lagrange_hash,
                        n,
                        challenge,
                    } => {
                        if party_id != self.id {
                            continue;
                        }
                        println!("\n📨 Party {}: Received request for public key", self.id);
                        self.handle_public_key_request(
                            &mut stream,
                            &lagrange_bytes,
                            lagrange_hash,
                            n,
                            challenge,
                        )
                        .await?;
                    }
                    CoordinatorMessage::RequestPartialDecryption {
                        party_id,
                        ct_bytes,
                        request_id,
                    } => {
                        if party_id != self.id {
                            continue;
                        }
                        println!(
                            "\n📨 Party {}: Received request for partial decryption",
                            self.id
                        );
                        self.handle_partial_decryption_request(&mut stream, &ct_bytes, request_id)
                            .await?;
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
            stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
            lagrange_bytes: &[u8],
            lagrange_hash: [u8; 32],
            n: usize,
            challenge: [u8; 32],
        ) -> Result<(), Box<dyn std::error::Error>> {
            // Obtain Lagrange parameters from cache or deserialize once
            let lagrange_params = if let Some((cached_hash, params)) = &self.lagrange_cache {
                if cached_hash == &lagrange_hash {
                    params.clone()
                } else {
                    self.load_lagrange_params(lagrange_bytes, lagrange_hash)?
                }
            } else {
                self.load_lagrange_params(lagrange_bytes, lagrange_hash)?
            };

            // Generate secret key
            let mut rng = SecureRng::new();
            let mut sk = SecretKey::<E>::new(&mut rng);

            // Party 0 is the dummy party
            if self.id == 0 {
                sk.nullify();
                println!(
                    "🔑 Party {}: Generated nullified secret key (dummy party)",
                    self.id
                );
            } else {
                println!("🔑 Party {}: Generated secret key", self.id);
            }

            // Compute public key using provided Lagrange parameters
            let pk = sk.lagrange_get_pk(self.id, lagrange_params.as_ref(), n)?;

            // Serialize and send public key
            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes)?;

            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(b"ste-pk-pop-v1");
            payload.extend_from_slice(&self.id.to_le_bytes());
            payload.extend_from_slice(&challenge);
            let message = bls_message_from_payload(&payload);
            let pop_sig = sk.sign_g2(&message);
            let mut pop_sig_bytes = Vec::new();
            pop_sig.serialize_compressed(&mut pop_sig_bytes)?;

            // Store secret key for later
            self.secret_key = Some(sk);

            let response = PartyMessage::PublicKey {
                party_id: self.id,
                pk_bytes,
                pop_sig: pop_sig_bytes,
            };

            self.send_message(stream, &response).await?;
            println!("✓ Party {}: Sent public key to coordinator", self.id);

            Ok(())
        }

        async fn handle_partial_decryption_request(
            &mut self,
            stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
            ct_bytes: &[u8],
            request_id: [u8; 32],
        ) -> Result<(), Box<dyn std::error::Error>> {
            // Deserialize ciphertext
            let ct = Ciphertext::<E>::deserialize_compressed(ct_bytes)?;

            // Compute partial decryption
            let sk = self
                .secret_key
                .as_ref()
                .ok_or("Secret key not initialized")?;
            let pd = sk.partial_decryption(&ct);

            // Serialize and send partial decryption
            let mut pd_bytes = Vec::new();
            pd.serialize_compressed(&mut pd_bytes)?;

            let ct_hash = hash_bytes(ct_bytes);
            let mut payload = Vec::with_capacity(96);
            payload.extend_from_slice(b"ste-pd-v1");
            payload.extend_from_slice(&self.id.to_le_bytes());
            payload.extend_from_slice(&request_id);
            payload.extend_from_slice(&ct_hash);
            let message = bls_message_from_payload(&payload);
            let signature = sk.sign_g2(&message);
            let mut signature_bytes = Vec::new();
            signature.serialize_compressed(&mut signature_bytes)?;

            let response = PartyMessage::PartialDecryption {
                party_id: self.id,
                pd_bytes,
                request_id,
                signature: signature_bytes,
            };

            self.send_message(stream, &response).await?;
            println!(
                "✓ Party {}: Sent partial decryption to coordinator",
                self.id
            );

            Ok(())
        }

        fn load_lagrange_params(
            &mut self,
            bytes: &[u8],
            expected_hash: [u8; 32],
        ) -> Result<Arc<LagrangePowers<E>>, Box<dyn std::error::Error>> {
            if bytes.is_empty() {
                return Err("Missing Lagrange parameters payload".into());
            }
            let digest_vec = Blake2b512::digest(bytes);
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&digest_vec[..32]);
            if self
                .bad_lagrange_digest
                .as_ref()
                .map_or(false, |bad| bad == &digest)
            {
                return Err("Lagrange parameters previously rejected".into());
            }
            if digest != expected_hash {
                self.bad_lagrange_digest = Some(digest);
                return Err("Lagrange parameters hash mismatch".into());
            }
            let params = LagrangePowers::<E>::deserialize_compressed(bytes)
                .map_err(|e| {
                    self.bad_lagrange_digest = Some(digest);
                    e
                })?;
            let arc = Arc::new(params);
            self.lagrange_cache = Some((expected_hash, arc.clone()));
            self.bad_lagrange_digest = None;
            Ok(arc)
        }

        async fn send_message(
            &self,
            stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
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
            stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
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
            /// Path to PEM-encoded certificate
            #[arg(long)]
            cert: Option<String>,
            /// Path to PEM-encoded private key
            #[arg(long)]
            key: Option<String>,
        },
        /// Run as party client
        Party {
            /// Party ID (0 to n-1)
            #[arg(short, long)]
            id: usize,
            /// Coordinator address (e.g., localhost:8080)
            #[arg(short, long)]
            coordinator: String,
            /// Path to trusted coordinator certificate (PEM). Required unless --allow-insecure is used.
            #[arg(long)]
            server_cert: Option<String>,
            /// Allow running without certificate verification (development only)
            #[arg(long, default_value_t = false)]
            allow_insecure: bool,
        },
    }

    pub async fn main_async() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::parse();

        match cli.command {
            Commands::Coordinator {
                port,
                parties,
                threshold,
                cert,
                key,
            } => {
                let mut coordinator = Coordinator::new(port, parties, threshold, cert, key)?;
                coordinator.run().await?;
            }
            Commands::Party {
                id,
                coordinator,
                server_cert,
                allow_insecure,
            } => {
                let mut party = Party::new(id, coordinator, server_cert, allow_insecure);
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
