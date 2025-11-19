# Silent Threshold Encryption

Rust implementation of silent threshold encryption from [ePrint:2024/263](https://eprint.iacr.org/2024/263).

## Overview

**Silent Threshold Encryption** allows encrypting to `n` parties where any `t+1` collaborators can decrypt without revealing their secret keys. This implementation provides two deployment architectures:

1. **Coordinator-Based** - Central server coordinates parties (simpler, single point of trust)
2. **Peer-to-Peer** - Fully decentralized with gossip protocol (more resilient, no central authority)

## Features

- **Flexible Party Counts**: Support for arbitrary n ≥ 2 (not just powers of 2)
- **Dynamic Quorum**: P2P mode builds aggregate key when minimum quorum (t+1) is reached
- **TLS 1.3 Protection**: Secure network communication (coordinator mode)
- **Ed25519 Authentication**: Message signing and verification (P2P mode)
- **Memory Safety**: Automatic zeroization of cryptographic secrets
- **Constant-Time Operations**: Timing attack resistance for sensitive operations

---

## Architecture Comparison

### Coordinator-Based Solution

**Architecture**: Star topology with central coordinator

```
    ┌─────────────┐
    │ Coordinator │
    └──────┬──────┘
       ┌───┼───┬────┐
       │   │   │    │
    Party0 Party1 Party2 Party3
```

#### ✅ Pros
- **Simple setup** - Single coordinator manages all communication
- **Reliable** - Direct TCP connections, no mesh formation delays
- **Easy testing** - Automated test scripts work perfectly
- **TLS 1.3** - Enterprise-grade transport security
- **Certificate pinning** - Verify coordinator identity

#### ❌ Cons
- **Central authority** - Coordinator is a single point of trust
- **Single point of failure** - If coordinator crashes, protocol halts
- **Network bottleneck** - All messages route through coordinator
- **Coordination required** - Must deploy and maintain coordinator

#### Quick Start

```bash
# Run automated test (4 parties, threshold 2)
./test_distributed_simple.sh

# Or manually:
cargo build --bin distributed_protocol --features distributed --release

# Start coordinator
./target/release/distributed_protocol coordinator \
    --port 8080 \
    --parties 4 \
    --threshold 2

# Start parties (in separate terminals)
./target/release/distributed_protocol party --id 0 --coordinator localhost:8080
./target/release/distributed_protocol party --id 1 --coordinator localhost:8080
./target/release/distributed_protocol party --id 2 --coordinator localhost:8080
./target/release/distributed_protocol party --id 3 --coordinator localhost:8080
```

---

### Peer-to-Peer Solution

**Architecture**: Fully decentralized mesh network

```
    Party0 ━━━━━━━━━ Party1
      ┃   ╲       ╱   ┃
      ┃     ╲   ╱     ┃
      ┃       ╳       ┃
      ┃     ╱   ╲     ┃
      ┃   ╱       ╲   ┃
    Party2 ━━━━━━━━━ Party3
```

#### ✅ Pros
- **No central authority** - Fully decentralized, no coordinator needed
- **Resilient** - No single point of failure
- **Auto-discovery** - mDNS finds peers on local networks
- **Cryptographic auth** - Ed25519 signatures prevent spoofing
- **Dynamic membership** - Supports quorum-based operation
- **Scalable** - Gossip protocol handles arbitrary peer counts

#### ❌ Cons
- **Complex setup** - Must configure bootstrap nodes for cross-network
- **Gossip delays** - 10-15 second mesh formation time
- **Manual testing** - Automated scripts unreliable due to timing
- **Network overhead** - More messages due to gossip propagation
- **Firewall complexity** - Peers must accept incoming connections

#### Quick Start

**Step 1**: Generate shared parameters
```bash
cargo build --bin p2p_peer --bin generate_peer_params --features distributed --release

./target/release/generate_peer_params \
    --parties 4 \
    --seed 42 \
    --output-dir artifacts/p2p
```

**Step 2**: Launch peers (4 separate terminals)

```bash
# Terminal 1: Party 0 (Initiator)
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 0 --parties 4 --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9000 \
    --mode initiator --auto-decrypt

# Terminal 2: Party 1
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 1 --parties 4 --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9001

# Terminal 3: Party 2
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 2 --parties 4 --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9002

# Terminal 4: Party 3
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 3 --parties 4 --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9003
```

**Expected Flow** (10-15 seconds):
1. Peers discover each other via mDNS
2. Ed25519-signed public keys exchanged
3. Aggregate key constructed
4. Party 0 encrypts message
5. Parties 0-2 provide signed partial decryptions
6. Party 0 recovers plaintext

---

## Which Architecture to Use?

| Use Case | Recommended |
|----------|-------------|
| Development/testing | **Coordinator** - simpler, faster |
| Trusted environment | **Coordinator** - less overhead |
| Production with available infrastructure | **Coordinator** - easier ops |
| Highly adversarial environment | **P2P** - no central trust point |
| Censorship resistance required | **P2P** - no single point of failure |
| Cross-organizational deployment | **P2P** - no neutral coordinator |
| Dynamic/mobile participants | **P2P** - auto-discovery |

---

## Library Usage

Both architectures use the same cryptographic primitives:

```rust
use silent_threshold_encryption::*;
use ark_bls12_381::Bls12_381 as E;
use ark_std::rand::rngs::OsRng;

let mut rng = OsRng;
let n = 5;  // Total parties (any n ≥ 2)
let t = 2;  // Threshold (need t+1 to decrypt)

// Setup
let tau = <E as Pairing>::ScalarField::rand(&mut rng);
let params = KZG10::setup(n, tau)?;
let lagrange_params = LagrangePowers::new(tau, n)?;

// Generate keys
let sk: Vec<SecretKey<E>> = (0..n).map(|_| SecretKey::new(&mut rng)).collect();
let pk: Vec<PublicKey<E>> = sk.iter()
    .enumerate()
    .map(|(i, sk)| sk.lagrange_get_pk(i, &lagrange_params, n))
    .collect::<Result<Vec<_>, _>>()?;

let agg_key = AggregateKey::new(pk, &params)?;

// Encrypt
let message = <E as Pairing>::ScalarField::rand(&mut rng);
let ct = encrypt(&agg_key, t, &params, &mut rng)?;

// Decrypt (with t+1 parties)
let mut partial_decs = vec![<E as Pairing>::G2::zero(); n];
let mut selector = vec![false; n];
for i in 0..=t {
    selector[i] = true;
    partial_decs[i] = sk[i].partial_decryption(&ct);
}

let recovered = agg_dec(&partial_decs, &ct, &selector, &agg_key, &params)?;
assert_eq!(message, recovered);
```

---

## Security Features

### Memory Protection
- **`SensitiveScalar<F>`**: Auto-zeroizing wrapper for secrets
- **`SecretKey` Zeroization**: Volatile writes prevent compiler optimization
- **Debug Redaction**: Sensitive types hide values in debug output

### Constant-Time Operations
```rust
use silent_threshold_encryption::security::*;

// Constant-time comparisons
constant_time_eq(&a, &b);           // Field elements
constant_time_eq_g1::<E>(&p1, &p2); // G1 elements
constant_time_eq_g2::<E>(&q1, &q2); // G2 elements

// Constant-time BLS signature verification
verify_bls_signature_ct::<E>(&sig, &pk, &msg);
```

### Network Security

**Coordinator Mode**:
- TLS 1.3 with modern ciphers (AES-GCM, ChaCha20-Poly1305)
- Certificate pinning via `--server-cert`
- Forward secrecy with X25519/P-256

**P2P Mode**:
- Ed25519 signature verification on all critical messages
- Libp2p Noise protocol for transport encryption
- Message authentication prevents spoofing attacks

---

## Building & Testing

```bash
# Run unit tests
cargo test

# Run benchmarks
cargo bench

# Build library only
cargo build --release

# Build distributed binaries
cargo build --features distributed --release

# Test coordinator mode (automated)
./test_distributed_simple.sh

# Test P2P mode (manual - see Quick Start above)
```

---

## Advanced Configuration

### Custom Party Counts

Both architectures support arbitrary n ≥ 2:

```bash
# Generate parameters for 7 parties
./target/release/generate_peer_params --parties 7 --seed 123 --output-dir artifacts/p2p

# Coordinator mode: 7 parties, threshold 4
./target/release/distributed_protocol coordinator --parties 7 --threshold 4

# P2P mode: 7 parties, threshold 4
./target/release/p2p_peer --party-id 0 --parties 7 --threshold 4 ...
```

### P2P Bootstrap Nodes

For cross-network deployments:

```bash
# Party 0 (bootstrap node)
./target/release/p2p_peer --party-id 0 --parties 4 --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9000

# Party 1 (connects to Party 0)
./target/release/p2p_peer --party-id 1 --parties 4 --threshold 2 \
    --bootstrap /ip4/192.168.0.100/tcp/9000/p2p/12D3KooW...
```

### Coordinator TLS Certificates

Production deployments should use CA-signed certificates:

```bash
./target/release/distributed_protocol coordinator \
    --cert /path/to/cert.pem \
    --key /path/to/key.pem

./target/release/distributed_protocol party \
    --server-cert /path/to/ca-cert.pem \
    --coordinator coordinator.example.com:8080
```

---

## Project Structure

```
src/
├── lib.rs               # Public API
├── setup.rs             # Key generation & aggregation
├── encryption.rs        # Silent threshold encryption
├── decryption.rs        # Partial decryption aggregation
├── security.rs          # Memory protection & constant-time ops
├── error.rs             # Error types
├── kzg.rs               # KZG commitments
├── trusted_setup.rs     # Multi-party ceremony
├── utils.rs             # Lagrange polynomial utilities
└── bin/
    ├── distributed_protocol.rs  # Coordinator-based protocol
    ├── p2p_peer.rs              # P2P protocol peer
    └── generate_peer_params.rs  # Parameter generation utility
```

---

## Security Considerations

⚠️ **This is an academic proof-of-concept**

Before production use:
1. **Security audit required** - Code has not been formally audited
2. **Trusted setup** - Use multi-party ceremony for tau generation
3. **Certificates** - Use CA-signed certificates in coordinator mode
4. **RNG** - Always use `OsRng`, never `test_rng()`
5. **Key management** - Secure storage for secret keys
6. **Network security** - Use TLS/Noise for all communications

### Trusted Setup Example

```rust
use silent_threshold_encryption::trusted_setup::Ceremony;

// Initialize ceremony
let mut ceremony = Ceremony::<E>::new(max_degree, &mut rng)?;

// Each participant contributes randomness
ceremony.contribute(&mut participant_rng)?;

// Verify all contributions
for i in 1..ceremony.num_participants() {
    assert!(ceremony.verify_contribution(i));
}

// Finalize to get parameters
let params = ceremony.finalize()?;
```

---

## Performance

### Party Count Flexibility

- **Power-of-2 counts** (2, 4, 8, 16, ...): O(n log n) via FFT
- **Arbitrary counts** (3, 5, 7, 9, ...): O(n²) via naive interpolation
- Still very fast for small n (< 100 parties)

### Benchmarks

Run `cargo bench` to measure performance on your hardware.

---

## References

- **Paper**: [ePrint:2024/263](https://eprint.iacr.org/2024/263) - Silent Threshold Encryption
- **TLS 1.3**: [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- **Libp2p**: [https://libp2p.io/](https://libp2p.io/) - Modular P2P networking
- **Noise Protocol**: [http://noiseprotocol.org/](http://noiseprotocol.org/)

---

## License

MIT License
