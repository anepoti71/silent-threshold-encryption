# Silent Threshold Encryption

Rust implementation of silent threshold encryption from [ePrint:2024/263](https://eprint.iacr.org/2024/263).

## Features

- **Silent Threshold Encryption**: Encrypt to n parties, decrypt with t+1 collaborators
- **TLS 1.3 Protection**: Secure network communication for distributed protocol
- **Memory Safety**: Automatic zeroization of cryptographic secrets
- **Constant-Time Operations**: Timing attack resistance for sensitive operations
- **Enhanced Error Handling**: Comprehensive error types with `thiserror`

## P2P Networking Stack

Fully decentralized deployments can build on the dedicated peer-to-peer stack under `src/p2p/`:

- `p2p::network` wires discovery, gossip and TCP transport into a reusable `P2PNetwork`
- `p2p::libp2p_network` provides an alternative transport backed by `rust-libp2p` (Noise + Gossipsub + mDNS)
- `p2p::transport` exposes authenticated stream management plus message framing
- `p2p::discovery` maintains peer metadata, bootstrap seeds and party-to-peer mapping
- `p2p::gossip` handles message deduplication and fanout-based propagation

The previous `src/network` scaffolding has been removed to avoid duplicating these responsibilities.

### Shared parameter artifacts

Sample parameters for a 4-party deployment live in `artifacts/p2p/` (`kzg_params.bin` and `lagrange_params.bin`). The `p2p_peer` binary defaults to those paths, so you can immediately launch peers without a separate setup step. To regenerate or create parameters for a different party count, run:

```bash
cargo run --bin generate_peer_params --features distributed --release -- --parties 8 --seed 123 --output-dir artifacts/p2p
```

Point `p2p_peer --kzg-params` and `--lagrange-params` at the generated files when booting your network.

## Quick Start

### Run Demo (4 parties, threshold 2)

```bash
./test_distributed_simple.sh
```

### Manual Usage

**Build:**
```bash
cargo build --bin distributed_protocol --features distributed --release
```

**Start Coordinator:**
```bash
./target/release/distributed_protocol coordinator \
    --port 8080 \
    --parties 4 \
    --threshold 2 \
    --cert ./coordinator_cert.pem \
    --key  ./coordinator_key.pem
```

**Start Parties (4 terminals):**
```bash
./target/release/distributed_protocol party --id 0 --coordinator localhost:8080 --server-cert ./coordinator_cert.pem
./target/release/distributed_protocol party --id 1 --coordinator localhost:8080 --server-cert ./coordinator_cert.pem
./target/release/distributed_protocol party --id 2 --coordinator localhost:8080 --server-cert ./coordinator_cert.pem
./target/release/distributed_protocol party --id 3 --coordinator localhost:8080 --server-cert ./coordinator_cert.pem
```

## Library Usage

```rust
use silent_threshold_encryption::*;
use ark_bls12_381::Bls12_381 as E;
use ark_std::rand::rngs::OsRng;

let mut rng = OsRng;
let n = 4;  // Total parties
let t = 2;  // Threshold (need t+1 to decrypt)

// Setup
let tau = Fr::rand(&mut rng);
let params = KZG10::setup(n, &tau)?;
let lagrange_params = LagrangePowers::new(tau, n)?;

// Generate keys
let sk: Vec<SecretKey<E>> = (0..n).map(|_| SecretKey::new(&mut rng)).collect();
let pk: Vec<PublicKey<E>> = sk.iter()
    .enumerate()
    .map(|(i, sk)| sk.get_pk(&lagrange_params, i, n))
    .collect::<Result<Vec<_>, _>>()?;

let agg_key = AggregateKey::new(pk, &lagrange_params, n)?;

// Encrypt
let message = Fr::rand(&mut rng);
let ct = encrypt(&message, &agg_key, &params, &mut rng)?;

// Decrypt (with t+1 parties)
let mut partial_decs = vec![G2::zero(); n];
let mut selector = vec![false; n];
for i in 0..=t {
    selector[i] = true;
    partial_decs[i] = sk[i].partial_decryption(&ct);
}

let recovered = agg_dec(&partial_decs, &ct, &selector, &agg_key, &params)?;
assert_eq!(message, recovered);
```

## Security Features

### Memory Protection

- **`SensitiveScalar<F>`**: Auto-zeroizing wrapper for secrets
- **`SecretKey` Zeroization**: Volatile writes prevent compiler optimization
- **Debug Redaction**: Sensitive types hide values in debug output

```rust
use silent_threshold_encryption::security::SensitiveScalar;

let tau = SensitiveScalar::new(Fr::rand(&mut rng));
// Automatically zeroized when dropped
```

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

### Enhanced Error Handling

```rust
use silent_threshold_encryption::SteError;

match operation() {
    Err(SteError::InvalidThreshold(msg)) => // Handle threshold error
    Err(SteError::DecryptionFailure(msg)) => // Handle decryption error
    Err(SteError::NetworkError(msg)) => // Handle network error
    Ok(result) => // Success
}
```

## Building & Testing

```bash
# Run tests
cargo test

# Run benchmarks
cargo bench

# Build library
cargo build --release

# Build distributed protocol
cargo build --features distributed --release
```

## TLS 1.3 Security

The distributed protocol uses TLS 1.3 for encrypted communication:

- **Certificate pinning**: Parties can (and by default must) trust a specific coordinator certificate via `--server-cert`
- **Auto-generated certificates** remain available for local experiments (combine with `--allow-insecure` on parties)
- **Forward secrecy** with X25519/P-256
- **Modern ciphers**: AES-GCM, ChaCha20-Poly1305
- **Production-ready** certificate loading

All cryptographic material (keys, ciphertexts, partial decryptions) is encrypted in transit. For development-only scenarios you can bypass verification with `--allow-insecure`, but this is not recommended.

## Project Structure

```
src/
├── setup.rs              # Key generation & aggregation
├── encryption.rs         # Silent threshold encryption
├── decryption.rs         # Partial decryption aggregation
├── security.rs           # Memory protection & constant-time ops
├── error.rs              # Error types with thiserror
├── kzg.rs                # KZG commitments
├── trusted_setup.rs      # Multi-party ceremony
└── bin/
    └── distributed_protocol.rs  # TLS-enabled distributed protocol
```

## Security Considerations

⚠️ **This is an academic proof-of-concept**

Before production use:
1. **Security audit required** - Not formally audited
2. **Trusted setup** - Use multi-party ceremony (see `trusted_setup` module)
3. **TLS certificates** - Use CA-signed certificates for production
4. **RNG**: Always use `OsRng`, never `test_rng()`

### Trusted Setup Example

```rust
use silent_threshold_encryption::trusted_setup::Ceremony;

// Initialize ceremony
let mut ceremony = Ceremony::<E>::new(max_degree, &mut rng)?;

// Each participant contributes
ceremony.contribute(&mut participant_rng)?;

// Verify contributions
for i in 1..ceremony.num_participants() {
    assert!(ceremony.verify_contribution(i));
}

// Finalize
let params = ceremony.finalize()?;
```

## WebAssembly Client

Browser-based party implementation available in `wasm-client/`:

```bash
cd wasm-client
wasm-pack build --target web --release
# Open distributed_party.html in browser
```

## Examples

**Small committee (4 parties, need 3):**
```bash
./target/release/distributed_protocol coordinator --parties 4 --threshold 2
```

**Board of directors (8 parties, need majority):**
```bash
./target/release/distributed_protocol coordinator --parties 8 --threshold 4
```

**Large organization (16 parties, high threshold):**
```bash
./target/release/distributed_protocol coordinator --parties 16 --threshold 10
```

## References

- Paper: [ePrint:2024/263](https://eprint.iacr.org/2024/263)
- rustls: [https://docs.rs/rustls/](https://docs.rs/rustls/)
- TLS 1.3: [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)

## License

MIT License
