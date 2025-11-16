# Distributed Silent Threshold Encryption Example

This example demonstrates a complete distributed implementation of the silent threshold encryption scheme with a coordinator server and multiple party clients communicating over TCP.

## Architecture

```
┌────────────────────────┐
│   Coordinator Server   │
│  (Orchestrates protocol)│
│  - Generates KZG params │
│  - Computes agg key     │
│  - Encrypts messages    │
│  - Aggregates decryptions│
└───────────┬────────────┘
            │
    ┌───────┴───────┬───────────┬───────────┐
    │               │           │           │
┌───▼────┐    ┌────▼───┐  ┌────▼───┐  ┌────▼───┐
│ Party 0│    │ Party 1│  │ Party 2│  │ Party n│
│(Dummy) │    │        │  │        │  │  ...   │
└────────┘    └────────┘  └────────┘  └────────┘
  (TCP Clients - Generate keys & partial decryptions)
```

## Protocol Flow

### Phase 1: Setup & Key Generation

1. **Coordinator**:
   - Generates `tau` (random field element)
   - Creates KZG parameters: `setup(n, tau)`
   - Preprocesses Lagrange powers
   - Waits for `n` parties to connect

2. **Parties**:
   - Connect to coordinator via TCP
   - Wait for public key generation request

3. **Key Exchange**:
   - Coordinator sends `tau` and `n` to each party
   - Each party generates `(sk_i, pk_i)` key pair
   - Party 0 nullifies their secret key (dummy party)
   - Parties send `pk_i` back to coordinator

4. **Aggregation**:
   - Coordinator collects all public keys
   - Computes aggregate key: `AggregateKey::new([pk_0, ..., pk_{n-1}])`

### Phase 2: Encryption

1. **Coordinator**:
   - Encrypts a message: `encrypt(agg_key, t, params)`
   - Generates ciphertext `ct`

### Phase 3: Decryption

1. **Party Selection**:
   - Coordinator selects `t+1` parties (including party 0)
   - Sends ciphertext to selected parties

2. **Partial Decryptions**:
   - Each selected party computes: `partial_dec = sk_i * ct.gamma_g2`
   - Parties send partial decryptions to coordinator

3. **Aggregation**:
   - Coordinator aggregates: `agg_dec(partial_decryptions, ct, selector, agg_key)`
   - Recovers the decryption key

4. **Verification**:
   - Coordinator verifies: `decrypted_key == ct.enc_key`

## Building

Build with the `distributed` feature enabled:

```bash
cargo build --example distributed_protocol --features distributed --release
```

## Running

### Method 1: Using Cargo (Development)

**Terminal 1 - Start Coordinator:**
```bash
cargo run --example distributed_protocol --features distributed -- \
  coordinator --port 8080 --parties 4 --threshold 2
```

**Terminals 2-5 - Start Parties:**
```bash
# Terminal 2
cargo run --example distributed_protocol --features distributed -- \
  party --id 0 --coordinator localhost:8080

# Terminal 3
cargo run --example distributed_protocol --features distributed -- \
  party --id 1 --coordinator localhost:8080

# Terminal 4
cargo run --example distributed_protocol --features distributed -- \
  party --id 2 --coordinator localhost:8080

# Terminal 5
cargo run --example distributed_protocol --features distributed -- \
  party --id 3 --coordinator localhost:8080
```

### Method 2: Using Binary (Production)

First, build the binary:
```bash
cargo build --example distributed_protocol --features distributed --release
```

Then run (replace paths as needed):

**Coordinator:**
```bash
./target/release/examples/distributed_protocol coordinator \
  --port 8080 --parties 8 --threshold 5
```

**Parties (run in separate terminals):**
```bash
./target/release/examples/distributed_protocol party --id 0 --coordinator localhost:8080
./target/release/examples/distributed_protocol party --id 1 --coordinator localhost:8080
# ... continue for all n parties
```

## Command-Line Options

### Coordinator

```bash
distributed_protocol coordinator [OPTIONS]

Options:
  -p, --port <PORT>           Port to listen on [default: 8080]
  -n, --parties <PARTIES>     Number of parties [default: 4]
  -t, --threshold <THRESHOLD> Threshold value (requires t+1 parties) [default: 2]
  -h, --help                  Print help
```

### Party

```bash
distributed_protocol party [OPTIONS]

Options:
  -i, --id <ID>                    Party ID (0 to n-1)
  -c, --coordinator <COORDINATOR>  Coordinator address (e.g., localhost:8080)
  -h, --help                       Print help
```

## Example Output

### Coordinator Output

```
🔧 Coordinator: Initializing with n=4, t=2
🔧 Coordinator: Setting up KZG parameters...
🔧 Coordinator: Preprocessing Lagrange powers...
✓ Coordinator: Setup complete
🌐 Coordinator: Listening on 127.0.0.1:8080
⏳ Coordinator: Waiting for 4 parties to connect...
✓ Coordinator: Party 0 connected from 127.0.0.1:xxxxx
✓ Coordinator: Party 1 connected from 127.0.0.1:xxxxx
✓ Coordinator: Party 2 connected from 127.0.0.1:xxxxx
✓ Coordinator: Party 3 connected from 127.0.0.1:xxxxx

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 1: Key Generation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Coordinator: Received public key from party 0
✓ Coordinator: Received public key from party 1
✓ Coordinator: Received public key from party 2
✓ Coordinator: Received public key from party 3

🔧 Coordinator: Computing aggregate key...
✓ Coordinator: Aggregate key computed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 2: Encryption
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 Coordinator: Encrypting message with threshold t=2...
✓ Coordinator: Ciphertext generated

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 3: Decryption
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Coordinator: Selected 3 parties for decryption: [0, 1, 2]
✓ Coordinator: Received partial decryption from party 0
✓ Coordinator: Received partial decryption from party 1
✓ Coordinator: Received partial decryption from party 2

🔓 Coordinator: Aggregating partial decryptions...
✓ Coordinator: Decryption complete

✅ SUCCESS: Decryption successful! Keys match.
```

### Party Output

```
🎭 Party 1: Initializing
🌐 Party 1: Connecting to coordinator at localhost:8080
✓ Party 1: Connected to coordinator

📨 Party 1: Received request for public key
🔑 Party 1: Generated secret key
✓ Party 1: Sent public key to coordinator

📨 Party 1: Received request for partial decryption
✓ Party 1: Sent partial decryption to coordinator

✅ Party 1: Protocol completed successfully
```

## Network Protocol

### Message Format

All messages use length-prefixed binary encoding:

```
┌─────────────┬────────────────────┐
│ Length (u32)│  Bincode Payload   │
│  4 bytes    │  Variable length   │
└─────────────┴────────────────────┘
```

### Message Types

#### Coordinator → Party

```rust
enum CoordinatorMessage {
    RequestPublicKey {
        party_id: usize,
        tau_bytes: Vec<u8>,  // Serialized Fr
        n: usize,
    },
    RequestPartialDecryption {
        party_id: usize,
        ct_bytes: Vec<u8>,   // Serialized Ciphertext
    },
    Success { message: String },
    Error { message: String },
}
```

#### Party → Coordinator

```rust
enum PartyMessage {
    Ready {
        party_id: usize,
    },
    PublicKey {
        party_id: usize,
        pk_bytes: Vec<u8>,   // Serialized PublicKey
    },
    PartialDecryption {
        party_id: usize,
        pd_bytes: Vec<u8>,   // Serialized G2
    },
    Error {
        party_id: usize,
        message: String,
    },
}
```

## Configuration Examples

### Small Setup (Testing)
```bash
# 4 parties, threshold 2 (need 3 to decrypt)
coordinator --parties 4 --threshold 2
```

### Medium Setup
```bash
# 16 parties, threshold 10 (need 11 to decrypt)
coordinator --parties 16 --threshold 10
```

### Large Setup (Performance Testing)
```bash
# 256 parties, threshold 128 (need 129 to decrypt)
coordinator --parties 256 --threshold 128
```

Note: `n` must be a power of 2 for the FFT-based polynomial operations.

## Performance Considerations

### Computation Times (2019 MacBook Pro, 2.4 GHz i9)

| n (parties) | KZG Setup | Lagrange Preprocess | Key Gen (per party) | Encrypt | Decrypt |
|-------------|-----------|---------------------|---------------------|---------|---------|
| 8           | ~10ms     | ~50ms              | ~2ms                | ~5ms    | ~20ms   |
| 16          | ~20ms     | ~150ms             | ~3ms                | ~5ms    | ~40ms   |
| 256         | ~300ms    | ~5s                | ~15ms               | ~10ms   | ~500ms  |
| 1024        | ~1.5s     | ~12s               | ~50ms               | ~15ms   | ~2s     |

### Network Overhead

- **Message Sizes** (compressed):
  - Public Key: ~500 bytes
  - Ciphertext: ~2 KB
  - Partial Decryption: ~200 bytes

- **Total Network Traffic** (n=16, t=10):
  - Setup Phase: ~8 KB (16 public keys)
  - Decryption Phase: ~2.2 KB (11 partial decryptions)
  - **Total**: ~10 KB

## Security Considerations

### Network Security

⚠️ **This example uses unencrypted TCP connections for demonstration purposes.**

For production use, you MUST:

1. **Use TLS/SSL**: Encrypt all network communication
   ```rust
   use tokio_rustls::TlsAcceptor;
   // Configure TLS for all connections
   ```

2. **Authenticate Parties**: Verify party identities
   - Use certificates
   - Implement challenge-response authentication
   - Verify party IDs match expected values

3. **Validate Messages**: Check message integrity
   - Use HMAC or digital signatures
   - Verify all serialized data before deserialization
   - Implement replay protection with nonces

4. **Rate Limiting**: Prevent DoS attacks
   - Limit connection attempts per IP
   - Implement timeouts for slow clients
   - Validate message sizes before allocation

### Trusted Setup

⚠️ **The coordinator generates `tau` and KZG parameters.**

In production:

1. Use a **distributed trusted setup ceremony** (e.g., Powers of Tau)
2. **Never** let a single party generate `tau`
3. Verify KZG parameters against known-good values
4. Consider using publicly available trusted setups

### Key Management

- Store secret keys securely (use HSMs in production)
- Never log or transmit secret keys
- Implement key rotation policies
- Zeroize keys in memory after use

## Troubleshooting

### "Connection refused"

**Problem**: Parties can't connect to coordinator

**Solutions**:
1. Ensure coordinator is running first
2. Check firewall settings
3. Verify correct port and address
4. Try `127.0.0.1` instead of `localhost`

### "Unexpected message"

**Problem**: Protocol message order mismatch

**Solutions**:
1. Ensure all parties have the same party ID
2. Check for duplicate party IDs
3. Verify `n` matches across coordinator and all parties
4. Restart all processes

### "Decryption failed"

**Problem**: Decrypted key doesn't match encrypted key

**Possible Causes**:
1. Incorrect tau value used by some party
2. Not enough parties participated (< t+1)
3. Party used wrong party_id when generating public key
4. Network corruption of serialized data

**Solutions**:
1. Verify all parties receive same `tau` from coordinator
2. Check `selector` has exactly `t+1` true values
3. Add logging to track party IDs
4. Implement message checksums

### Performance Issues

**Problem**: Protocol is too slow

**Solutions**:
1. Reduce `n` (number of parties)
2. Enable parallel feature: `--features "distributed,parallel"`
3. Use release build: `--release`
4. Run on faster hardware
5. Reduce network latency (use localhost for testing)

## Extending the Example

### Adding Authentication

```rust
use tokio_rustls::TlsAcceptor;

// In coordinator
let tls_config = load_tls_config()?;
let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
let tls_stream = tls_acceptor.accept(tcp_stream).await?;
```

### Adding Persistent Storage

```rust
use serde_json;

// Save party state
let state = PartyState {
    id: self.id,
    secret_key: self.secret_key.clone(),
};
fs::write("party_state.json", serde_json::to_string(&state)?)?;
```

### Adding Multiple Encryption Rounds

Modify the coordinator to:
1. Maintain party connections
2. Support multiple `encrypt()` -> `decrypt()` cycles
3. Implement message routing for concurrent operations

## References

- [Silent Threshold Encryption Paper (ePrint:2024/263)](https://eprint.iacr.org/2024/263)
- [BLS12-381 Curve](https://hackmd.io/@benjaminion/bls12-381)
- [KZG Polynomial Commitments](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html)
- [Tokio Async Runtime](https://tokio.rs/)

## License

MIT License - Same as the main library
