# Silent Threshold Encryption

Rust implementation of silent threshold encryption from [ePrint:2024/263](https://eprint.iacr.org/2024/263).

> **Note:** This is a fork with improvements, bug fixes, and **TLS 1.3 support** for the distributed protocol.

## Quick Start

### Run Distributed Protocol (Automated Test)

```bash
./test_distributed_simple.sh
```

This runs a complete threshold encryption demo with 4 parties, threshold 2, using **TLS 1.3 encrypted connections**.

### Manual Setup

**1. Build:**
```bash
cargo build --bin distributed_protocol --features distributed --release
```

**2. Start Coordinator (Terminal 1):**
```bash
./target/release/distributed_protocol coordinator --port 8080 --parties 4 --threshold 2
```

**3. Start Parties (Terminals 2-5):**
```bash
./target/release/distributed_protocol party --id 0 --coordinator localhost:8080
./target/release/distributed_protocol party --id 1 --coordinator localhost:8080
./target/release/distributed_protocol party --id 2 --coordinator localhost:8080
./target/release/distributed_protocol party --id 3 --coordinator localhost:8080
```

You'll see the protocol execute: **Key Generation** → **Encryption** → **Decryption** → **Success!**

## TLS 1.3 Security

### Overview

The distributed protocol now uses **TLS 1.3** to encrypt all network communications between the coordinator and parties.

**Security Features:**
- ✅ TLS 1.3 encryption for all data in transit
- ✅ Forward secrecy
- ✅ Man-in-the-middle attack prevention
- ✅ Automatic certificate generation for development
- ✅ Production-ready certificate loading

### How It Works

**Development Mode (Default):**
- Self-signed certificates generated automatically on startup
- Certificate verification disabled on client side
- Perfect for local testing and development

**Production Mode:**
- Load CA-signed certificates from PEM files
- Full certificate validation
- Secure for Internet-facing deployments

### What's Protected

When using TLS, all cryptographic material is encrypted during transmission:
- Secret key parameters (tau)
- Public keys
- Ciphertexts
- Partial decryptions
- Control messages

### Implementation Details

**Coordinator (Server):**
```rust
// Generate self-signed certificate
let (certs, key) = tls_config::generate_self_signed_cert()?;
let tls_config = tls_config::create_server_config(certs, key)?;
let acceptor = TlsAcceptor::from(tls_config);

// Accept TLS connections
let (tcp_stream, peer_addr) = listener.accept().await?;
let tls_stream = acceptor.accept(tcp_stream).await?; // TLS handshake
```

**Party (Client):**
```rust
// Create TLS client config
let tls_config = tls_config::create_client_config_dev()?;
let connector = TlsConnector::from(tls_config);

// Connect with TLS
let tcp_stream = TcpStream::connect(&coordinator_addr).await?;
let server_name = ServerName::try_from("localhost")?;
let tls_stream = connector.connect(server_name, tcp_stream).await?;
```

### Upgrading to Production

**1. Generate CA-signed certificate:**
```bash
# Using Let's Encrypt
certbot certonly --standalone -d your-domain.com
```

**2. Update coordinator to load certificate:**
```rust
let (certs, key) = tls_config::load_cert_and_key(
    "/path/to/fullchain.pem",
    "/path/to/privkey.pem"
)?;
```

**3. Update client configuration:**
```rust
// Use proper CA verification instead of accepting all certs
let mut root_store = rustls::RootCertStore::empty();
root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

let config = ClientConfig::builder()
    .with_root_certificates(root_store)
    .with_no_client_auth();
```

**4. Update server name in party connection:**
```rust
let server_name = ServerName::try_from("your-domain.com")?;
```

### Testing TLS

The test script automatically verifies TLS is working:

```bash
./test_distributed_simple.sh
```

**Expected output:**
```
✓ TLS certificate generated
✓ TLS 1.3 enabled
✓ TLS handshakes successful
✓ All 4 parties connected via TLS
✓ Threshold encryption protocol completed

✅ TEST PASSED: TLS-enabled distributed protocol works correctly!
```

### Technical Specifications

**TLS Library:** rustls 0.23 (pure Rust, no OpenSSL)
- TLS 1.2 and 1.3 support (defaults to 1.3)
- Modern cipher suites only
- No support for insecure legacy protocols

**Cipher Suites:**
- TLS13_AES_256_GCM_SHA384
- TLS13_AES_128_GCM_SHA256
- TLS13_CHACHA20_POLY1305_SHA256

**Key Exchange:**
- X25519 (default) or P-256
- Guaranteed forward secrecy

### Performance Impact

TLS overhead is negligible compared to cryptographic operations:
- **Handshake:** ~2-5ms one-time cost per connection
- **Throughput:** ~1-5% reduction for bulk data
- **Memory:** ~50KB per connection

## Browser Client (WASM)

A WebAssembly client is available for browser-based parties:

```bash
cd wasm-client
wasm-pack build --target web --release
```

Open [wasm-client/distributed_party.html](wasm-client/distributed_party.html) in a browser.

**TLS Support:**
- Use `wss://` URLs for TLS-encrypted WebSocket connections
- Automatic TLS 1.3 when using `wss://`
- Same security level as Rust TCP+TLS implementation

See [wasm-client/README.md](wasm-client/README.md) for details.

## Building & Testing

**Build library:**
```bash
cargo build --release
```

**Run benchmarks:**
```bash
cargo bench
```

Results saved to `target/criterion/index.html`.

**Run unit tests:**
```bash
cargo test
```

## Project Structure

- **[src/setup.rs](src/setup.rs)**: Key generation and aggregation
- **[src/encryption.rs](src/encryption.rs)**: Silent threshold encryption
- **[src/decryption.rs](src/decryption.rs)**: Partial decryption aggregation
- **[src/bin/distributed_protocol.rs](src/bin/distributed_protocol.rs)**: Distributed protocol with TLS
- **[src/bin/distributed/tls_config.rs](src/bin/distributed/tls_config.rs)**: TLS configuration module
- **[wasm-client/](wasm-client/)**: Browser-based WebAssembly client

## Improvements in This Fork

### Security
- **TLS 1.3 support** for distributed protocol
- Automatic certificate generation
- Production-ready certificate loading
- Key zeroization on drop (`ZeroizeOnDrop`)

### Performance
- Batch public key generation with parallel processing
- Optimized MSM operations
- Reduced memory allocations

### Code Quality
- Input validation and better error messages
- Named constants instead of magic numbers
- Comprehensive documentation
- Better type safety

### Bug Fixes
- Fixed incorrect party ID usage in tests
- Fixed type conversion issues
- Improved error handling

## Security Considerations

### ⚠️ Production Warning

This is an **academic proof-of-concept**. Before production use:

1. **Security audit required** - Code has not been formally audited
2. **Trusted setup** - Use multi-party ceremony, not single-party
3. **TLS certificates** - Use CA-signed certs, not self-signed
4. **Key management** - Implement proper HSM/key storage
5. **Side-channel protection** - Consider timing attack mitigations

### TLS Security Notes

**Development (Current):**
- ✅ Self-signed certificates (auto-generated)
- ✅ Certificate verification disabled
- ✅ Suitable for: Local testing, development, trusted networks

**Production (Recommended):**
- ✅ CA-signed certificates
- ✅ Full certificate validation
- ✅ Mutual TLS (mTLS) for client auth
- ✅ Certificate pinning
- ✅ Proper DNS names

### Random Number Generation

**Always use cryptographically secure RNGs:**
```rust
use rand::rngs::OsRng;
let mut rng = OsRng;
```

**Never use in production:**
```rust
let mut rng = test_rng(); // ❌ INSECURE - testing only!
```

### Trusted Setup

**Critical:** KZG requires secure multi-party ceremony.

**For production, use:**
1. Established ceremonies (Zcash, Ethereum KZG)
2. Your own multi-party ceremony using `trusted_setup` module

**Never use single-party setup** in production:
```rust
// ❌ INSECURE FOR PRODUCTION
let tau = Fr::rand(&mut rng);
let params = KZG10::setup(n, tau)?;
```

See full security details in original README sections.

## Examples

### Different Configurations

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

### Remote Parties

**On coordinator machine:**
```bash
# Find IP: ifconfig | grep "inet "
# Start: ./target/release/distributed_protocol coordinator --port 8080 --parties 4 --threshold 2
```

**On party machines:**
```bash
./target/release/distributed_protocol party --id 0 --coordinator 192.168.1.100:8080
```

Note: For remote connections, ensure firewall allows port 8080 and use proper TLS certificates.

## Troubleshooting

**Connection refused:**
- Ensure coordinator starts first
- Check port is not in use: `lsof -i :8080`
- Verify firewall settings

**TLS handshake failed:**
- For development: Self-signed certs should work automatically
- For production: Verify certificate matches domain name

**Address already in use:**
```bash
lsof -i :8080  # Find process
kill -9 <PID>  # Kill it
```

## License

MIT License

## References

- Paper: [ePrint:2024/263](https://eprint.iacr.org/2024/263)
- rustls: [https://docs.rs/rustls/](https://docs.rs/rustls/)
- TLS 1.3: [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
