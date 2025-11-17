# Silent Threshold Encryption [ePrint:2024/263](https://eprint.iacr.org/2024/263)

> **Note:** This is a fork of the original repository with improvements and bug fixes.

Rust implementation of the silent-threshold encryption introduced in [ePrint:2024/263](https://eprint.iacr.org/2024/263). Benchmarks reported in the paper were run on a 2019 MacBook Pro with a 2.4 GHz Intel Core i9 processor. The library has been confirmed to work with version 1.76.0 of the Rust compiler.

A distributed protocol implementation is provided as a binary in `src/bin/distributed_protocol.rs`.

## Client Implementations

- **WebAssembly Client** ([`wasm-client/`](wasm-client/)): Browser-based distributed client for web applications

The WASM client enables threshold encryption in web browsers, allowing parties to participate in the protocol from anywhere with a modern browser.

- **Distributed Protocol Test** ([`test_distributed_simple.sh`](test_distributed_simple.sh)): Simple test script for the distributed protocol example

## Distributed Protocol Quickstart

This guide shows you how to run a complete distributed threshold encryption system with a coordinator and multiple parties.

### Quick Demo (Automated)

The fastest way to see the distributed protocol in action:

```bash
# Run the simple test script (4 parties, threshold 2)
./test_distributed_simple.sh
```

This script will:
1. Build the distributed protocol binary
2. Start the coordinator
3. Start all party clients
4. Run the complete protocol
5. Show you the output
6. Save logs to `test_logs/` directory

### Manual Setup (Step-by-Step)

For more control, run each component manually:

#### Step 1: Build

```bash
cargo build --bin distributed_protocol --features distributed --release
```

#### Step 2: Start Coordinator (Terminal 1)

```bash
./target/release/distributed_protocol coordinator \
    --port 8080 \
    --parties 4 \
    --threshold 2
```

You'll see:
```
🔧 Coordinator: Initializing with n=4, t=2
🔧 Coordinator: Setting up KZG parameters...
🔧 Coordinator: Preprocessing Lagrange powers...
✓ Coordinator: Setup complete
🌐 Coordinator: Listening on 127.0.0.1:8080
⏳ Coordinator: Waiting for 4 parties to connect...
```

#### Step 3: Start Parties (Terminals 2-5)

Open 4 new terminals and run one command in each:

**Terminal 2 (Party 0):**
```bash
./target/release/distributed_protocol party \
    --id 0 \
    --coordinator localhost:8080
```

**Terminal 3 (Party 1):**
```bash
./target/release/distributed_protocol party \
    --id 1 \
    --coordinator localhost:8080
```

**Terminal 4 (Party 2):**
```bash
./target/release/distributed_protocol party \
    --id 2 \
    --coordinator localhost:8080
```

**Terminal 5 (Party 3):**
```bash
./target/release/distributed_protocol party \
    --id 3 \
    --coordinator localhost:8080
```

#### Step 4: Watch the Protocol Execute

Once all parties connect, you'll see the protocol execute automatically:

**Coordinator Output:**
```
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
  Encrypted key: Fq12(...)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 3: Decryption
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Coordinator: Selected 3 parties for decryption: [0, 1, 2]
✓ Coordinator: Received partial decryption from party 0
✓ Coordinator: Received partial decryption from party 1
✓ Coordinator: Received partial decryption from party 2

🔓 Coordinator: Aggregating partial decryptions...
✓ Coordinator: Decryption complete
  Decrypted key: Fq12(...)

✅ SUCCESS: Decryption successful! Keys match.
```

**Party Output (each terminal):**
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

### Example Scenarios

#### Scenario 1: Small Committee (4 parties, need 3 to decrypt)

```bash
# Terminal 1
./target/release/distributed_protocol coordinator --parties 4 --threshold 2

# Terminals 2-5 (run in parallel)
./target/release/distributed_protocol party --id 0 --coordinator localhost:8080 &
./target/release/distributed_protocol party --id 1 --coordinator localhost:8080 &
./target/release/distributed_protocol party --id 2 --coordinator localhost:8080 &
./target/release/distributed_protocol party --id 3 --coordinator localhost:8080 &
wait
```

#### Scenario 2: Board of Directors (8 parties, need majority)

```bash
# Coordinator
./target/release/distributed_protocol coordinator --parties 8 --threshold 4

# Start 8 parties (in separate terminals or background)
for i in {0..7}; do
    ./target/release/distributed_protocol party --id $i --coordinator localhost:8080 &
done
wait
```

#### Scenario 3: Large Organization (16 parties, high threshold)

```bash
# Coordinator
./target/release/distributed_protocol coordinator --parties 16 --threshold 10

# Start 16 parties
for i in {0..15}; do
    ./target/release/distributed_protocol party --id $i --coordinator localhost:8080 &
done
wait
```

### Running on Different Machines

To run the coordinator and parties on different computers:

**On Machine A (Coordinator):**

1. Find your IP address:
   ```bash
   # Linux/Mac
   ifconfig | grep "inet "
   # Or
   hostname -I
   ```

2. Start coordinator (bind to all interfaces):
   ```bash
   # Edit the code to bind to 0.0.0.0 instead of 127.0.0.1, or use SSH tunneling
   ./target/release/distributed_protocol coordinator --port 8080 --parties 4 --threshold 2
   ```

3. Make sure firewall allows port 8080

**On Machines B, C, D, E (Parties):**

```bash
# Replace 192.168.1.100 with actual coordinator IP
./target/release/distributed_protocol party --id 0 --coordinator 192.168.1.100:8080
./target/release/distributed_protocol party --id 1 --coordinator 192.168.1.100:8080
./target/release/distributed_protocol party --id 2 --coordinator 192.168.1.100:8080
./target/release/distributed_protocol party --id 3 --coordinator 192.168.1.100:8080
```

### Using tmux for Multiple Terminals

If you want to run everything in one window:

```bash
# Install tmux if needed
# Ubuntu/Debian: apt-get install tmux
# Mac: brew install tmux

# Start a tmux session
tmux new -s ste

# Create panes (Ctrl+b, %)
# Split horizontally: Ctrl+b %
# Split vertically: Ctrl+b "
# Navigate: Ctrl+b <arrow keys>

# In first pane (coordinator)
./target/release/distributed_protocol coordinator --parties 4 --threshold 2

# In other panes (parties)
./target/release/distributed_protocol party --id 0 --coordinator localhost:8080
./target/release/distributed_protocol party --id 1 --coordinator localhost:8080
./target/release/distributed_protocol party --id 2 --coordinator localhost:8080
./target/release/distributed_protocol party --id 3 --coordinator localhost:8080

# Detach: Ctrl+b d
# Reattach: tmux attach -t ste
# Kill session: tmux kill-session -t ste
```

### Checking Logs

After running with the test script, check the logs:

```bash
cd test_logs

# Coordinator log
cat coordinator.log

# Party logs
cat party_0.log
cat party_1.log
cat party_2.log
cat party_3.log

# Or view all together
tail -f coordinator.log party_*.log
```

### Performance Testing

Test with different configurations by modifying the test script or using manual setup:

```bash
# Test with default settings
time ./test_distributed_simple.sh

# For custom configurations, modify the script or use manual setup
```

### Troubleshooting

#### "Address already in use"

Another process is using port 8080:

```bash
# Find the process
lsof -i :8080

# Kill it
kill -9 <PID>

# Or modify the test script to use a different port
```

#### "Connection refused"

Coordinator not running or wrong address:

1. Make sure coordinator starts first
2. Check coordinator is listening: `netstat -an | grep 8080`
3. Verify correct hostname/IP
4. Check firewall settings

#### "Not enough parties"

Make sure you start exactly `n` parties with IDs `0` to `n-1`.

#### Parties stuck "Connecting..."

- Coordinator may not be ready
- Wrong address/port
- Firewall blocking connection

**Solution**:
1. Start coordinator first
2. Wait for "Listening on..." message
3. Then start parties

### Protocol Flow

1. **Setup**: Coordinator generates KZG parameters and Lagrange precomputation
2. **Connection**: Each party connects via TCP to coordinator
3. **Key Gen**:
   - Coordinator sends `tau` parameter to each party
   - Each party generates their secret/public key pair
   - Parties send public keys back to coordinator
4. **Aggregation**: Coordinator computes aggregate public key from all party public keys
5. **Encryption**: Coordinator encrypts a message using the aggregate key
6. **Selection**: Coordinator selects t+1 parties (including party 0) for decryption
7. **Partial Dec**: Selected parties compute and send partial decryptions
8. **Final Dec**: Coordinator aggregates partial decryptions and recovers the key
9. **Verification**: Check if decrypted key matches original encrypted key

⚠️ **Note**: The distributed protocol uses unencrypted TCP connections. For production, use TLS/SSL, authenticate parties, use distributed trusted setup, validate all messages, and implement rate limiting. See the [Security Considerations](#security-considerations) section for more details.

## Dependencies
Install rust via:

```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh```

## Benchmarking
The library can be built using ```cargo build --release```.

Use ```cargo bench``` to benchmark `setup` (KeyGen in the paper), `encryption`, and `decryption`. This is expected to take approximately 20 minutes. To run a specific benchmark, use ```cargo bench --bench <bench_name>```.

Use ```./test_distributed_simple.sh``` to test the distributed protocol implementation. See the [Distributed Protocol Quickstart](#distributed-protocol-quickstart) section for detailed instructions.

The results are saved in the `target/criterion` directory. A concise HTML report is generated in `target/criterion/index.html` and can be viewed on a browser (Google Chrome recommended).

If you wish to benchmark for a different set of parameters, you can modify the files in the `benches/` directory. 

## Unit Tests
Additionally, you can find individual unit tests at the end of the respective files in the `src/` directory. These can be run using ```cargo test <test_name>```. This will allow you to test the correctness of the implementation.

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Improvements in This Fork

This fork includes the following improvements over the original implementation:

### Bug Fixes
- Fixed incorrect party ID usage in encryption test (was using ID 0 for all parties)
- Fixed missing error handling in examples
- Fixed redundant error check in `LagrangePowers::new`
- Improved type conversions for better precision (u32 → u64 for large values)

### Performance Optimizations
- **Batch Public Key Generation**: Added `batch_lagrange_get_pk` method that uses parallel processing to generate all public keys efficiently
- Optimized MSM operations by reducing code duplication and reusing buffers

### Code Quality
- Extracted magic numbers to named constants (`SA1_SIZE`, `SA2_SIZE`, `ENCRYPTION_RANDOMNESS_SIZE`)
- Changed function parameters from `&Vec<T>` to `&[T]` for better ergonomics
- Removed unused code (`skip_leading_zeros_and_convert_to_bigints`)

### Validation & Robustness
- Added input validation for edge cases (n == 0, t == 0)
- Improved error messages for better debugging
- Enhanced type safety with better type conversions

### Documentation
- Added comprehensive module-level documentation with usage examples
- Added detailed struct documentation explaining the scheme components
- Improved inline comments and docstrings throughout the codebase

## Overview
* [`src/setup`](src/setup.rs): Contains an implementation for sampling public key pairs and aggregating keys of a chosen committee. Also contains the `partial_decryption` method which is essentially a BLS signature. The `lagrange_get_pk` method uses preprocessed commitments to Lagrange polynomials for O(n) per-key generation. For generating all n keys, use `batch_lagrange_get_pk` which leverages parallel processing for better performance.
* [`src/encryption`](src/encryption.rs): Contains an implementation of the `encrypt` method for the silent threshold encryption scheme.
* [`src/decryption`](src/decryption.rs): Contains an implementation of `agg_dec` which gathers partial decryptions and recovers the message.

## Security Considerations

### Production Readiness
**⚠️ CRITICAL:** This implementation is an academic proof-of-concept prototype and has **NOT** received comprehensive security auditing. It is **NOT ready for production use** and should **NOT** be used to protect sensitive data in real-world applications without thorough security review.

### Random Number Generation
- **Library Functions**: When using the library directly, ensure you provide a cryptographically secure RNG. **Never use deterministic or predictable RNGs** (like `test_rng()`) in production.
- Always use `rand::rngs::OsRng` when generating seeds for RNGs. OsRng directly sources entropy from the operating system's secure random number generator (e.g., `/dev/urandom` on Unix, `BCryptGenRandom` on Windows, `getrandom()` system call on Linux).

### Secret Key Management
- **Secret Key Storage**: Secret keys must be stored securely and protected from unauthorized access. Consider using hardware security modules (HSMs) or secure key management systems for production deployments.
- **Key Zeroization**: The `SecretKey` struct implements `Zeroize` and `ZeroizeOnDrop` traits from the `zeroize` crate. Secret keys are automatically zeroized (set to zero) when dropped, helping to prevent secret material from remaining in memory. However, note that:
  - Zeroization works best for owned values; `Copy` types (like `ScalarField`) may have limitations
  - The zeroize crate provides best-effort memory clearing, but cannot guarantee complete erasure in all scenarios (e.g., compiler optimizations, memory-mapped files)
  - For maximum security, consider using secure memory allocators or hardware-backed key storage
- **Key Derivation**: Ensure secret keys are derived from cryptographically secure random sources with sufficient entropy.
- **Party 0 (Dummy Party)**: Party 0 is the "dummy party" with a nullified secret key (set to 1). This is by design in the scheme and always participates in decryption.

### Input Validation
- The library performs input validation (n must be power of 2, threshold constraints, etc.), but additional validation may be required in your application:
  - Validate all inputs from untrusted sources before passing to library functions
  - Ensure threshold `t` satisfies security requirements for your use case
  - Validate that sufficient parties are selected for decryption (at least t+1)
- Invalid inputs may cause operations to fail with errors; always handle `Result` types appropriately.

### Side-Channel Attacks
- **Timing Attacks**: The current implementation does not provide explicit protection against timing-based side-channel attacks. For high-security applications, consider:
  - Constant-time implementations for sensitive operations
  - Hardware-based protections
  - Power analysis countermeasures
- **Memory Access Patterns**: Sensitive data structures may have observable memory access patterns.

### Cryptographic Assumptions
- This implementation relies on the security of:
  - **BLS12-381 pairing-friendly elliptic curve**: The discrete logarithm assumption in the curve groups
  - **KZG10 polynomial commitment scheme**: Security depends on the trusted setup (powers of tau)
  - **Threshold scheme**: Assumes honest majority (at least t+1 out of n parties are honest)

### Trusted Setup (Powers of Tau)

**⚠️ CRITICAL SECURITY REQUIREMENT**: The KZG polynomial commitment scheme requires a secure "powers of tau" trusted setup ceremony. The security of the entire system depends on this setup being generated correctly.

#### What is a Trusted Setup?

The trusted setup generates parameters of the form `{τ^i G, τ^i H}` where τ is a secret value that **must be destroyed** after the ceremony. If an attacker learns τ, they can break the system entirely.

#### Security Model

The ceremony is secure as long as **at least ONE participant**:
1. Generates their contribution using cryptographically secure randomness
2. **Destroys** their secret randomness after contributing
3. Does not collude with all other participants

This is called a "1-of-N" trust model - you only need to trust that one participant was honest.

#### Implementation Options

This library provides a `trusted_setup` module for multi-party ceremonies:

```rust
use silent_threshold_encryption::trusted_setup::Ceremony;

// Initialize ceremony (first participant)
let mut ceremony = Ceremony::<E>::new(max_degree, &mut secure_rng)?;

// Additional participants contribute
ceremony.contribute(&mut secure_rng)?;

// Verify contributions
for i in 1..ceremony.num_participants() {
    assert!(ceremony.verify_contribution(i));
}

// Extract final parameters
let params = ceremony.finalize();
```

#### Production Recommendations

For production systems, you should:

1. **Use Existing Trusted Setups**: Consider using powers-of-tau parameters from established ceremonies:
   - Zcash Powers of Tau ceremony (https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony/)
   - Ethereum KZG Ceremony (https://ceremony.ethereum.org/)
   - Perpetual Powers of Tau (https://github.com/privacy-scaling-explorations/perpetualpowersoftau)

2. **Run Your Own Multi-Party Ceremony**:
   - Use the `trusted_setup` module with multiple independent participants
   - Each participant must use `OsRng` or equivalent cryptographically secure RNG
   - Each participant must destroy their secret τ after contributing (ideally using secure erasure)
   - Publish transcripts publicly for transparency
   - Implement full pairing-based verification (see module documentation)

3. **Never Use Single-Party Setup in Production**:
   - The example code and tests use single-party setup for simplicity
   - Single-party setups are **ONLY** acceptable for testing/development
   - A compromised single party can break all security guarantees

#### Current Implementation Status

⚠️ **WARNING**: The examples currently use a **single-party** setup for simplicity:
```rust
// INSECURE FOR PRODUCTION - Demo/test only
let tau = Fr::rand(&mut rng);
let kzg_params = KZG10::<E, UniPoly381>::setup(n, tau)?;
```

This is **acceptable ONLY** for:
- Development and testing
- Academic demonstrations
- Prototype systems

For production, you **MUST** either:
- Use parameters from a public multi-party ceremony
- Run your own multi-party ceremony using the `trusted_setup` module

### Parameter Selection
- **Number of Parties (n)**: Must be a power of 2. Consider computational and communication costs when selecting n.
- **Threshold (t)**: Must satisfy `1 <= t < n`. Choose t based on your security and availability requirements:
  - Lower t: More availability (fewer parties needed) but less security (fewer corrupted parties tolerated)
  - Higher t: More security (more corrupted parties tolerated) but less availability (more parties required)
- **Balancing Security vs. Availability**: The threshold t determines the trade-off between fault tolerance and availability.

### Partial Decryption Security
- **Partial Decryption Privacy**: Partial decryptions reveal information about the participating parties' secret keys. Ensure secure communication channels when transmitting partial decryptions.
- **Selector Validation**: The `agg_dec` function validates that:
  - Party 0 (dummy party) is always selected
  - At least t+1 parties are selected
  - No more than n parties are selected
- **Decryption Authentication**: Verify the source and integrity of partial decryptions before aggregation.

### Best Practices
1. **Never commit secret keys to version control**
2. **Use secure channels for transmitting cryptographic materials**
3. **Implement proper key rotation policies**
4. **Monitor for anomalous behavior in threshold decryption**
5. **Regularly audit and review security assumptions**
6. **Keep dependencies up to date** (especially cryptographic libraries)
7. **Use secure defaults** and avoid optional security-relevant parameters
8. **Implement comprehensive logging** (without logging sensitive data) for security auditing

### Reporting Security Issues
If you discover a security vulnerability, please:
1. **DO NOT** open a public issue
2. Contact the maintainers through secure channels
3. Provide detailed information about the vulnerability
4. Allow reasonable time for the issue to be addressed before public disclosure

## License
This library is released under the MIT License.
