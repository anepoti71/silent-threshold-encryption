# Silent Threshold Encryption [ePrint:2024/263](https://eprint.iacr.org/2024/263)

> **Note:** This is a fork of the original repository with improvements and bug fixes.

Rust implementation of the silent-threshold encryption introduced in [ePrint:2024/263](https://eprint.iacr.org/2024/263). Benchmarks reported in the paper were run on a 2019 MacBook Pro with a 2.4 GHz Intel Core i9 processor. The library has been confirmed to work with version 1.76.0 of the Rust compiler. 

An end to end example is provided in the `examples/` directory.

## Dependencies
Install rust via:

```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh```

## Benchmarking
The library can be built using ```cargo build --release```.

Use ```cargo bench``` to benchmark `setup` (KeyGen in the paper), `encryption`, and `decryption`. This is expected to take approximately 20 minutes. To run a specific benchmark, use ```cargo bench --bench <bench_name>```.

Use ```cargo run --example endtoend``` to check correctness of the implementation.

The results are saved in the `target/criterion` directory. A concise HTML report is generated in `target/criterion/index.html` and can be viewed on a browser (Google Chrome recommended).

If you wish to benchmark for a different set of parameters, you can modify the files in the `benches/` directory. 

## Unit Tests
Additionally, you can find individual unit tests at the end of the respective files in the `src/` directory. These can be run using ```cargo test <test_name>```. This will allow you to test the correctness of the implementation.

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Improvements in This Fork

This fork includes the following improvements over the original implementation:

### Bug Fixes
- Fixed incorrect party ID usage in encryption test (was using ID 0 for all parties)
- Fixed missing error handling in `endtoend.rs` example
- Fixed redundant error check in `LagrangePowers::new`
- Improved type conversions for better precision (u32 → u64 for large values)

### Code Quality
- Extracted magic numbers to named constants (`SA1_SIZE`, `SA2_SIZE`, `ENCRYPTION_RANDOMNESS_SIZE`)
- Optimized MSM operations by reducing code duplication and reusing buffers
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
* [`src/setup`](src/setup.rs): Contains an implementation for sampling public key pairs and aggregating keys of a chosen committee. Also contains the `partial_decryption` method which is essentially a BLS signature. Note that the `get_pk` method runs in quadratic time. This can be reduced to linear time by preprocessing commitments to lagrange polynomials.
* [`src/encryption`](src/encryption.rs): Contains an implementation of the `encrypt` method for the silent threshold encryption scheme.
* [`src/decryption`](src/decryption.rs): Contains an implementation of `agg_dec` which gathers partial decryptions and recovers the message.

## Security Considerations

### Production Readiness
**⚠️ CRITICAL:** This implementation is an academic proof-of-concept prototype and has **NOT** received comprehensive security auditing. It is **NOT ready for production use** and should **NOT** be used to protect sensitive data in real-world applications without thorough security review.

### Random Number Generation
- **Client Application**: The client demo (`client/`) uses cryptographically secure OS-backed random number generation (`SecureRng`) seeded from the operating system via `getrandom::fill()`.
- **Library Functions**: When using the library directly, ensure you provide a cryptographically secure RNG. **Never use deterministic or predictable RNGs** (like `test_rng()`) in production.
- Always use `getrandom` directly or `rand::rngs::OsRng` (which uses `getrandom` internally) when generating seeds for RNGs. These directly source entropy from the operating system's secure random number generator (e.g., `/dev/urandom` on Unix, `BCryptGenRandom` on Windows).

### Secret Key Management
- **Secret Key Storage**: Secret keys must be stored securely and protected from unauthorized access. Consider using hardware security modules (HSMs) or secure key management systems for production deployments.
- **Key Zeroization**: The current implementation does not explicitly zeroize secret key material in memory. In memory-constrained or high-security environments, consider implementing explicit zeroization.
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
   - Each participant must use `getrandom` or equivalent OS entropy
   - Each participant must destroy their secret τ after contributing (ideally using secure erasure)
   - Publish transcripts publicly for transparency
   - Implement full pairing-based verification (see module documentation)

3. **Never Use Single-Party Setup in Production**:
   - The example code and tests use single-party setup for simplicity
   - Single-party setups are **ONLY** acceptable for testing/development
   - A compromised single party can break all security guarantees

#### Current Implementation Status

⚠️ **WARNING**: The demo client (`client/`) currently uses a **single-party** setup for simplicity:
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
