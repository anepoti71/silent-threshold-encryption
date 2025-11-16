# Silent Threshold Encryption - Client

A client application demonstrating the usage of the Silent Threshold Encryption library.

## Building

From the root of the repository:

```bash
cd client
cargo build --release
```

## Running

Run the client demo:

```bash
cargo run --release
```

Or run the built binary:

```bash
./target/release/ste-client
```

## Usage

The client will prompt you for:
1. **Number of parties (n)**: Total number of parties in the system (default: 16)
   - Must be a power of 2 (will be automatically adjusted if not)
   
2. **Threshold (t)**: Minimum number of parties needed for decryption (default: n/2)
   - Must be less than n

The client will then demonstrate the complete threshold encryption workflow:

1. **Setup**: Generate KZG parameters and preprocess Lagrange powers
2. **Key Generation**: Generate key pairs for all parties
3. **Aggregate Key Computation**: Compute the aggregate public key
4. **Encryption**: Encrypt a message using the aggregate key
5. **Decryption**: Demonstrate threshold decryption with selected parties

## Example Output

```
╔════════════════════════════════════════════════════════════╗
║   Silent Threshold Encryption - Client Demo               ║
╚════════════════════════════════════════════════════════════╝

Configuration:
  Total parties (n): 16
  Threshold (t): 8

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 1: Setup
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ KZG parameters generated
✓ Lagrange powers preprocessed

... (continues with remaining phases)
```

## Features

- Interactive parameter configuration
- Step-by-step demonstration of all phases
- Automatic validation of inputs
- Clear visual output with progress indicators
- Verification of decryption correctness

