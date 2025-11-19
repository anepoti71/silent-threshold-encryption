# P2P Threshold Encryption Quick Start Guide

This guide shows you how to test the **fully decentralized P2P threshold encryption** protocol with **Ed25519 signature verification**.

## Prerequisites

Build the P2P binaries:

```bash
cargo build --bin p2p_peer --bin generate_peer_params --features distributed --release
```

## Step 1: Generate Shared Parameters

First, generate the shared KZG and Lagrange parameters that all peers will use:

```bash
./target/release/generate_peer_params \
    --parties 4 \
    --seed 42 \
    --output-dir artifacts/p2p
```

This creates:
- `artifacts/p2p/kzg_params.bin` - KZG commitment parameters
- `artifacts/p2p/lagrange_params.bin` - Preprocessed Lagrange polynomial evaluations

## Step 2: Start the Peers

Open **4 separate terminals** and run one peer in each:

### Terminal 1: Party 0 (Initiator)

```bash
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 0 \
    --parties 4 \
    --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9000 \
    --mode initiator \
    --auto-decrypt
```

### Terminal 2: Party 1 (Passive)

```bash
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 1 \
    --parties 4 \
    --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9001
```

### Terminal 3: Party 2 (Passive)

```bash
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 2 \
    --parties 4 \
    --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9002
```

### Terminal 4: Party 3 (Passive)

```bash
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 3 \
    --parties 4 \
    --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9003
```

## What to Expect

### Phase 1: Peer Discovery (5-10 seconds)

You should see peers discovering each other via mDNS:

```
INFO libp2p_mdns::behaviour: discovered peer on address peer=12D3KooW...
INFO silent_threshold_encryption::p2p::protocol: Connected to peer 12D3KooW...
```

###Phase 2: Public Key Exchange (automatic)

Each peer broadcasts its public key with an **Ed25519 signature**:

```
INFO ✓ Verified signature for public key from party 1 (peer 12D3KooW...)
INFO Registered public key for party 1
INFO Aggregate key constructed for all 4 parties.
```

**Key Security Feature**: The `✓ Verified signature` messages show that signature verification is working!

### Phase 3: Encryption (Party 0 only)

The initiator (Party 0) will automatically encrypt once all keys are collected:

```
INFO Aggregate key ready; initiating encryption run.
```

### Phase 4: Decryption

Party 0 will request partial decryptions from parties {0, 1, 2}:

```
INFO Requesting partial decryptions from parties [0, 1, 2]
```

Other parties respond:

```
INFO Responding to partial decryption request ... as party 1
INFO ✓ Verified signature for partial decryption from party 1 (peer 12D3KooW...)
```

**Key Security Feature**: Partial decryptions are also signature-verified!

Finally, Party 0 recovers the encrypted key:

```
INFO Recovered encrypted key for request ...: PairingOutput(...)
```

## Troubleshooting

### "InsufficientPeers" errors

This is normal during startup. Wait 10-15 seconds for gossipsub mesh formation.

### Peers not discovering each other

- Make sure all peers are on the same network
- Check firewall settings
- Verify different ports are used for each peer

### No public keys registered

- Wait longer (up to 30 seconds) for gossipsub to stabilize
- Check that all 4 peers are running
- Verify `artifacts/p2p/*.bin` files exist

### Signature verification failures

If you see signature errors, this means someone is trying to spoof messages - **the security is working correctly!**

## Verify Signature Verification is Working

To confirm signatures are being verified, look for these log messages:

✅ **Public Key Verification:**
```
✓ Verified signature for public key from party X
```

✅ **Partial Decryption Verification:**
```
✓ Verified signature for partial decryption from party X
```

You should see **at least 12 public key verifications** (each party verifies 3 others' keys) and **at least 3 partial decryption verifications** (Party 0 verifies 3 responses).

## Advanced Usage

### Using Bootstrap Nodes (instead of mDNS)

If peers are on different networks:

```bash
# Party 0 (bootstrap node)
./target/release/p2p_peer --party-id 0 ... --listen /ip4/0.0.0.0/tcp/9000

# Party 1 (connects to Party 0)
./target/release/p2p_peer --party-id 1 ... \
    --bootstrap /ip4/192.168.0.100/tcp/9000/p2p/12D3KooW...
```

### Custom Gossip Topic

To isolate multiple protocol instances:

```bash
./target/release/p2p_peer ... --gossip-topic my-custom-topic-v2
```

### Different Threshold Settings

Try different (n, t) configurations:

```bash
# 8 parties, threshold 5
./target/release/generate_peer_params --parties 8 --threshold 5 ...
./target/release/p2p_peer --parties 8 --threshold 5 ...
```

## Architecture Comparison

| Feature | Coordinator Protocol | P2P Protocol |
|---------|---------------------|--------------|
| **Central Authority** | Yes (coordinator) | No (fully decentralized) |
| **Security** | TLS 1.3 | Ed25519 signatures |
| **Discovery** | Static addresses | mDNS + bootstrap |
| **Resilience** | Single point of failure | No single point of failure |
| **Test Script** | `./test_distributed_simple.sh` | Manual (this guide) |

Both protocols use the same cryptographic primitives and provide the same threshold encryption security guarantees.

## Summary

The P2P protocol provides:

✅ **Decentralization** - No coordinator needed
✅ **Signature Verification** - Ed25519 authentication on all critical messages
✅ **Automatic Discovery** - mDNS for local networks
✅ **Gossip Protocol** - Efficient message propagation
✅ **Production-Ready** - Built on battle-tested libp2p

You've successfully added cryptographic message authentication to prevent spoofing attacks!
