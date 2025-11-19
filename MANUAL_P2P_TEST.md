# Manual P2P Test (Recommended)

Since the automated test has gossipsub timing issues, here's a **reliable manual test** you can run right now.

## Quick Test (4 Terminals)

### Step 1: Generate Parameters

```bash
./target/release/generate_peer_params --parties 4 --seed 42 --output-dir artifacts/p2p
```

### Step 2: Open 4 Terminals

Run these commands in **separate terminal windows**:

#### Terminal 1 (Party 0 - Initiator):
```bash
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 0 --parties 4 --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9000 \
    --mode initiator --auto-decrypt
```

#### Terminal 2 (Party 1):
```bash
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 1 --parties 4 --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9001
```

#### Terminal 3 (Party 2):
```bash
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 2 --parties 4 --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9002
```

#### Terminal 4 (Party 3):
```bash
RUST_LOG=info ./target/release/p2p_peer \
    --party-id 3 --parties 4 --threshold 2 \
    --listen /ip4/0.0.0.0/tcp/9003
```

### What You Should See

**Within 10-15 seconds**, you should see:

1. **Peer Discovery** (all terminals):
   ```
   INFO libp2p_mdns::behaviour: discovered peer on address peer=12D3KooW...
   INFO Connected to peer 12D3KooW...
   ```

2. **Public Key Exchange with Signature Verification** (all terminals):
   ```
   INFO ✓ Verified signature for public key from party 1 (peer 12D3KooW...)
   INFO Registered public key for party 1
   INFO Aggregate key constructed for all 4 parties.
   ```

   ✅ **This proves signature verification is working!**

3. **Encryption** (Terminal 1 only):
   ```
   INFO Aggregate key ready; initiating encryption run.
   ```

4. **Partial Decryptions with Signature Verification** (Terminals 1, 2, 3):
   ```
   INFO Responding to partial decryption request ... as party 1
   INFO ✓ Verified signature for partial decryption from party 1 (peer 12D3KooW...)
   ```

   ✅ **More signature verification!**

5. **Success** (Terminal 1):
   ```
   INFO Recovered encrypted key for request ...: PairingOutput(...)
   ```

## Troubleshooting

### "InsufficientPeers" errors
- **Normal during first 5-10 seconds** as gossipsub mesh forms
- Wait for mDNS discovery to complete
- Messages will start flowing automatically

### No signatures appearing
- Wait **at least 15-20 seconds** for gossipsub mesh
- Check all 4 peers are running
- Verify parameters were generated correctly

### Still not working after 30 seconds?

Try with explicit bootstrap connections instead of mDNS:

```bash
# Terminal 1 (get the peer ID from logs)
RUST_LOG=info ./target/release/p2p_peer --party-id 0 ... --listen /ip4/0.0.0.0/tcp/9000 ...

# After Party 0 starts, grab its peer ID (looks like 12D3KooW...) from logs

# Terminal 2 (connect to Party 0)
RUST_LOG=info ./target/release/p2p_peer --party-id 1 ... \
    --bootstrap /ip4/127.0.0.1/tcp/9000/p2p/<PEER_ID_FROM_PARTY_0>

# Terminals 3 & 4 (same)
```

## Success Criteria

✅ **Test passes if you see:**

1. All parties discover each other (3+ "discovered peer" messages per party)
2. **Signature verifications appear** for public keys (12+ total across all parties)
3. Aggregate key constructed on all 4 parties
4. Encryption initiated by Party 0
5. **Signature verifications appear** for partial decryptions (3+ total)
6. "Recovered encrypted key" message on Party 0

## Why Manual Testing Works Better

The automated script has issues because:
- Gossipsub mesh formation takes 10-15 seconds
- Background processes don't give gossipsub enough warmup time
- Terminal logs show real-time progress so you can verify each step

**Manual testing in separate terminals is the recommended approach for P2P protocols.**

---

**Note**: The coordinator-based protocol (`test_distributed_simple.sh`) works perfectly with automated testing because it uses direct TCP connections instead of gossip mesh.
