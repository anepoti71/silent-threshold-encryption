# Quickstart: Distributed Threshold Encryption

This guide shows you how to run a complete distributed threshold encryption system with a coordinator and multiple parties.

## Quick Demo (Automated)

The fastest way to see the distributed protocol in action:

```bash
# Navigate to the examples directory
cd examples

# Run with default settings (4 parties, threshold 2)
./run_distributed.sh

# Or customize: ./run_distributed.sh [n_parties] [threshold] [port]
./run_distributed.sh 8 5 8080
```

This script will:
1. Build the distributed example
2. Start the coordinator
3. Start all party clients
4. Run the complete protocol
5. Show you the output
6. Save logs to `logs/` directory

---

## Manual Setup (Step-by-Step)

For more control, run each component manually:

### Step 1: Build

```bash
cargo build --example distributed_protocol --features distributed --release
```

### Step 2: Start Coordinator (Terminal 1)

```bash
./target/release/examples/distributed_protocol coordinator \
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

### Step 3: Start Parties (Terminals 2-5)

Open 4 new terminals and run one command in each:

**Terminal 2 (Party 0):**
```bash
./target/release/examples/distributed_protocol party \
    --id 0 \
    --coordinator localhost:8080
```

**Terminal 3 (Party 1):**
```bash
./target/release/examples/distributed_protocol party \
    --id 1 \
    --coordinator localhost:8080
```

**Terminal 4 (Party 2):**
```bash
./target/release/examples/distributed_protocol party \
    --id 2 \
    --coordinator localhost:8080
```

**Terminal 5 (Party 3):**
```bash
./target/release/examples/distributed_protocol party \
    --id 3 \
    --coordinator localhost:8080
```

### Step 4: Watch the Protocol Execute

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

---

## Example Scenarios

### Scenario 1: Small Committee (4 parties, need 3 to decrypt)

```bash
# Terminal 1
./target/release/examples/distributed_protocol coordinator --parties 4 --threshold 2

# Terminals 2-5 (run in parallel)
./target/release/examples/distributed_protocol party --id 0 --coordinator localhost:8080 &
./target/release/examples/distributed_protocol party --id 1 --coordinator localhost:8080 &
./target/release/examples/distributed_protocol party --id 2 --coordinator localhost:8080 &
./target/release/examples/distributed_protocol party --id 3 --coordinator localhost:8080 &
wait
```

### Scenario 2: Board of Directors (8 parties, need majority)

```bash
# Coordinator
./target/release/examples/distributed_protocol coordinator --parties 8 --threshold 4

# Start 8 parties (in separate terminals or background)
for i in {0..7}; do
    ./target/release/examples/distributed_protocol party --id $i --coordinator localhost:8080 &
done
wait
```

### Scenario 3: Large Organization (16 parties, high threshold)

```bash
# Coordinator
./target/release/examples/distributed_protocol coordinator --parties 16 --threshold 10

# Start 16 parties
for i in {0..15}; do
    ./target/release/examples/distributed_protocol party --id $i --coordinator localhost:8080 &
done
wait
```

### Scenario 4: Using Helper Script (Recommended)

```bash
cd examples

# Small test
./run_distributed.sh 4 2 8080

# Medium setup
./run_distributed.sh 16 10 8080

# Large setup (will take several minutes)
./run_distributed.sh 256 128 8080
```

---

## Running on Different Machines

To run the coordinator and parties on different computers:

### On Machine A (Coordinator):

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
   ./target/release/examples/distributed_protocol coordinator --port 8080 --parties 4 --threshold 2
   ```

3. Make sure firewall allows port 8080

### On Machines B, C, D, E (Parties):

```bash
# Replace 192.168.1.100 with actual coordinator IP
./target/release/examples/distributed_protocol party --id 0 --coordinator 192.168.1.100:8080
./target/release/examples/distributed_protocol party --id 1 --coordinator 192.168.1.100:8080
./target/release/examples/distributed_protocol party --id 2 --coordinator 192.168.1.100:8080
./target/release/examples/distributed_protocol party --id 3 --coordinator 192.168.1.100:8080
```

---

## Using tmux for Multiple Terminals

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
./target/release/examples/distributed_protocol coordinator --parties 4 --threshold 2

# In other panes (parties)
./target/release/examples/distributed_protocol party --id 0 --coordinator localhost:8080
./target/release/examples/distributed_protocol party --id 1 --coordinator localhost:8080
./target/release/examples/distributed_protocol party --id 2 --coordinator localhost:8080
./target/release/examples/distributed_protocol party --id 3 --coordinator localhost:8080

# Detach: Ctrl+b d
# Reattach: tmux attach -t ste
# Kill session: tmux kill-session -t ste
```

---

## Checking Logs

After running with the helper script, check the logs:

```bash
cd examples/logs

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

---

## Performance Testing

Test with different configurations:

```bash
cd examples

# Test small (< 1 second)
time ./run_distributed.sh 4 2

# Test medium (~5 seconds)
time ./run_distributed.sh 16 8

# Test large (~30 seconds)
time ./run_distributed.sh 64 32

# Test very large (~2 minutes)
time ./run_distributed.sh 256 128
```

---

## Troubleshooting

### "Address already in use"

Another process is using port 8080:

```bash
# Find the process
lsof -i :8080

# Kill it
kill -9 <PID>

# Or use a different port
./run_distributed.sh 4 2 8081
```

### "Connection refused"

Coordinator not running or wrong address:

1. Make sure coordinator starts first
2. Check coordinator is listening: `netstat -an | grep 8080`
3. Verify correct hostname/IP
4. Check firewall settings

### "Not enough parties"

Make sure you start exactly `n` parties with IDs `0` to `n-1`.

### Parties stuck "Connecting..."

- Coordinator may not be ready
- Wrong address/port
- Firewall blocking connection

**Solution**:
1. Start coordinator first
2. Wait for "Listening on..." message
3. Then start parties

---

## What's Happening Under the Hood

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

---

## Next Steps

- **Read**: Full documentation in [`examples/DISTRIBUTED_EXAMPLE.md`](examples/DISTRIBUTED_EXAMPLE.md)
- **Customize**: Modify the protocol for your use case
- **Secure**: Add TLS, authentication, and other security features
- **Deploy**: Use in your distributed application

---

## Security Reminder

⚠️ **This example uses unencrypted TCP connections**

For production:
- ✅ Use TLS/SSL
- ✅ Authenticate parties
- ✅ Use distributed trusted setup (don't let coordinator generate tau alone)
- ✅ Validate all messages
- ✅ Implement rate limiting

See [`examples/DISTRIBUTED_EXAMPLE.md`](examples/DISTRIBUTED_EXAMPLE.md) for detailed security considerations.

---

## Questions?

- Check [`README.md`](README.md) for overview
- Check [`examples/DISTRIBUTED_EXAMPLE.md`](examples/DISTRIBUTED_EXAMPLE.md) for details
- Report issues at https://github.com/your-repo/issues
