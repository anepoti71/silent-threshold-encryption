#!/bin/bash
# Test P2P Silent Threshold Encryption with Signature Verification
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}Testing P2P Silent Threshold Encryption${NC}"
echo -e "${BLUE}This test verifies:${NC}"
echo -e "${BLUE}  • Fully decentralized peer-to-peer protocol${NC}"
echo -e "${BLUE}  • Ed25519 signature verification on public keys${NC}"
echo -e "${BLUE}  • Ed25519 signature verification on partial decryptions${NC}"
echo -e "${BLUE}  • libp2p gossip-based communication${NC}"
echo -e "${BLUE}  • Complete threshold encryption protocol${NC}"
echo ""

# Check if release binaries exist
P2P_BINARY="./target/release/p2p_peer"
PARAM_GEN="./target/release/generate_peer_params"

if [ ! -f "$P2P_BINARY" ]; then
    echo -e "${RED}Error: P2P peer binary not found at $P2P_BINARY${NC}"
    echo ""
    echo -e "${YELLOW}Please build the binary first:${NC}"
    echo -e "${GREEN}cargo build --bin p2p_peer --features distributed --release${NC}"
    echo ""
    exit 1
fi

if [ ! -f "$PARAM_GEN" ]; then
    echo -e "${RED}Error: Parameter generation binary not found at $PARAM_GEN${NC}"
    echo ""
    echo -e "${YELLOW}Please build the binary first:${NC}"
    echo -e "${GREEN}cargo build --bin generate_peer_params --features distributed --release${NC}"
    echo ""
    exit 1
fi

# Kill any existing processes
pkill -f p2p_peer 2>/dev/null || true
sleep 1

# Create logs and artifacts directories
mkdir -p test_logs
mkdir -p artifacts/p2p
rm -f test_logs/p2p_*.log

echo -e "${YELLOW}Checking local networking permissions...${NC}"
if ! python3 - <<'PY' >/dev/null 2>&1; then
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
s.close()
PY
    echo -e "${YELLOW}⚠ Networking is not permitted in this environment; skipping P2P test.${NC}"
    exit 0
fi

# Precompute bootstrap lists for manual discovery (mDNS is disabled in CI/sandbox)
BOOTSTRAP_0=(--bootstrap /ip4/127.0.0.1/tcp/9001 --bootstrap /ip4/127.0.0.1/tcp/9002 --bootstrap /ip4/127.0.0.1/tcp/9003)
BOOTSTRAP_1=(--bootstrap /ip4/127.0.0.1/tcp/9000 --bootstrap /ip4/127.0.0.1/tcp/9002 --bootstrap /ip4/127.0.0.1/tcp/9003)
BOOTSTRAP_2=(--bootstrap /ip4/127.0.0.1/tcp/9000 --bootstrap /ip4/127.0.0.1/tcp/9001 --bootstrap /ip4/127.0.0.1/tcp/9003)
BOOTSTRAP_3=(--bootstrap /ip4/127.0.0.1/tcp/9000 --bootstrap /ip4/127.0.0.1/tcp/9001 --bootstrap /ip4/127.0.0.1/tcp/9002)

# Generate shared KZG and Lagrange parameters
echo -e "${YELLOW}Generating shared cryptographic parameters...${NC}"
echo -e "${CYAN}  • Parties: 4${NC}"
echo -e "${CYAN}  • Threshold: 2${NC}"
echo -e "${CYAN}  • Seed: 42 (deterministic)${NC}"

$PARAM_GEN --parties 4 --seed 42 --output-dir artifacts/p2p > test_logs/param_gen.log 2>&1

if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to generate parameters!${NC}"
    cat test_logs/param_gen.log
    exit 1
fi

echo -e "${GREEN}✓ Parameters generated${NC}"
echo -e "${CYAN}  • KZG params: artifacts/p2p/kzg_params.bin${NC}"
echo -e "${CYAN}  • Lagrange params: artifacts/p2p/lagrange_params.bin${NC}"
echo ""

# Start peers in background (all on different ports)
echo -e "${YELLOW}Starting P2P peers...${NC}"

# Party 0 (Initiator with auto-decrypt)
echo -e "${CYAN}  • Party 0 (Initiator) on /ip4/127.0.0.1/tcp/9000${NC}"
$P2P_BINARY \
    --party-id 0 \
    --parties 4 \
    --threshold 2 \
    --listen /ip4/127.0.0.1/tcp/9000 \
    --mode initiator \
    --auto-decrypt \
    --disable-mdns \
    "${BOOTSTRAP_0[@]}" \
    > test_logs/p2p_party0.log 2>&1 &
PARTY0_PID=$!
sleep 1

# Party 1 (Passive)
echo -e "${CYAN}  • Party 1 (Passive) on /ip4/127.0.0.1/tcp/9001${NC}"
$P2P_BINARY \
    --party-id 1 \
    --parties 4 \
    --threshold 2 \
    --listen /ip4/127.0.0.1/tcp/9001 \
    --disable-mdns \
    "${BOOTSTRAP_1[@]}" \
    > test_logs/p2p_party1.log 2>&1 &
PARTY1_PID=$!
sleep 1

# Party 2 (Passive)
echo -e "${CYAN}  • Party 2 (Passive) on /ip4/127.0.0.1/tcp/9002${NC}"
$P2P_BINARY \
    --party-id 2 \
    --parties 4 \
    --threshold 2 \
    --listen /ip4/127.0.0.1/tcp/9002 \
    --disable-mdns \
    "${BOOTSTRAP_2[@]}" \
    > test_logs/p2p_party2.log 2>&1 &
PARTY2_PID=$!
sleep 1

# Party 3 (Passive)
echo -e "${CYAN}  • Party 3 (Passive) on /ip4/127.0.0.1/tcp/9003${NC}"
$P2P_BINARY \
    --party-id 3 \
    --parties 4 \
    --threshold 2 \
    --listen /ip4/127.0.0.1/tcp/9003 \
    --disable-mdns \
    "${BOOTSTRAP_3[@]}" \
    > test_logs/p2p_party3.log 2>&1 &
PARTY3_PID=$!

echo -e "${GREEN}✓ All peers started${NC}"
echo -e "${CYAN}  • Party 0 PID: $PARTY0_PID${NC}"
echo -e "${CYAN}  • Party 1 PID: $PARTY1_PID${NC}"
echo -e "${CYAN}  • Party 2 PID: $PARTY2_PID${NC}"
echo -e "${CYAN}  • Party 3 PID: $PARTY3_PID${NC}"
echo ""

echo -e "${YELLOW}Running protocol (waiting 25 seconds for peer discovery and completion)...${NC}"
echo -e "${CYAN}  • Waiting for mDNS discovery...${NC}"
sleep 5
echo -e "${CYAN}  • Waiting for gossipsub mesh formation...${NC}"
sleep 5
echo -e "${CYAN}  • Waiting for protocol execution...${NC}"
sleep 15

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Party 0 Output (Initiator):${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
cat test_logs/p2p_party0.log

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Party 1 Output:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
cat test_logs/p2p_party1.log

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Party 2 Output:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
cat test_logs/p2p_party2.log

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Party 3 Output:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
cat test_logs/p2p_party3.log

# Check results
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Test Results:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"

EXIT_CODE=0

# Count signature verifications
PUBKEY_SIG_COUNT=$(grep -h "✓ Verified signature for public key" test_logs/p2p_party*.log 2>/dev/null | wc -l | tr -d ' ')
PARTIAL_SIG_COUNT=$(grep -h "✓ Verified signature for partial decryption" test_logs/p2p_party*.log 2>/dev/null | wc -l | tr -d ' ')

echo -e "${CYAN}Signature Verification:${NC}"
if [ "$PUBKEY_SIG_COUNT" -ge 12 ]; then
    echo -e "${GREEN}✓ Public key signatures verified: $PUBKEY_SIG_COUNT (expected ≥12)${NC}"
else
    echo -e "${RED}✗ Public key signatures verified: $PUBKEY_SIG_COUNT (expected ≥12)${NC}"
    EXIT_CODE=1
fi

if [ "$PARTIAL_SIG_COUNT" -ge 3 ]; then
    echo -e "${GREEN}✓ Partial decryption signatures verified: $PARTIAL_SIG_COUNT (expected ≥3)${NC}"
else
    echo -e "${RED}✗ Partial decryption signatures verified: $PARTIAL_SIG_COUNT (expected ≥3)${NC}"
    EXIT_CODE=1
fi

# Check peer discovery
PEER_CONNECTED=$(grep -h "PeerConnected" test_logs/p2p_party*.log 2>/dev/null | wc -l | tr -d ' ')
if [ "$PEER_CONNECTED" -ge 4 ]; then
    echo -e "${GREEN}✓ Peer discovery working: $PEER_CONNECTED connections${NC}"
else
    echo -e "${YELLOW}⚠ Peer discovery: $PEER_CONNECTED connections (may still work via mDNS)${NC}"
fi

# Check aggregate key construction
AGG_KEY_COUNT=$(grep -h "Aggregate key constructed" test_logs/p2p_party*.log 2>/dev/null | wc -l | tr -d ' ')
if [ "$AGG_KEY_COUNT" -ge 4 ]; then
    echo -e "${GREEN}✓ All parties constructed aggregate key${NC}"
else
    echo -e "${RED}✗ Only $AGG_KEY_COUNT parties constructed aggregate key (expected 4)${NC}"
    EXIT_CODE=1
fi

# Check encryption
if grep -q "Aggregate key ready; initiating encryption" test_logs/p2p_party0.log 2>/dev/null; then
    echo -e "${GREEN}✓ Initiator encrypted message${NC}"
else
    echo -e "${RED}✗ Encryption not initiated${NC}"
    EXIT_CODE=1
fi

# Check ciphertext broadcast
CT_RECEIVED=$(grep -h "Received ciphertext broadcast" test_logs/p2p_party*.log 2>/dev/null | wc -l | tr -d ' ')
if [ "$CT_RECEIVED" -ge 1 ]; then
    echo -e "${GREEN}✓ Ciphertext broadcast received by parties${NC}"
else
    echo -e "${RED}✗ Ciphertext not broadcast${NC}"
    EXIT_CODE=1
fi

# Check partial decryptions
# Count responses from passive parties + check if initiator included itself
PARTIAL_RESPONSES=$(grep -h "Responding to partial decryption request" test_logs/p2p_party*.log 2>/dev/null | wc -l | tr -d ' ')
PARTIAL_RESPONSES=$(echo "${PARTIAL_RESPONSES:-0}" | tr -d '[:space:]')
if [ -z "$PARTIAL_RESPONSES" ]; then
    PARTIAL_RESPONSES=0
fi
INITIATOR_INCLUDED=$(grep -h "Requesting partial decryptions from parties" test_logs/p2p_party0.log 2>/dev/null | grep -c "\[0," || true)
INITIATOR_INCLUDED=$(echo "${INITIATOR_INCLUDED:-0}" | tr -d '[:space:]')
if [ -z "$INITIATOR_INCLUDED" ]; then
    INITIATOR_INCLUDED=0
fi
PARTIAL_COUNT=$((PARTIAL_RESPONSES + INITIATOR_INCLUDED))

if [ "$PARTIAL_COUNT" -ge 3 ]; then
    echo -e "${GREEN}✓ Partial decryptions generated: $PARTIAL_COUNT (${PARTIAL_RESPONSES} responses + ${INITIATOR_INCLUDED} local)${NC}"
else
    echo -e "${RED}✗ Only $PARTIAL_COUNT partial decryptions (expected ≥3): ${PARTIAL_RESPONSES} responses + ${INITIATOR_INCLUDED} local${NC}"
    EXIT_CODE=1
fi

# Check successful decryption
if grep -q "Recovered encrypted key" test_logs/p2p_party0.log 2>/dev/null; then
    echo -e "${GREEN}✓ Decryption successful (key recovered)${NC}"
else
    echo -e "${RED}✗ Decryption did not complete${NC}"
    EXIT_CODE=1
fi

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ TEST PASSED: P2P threshold encryption with signature verification works!${NC}"
else
    echo -e "${RED}❌ TEST FAILED: See logs above for details${NC}"
fi
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"

# Cleanup
pkill -f p2p_peer 2>/dev/null || true

exit $EXIT_CODE
