#!/bin/bash
# Test distributed protocol with TLS 1.3
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}Testing Distributed Silent Threshold Encryption (TLS 1.3)${NC}"
echo -e "${BLUE}This test verifies:${NC}"
echo -e "${BLUE}  • TLS 1.3 certificate generation${NC}"
echo -e "${BLUE}  • TLS handshake between coordinator and parties${NC}"
echo -e "${BLUE}  • Encrypted communication of cryptographic material${NC}"
echo -e "${BLUE}  • Complete threshold encryption protocol${NC}"
echo ""

# Check if release binary exists
BINARY_PATH="./target/release/distributed_protocol"
if [ ! -f "$BINARY_PATH" ]; then
    echo -e "${RED}Error: Release binary not found at $BINARY_PATH${NC}"
    echo ""
    echo -e "${YELLOW}Please build the binary first:${NC}"
    echo -e "${GREEN}cargo build --bin distributed_protocol --features distributed --release${NC}"
    echo ""
    exit 1
fi

# Kill any existing processes
pkill -f distributed_protocol 2>/dev/null || true
sleep 1

# Create logs directory
mkdir -p test_logs
rm -f test_logs/*.log

# Start coordinator in background
echo -e "${YELLOW}Starting coordinator...${NC}"
./target/release/distributed_protocol coordinator \
    --port 9999 --parties 4 --threshold 2 \
    > test_logs/coordinator.log 2>&1 &
COORD_PID=$!

# Wait for coordinator to be ready
sleep 3

if ! ps -p $COORD_PID > /dev/null; then
    echo -e "${RED}Coordinator failed!${NC}"
    cat test_logs/coordinator.log
    exit 1
fi

echo -e "${GREEN}✓ Coordinator running (PID: $COORD_PID)${NC}"

# Start parties in background
for i in {0..3}; do
    echo -e "${YELLOW}Starting party $i...${NC}"
    ./target/release/distributed_protocol party \
        --id $i --coordinator localhost:9999 \
        > test_logs/party_$i.log 2>&1 &
    PARTY_PIDS[$i]=$!
    sleep 0.5
done

echo -e "${GREEN}✓ All parties started${NC}"
echo ""
echo -e "${YELLOW}Running protocol...${NC}"
echo ""

# Wait for coordinator to finish (max 60 seconds)
for i in {1..60}; do
    if ! ps -p $COORD_PID > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Give parties time to finish
sleep 2

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Coordinator Output:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
cat test_logs/coordinator.log

echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Party Outputs:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
for i in {0..3}; do
    echo ""
    echo -e "${GREEN}Party $i:${NC}"
    cat test_logs/party_$i.log
done

# Check results
echo ""
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Test Results:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"

# Verify TLS was used
TLS_VERIFIED=0
if grep -q "TLS certificate ready" test_logs/coordinator.log; then
    echo -e "${GREEN}✓ TLS certificate generated${NC}"
    TLS_VERIFIED=$((TLS_VERIFIED + 1))
fi

if grep -q "TLS 1.3" test_logs/coordinator.log; then
    echo -e "${GREEN}✓ TLS 1.3 enabled${NC}"
    TLS_VERIFIED=$((TLS_VERIFIED + 1))
fi

if grep -q "connected with TLS" test_logs/coordinator.log; then
    echo -e "${GREEN}✓ TLS handshakes successful${NC}"
    TLS_VERIFIED=$((TLS_VERIFIED + 1))
fi

# Check for party TLS connections
PARTY_TLS_COUNT=$(grep -h "TLS connection established" test_logs/party_*.log 2>/dev/null | wc -l)
if [ "$PARTY_TLS_COUNT" -eq 4 ]; then
    echo -e "${GREEN}✓ All 4 parties connected via TLS${NC}"
    TLS_VERIFIED=$((TLS_VERIFIED + 1))
fi

# Verify protocol success
if grep -q "SUCCESS" test_logs/coordinator.log; then
    echo -e "${GREEN}✓ Threshold encryption protocol completed${NC}"
    echo ""

    if [ "$TLS_VERIFIED" -ge 3 ]; then
        echo -e "${GREEN}✅ TEST PASSED: TLS-enabled distributed protocol works correctly!${NC}"
        EXIT_CODE=0
    else
        echo -e "${YELLOW}⚠️  Protocol succeeded but TLS verification incomplete${NC}"
        EXIT_CODE=1
    fi
else
    echo -e "${RED}❌ TEST FAILED: Protocol did not complete successfully${NC}"
    EXIT_CODE=1
fi
echo -e "${YELLOW}═══════════════════════════════════════════════${NC}"

# Cleanup
pkill -f distributed_protocol 2>/dev/null || true

exit $EXIT_CODE
