#!/bin/bash
# Helper script to run the distributed threshold encryption example
# Usage: ./run_distributed.sh [n_parties] [threshold] [port]

set -e

# Default values
N_PARTIES=${1:-4}
THRESHOLD=${2:-2}
PORT=${3:-8080}

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Distributed Silent Threshold Encryption${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}Configuration:${NC}"
echo -e "  Parties (n):  ${YELLOW}${N_PARTIES}${NC}"
echo -e "  Threshold (t): ${YELLOW}${THRESHOLD}${NC}"
echo -e "  Port:          ${YELLOW}${PORT}${NC}"
echo ""

# Validate inputs
if [ $((N_PARTIES)) -lt 2 ]; then
    echo -e "${RED}Error: Number of parties must be at least 2${NC}"
    exit 1
fi

if [ $((THRESHOLD)) -ge $((N_PARTIES)) ]; then
    echo -e "${RED}Error: Threshold must be less than number of parties${NC}"
    exit 1
fi

# Check if n is a power of 2
if [ $((N_PARTIES & (N_PARTIES - 1))) -ne 0 ]; then
    echo -e "${YELLOW}Warning: n should be a power of 2 for optimal performance${NC}"
    # Find next power of 2
    NEXT_POW2=1
    while [ $NEXT_POW2 -lt $N_PARTIES ]; do
        NEXT_POW2=$((NEXT_POW2 * 2))
    done
    echo -e "${YELLOW}Suggested value: ${NEXT_POW2}${NC}"
    echo ""
fi

# Build the example
echo -e "${GREEN}Building distributed protocol...${NC}"
cargo build --example distributed_protocol --features distributed --release

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"
echo ""

# Create log directory
mkdir -p logs

# Function to cleanup background processes
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${NC}"
    kill $(jobs -p) 2>/dev/null
    wait 2>/dev/null
    echo -e "${GREEN}All processes stopped${NC}"
}

trap cleanup EXIT INT TERM

# Start coordinator in background
echo -e "${BLUE}Starting coordinator on port ${PORT}...${NC}"
./target/release/examples/distributed_protocol coordinator \
    --port "$PORT" \
    --parties "$N_PARTIES" \
    --threshold "$THRESHOLD" \
    > logs/coordinator.log 2>&1 &

COORDINATOR_PID=$!

# Wait for coordinator to be ready
sleep 2

if ! ps -p $COORDINATOR_PID > /dev/null; then
    echo -e "${RED}Coordinator failed to start!${NC}"
    cat logs/coordinator.log
    exit 1
fi

echo -e "${GREEN}✓ Coordinator started (PID: $COORDINATOR_PID)${NC}"
echo ""

# Start all parties
echo -e "${BLUE}Starting ${N_PARTIES} parties...${NC}"
for i in $(seq 0 $((N_PARTIES - 1))); do
    echo -e "  Starting party ${i}..."
    ./target/release/examples/distributed_protocol party \
        --id "$i" \
        --coordinator "localhost:${PORT}" \
        > "logs/party_${i}.log" 2>&1 &

    PARTY_PID=$!

    # Brief pause to avoid overwhelming the coordinator
    sleep 0.1

    if ! ps -p $PARTY_PID > /dev/null; then
        echo -e "${RED}Party ${i} failed to start!${NC}"
        cat "logs/party_${i}.log"
        exit 1
    fi
done

echo -e "${GREEN}✓ All parties started${NC}"
echo ""

# Monitor coordinator output
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Protocol Execution (Coordinator Log)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo ""

# Tail coordinator log and wait for completion
tail -f logs/coordinator.log &
TAIL_PID=$!

# Wait for coordinator to finish
wait $COORDINATOR_PID
COORDINATOR_EXIT_CODE=$?

# Stop tailing
kill $TAIL_PID 2>/dev/null || true

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"

if [ $COORDINATOR_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Protocol completed successfully!${NC}"
    echo ""
    echo -e "${GREEN}Summary:${NC}"
    echo -e "  Total parties:    ${N_PARTIES}"
    echo -e "  Threshold:        ${THRESHOLD}"
    echo -e "  Required signers: $((THRESHOLD + 1))"
    echo ""
    echo -e "Logs available in: ${BLUE}logs/${NC}"
    echo -e "  - coordinator.log"
    for i in $(seq 0 $((N_PARTIES - 1))); do
        echo -e "  - party_${i}.log"
    done
else
    echo -e "${RED}❌ Protocol failed with exit code: $COORDINATOR_EXIT_CODE${NC}"
    echo ""
    echo -e "${RED}Check logs for details:${NC}"
    echo -e "  Coordinator: logs/coordinator.log"
    echo -e "  Parties: logs/party_*.log"
fi

echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
