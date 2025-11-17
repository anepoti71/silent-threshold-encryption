#!/bin/bash

# Build script for WASM client
set -e

echo "Building Silent Threshold Encryption WASM Client..."

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "Error: wasm-pack is not installed"
    echo "Install it with: cargo install wasm-pack"
    exit 1
fi

# Build for web
echo "Building for web target..."
wasm-pack build --target web --out-dir pkg

echo "Build complete! Output is in pkg/"
echo ""
echo "To use in a web page:"
echo "1. Serve the directory with a local HTTP server"
echo "2. Import the module: import init, { Coordinator, Party } from './pkg/silent_threshold_encryption_wasm.js'"
echo ""
echo "Example: python3 -m http.server 8000"
