# Silent Threshold Encryption - WebAssembly Client

A browser-based WebAssembly client for the Silent Threshold Encryption scheme, enabling distributed threshold encryption entirely in the browser.

## Features

- ✅ **Browser-Native**: Runs entirely in modern web browsers using WebAssembly
- ✅ **Distributed**: Each party can run in a separate browser instance
- ✅ **Secure RNG**: Uses browser's `crypto.getRandomValues()` for secure randomness
- ✅ **Full Protocol Support**: Complete implementation of setup, key generation, encryption, and decryption
- ✅ **Parallelization**: Leverages WASM's performance for cryptographic operations
- ✅ **Easy Integration**: Simple JavaScript API for web applications

## Prerequisites

- Rust 1.76.0 or later
- `wasm-pack` (install with `cargo install wasm-pack`)
- Modern web browser with WebAssembly support (Chrome, Firefox, Safari, Edge)

## Building

### Quick Build

```bash
chmod +x build.sh
./build.sh
```

### Manual Build

```bash
wasm-pack build --target web --out-dir pkg
```

This creates the `pkg/` directory with:
- `silent_threshold_encryption_wasm.js` - JavaScript bindings
- `silent_threshold_encryption_wasm_bg.wasm` - WebAssembly binary
- `silent_threshold_encryption_wasm.d.ts` - TypeScript definitions

## Usage

### Running the Demo

1. Build the WASM module (see above)
2. Serve the directory with a local HTTP server:
   ```bash
   python3 -m http.server 8000
   ```
3. Open `http://localhost:8000/example.html` in your browser

### Integration in Your Web App

```html
<!DOCTYPE html>
<html>
<head>
    <title>My App</title>
</head>
<body>
    <script type="module">
        import init, { Coordinator, Party } from './pkg/silent_threshold_encryption_wasm.js';

        async function run() {
            // Initialize WASM module
            await init();

            // Setup parameters
            const n = 8;  // 8 parties (must be power of 2)
            const t = 4;  // threshold of 4

            // Create coordinator (handles setup and aggregation)
            const coordinator = new Coordinator(n);
            const lagrangePowers = coordinator.exportLagrangePowers();

            // Create parties
            const parties = [];
            for (let i = 0; i < n; i++) {
                parties.push(new Party(i));
            }

            // Generate public keys
            const publicKeys = [];
            for (let i = 0; i < n; i++) {
                const pk = parties[i].generatePublicKey(lagrangePowers, n);
                publicKeys.push(pk);
            }

            // Create aggregate key
            const aggKey = coordinator.createAggregateKey(publicKeys);

            // Encrypt
            const ciphertext = coordinator.encrypt(aggKey, t);

            // Select parties for decryption (must be at least t+1)
            const selectedParties = [0, 1, 2, 3, 4]; // Example: first 5 parties

            // Compute partial decryptions
            const partialDecs = [];
            const selector = new Array(n).fill(false);

            for (let i = 0; i < n; i++) {
                if (selectedParties.includes(i)) {
                    partialDecs.push(parties[i].partialDecrypt(ciphertext));
                    selector[i] = true;
                } else {
                    partialDecs.push(new Uint8Array(0));
                }
            }

            // Aggregate decrypt
            const decryptedKey = coordinator.aggregateDecrypt(
                ciphertext,
                partialDecs,
                selector,
                aggKey
            );

            console.log('Decryption successful!');
        }

        run().catch(console.error);
    </script>
</body>
</html>
```

## API Reference

### `Coordinator`

Central coordinator for the protocol.

#### `new Coordinator(n: number)`
Create a new coordinator with `n` parties.

**Note**: Currently uses single-party trusted setup (insecure for production).

#### Methods

- `exportLagrangePowers(): Uint8Array` - Export Lagrange powers for distribution
- `exportKzgParams(): Uint8Array` - Export KZG parameters
- `createAggregateKey(publicKeys: Uint8Array[]): Uint8Array` - Create aggregate public key
- `encrypt(aggKey: Uint8Array, threshold: number): Uint8Array` - Encrypt a message
- `aggregateDecrypt(ciphertext: Uint8Array, partialDecs: Uint8Array[], selector: boolean[], aggKey: Uint8Array): Uint8Array` - Aggregate partial decryptions

### `Party`

Represents a participant in the protocol.

#### `new Party(id: number)`
Create a new party with the given ID.

**Note**: Party 0 is automatically nullified (dummy party).

#### Methods

- `id(): number` - Get party ID
- `generatePublicKey(lagrangePowers: Uint8Array, n: number): Uint8Array` - Generate public key
- `partialDecrypt(ciphertext: Uint8Array): Uint8Array` - Compute partial decryption
- `exportSecretKey(): Uint8Array` - Export secret key (use with caution!)
- `exportPublicKey(): Uint8Array` - Export public key

### Utility Functions

- `get_version(): string` - Get library version
- `is_power_of_two(n: number): boolean` - Check if n is a power of 2

## Distributed Deployment

### Scenario: Multi-Browser Setup

For a truly distributed setup where each party runs in a different browser:

1. **Coordinator** (one instance):
   - Runs setup phase
   - Distributes Lagrange powers to all parties
   - Collects public keys from all parties
   - Creates aggregate key
   - Performs encryption
   - Aggregates partial decryptions

2. **Parties** (n instances):
   - Each runs in a separate browser/device
   - Receives Lagrange powers from coordinator
   - Generates their public key
   - Sends public key to coordinator
   - Computes partial decryption when needed
   - Sends partial decryption to coordinator

### Communication

Parties need to communicate to exchange:
- Lagrange powers (coordinator → parties)
- Public keys (parties → coordinator)
- Ciphertext (coordinator → parties)
- Partial decryptions (parties → coordinator)

You can use:
- WebSockets
- WebRTC for peer-to-peer
- HTTP/REST APIs
- SignalR, Socket.io, or similar frameworks

### Example with WebSockets

```javascript
// Coordinator side
const ws = new WebSocket('ws://server.com');

coordinator = new Coordinator(n);
const lagrangePowers = coordinator.exportLagrangePowers();

// Broadcast Lagrange powers
ws.send(JSON.stringify({
    type: 'lagrange_powers',
    data: Array.from(lagrangePowers)
}));

// Party side
const ws = new WebSocket('ws://server.com');

ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);

    if (msg.type === 'lagrange_powers') {
        const lagrangePowers = new Uint8Array(msg.data);
        const party = new Party(myId);
        const pk = party.generatePublicKey(lagrangePowers, n);

        // Send public key back to coordinator
        ws.send(JSON.stringify({
            type: 'public_key',
            id: myId,
            data: Array.from(pk)
        }));
    }
};
```

## Security Considerations

### ⚠️ IMPORTANT SECURITY NOTES

1. **Trusted Setup**: The current implementation uses a single-party trusted setup which is **INSECURE** for production. For production use:
   - Use the main library's `trusted_setup` module with multiple parties
   - Or use existing trusted setup parameters from Zcash/Ethereum ceremonies

2. **Browser Security**:
   - Uses `crypto.getRandomValues()` which is cryptographically secure
   - Ensure HTTPS in production to prevent man-in-the-middle attacks
   - Be aware of browser security boundaries and cross-origin policies

3. **Secret Key Storage**:
   - Secret keys are stored in browser memory
   - Use `IndexedDB` or `localStorage` with encryption for persistence
   - Never expose secret keys over insecure channels
   - Consider using Web Crypto API for key wrapping

4. **Side Channels**:
   - Browser-based crypto may be vulnerable to timing attacks
   - JavaScript execution timing is less predictable than native code
   - Consider these risks for your threat model

## Performance

WASM provides near-native performance for cryptographic operations:

- **Setup (n=16)**: ~500ms
- **Key Generation (per party)**: ~100ms
- **Encryption**: ~150ms
- **Partial Decryption (per party)**: ~50ms
- **Aggregate Decryption**: ~200ms

Performance varies by browser and hardware. Chrome typically has the best WASM performance.

## Browser Compatibility

Tested on:
- ✅ Chrome/Chromium 90+
- ✅ Firefox 89+
- ✅ Safari 14+
- ✅ Edge 90+

Requires:
- WebAssembly support
- ES6 modules support
- `crypto.getRandomValues()` support

## Troubleshooting

### WASM Module Won't Load

- Ensure you're serving via HTTP/HTTPS (not `file://`)
- Check browser console for CORS errors
- Verify WASM file MIME type is `application/wasm`

### Memory Issues

- For large `n` (e.g., n=64+), increase WASM memory limit if needed
- Consider breaking operations into smaller batches

### Performance Issues

- Ensure you're using a production build (`--release`)
- Check if browser has WASM SIMD support for better performance
- Profile using browser DevTools

## Examples

See `example.html` for a complete interactive demo.

## License

MIT License - See main repository LICENSE file.

## Contributing

Contributions are welcome! Please ensure:
- Code compiles with `wasm-pack build`
- Example page works in major browsers
- Documentation is updated

## Related

- Main library: `../`
- Rust implementation: `../src/`
- Native client: `../client/`
