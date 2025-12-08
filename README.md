# ChainFeed - Encrypted Ethscription Messaging

A decentralized, end-to-end encrypted messaging app on Ethereum. Messages are encrypted using deterministic ECDH key derivation from wallet addresses and stored as ethscriptions (on-chain calldata). No server required - all encryption happens client-side.

## Features

- 🔐 **End-to-End Encryption**: Deterministic ECDH + AES-256-GCM encryption
- 🔑 **No Private Key Export**: Keys derived directly from your Ethereum address
- 📬 **On-Chain Storage**: All messages stored as ethscriptions on Ethereum mainnet
- 💾 **Local Caching**: Messages cached in IndexedDB for instant loading
- 🌐 **Fully Decentralized**: No backend servers, all crypto happens in browser
- 🎨 **Clean UI**: Built with React 19 and RainbowKit wallet integration

## How It Works

1. **Deterministic Key Derivation**
   - Each Ethereum address generates a deterministic ECDSA keypair
   - Derived using: `keccak256(address.toLowerCase() + "SecureChat")`
   - No private key exports needed - keys are reproducible from address
   
2. **ECDH Encryption**
   - Sender derives their own keypair and recipient's public key
   - Computes shared secret using ECDH (sender private + recipient public)
   - Encrypts message with AES-256-GCM using shared secret
   - Encrypted data includes sender's public key for decryption
   
3. **Ethscription Storage**
   - Encrypted message sent as transaction calldata
   - Format: `data:,{"p":"chainfeed.online","op":"msg"}<base64_encrypted_data>`
   - Sent to recipient's address with 0 ETH value
   - ~200 bytes per message (vs ~2900 bytes with HTML format)
   
4. **Message Retrieval & Decryption**
   - App queries Alchemy API for transactions to your address
   - Filters for chainfeed.online protocol messages
   - Recipient derives their private key and sender's public key
   - Computes same shared secret and decrypts using AES-GCM

## Installation

```bash
npm install
```

## Environment Setup

Create a `.env` file with your Alchemy API key:

```bash
VITE_ALCHEMY_API_KEY=your_api_key_here
```

## Development

```bash
npm install
npm run dev
```

Opens at http://localhost:3000 (or 3001 if 3000 is in use)

## Building

```bash
npm run build
```

## Usage

1. **Connect Wallet**: Click "Connect Wallet" using RainbowKit (supports MetaMask, WalletConnect, etc.)
2. **Send Message**: 
   - Enter recipient's Ethereum address
   - Type your message
   - Click "Send Encrypted Message"
   - Confirm the transaction in your wallet
3. **Receive Messages**: 
   - Messages automatically load when you connect
   - Click "Refresh Messages" to check for new ones

## Security Notes

⚠️ **Important**: This is experimental cryptographic software. 

- Messages are encrypted end-to-end using deterministic ECDH
- Only the intended recipient can decrypt messages (no one else, including you after sending)
- Keys are derived from your Ethereum address - no private key exports
- Each address always generates the same keypair (deterministic)
- No signatures required - keys derived directly from address
- Old messages (before block 23969000) are filtered out

## Technical Stack

- **Frontend**: React 19, RainbowKit 2.2, Wagmi 2.x, Viem 2.x
- **Blockchain**: Ethereum Mainnet (ethers.js v6)
- **Encryption**: Deterministic ECDH + AES-256-GCM (Web Crypto API)
- **APIs**: Alchemy for transaction history, Ethscriptions API fallback
- **Storage**: IndexedDB for message caching with 5-minute TTL
- **Build**: Vite 5.4

## Protocol

### Message Format
```
data:,{"p":"chainfeed.online","op":"msg"}<base64_json>

Base64 decoded JSON:
{
  "senderPublicKey": "0x04...",
  "iv": "hex_string",
  "ciphertext": "hex_string"
}
```

Where:
- `p`: Protocol identifier (chainfeed.online)
- `op`: Operation type (msg = message, notify = notification)
- `senderPublicKey`: Sender's deterministic public key for ECDH
- `iv`: AES-GCM initialization vector (12 bytes)
- `ciphertext`: AES-256-GCM encrypted message

## Inspired By

- [textmessage.eth](https://github.com/hunterlong/textmessage.eth) - On-chain messaging patterns
- [web3-group-encryption](https://github.com/d1ll0n/web3-group-encryption) - ECDH key management

## License

MIT

## Author

Built with ❤️ for secure, decentralized communication
