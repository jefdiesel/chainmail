
# Chainmail — Signal Protocol On-Chain Messaging

Chainmail is an end-to-end encrypted messaging app that uses the **Signal Protocol** (X3DH + Double Ratchet) and stores messages on Ethereum as ethscriptions.

**v3.0**: Full Signal Protocol implementation with X3DH key agreement and Double Ratchet algorithm for forward secrecy and post-compromise security.

## Why Signal Protocol?

Signal Protocol is the gold standard for secure messaging, used by Signal, WhatsApp, and Facebook Messenger. It provides:

- **Perfect Forward Secrecy**: Compromising keys now doesn't reveal past messages
- **Post-Compromise Security**: Future messages remain secure even after key compromise
- **Authenticated Encryption**: Cryptographic proof messages haven't been tampered with
- **Asynchronous Communication**: Send messages even when recipient is offline

## Key Features

- **Signal Protocol (X3DH + Double Ratchet)**: Industry-standard end-to-end encryption
- **BIP39 Backup/Restore**: Secure backup with 12-word mnemonic + AES-256-GCM encryption
- **On-chain prekey bundles**: Public keys published as ethscriptions for key exchange
- **Per-wallet identities**: Each Ethereum address has its own Signal identity
- **Forward secrecy**: Every message uses new encryption keys
- **ENS support**: Send to ENS names like vitalik.eth
- **Privacy-first**: Messages self-sent (no recipient address visible on-chain)
- **Browser-native**: Runs entirely in your browser using Web Crypto API

> **Note**: UI/UX improvements are ongoing. Current focus is on refining the user experience and visual design.

## How It Works

### First Time Setup
1. Connect your wallet (MetaMask, etc.)
2. Generate Signal identity (X25519 keys, registration ID)
3. Publish prekey bundle on-chain as ethscription (~$0.20)
4. Ready to send and receive encrypted messages

### Sending a Message
1. Fetch recipient's prekey bundle from chain
2. Perform X3DH handshake to derive shared secret
3. Initialize Double Ratchet with sender's ephemeral DH ratchet key
4. Encrypt message with ratchet-derived key (AES-256-GCM)
5. Self-send encrypted message as ethscription

### Receiving a Message
1. Fetch encrypted messages addressed to you
2. For first message: Perform X3DH handshake, initialize Double Ratchet
3. Advance ratchet state, derive message key
4. Decrypt message (AES-256-GCM with authentication)
5. Display plaintext message

## Quick Start

### Installation

```bash
npm install
```

### Development

```bash
# Copy example env and add your Alchemy API key
cp .env.example .env

# Start dev server
npm run dev
```

Open http://localhost:3000

### First Message Flow

1. **Sender**: Click "Publish Prekeys" (one-time setup, ~$0.20)
2. **Recipient**: Click "Publish Prekeys" (one-time setup, ~$0.20)
3. **Sender**: Enter recipient address/ENS, type message, send
4. **Recipient**: Refresh inbox to see decrypted message

## Technical Architecture

### Cryptographic Primitives

- **X25519**: Elliptic curve Diffie-Hellman (key agreement)
- **HKDF-SHA256**: Key derivation function
- **AES-256-GCM**: Authenticated encryption (message encryption)
- **Ed25519**: Digital signatures (prekey bundle signing)

### Protocol Flow

```
┌─────────────────┐                           ┌─────────────────┐
│  Alice (Sender) │                           │  Bob (Recipient)│
└────────┬────────┘                           └────────┬────────┘
         │                                              │
         │  1. Fetch Bob's prekey bundle               │
         │────────────────────────────────────────────▶│
         │     (identityKey, signedPreKey,             │
         │      initialRatchetKey, oneTimePreKeys)     │
         │                                              │
         │  2. X3DH Handshake                          │
         │     DH1 = DH(IKa, SPKb)                     │
         │     DH2 = DH(EKa, IKb)                      │
         │     DH3 = DH(EKa, SPKb)                     │
         │     DH4 = DH(EKa, OPKb)                     │
         │     SK = HKDF(DH1||DH2||DH3||DH4)           │
         │                                              │
         │  3. Initialize Double Ratchet               │
         │     Generate new DH ratchet keypair         │
         │     Derive root key & chain keys from SK    │
         │                                              │
         │  4. Encrypt message                         │
         │     messageKey = ratchet.nextKey()          │
         │     ciphertext = AES-GCM(messageKey, msg)   │
         │                                              │
         │  5. Send encrypted message on-chain         │
         │────────────────────────────────────────────▶│
         │     (x3dh params, header, iv, ciphertext)   │
         │                                              │
         │                                    6. Receive & decrypt
         │                                       Initialize ratchet from x3dh
         │                                       Derive same messageKey
         │                                       Decrypt with AES-GCM
         │                                              │
```

### File Structure

```
├── App.jsx                 # Main UI & message orchestration
├── About.jsx               # Technical documentation page
├── signalProtocol.js       # X3DH + Double Ratchet core implementation
├── signalStore.js          # Session management & key storage
├── prekeyRegistry.js       # On-chain prekey bundle publishing/fetching
├── crypto.js               # High-level encryption wrapper
├── ethscription.js         # Ethscriptions API & message fetching
├── messageIndex.js         # IndexedDB cache for messages
└── backup.js               # BIP39 backup/restore with AES-256-GCM encryption
```

## Deployment (Vercel)

Add environment variable in Vercel project settings:

- `VITE_ALCHEMY_API_KEY` — Your Alchemy API key (required for message fetching)

## Security Model

### What's Protected ✅

- **Message confidentiality**: Only sender and recipient can read messages
- **Forward secrecy**: Past messages safe even if keys compromised later
- **Post-compromise security**: Future messages safe after re-keying
- **Message authentication**: Cryptographic proof of sender identity
- **Metadata privacy**: Recipient address hidden (messages self-sent)

### Threat Model ⚠️

**Does NOT protect against:**
- Compromised wallet private key (game over)
- Client-side malware (keylogger, screen capture)
- Blockchain metadata analysis (timing, transaction patterns)
- Network traffic analysis (message sizes, timing)

**Breaking changes:**
- v2.0 messages (ephemeral ECDH) cannot be decrypted
- v1.0 messages (deterministic keys) cannot be decrypted

### Key Storage

- **Identity keys**: Stored in browser localStorage (persistent)
- **Prekeys**: Stored locally + published on-chain (public)
- **Session states**: Stored in memory (cleared on page reload)

⚠️ **This is experimental software. Use at your own risk.**

## Protocol Versions

| Version | Protocol | Forward Secrecy | Notes |
|---------|----------|-----------------|-------|
| v1.0 | Deterministic ECDH | ❌ | Deprecated, insecure |
| v2.0 | Ephemeral ECDH + AES-GCM | ✅ | No session continuity |
| **v3.0** | **Signal Protocol (X3DH + Double Ratchet)** | **✅✅** | **Current** |

## FAQ

### How much does it cost?

- Publishing prekeys: ~$0.20 (one-time per wallet)
- Sending message: ~$0.20 per message (Ethereum mainnet)

### Can I decrypt my sent messages?

No. Forward secrecy means you use ephemeral keys that are discarded after sending. This is a security feature, not a bug.

### What if I lose my keys?

Keys are stored in localStorage. If you clear browser data, you lose your keys and session state.

**Backup/Restore available**: Use the "Backup" button to create an encrypted backup:
- Generates a 12-word BIP39 recovery phrase (encryption key)
- Downloads encrypted JSON file with your Signal identity and session state
- To restore: You need BOTH the JSON file AND the 12-word phrase
- Store them separately for security

Without a backup, key loss is permanent and by design for security.

### Can anyone see who I'm messaging?

No. Messages are self-sent to your own address. The actual recipient is encrypted inside the message payload.

### How do I verify it's working?

Check the browser console for logs showing:
- `✅ Signal session initialized`
- X3DH handshake values
- Double Ratchet key derivation
- `🔐 ratchetEncrypt: messageKey: ...`
- `🔓 ratchetDecrypt: messageKey: ...`

### What happens if I send to someone without prekeys?

**Short answer:** Your message is still encrypted, but with fallback encryption instead of full Signal Protocol.

**What this means:**
- The app automatically detects if the recipient hasn't published prekeys yet
- Shows a ⚠️ warning indicator while you're typing their address
- Uses fallback encryption (v2.0: ephemeral ECDH + AES-256-GCM)
- Message is still encrypted end-to-end - only the recipient can read it
- However, it lacks **forward secrecy** - if their keys are compromised later, this message could be decrypted

**Security warning modal:**
When you try to send, a warning appears explaining:
- "Do not send sensitive information"
- Option to copy an invite link to share Chainmail with them
- Requires explicit "I Understand, Send Anyway" confirmation

**Best practices:**
1. **Check the status indicator** - Look for ✅ (full encryption) or ⚠️ (fallback) before typing your message
2. **Share Chainmail first** - Send them the app link and ask them to publish prekeys (takes 30 seconds, costs ~$0.03)
3. **Save sensitive messages** - If you need to send something private, wait for them to set up or use another channel
4. **It's still useful for** - Non-sensitive messages, initial contact, invitations, public announcements

**Think of it like this:** Fallback encryption is like sending a locked box. Full Signal Protocol is like sending a locked box that self-destructs the key after opening and generates a new lock for every message. Both are secure, but Signal Protocol is future-proof against key compromise.

The app makes this easy to understand with real-time status checks and clear warnings. You always know what level of encryption you're getting.

### I received a message - what's this prekey setup about?

**Congrats on your first Chainmail message!** 🎉

Someone sent you an encrypted message. To read it and respond with full Signal Protocol encryption, you need to **publish your prekey bundle** (one-time setup).

**What are prekeys?**
Prekeys are public cryptographic keys that let others send you fully encrypted messages using the Signal Protocol (the same encryption used by Signal messenger and WhatsApp). They enable:
- ✅ **Forward secrecy** - Past messages stay secure even if keys are compromised later
- ✅ **Post-compromise security** - Future messages become secure again after key rotation
- ✅ **Asynchronous messaging** - People can message you even when you're offline

**How to set up (takes 30 seconds):**

1. **Connect your wallet** - Click "Connect Wallet" (top right)
2. **Publish prekeys** - Click the orange "Publish Prekey Bundle" button
3. **Sign the transaction** - Costs about $0.03-0.10 in gas (one-time)
4. **Done!** - You'll see a green ✓ checkmark when ready

**What happens after setup:**
- Future senders can use full Signal Protocol with forward secrecy
- You can respond to messages with Signal Protocol encryption
- The green checkmark shows you're ready
- Others know you're set up for secure messaging

**Note:** If someone already sent you a message before you published prekeys, it was encrypted with fallback encryption (v2.0). You can already read it once you connect your wallet - publishing prekeys only enables Signal Protocol for new messages going forward.

**Why the cost?**
The $0.03 gas fee publishes your prekeys to the Ethereum blockchain (as an ethscription). This is a one-time cost that makes you discoverable for encrypted messaging without any central server. True decentralization has a small price tag.

**No prekeys published?**
You can still receive messages with fallback encryption, but you won't have forward secrecy. If you're only receiving non-sensitive messages, you can skip setup. But for private conversations, publishing prekeys is highly recommended.

[Get Started →](https://chainmail.app)

## Contributing

Issues and PRs welcome! This is experimental cryptographic software - security audits appreciated.

## Resources

- [Signal Protocol Specification](https://signal.org/docs/)
- [X3DH Key Agreement](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [Ethscriptions](https://ethscriptions.com/)

## License

MIT

## Author

Built by jefdiesel — https://github.com/jefdiesel/chainmail

**Powered by the Signal Protocol** — The same encryption used by Signal, WhatsApp, and 2+ billion users worldwide.
