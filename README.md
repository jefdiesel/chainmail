
# Chainmail — Encrypted On-Chain Messaging

Chainmail is a browser-based end-to-end encrypted messaging app that stores encrypted messages on-chain as ethscriptions. 

**v2.0 Security Upgrade**: Now uses wallet-signature-based key derivation instead of deterministic address hashing. All messages use ephemeral keys by default for forward secrecy.

Key features
------------

- **Secure key derivation**: Private keys derived from wallet signatures (not predictable from addresses)
- **Ephemeral encryption**: Random keypair per message (forward secrecy by default)
- **Privacy-first**: Messages self-sent (no wallet history pollution)
- **ENS support**: Send and display ENS names
- **Subject encryption**: Both subject and body encrypted together
- **Optional outbox**: Disable forward secrecy to save copy you can decrypt later

Quick start
-----------

1. Install dependencies

```bash
npm install
```

2. Local development

```bash
# Copy example env and add key
cp .env.example .env
# Add your Alchemy API key in .env
npm run dev
```

Open http://localhost:3000

Deployment (Vercel)
-------------------

Add the environment variable in your Vercel project settings:

- `VITE_ALCHEMY_API_KEY` — your Alchemy API key (optional but required for historical fetching)

If the key is not present, the app will run but will not be able to fetch past messages from the chain.

Files of interest
-----------------

- `App.jsx` — main UI and orchestration
- `crypto.js` — encryption and decryption logic (ECDH + AES-GCM)
- `ethscription.js` — fetching/parsing ethscriptions and Alchemy interactions
- `messageIndex.js` — IndexedDB cache
- `styles.css` — theme and layout

About & source
--------------

Visit the project repository: https://github.com/jefdiesel/chainmail

Security notes
--------------

**v2.0 Architecture**:

- **Recipient keys**: Derived from wallet signature (one-time prompt per session) → only you can decrypt
- **Sender keys**: Random ephemeral keypair per message → forward secrecy (you can't decrypt sent messages)
- **Privacy**: Messages self-sent to your own address (no recipient wallet spam)
- **Protocol**: `chainfeed.online` with base64-encoded JSON payloads

**Breaking change**: Old messages (v1.0) remain encrypted with legacy deterministic keys and cannot be migrated.

**Threat model**:
- ✅ Protects against: Passive surveillance, deterministic key cracking, wallet history analysis
- ✅ Provides: Forward secrecy, deniability (for ephemeral messages)
- ⚠️ Does not protect against: Compromised wallet private key, client-side malware, metadata analysis

This is experimental software. Use with caution.

License
-------

MIT

Author
------

Built by jefdiesel — https://github.com/jefdiesel/chainmail
