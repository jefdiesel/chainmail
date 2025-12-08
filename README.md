
# Chainmail — Encrypted On-Chain Messaging

Chainmail is a browser-based end-to-end encrypted messaging app that stores encrypted messages on-chain as ethscriptions. It encrypts subjects and message bodies together using deterministic ECDH key derivation (from Ethereum addresses) and AES-256-GCM.

Key features
------------

- End-to-end encryption (ECDH-derived keys + AES-256-GCM)
- Optional outbox copy (disable forward secrecy to allow sender decryption)
- Ephemeral messages for forward secrecy (sender cannot decrypt later)
- ENS support for sending and displaying names
- Historical message fetching via Alchemy (requires API key)

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

This is experimental software. Use with caution:

- Keys are derived deterministically from addresses (no private key export)
- Ephemeral messages cannot be decrypted by the sender later (forward secrecy)
- Saving to outbox disables forward secrecy so the sender can decrypt later

License
-------

MIT

Author
------

Built by jefdiesel — https://github.com/jefdiesel/chainmail
