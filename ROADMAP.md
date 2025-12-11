# Wrap Protocol Roadmap

## Vision

Encrypted on-chain archival and messaging. ENS for public identities, raw addresses for private. No servers, no custody, no trust.

---

## Phase 1: Core Infrastructure

### Indexer
- [ ] Scan Base blocks for `data:wrap,` calldata
- [ ] Index by sender/recipient identity keys
- [ ] Track chunk sets (id, parts received, complete status)
- [ ] Store tx hashes + block numbers for retrieval
- [ ] Support historical backfill + live streaming
- [ ] SQLite for local, Postgres for hosted

### ENS Integration
- [ ] Set wrap keys via ENS app (text records)
  - `wrap.identityKey` - X25519 identity public key
  - `wrap.signedPreKey` - X25519 signed prekey
- [ ] Resolve recipients by ENS name
- [ ] Support base.eth subnames (Basenames)
- [ ] Key rotation flow (update ENS, re-announce)

---

## Phase 2: API Layer

### Archive Recall API
- [ ] `GET /messages` - List messages for identity
- [ ] `GET /messages/:id` - Get specific message/file
- [ ] `GET /messages/:id/chunks` - Get chunk status
- [ ] `POST /send` - Wrap + broadcast to Base
- [ ] `GET /identity/:ens` - Resolve ENS to bundle
- [ ] `GET /identity/:address` - Lookup by address
- [ ] WebSocket for real-time message notifications
- [ ] Rate limiting + API keys for hosted version

### SDK
- [ ] `@chainmail/wrap` npm package (done)
- [ ] `@chainmail/client` - API client
- [ ] React hooks: `useMessages`, `useIdentity`, `useSend`

---

## Phase 3: Messenger App

### Core Features
- [ ] Clean modern UI (email-style inbox)
- [ ] Conversation threads by sender
- [ ] Compose with recipient lookup (ENS or address)
- [ ] Attachment support (images, documents)
- [ ] Chunk progress indicator for large files
- [ ] Read/unread status (local)
- [ ] Search messages (local decrypt + search)

### Identity
- [ ] Generate keypair on first launch
- [ ] Seed phrase backup (BIP39)
- [ ] Import existing keys
- [ ] ENS linking flow
- [ ] Multiple identities support

### UX
- [ ] Desktop-first (Electron or web)
- [ ] Mobile responsive
- [ ] Dark mode
- [ ] Notifications (new messages)
- [ ] Offline support (cached messages)

---

## Phase 4: Drop Box

### Public File Inbox
- [ ] Generate shareable link: `wrap.to/alice.eth`
- [ ] Anyone can drop encrypted files
- [ ] No account needed for senders
- [ ] Size limits configurable
- [ ] Auto-expire links option

### Features
- [ ] Drag-and-drop upload
- [ ] Progress indicator (chunking + broadcast)
- [ ] Receipt confirmation (tx hash)
- [ ] Optional sender identification
- [ ] Spam protection (captcha or small fee)

---

## Phase 5: Future

### Base Account Integration
- [ ] Passkey-based smart wallet onboarding
- [ ] No seed phrase, no wallet install friction
- [ ] One-tap USDC payments for premium features
- [ ] Universal identity across Base apps
- [ ] Self-custodial (we never touch keys)
- [ ] Ref: https://docs.base.org/base-account/overview/what-is-base-account

### WebAuthn PRF (see FUTURE_IDEAS.md)
- [ ] Passkey-derived encryption keys (for wrap protocol itself)
- [ ] Combine with Base Account for seamless UX
- [ ] No seed phrase needed
- [ ] Hardware-backed security
- [ ] Wait for broader platform support (~2026)

### Advanced Features
- [ ] Group messaging (shared symmetric key)
- [ ] Disappearing messages (time-locked decrypt)
- [ ] Multi-chain support (other L2s)
- [ ] IPFS fallback for very large files
- [ ] Mobile apps (iOS/Android)

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Protocol | X3DH + AES-256-GCM |
| Chain | Base L2 (OP Stack) |
| Indexer | Node.js + SQLite/Postgres |
| API | Hono or Express |
| Frontend | React + Vite + TailwindCSS |
| Wallet | RainbowKit + wagmi |
| Keys | @noble/curves (X25519) |

---

## Milestones

1. **v0.1** - Indexer + basic message retrieval
2. **v0.2** - ENS integration + API
3. **v0.3** - Messenger app MVP
4. **v0.4** - Drop box feature
5. **v1.0** - Production ready

---

## Open Questions

- Hosted indexer vs self-hosted only?
- Monetization: API fees, premium features, or pure open source?
- Domain: wrap.to? chainmail.xyz?
- Mobile: PWA first or native apps?
