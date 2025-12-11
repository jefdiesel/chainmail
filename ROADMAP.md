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

**Infrastructure:**
- Cloudflare Worker (indexer logic, cron every 10-30 sec)
- Cloudflare D1 (SQLite at edge, 5M rows / 5GB free)
- Alchemy Base RPC (300M compute units/mo free)
  - ~25M CUs/month for continuous indexing (12x headroom)
  - eth_getBlockByNumber: ~20 CUs
  - eth_getLogs: 75 CUs

**Schema:**
```sql
CREATE TABLE wraps (
  tx_hash TEXT PRIMARY KEY,
  block_number INTEGER,
  block_timestamp INTEGER,
  from_address TEXT,
  sender_identity_key TEXT,
  recipient_identity_keys TEXT,  -- JSON array
  calldata_size INTEGER
);
CREATE INDEX idx_recipient ON wraps(recipient_identity_keys);
CREATE INDEX idx_sender ON wraps(sender_identity_key);
```

**Index Compression (future):**
- Offload indexed wrap tx hashes to chain as batched tx
- 1,111 tx hashes per batch (~73KB, safe margin)
- Periodic checkpoint: "all wraps from block X to Y are indexed"
- Self-referential: wrap index stored via wrap protocol
- Decentralizes the index itself
- Anyone can verify/rebuild index from chain

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

### M1: Protocol Complete
- [x] X3DH multi-recipient encryption
- [x] Chunking for large payloads
- [x] `data:wrap,` calldata format
- [x] Test suite passing
- [ ] npm package published

### M2: Indexer Live
- [ ] CF Worker scanning Base blocks
- [ ] D1 storing wrap tx metadata
- [ ] API endpoints for query
- [ ] Backfill historical wraps

### M3: Identity
- [x] ENS text record integration (library done)
- [x] Resolve by ENS or address (`resolve('alice.eth')`)
- [ ] Key generation + backup flow (in app)
- [ ] UI to set your own ENS text records

### M4: Messenger MVP
- [ ] Inbox view (list received wraps)
- [ ] Compose + send
- [ ] Decrypt + view messages
- [ ] Basic file attachments

### M5: Drop Box
- [ ] Public inbox via ENS
- [ ] Anonymous sender support
- [ ] Drag-drop upload

### M6: Production
- [ ] Base Account passkey login
- [ ] Mobile responsive
- [ ] Index checkpoints on-chain

---

## Open Questions

- Hosted indexer vs self-hosted only?
- Monetization: API fees, premium features, or pure open source?
- Domain: wrap.to? chainmail.xyz?
- Mobile: PWA first or native apps?
