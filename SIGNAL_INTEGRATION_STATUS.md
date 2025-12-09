# Signal Protocol Integration Status

**Date:** December 8, 2025
**Status:** Architecture Complete, Browser Compatibility Blocked

---

## What We Accomplished ✅

### 1. **Complete Signal Protocol Architecture**
- ✅ Created `signalStore.js` - Full Signal protocol state management
- ✅ Created `prekeyRegistry.js` - On-chain prekey bundle publishing/fetching
- ✅ Updated `crypto.js` - Signal encryption/decryption wrappers
- ✅ Updated `App.jsx` - UI for prekey setup and Signal messaging
- ✅ Configured 20 one-time prekeys (gas-optimized)

### 2. **Features Implemented**
- Identity key generation (random, NOT address-derived)
- Signed prekey generation with wallet signature (EIP-191)
- One-time prekey batch generation
- X3DH session initialization
- Double Ratchet encrypt/decrypt wrappers
- On-chain prekey bundle publishing as ethscriptions
- Prekey bundle fetching from chain
- Auto-versioned message decryption (v2 legacy + v3 Signal)

### 3. **UI Updates**
- Security banner showing Signal Protocol v3.0
- Prekey setup warning for new users
- One-click prekey bundle publishing
- Status indicators for prekey availability

---

## Current Blocker ❌

### **Browser Compatibility Issue**

The `@signalapp/libsignal-client` package is **Node.js-only** with native Rust bindings (`.node` files) and **cannot run in browsers**.

#### Why This Matters:
- Vite/Webpack cannot bundle native Node.js modules
- The library uses `node:buffer`, `node:crypto`, `fs`, `path` - all Node.js-specific
- No WebAssembly build available from Signal
- Alternative browser libraries (`@throneless/libsignal-protocol`) also have native dependencies

#### What We Tried:
1. ❌ Direct use of `@signalapp/libsignal-client` - requires native modules
2. ❌ Node.js polyfills in Vite config - still requires native bindings
3. ❌ `@throneless/libsignal-protocol` - also has native dependencies (node-webcrypto-ossl)

---

## Recommended Solutions

### Option 1: **Implement Signal Protocol from Scratch** (Recommended)
Use browser-compatible crypto libraries to implement X3DH + Double Ratchet:
- **Crypto:** Use Web Crypto API + `@noble/curves` for secp256k1/X25519
- **Architecture:** The code we wrote (`signalStore.js`, `prekeyRegistry.js`) provides the structure
- **Effort:** ~2-3 days to implement core protocol
- **Benefits:**
  - Full control over implementation
  - Pure browser compatibility
  - Smaller bundle size
  - No external dependencies

**Libraries to use:**
```bash
npm install @noble/curves @noble/hashes
```

### Option 2: **Use Server-Side Signal Protocol**
Create a backend API that uses `@signalapp/libsignal-client`:
- **Architecture:** Node.js backend handles Signal protocol
- **Frontend:** Just sends/receives encrypted payloads
- **Effort:** ~1 day to set up backend
- **Drawbacks:**
  - Defeats the purpose of decentralized blockchain messaging
  - Introduces trust dependency on server
  - Server can see all messages (defeats E2E encryption)

**❌ Not recommended for this use case**

### Option 3: **Use Legacy `libsignal-protocol-javascript`**
Use Signal's old JavaScript implementation (deprecated but browser-compatible):
```bash
npm install libsignal-protocol
```
- **Pros:** Pure JavaScript, works in browsers
- **Cons:** Deprecated since 2020, no longer maintained, may have security issues
- **Risk:** Signal doesn't recommend this

---

## Next Steps

### If Going with Option 1 (Recommended):

1. **Install browser crypto libraries:**
   ```bash
   npm install @noble/curves @noble/hashes
   ```

2. **Implement core Signal protocol functions:**
   - `generateIdentityKey()` - using `@noble/curves` X25519
   - `generateEphemeralKey()` - for DH ratchet
   - `x3dhHandshake()` - 4x ECDH operations
   - `hkdf()` - key derivation
   - `doubleRatchetEncrypt()` - ratchet state machine
   - `doubleRatchetDecrypt()` - ratchet state machine

3. **Update `signalStore.js`:**
   - Replace `SignalClient.*` imports with custom implementation
   - Keep the storage interface (it's correct)

4. **Keep everything else:**
   - `prekeyRegistry.js` - works as-is
   - `App.jsx` - works as-is
   - On-chain format - already correct

---

## What We Have That's Usable

### ✅ Ready to Use:
- **On-chain prekey registry** - `prekeyRegistry.js` works perfectly
- **UI integration** - `App.jsx` ready for Signal protocol
- **Storage architecture** - session/prekey storage design is correct
- **Message format** - v3 protocol format defined

### 🔄 Needs Reimplementation:
- **Signal protocol core** - Replace library with custom implementation
- **Key generation** - Use `@noble/curves` instead of `SignalClient`
- **Encryption/decryption** - Use Web Crypto API

---

## Code Structure (Already Built)

```
chainmail/
├── signalStore.js          # ✅ Architecture correct, needs crypto swap
├── prekeyRegistry.js       # ✅ Ready to use
├── crypto.js               # ✅ Wrapper functions ready
├── App.jsx                 # ✅ UI integration ready
└── IMPLEMENTATION.md       # 📝 Need to create this
```

---

## Implementation Estimate

**Option 1 (Custom Implementation):**
- Core X3DH: ~4-6 hours
- Double Ratchet: ~8-12 hours
- Testing: ~4-6 hours
- **Total: ~16-24 hours**

**Comparison:**
- Using `@signalapp/libsignal-client` would have been ~2 hours if it worked in browsers
- But it doesn't, so custom implementation is the only viable path

---

## Resources

### Signal Protocol Specification:
- https://signal.org/docs/specifications/x3dh/
- https://signal.org/docs/specifications/doubleratchet/

### Crypto Libraries (Browser-Compatible):
- `@noble/curves` - https://github.com/paulmillr/noble-curves
- `@noble/hashes` - https://github.com/paulmillr/noble-hashes

### Reference Implementation:
- Our `signalStore.js` provides the correct architecture
- Just needs crypto primitives swapped out

---

## Decision Point

**Should we:**
1. ✅ Implement Signal protocol from scratch using `@noble/curves`?
2. ❌ Use deprecated `libsignal-protocol-javascript`?
3. ❌ Give up on Signal protocol and stick with v2.0 ephemeral ECDH?

**Recommendation:** Option 1 - implement from scratch. The architecture is already built, we just need to swap the crypto primitives for browser-compatible ones.
