# Chainmail - Current Status

**Date:** December 8, 2025  
**Version:** v2.0 (in progress)

---

## ✅ What's Working

### Message Fetching
- ✅ Ethscriptions API integration working
- ✅ Queries `mimetype=text/plain` to get all text ethscriptions
- ✅ Client-side filtering for `chainfeed.online` protocol
- ✅ Recipient address filtering (checks `to` field in encrypted payload)
- ✅ Self-send architecture (messages sent to sender's own address)
- ✅ Proper API response handling (direct array vs wrapped object)

### Message Display
- ✅ Messages appear in UI
- ✅ Real-time decryption working
- ✅ ENS name resolution for sender addresses
- ✅ Timestamp display
- ✅ Transaction link to Etherscan
- ✅ Reply functionality

### UI/UX
- ✅ RainbowKit wallet connection
- ✅ React Router navigation (home + about page)
- ✅ Detailed About page with full documentation
- ✅ Navigation links in header next to logo
- ✅ Clean lime-green theme
- ✅ Security notice banner

---

## 🔧 Current Implementation

### Encryption/Decryption
**Status:** Using deterministic keys (v1.0 method)

```javascript
// Sending (crypto.js:101)
const recipientPublicKey = derivePublicKeyFromAddress(recipientAddress);

// Receiving (App.jsx:222)
const { privateKey } = deriveKeypairFromAddress(address);
```

**Key Derivation:**
```javascript
keccak256(address.toLowerCase() + "SecureChat")
```

**Encryption Method:**
- ECDH shared secret from sender private + recipient public
- AES-256-GCM symmetric encryption
- Ephemeral sender keys by default (forward secrecy)
- Optional "Save to Outbox" for persistent sender keys

### Message Format
```json
{
  "to": "0xRecipientAddress",
  "senderPublicKey": "0x04...",
  "iv": "hex",
  "ciphertext": "hex",
  "saveOutbox": false
}
```

### Protocol Format
```
data:,{"p":"chainfeed.online","op":"msg"}base64EncodedPayload
```

---

## ⚠️ Known Issues

### Security
1. **Deterministic Key Derivation** (CRITICAL)
   - Keys derived from public address alone
   - Anyone can compute recipient's private key: `keccak256(address + "SecureChat")`
   - No wallet signature required
   - **Fix:** Implement wallet-signature key derivation (partially implemented but disabled)

2. **No Key Exchange Mechanism**
   - Sender encrypts using recipient's deterministic public key
   - Recipient needs same derivation method to decrypt
   - Cannot switch to wallet-signature keys without coordination
   - **Fix:** Need public key registry or key exchange protocol

### Functional
3. **Old Message Compatibility**
   - Old `secrechat` protocol messages cause parse errors
   - Fixed by filtering them out, but they're in IndexedDB cache
   - **Fix:** Clear IndexedDB or migrate old messages

4. **IndexedDB Not Used**
   - Messages fetched fresh every time (no caching)
   - `getCachedMessages` queries by `to` field, but v2.0 messages self-send
   - **Fix:** Either fix cache queries or remove IndexedDB entirely

5. **ENS CORS Errors**
   - ENS lookups failing due to CORS on euc.li
   - Non-blocking but spammy in console
   - **Fix:** Use different ENS resolver or handle CORS properly

---

## 🚧 Partially Implemented (Disabled)

### Wallet-Signature Key Derivation
**Code exists but not active:**

```javascript
// crypto.js:33-53
export async function deriveKeypairFromWalletSignature(signMessageFn, address) {
    const message = `Chainmail v2.0 Messaging Key\n\nAddress: ${address.toLowerCase()}`;
    const signature = await signMessageFn({ message });
    const seed = ethers.keccak256(signature);
    const privateKey = '0x' + seed.slice(2, 66);
    // ...
}
```

**Why disabled:**
- Sender encrypts with `derivePublicKeyFromAddress(recipientAddress)`
- Recipient would decrypt with wallet-signature derived key
- Keys don't match → decryption fails
- Need key exchange mechanism first

---

## 🎯 Next Steps (Priority Order)

### Immediate
1. **Remove IndexedDB** or fix cache queries
2. **Clean up console logging** (remove debug logs)
3. **Fix ENS CORS** issues
4. **Add error handling** for failed decryption (show friendly message)

### Short-term
5. **Implement Key Exchange Protocol**
   - Option A: On-chain key registry (publish public key via ethscription)
   - Option B: First message includes sender's public key for replies
   - Option C: DHT/IPFS key storage

6. **Enable Wallet-Signature Keys** (after key exchange)
   - One-time signature prompt per session
   - Cache derived key in memory
   - Show security benefits in UI

### Long-term
7. **Group Messaging** support
8. **File Attachments** (IPFS + encrypted)
9. **X3DH + Double Ratchet** (Signal protocol)
10. **L2 Support** (Arbitrum, Base, etc.)

---

## 📝 Technical Debt

- [ ] Remove unused `deriveKeypairFromWalletSignature` references
- [ ] Remove unused `cachedPrivateKey` state
- [ ] Clean up duplicate Alchemy fallback code (not used)
- [ ] Remove old `secrechat` protocol handling
- [ ] Fix IndexedDB schema for self-send messages
- [ ] Add proper TypeScript types
- [ ] Add unit tests for crypto functions
- [ ] Add E2E tests for message flow

---

## 🔐 Security Notes

### Current Threat Model
**❌ Does NOT protect against:**
- Address-based key derivation attacks (trivial to compute private key)
- Passive surveillance by blockchain analysis
- Quantum computers (secp256k1 vulnerable)

**✅ DOES protect against:**
- Plaintext message reading
- Spam attacks (self-send prevents wallet pollution)
- Message interception in transit (encrypted before blockchain)

### With Wallet-Signature Keys (when enabled)
**✅ Would protect against:**
- Address-based key derivation attacks
- Deterministic key prediction
- Passive surveillance of message contents

**❌ Still would NOT protect against:**
- Compromised wallet private key
- Client-side malware
- Metadata analysis (timestamps, transaction patterns)
- Quantum computers

---

## 🚀 Deployment

**Live URL:** https://mail.chainfeed.online  
**Network:** Ethereum Mainnet  
**Protocol:** chainfeed.online ethscriptions  

**Recent Transactions:**
- Test message 1: `0x235dded8ab75279146050db4bdd44775d9c877c3c710717f72c9536526ad5f77`
- Test message 2: `0x96de01c3ab675c720c4469486e6c7b19198a1160cddf24bce089f903a39e932c`

---

## 📊 Stats

- **Total ethscriptions queried:** 25-500 per fetch
- **Chainfeed.online messages found:** ~1-4 in recent batch
- **Gas cost per message:** ~$5-50 USD (varies with network)
- **Message size limit:** ~90KB (ethscription limit)
- **Decryption time:** <100ms per message

---

## 🤝 Contributing

**Current blockers for contributors:**
1. Key exchange mechanism design decision needed
2. Security audit required before promoting wallet-signature keys
3. ENS resolver CORS issue needs resolution

**Good first issues:**
- [ ] Add loading skeleton for message list
- [ ] Improve error messages for failed decryption
- [ ] Add message export functionality
- [ ] Implement dark/light theme toggle
- [ ] Add keyboard shortcuts
