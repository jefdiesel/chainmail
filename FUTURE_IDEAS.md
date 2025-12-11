# Chainmail Future Ideas

## WebAuthn PRF Extension for Key Derivation

**Source:** https://www.corbado.com/blog/passkeys-prf-webauthn

### What is PRF?

WebAuthn PRF (Pseudo-Random Function) extension lets you derive a 32-byte cryptographic key directly from a passkey during authentication. The output is deterministic - same passkey + same salt = same output every time.

### Why it matters for Wrap protocol

**Current X3DH flow:**
```
User → Identity Key + Signed PreKey + Bundle management → X3DH → Symmetric Key → Encrypt
```

**With PRF:**
```
User → Passkey login → PRF output → HKDF → Symmetric Key → Encrypt
```

No key bundles. No prekey servers. No seed phrases. The passkey IS the identity.

### How it could work for messaging

1. **Registration:** User creates passkey, PRF outputs 32 bytes as their "wrap key seed"
2. **Key derivation:** Use PRF seed to deterministically derive X25519 keypair
3. **Multi-recipient:** Still works - PRF-derived keys can participate in X3DH or similar protocols
4. **Recovery:** iCloud Keychain / Google Password Manager sync passkeys across devices

### Technical details

- PRF accepts two "salts" - enables key rotation (current key + next key)
- Output goes through HKDF before use as encryption key
- Hardware-backed via CTAP2 `hmac-secret` extension
- Context string prevents cross-purpose key derivation attacks

### Platform support (Dec 2025)

| Platform | Support | Notes |
|----------|---------|-------|
| Android (Chrome/Edge/Samsung) | ✅ | Full support, Google Password Manager passkeys have PRF by default |
| iOS/iPadOS 18.4+ | ✅ | Fixed bugs from 18.0-18.3, iCloud Keychain works |
| macOS 15+ (Safari 18+, Chrome 132+, Firefox 139) | ✅ | Both iCloud Keychain and security keys |
| Windows 11 | ⚠️ | Security keys only, Windows Hello lacks hmac-secret |
| Firefox Android | ❌ | No support yet |

### Considerations

**Pros:**
- No separate key management - passkey is the only thing user needs
- Hardware-backed security (Secure Enclave / TPM)
- Passkeys sync across devices automatically
- Phishing resistant by design
- True passwordless E2EE

**Cons:**
- Lose passkey = lose access (need recovery strategy)
- Windows support limited to hardware security keys
- PRF gives symmetric key - need to derive asymmetric keys for multi-party messaging
- Can't treat as core dependency yet due to fragmented support

### Implementation approach

1. **Phase 1:** Add PRF as optional key derivation method alongside X3DH
2. **Phase 2:** PRF-derived seed → deterministic X25519 keypair generation
3. **Phase 3:** Full PRF-based identity (when support matures ~2026)

### Key rotation with dual salts

```javascript
// Request both current and next key during auth
const prfResult = await navigator.credentials.get({
  publicKey: {
    extensions: {
      prf: {
        eval: {
          first: currentSalt,  // derives current key
          second: nextSalt     // derives next key for rotation
        }
      }
    }
  }
});
```

### References

- WebAuthn Level 3 Spec: https://www.w3.org/TR/webauthn-3/
- Corbado PRF Guide: https://www.corbado.com/blog/passkeys-prf-webauthn
- CTAP2 hmac-secret: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html

---

## Other Future Ideas

(Add more ideas here as they come up)
