/**
 * Wrap Protocol - Browser Build
 * Uses Web Crypto API instead of Node crypto
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

// ============================================================================
// Browser Crypto
// ============================================================================

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function encrypt(key, plaintext) {
  const iv = randomBytes(12);
  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt'])
    .then(cryptoKey => crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext))
    .then(encrypted => {
      const ciphertext = new Uint8Array(encrypted.slice(0, -16));
      const authTag = new Uint8Array(encrypted.slice(-16));
      return { iv, ciphertext, authTag };
    });
}

function decrypt(key, iv, ciphertext, authTag) {
  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext);
  combined.set(authTag, ciphertext.length);

  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt'])
    .then(cryptoKey => crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, combined))
    .then(decrypted => new Uint8Array(decrypted));
}

// Sync versions using a simple approach
function encryptSync(key, plaintext) {
  // For browser we need async, so we'll use a simpler XOR for local testing
  // In production, all wrap/unwrap should be async
  throw new Error('Use async wrapAsync/unwrapAsync in browser');
}

// ============================================================================
// Utils
// ============================================================================

export function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export function bundleToHex(bundle) {
  return {
    identityKey: toHex(bundle.identityKey),
    signedPreKey: toHex(bundle.signedPreKey),
  };
}

export function bundleFromHex(hex) {
  return {
    identityKey: fromHex(hex.identityKey),
    signedPreKey: fromHex(hex.signedPreKey),
  };
}

// ============================================================================
// Key Generation
// ============================================================================

export function generateKeyPair() {
  const privateKey = randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function generateFullKeyPair() {
  const identity = generateKeyPair();
  const signedPreKey = generateKeyPair();
  return {
    identity,
    signedPreKey,
    bundle: {
      identityKey: identity.publicKey,
      signedPreKey: signedPreKey.publicKey,
    },
  };
}

// ============================================================================
// Derived Keys
// ============================================================================

export function deriveKeysFromSignature(signature) {
  const sigBytes = new TextEncoder().encode(signature);
  const seed = sha256(sigBytes);

  const identitySalt = new TextEncoder().encode('wrap-identity');
  const signedPreKeySalt = new TextEncoder().encode('wrap-signed-prekey');
  const info = new TextEncoder().encode('wrap-keys-v1');

  const identityPrivate = hkdf(sha256, seed, identitySalt, info, 32);
  const signedPreKeyPrivate = hkdf(sha256, seed, signedPreKeySalt, info, 32);

  const identity = {
    privateKey: identityPrivate,
    publicKey: x25519.getPublicKey(identityPrivate),
  };

  const signedPreKey = {
    privateKey: signedPreKeyPrivate,
    publicKey: x25519.getPublicKey(signedPreKeyPrivate),
  };

  return {
    identity,
    signedPreKey,
    bundle: {
      identityKey: identity.publicKey,
      signedPreKey: signedPreKey.publicKey,
    },
  };
}

export async function deriveKeysFromSigner(signer, index = 0) {
  const message = index === 0 ? 'wrap-keys-v1' : `wrap-keys-v1:${index}`;
  const signature = await signer.signMessage({ message });
  return deriveKeysFromSignature(signature);
}

// ============================================================================
// Key Export/Import
// ============================================================================

export function exportKeys(keys) {
  return {
    identityPrivate: toHex(keys.identity.privateKey),
    identityPublic: toHex(keys.identity.publicKey),
    signedPreKeyPrivate: toHex(keys.signedPreKey.privateKey),
    signedPreKeyPublic: toHex(keys.signedPreKey.publicKey),
  };
}

export function importKeys(exported) {
  const identity = {
    privateKey: fromHex(exported.identityPrivate),
    publicKey: fromHex(exported.identityPublic),
  };
  const signedPreKey = {
    privateKey: fromHex(exported.signedPreKeyPrivate),
    publicKey: fromHex(exported.signedPreKeyPublic),
  };
  return {
    identity,
    signedPreKey,
    bundle: {
      identityKey: identity.publicKey,
      signedPreKey: signedPreKey.publicKey,
    },
  };
}

// ============================================================================
// X3DH
// ============================================================================

function dh(privateKey, publicKey) {
  return x25519.getSharedSecret(privateKey, publicKey);
}

function deriveKey(ikm, salt, info, length = 32) {
  const saltBytes = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;
  return hkdf(sha256, ikm, saltBytes, infoBytes, length);
}

function x3dhSender(senderIdentity, recipientBundle) {
  const ephemeral = generateKeyPair();
  const dh1 = dh(senderIdentity.privateKey, recipientBundle.signedPreKey);
  const dh2 = dh(ephemeral.privateKey, recipientBundle.identityKey);
  const dh3 = dh(ephemeral.privateKey, recipientBundle.signedPreKey);

  const dhConcat = new Uint8Array(96);
  dhConcat.set(dh1, 0);
  dhConcat.set(dh2, 32);
  dhConcat.set(dh3, 64);

  const sharedSecret = deriveKey(dhConcat, new Uint8Array(32), 'WrapProtocol', 32);
  return { sharedSecret, ephemeralPublicKey: ephemeral.publicKey };
}

function x3dhRecipient(recipientIdentity, recipientSignedPreKey, senderIdentityKey, ephemeralKey) {
  const dh1 = dh(recipientSignedPreKey.privateKey, senderIdentityKey);
  const dh2 = dh(recipientIdentity.privateKey, ephemeralKey);
  const dh3 = dh(recipientSignedPreKey.privateKey, ephemeralKey);

  const dhConcat = new Uint8Array(96);
  dhConcat.set(dh1, 0);
  dhConcat.set(dh2, 32);
  dhConcat.set(dh3, 64);

  return deriveKey(dhConcat, new Uint8Array(32), 'WrapProtocol', 32);
}

// ============================================================================
// Wrap Protocol Constants
// ============================================================================

export const WRAP_PREFIX = 'data:wrap,';
export const WRAP_KEYS_PREFIX = 'data:wrap-keys,';

// ============================================================================
// Wrap Keys Announcement
// ============================================================================

export function announceKeys(keys) {
  const announcement = {
    identityKey: toHex(keys.identity.publicKey),
    signedPreKey: toHex(keys.signedPreKey.publicKey),
    timestamp: Date.now(),
  };
  return WRAP_KEYS_PREFIX + btoa(JSON.stringify(announcement));
}

export function parseKeys(calldata) {
  if (!calldata.startsWith(WRAP_KEYS_PREFIX)) return null;
  try {
    return JSON.parse(atob(calldata.slice(WRAP_KEYS_PREFIX.length)));
  } catch {
    return null;
  }
}

export function isWrapKeys(calldata) {
  return calldata.startsWith(WRAP_KEYS_PREFIX);
}

// ============================================================================
// Async Wrap/Unwrap (Browser)
// ============================================================================

export async function wrapAsync(senderKeys, recipients, plaintext) {
  const symmetricKey = randomBytes(32);
  const { iv, ciphertext, authTag } = await encrypt(symmetricKey, plaintext);

  const allRecipients = [
    { id: 'sender', bundle: senderKeys.bundle },
    ...recipients,
  ];

  const keys = await Promise.all(allRecipients.map(async r => {
    const { sharedSecret, ephemeralPublicKey } = x3dhSender(senderKeys.identity, r.bundle);
    const wrapped = await encrypt(sharedSecret, symmetricKey);
    return {
      recipientId: r.id,
      recipientIdentityKey: toHex(r.bundle.identityKey),
      ephemeralKey: toHex(ephemeralPublicKey),
      wrappedKey: toHex(wrapped.ciphertext),
      iv: toHex(wrapped.iv),
      authTag: toHex(wrapped.authTag),
    };
  }));

  const payload = {
    version: 2,
    senderIdentityKey: toHex(senderKeys.identity.publicKey),
    iv: toHex(iv),
    ciphertext: btoa(String.fromCharCode(...ciphertext)),
    authTag: toHex(authTag),
    keys,
  };

  return WRAP_PREFIX + btoa(JSON.stringify(payload));
}

export async function unwrapAsync(recipientId, recipientKeys, calldata) {
  if (!calldata.startsWith(WRAP_PREFIX)) return null;

  try {
    const encrypted = JSON.parse(atob(calldata.slice(WRAP_PREFIX.length)));

    const keyEntry = encrypted.keys.find(k =>
      k.recipientId === recipientId ||
      k.recipientIdentityKey === toHex(recipientKeys.identity.publicKey)
    );
    if (!keyEntry) return null;

    const sharedSecret = x3dhRecipient(
      recipientKeys.identity,
      recipientKeys.signedPreKey,
      fromHex(encrypted.senderIdentityKey),
      fromHex(keyEntry.ephemeralKey)
    );

    const symmetricKey = await decrypt(
      sharedSecret,
      fromHex(keyEntry.iv),
      fromHex(keyEntry.wrappedKey),
      fromHex(keyEntry.authTag)
    );

    const ciphertextBytes = Uint8Array.from(atob(encrypted.ciphertext), c => c.charCodeAt(0));

    return decrypt(
      symmetricKey,
      fromHex(encrypted.iv),
      ciphertextBytes,
      fromHex(encrypted.authTag)
    );
  } catch (e) {
    console.error('Unwrap failed:', e);
    return null;
  }
}

// ============================================================================
// Chunking
// ============================================================================

export const MAX_CHUNK_SIZE = 33333;

export async function wrapAndChunkAsync(senderKeys, recipients, payload) {
  const messageId = toHex(randomBytes(16));
  const payloadStr = JSON.stringify(payload);
  const payloadBytes = new TextEncoder().encode(payloadStr);
  const totalChunks = Math.ceil(payloadBytes.length / MAX_CHUNK_SIZE);
  const chunks = [];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * MAX_CHUNK_SIZE;
    const end = Math.min(start + MAX_CHUNK_SIZE, payloadBytes.length);
    const chunkData = btoa(String.fromCharCode(...payloadBytes.slice(start, end)));

    const message = {
      id: messageId,
      part: i + 1,
      total: totalChunks,
      data: chunkData,
    };

    const calldata = await wrapAsync(senderKeys, recipients, new TextEncoder().encode(JSON.stringify(message)));
    chunks.push({ calldata, part: i + 1, total: totalChunks });
  }

  return chunks;
}

// ============================================================================
// ENS Resolution
// ============================================================================

export async function resolveENS(ensName, config = {}) {
  // Use public ENS resolution
  try {
    const response = await fetch(`https://api.ensideas.com/ens/resolve/${ensName}`);
    if (!response.ok) return null;
    const data = await response.json();
    return data.address || null;
  } catch {
    return null;
  }
}
