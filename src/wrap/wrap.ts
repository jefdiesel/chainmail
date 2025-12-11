/**
 * Wrap Protocol - Core Cryptographic Primitives
 * Multi-recipient X3DH encryption for on-chain archival
 *
 * Protocol: data:wrap,<base64-encrypted-payload>
 */

// @ts-ignore
import { x25519 } from '@noble/curves/ed25519.js';
// @ts-ignore
import { hkdf } from '@noble/hashes/hkdf.js';
// @ts-ignore
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

// ============================================================================
// Types
// ============================================================================

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface KeyBundle {
  identityKey: Uint8Array;
  signedPreKey: Uint8Array;
}

export interface FullKeyPair {
  identity: KeyPair;
  signedPreKey: KeyPair;
  bundle: KeyBundle;
}

export interface Recipient {
  id: string;
  bundle: KeyBundle;
}

interface WrappedKey {
  recipientId: string;
  recipientIdentityKey: string;
  ephemeralKey: string;
  wrappedKey: string;
  iv: string;
  authTag: string;
}

export interface EncryptedPayload {
  version: number;
  senderIdentityKey: string;
  iv: string;
  ciphertext: string;
  authTag: string;
  keys: WrappedKey[];
}

// ============================================================================
// Constants
// ============================================================================

export const WRAP_PREFIX = 'data:wrap,';
export const PROTOCOL_VERSION = 2;

// ============================================================================
// Utilities
// ============================================================================

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export function bundleToHex(bundle: KeyBundle): { identityKey: string; signedPreKey: string } {
  return {
    identityKey: toHex(bundle.identityKey),
    signedPreKey: toHex(bundle.signedPreKey),
  };
}

export function bundleFromHex(hex: { identityKey: string; signedPreKey: string }): KeyBundle {
  return {
    identityKey: fromHex(hex.identityKey),
    signedPreKey: fromHex(hex.signedPreKey),
  };
}

// ============================================================================
// Key Generation
// ============================================================================

export function generateKeyPair(): KeyPair {
  // x25519.utils has randomSecretKey in newer versions
  const privateKey = (x25519.utils as any).randomPrivateKey?.()
    || (x25519.utils as any).randomSecretKey?.()
    || new Uint8Array(randomBytes(32));
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function generateFullKeyPair(): FullKeyPair {
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
// Crypto Primitives
// ============================================================================

function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

function deriveKey(ikm: Uint8Array, salt: Uint8Array | string, info: string, length = 32): Uint8Array {
  const saltBytes = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;
  const infoBytes = new TextEncoder().encode(info);
  return hkdf(sha256, ikm, saltBytes, infoBytes, length);
}

function encrypt(key: Uint8Array, plaintext: Uint8Array): { iv: Uint8Array; ciphertext: Uint8Array; authTag: Uint8Array } {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return {
    iv: new Uint8Array(iv),
    ciphertext: new Uint8Array(encrypted),
    authTag: new Uint8Array(cipher.getAuthTag()),
  };
}

function decrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, authTag: Uint8Array): Uint8Array {
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(iv));
  decipher.setAuthTag(Buffer.from(authTag));
  return new Uint8Array(Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]));
}

// ============================================================================
// X3DH Key Exchange
// ============================================================================

function x3dhSender(
  senderIdentity: KeyPair,
  recipientBundle: KeyBundle
): { sharedSecret: Uint8Array; ephemeralPublicKey: Uint8Array } {
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

function x3dhRecipient(
  recipientIdentity: KeyPair,
  recipientSignedPreKey: KeyPair,
  senderIdentityKey: Uint8Array,
  ephemeralKey: Uint8Array
): Uint8Array {
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
// Multi-Recipient Encryption
// ============================================================================

/**
 * Encrypt payload for multiple recipients (sender always included)
 */
export function encryptForRecipients(
  senderKeys: FullKeyPair,
  recipients: Recipient[],
  plaintext: Uint8Array
): EncryptedPayload {
  const symmetricKey = randomBytes(32);
  const { iv, ciphertext, authTag } = encrypt(new Uint8Array(symmetricKey), plaintext);

  // Always include sender so they can decrypt their own messages
  const allRecipients: Recipient[] = [
    { id: 'sender', bundle: senderKeys.bundle },
    ...recipients,
  ];

  const keys: WrappedKey[] = allRecipients.map(r => {
    const { sharedSecret, ephemeralPublicKey } = x3dhSender(senderKeys.identity, r.bundle);
    const wrapped = encrypt(sharedSecret, symmetricKey);
    return {
      recipientId: r.id,
      recipientIdentityKey: toHex(r.bundle.identityKey),
      ephemeralKey: toHex(ephemeralPublicKey),
      wrappedKey: toHex(wrapped.ciphertext),
      iv: toHex(wrapped.iv),
      authTag: toHex(wrapped.authTag),
    };
  });

  return {
    version: PROTOCOL_VERSION,
    senderIdentityKey: toHex(senderKeys.identity.publicKey),
    iv: toHex(iv),
    ciphertext: Buffer.from(ciphertext).toString('base64'),
    authTag: toHex(authTag),
    keys,
  };
}

/**
 * Decrypt payload for a specific recipient
 */
export function decryptForRecipient(
  recipientId: string,
  recipientKeys: FullKeyPair,
  encrypted: EncryptedPayload
): Uint8Array {
  // Find key entry by ID or identity key match
  const keyEntry = encrypted.keys.find(k =>
    k.recipientId === recipientId ||
    k.recipientIdentityKey === toHex(recipientKeys.identity.publicKey)
  );

  if (!keyEntry) {
    throw new Error(`No key found for recipient: ${recipientId}`);
  }

  const sharedSecret = x3dhRecipient(
    recipientKeys.identity,
    recipientKeys.signedPreKey,
    fromHex(encrypted.senderIdentityKey),
    fromHex(keyEntry.ephemeralKey)
  );

  const symmetricKey = decrypt(
    sharedSecret,
    fromHex(keyEntry.iv),
    fromHex(keyEntry.wrappedKey),
    fromHex(keyEntry.authTag)
  );

  return decrypt(
    symmetricKey,
    fromHex(encrypted.iv),
    new Uint8Array(Buffer.from(encrypted.ciphertext, 'base64')),
    fromHex(encrypted.authTag)
  );
}

// ============================================================================
// Wrap/Unwrap Calldata
// ============================================================================

/**
 * Wrap plaintext into calldata format
 */
export function wrap(
  senderKeys: FullKeyPair,
  recipients: Recipient[],
  plaintext: Uint8Array
): string {
  const encrypted = encryptForRecipients(senderKeys, recipients, plaintext);
  return WRAP_PREFIX + Buffer.from(JSON.stringify(encrypted)).toString('base64');
}

/**
 * Unwrap calldata back to plaintext
 */
export function unwrap(
  recipientId: string,
  recipientKeys: FullKeyPair,
  calldata: string
): Uint8Array | null {
  if (!calldata.startsWith(WRAP_PREFIX)) {
    return null;
  }

  try {
    const base64 = calldata.slice(WRAP_PREFIX.length);
    const encrypted: EncryptedPayload = JSON.parse(Buffer.from(base64, 'base64').toString());
    return decryptForRecipient(recipientId, recipientKeys, encrypted);
  } catch {
    return null; // Can't decrypt - not for us
  }
}

/**
 * Check if calldata is a wrap message
 */
export function isWrap(calldata: string): boolean {
  return calldata.startsWith(WRAP_PREFIX);
}

/**
 * Get sender identity key from wrap calldata (without decrypting)
 */
export function getSender(calldata: string): string | null {
  if (!calldata.startsWith(WRAP_PREFIX)) {
    return null;
  }

  try {
    const base64 = calldata.slice(WRAP_PREFIX.length);
    const encrypted: EncryptedPayload = JSON.parse(Buffer.from(base64, 'base64').toString());
    return encrypted.senderIdentityKey;
  } catch {
    return null;
  }
}

/**
 * Get recipient identity keys from wrap calldata (without decrypting)
 */
export function getRecipients(calldata: string): string[] {
  if (!calldata.startsWith(WRAP_PREFIX)) {
    return [];
  }

  try {
    const base64 = calldata.slice(WRAP_PREFIX.length);
    const encrypted: EncryptedPayload = JSON.parse(Buffer.from(base64, 'base64').toString());
    return encrypted.keys.map(k => k.recipientIdentityKey);
  } catch {
    return [];
  }
}
