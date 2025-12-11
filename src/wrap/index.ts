/**
 * Wrap Protocol
 * Multi-recipient X3DH encrypted on-chain archival
 *
 * Protocol: data:wrap,<base64-encrypted-payload>
 *
 * Features:
 * - X3DH key exchange (sender always included)
 * - AES-256-GCM encryption
 * - Chunked payloads for large files
 * - ENS key discovery for public identities
 * - Address-based registry for private/anonymous use
 *
 * @example
 * ```ts
 * import { generateFullKeyPair, wrap, unwrap, resolve } from '@chainmail/wrap';
 *
 * // Generate keys
 * const alice = generateFullKeyPair();
 * const bob = generateFullKeyPair();
 *
 * // Encrypt for Bob
 * const calldata = wrap(alice, [{ id: 'bob', bundle: bob.bundle }], Buffer.from('hello'));
 *
 * // Bob decrypts
 * const message = unwrap('bob', bob, calldata);
 * ```
 */

// Core wrap protocol
export {
  // Types
  type KeyPair,
  type KeyBundle,
  type FullKeyPair,
  type Recipient,
  type EncryptedPayload,
  type WrapKeysAnnouncement,

  // Constants
  WRAP_PREFIX,
  WRAP_KEYS_PREFIX,
  PROTOCOL_VERSION,

  // Key generation
  generateKeyPair,
  generateFullKeyPair,

  // Encryption
  encryptForRecipients,
  decryptForRecipient,

  // High-level API
  wrap,
  unwrap,
  isWrap,
  getSender,
  getRecipients,

  // Wrap-keys announcements
  announceKeys,
  parseKeys,
  isWrapKeys,

  // Utilities
  toHex,
  fromHex,
  bundleToHex,
  bundleFromHex,
} from './wrap.js';

// Chunking for large payloads
export {
  // Types
  type ChunkMessage,
  type ChunkedTx,

  // Constants
  MAX_CHUNK_SIZE,

  // Chunking API
  wrapAndChunk,
  unwrapChunk,
  reassembleChunks,

  // Streaming
  ChunkTracker,

  // Estimation
  estimateChunks,
  estimateWrappedSize,
} from './chunking.js';

// Key discovery
export {
  // Types
  type ResolvedIdentity,
  type RegistryConfig,

  // ENS → address
  resolveENS,
  resolve,
  resolveMany,

  // Local address registry (for caching prekeys)
  registerAddress,
  getAddressBundle,
  unregisterAddress,
  clearRegistry,
  exportRegistry,
  importRegistry,
} from './registry.js';
