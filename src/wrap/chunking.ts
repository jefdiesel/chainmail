/**
 * Wrap Protocol - Chunking
 * Split large payloads into chunks for on-chain storage
 *
 * Base L2 (OP Stack) limit: ~128KB per tx
 * Safe chunk size: 33.3KB raw → ~78KB wrapped
 *
 * All chunk metadata (id, part, total) is INSIDE the encrypted payload
 * for privacy - observers cannot correlate chunks without decryption
 */

import { randomBytes } from 'crypto';
import {
  type FullKeyPair,
  type Recipient,
  type EncryptedPayload,
  encryptForRecipients,
  decryptForRecipient,
  WRAP_PREFIX,
} from './wrap.js';

// ============================================================================
// Constants
// ============================================================================

export const MAX_CHUNK_SIZE = 33333; // 33.3KB chunks → ~78KB wrapped, safe under 128KB limit

// ============================================================================
// Types
// ============================================================================

export interface ChunkMessage {
  id: string;      // Random message ID (hex)
  part: number;    // 1-indexed chunk number
  total: number;   // Total chunks
  data: string;    // Base64-encoded chunk data
}

export interface ChunkedTx {
  calldata: string;
  part: number;
  total: number;
}

// ============================================================================
// Chunking
// ============================================================================

/**
 * Wrap and chunk a payload for multi-recipient encryption
 * Returns array of calldata strings ready to send as txs
 */
export function wrapAndChunk(
  senderKeys: FullKeyPair,
  recipients: Recipient[],
  payload: unknown
): ChunkedTx[] {
  const messageId = randomBytes(16).toString('hex');
  const payloadStr = JSON.stringify(payload);
  const payloadBytes = Buffer.from(payloadStr);

  const totalChunks = Math.ceil(payloadBytes.length / MAX_CHUNK_SIZE);
  const chunks: ChunkedTx[] = [];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * MAX_CHUNK_SIZE;
    const end = Math.min(start + MAX_CHUNK_SIZE, payloadBytes.length);
    const chunkData = payloadBytes.slice(start, end).toString('base64');

    const message: ChunkMessage = {
      id: messageId,
      part: i + 1,
      total: totalChunks,
      data: chunkData,
    };

    const messageBuf = Buffer.from(JSON.stringify(message));
    const encrypted = encryptForRecipients(
      senderKeys,
      recipients,
      new Uint8Array(messageBuf)
    );

    const calldata = WRAP_PREFIX + Buffer.from(JSON.stringify(encrypted)).toString('base64');

    chunks.push({
      calldata,
      part: i + 1,
      total: totalChunks,
    });
  }

  return chunks;
}

/**
 * Decrypt a single chunk
 */
export function unwrapChunk(
  recipientId: string,
  recipientKeys: FullKeyPair,
  calldata: string
): ChunkMessage | null {
  if (!calldata.startsWith(WRAP_PREFIX)) {
    return null;
  }

  try {
    const base64 = calldata.slice(WRAP_PREFIX.length);
    const encrypted: EncryptedPayload = JSON.parse(Buffer.from(base64, 'base64').toString());

    const decrypted = decryptForRecipient(recipientId, recipientKeys, encrypted);
    return JSON.parse(Buffer.from(decrypted).toString());
  } catch {
    return null; // Can't decrypt - not for us
  }
}

/**
 * Reassemble chunked messages by ID
 * Returns null if incomplete, single payload if one message, array if multiple
 */
export function reassembleChunks(messages: ChunkMessage[]): unknown {
  if (messages.length === 0) return null;

  // Group by ID
  const byId = new Map<string, ChunkMessage[]>();
  for (const msg of messages) {
    const existing = byId.get(msg.id) || [];
    existing.push(msg);
    byId.set(msg.id, existing);
  }

  const results: unknown[] = [];

  for (const [id, chunks] of byId) {
    // Check if complete
    const total = chunks[0].total;
    if (chunks.length !== total) {
      continue; // Incomplete
    }

    // Sort by part
    chunks.sort((a, b) => a.part - b.part);

    // Verify all parts present
    const allPresent = chunks.every((c, i) => c.part === i + 1);
    if (!allPresent) {
      continue; // Missing parts
    }

    // Reassemble
    const fullData = chunks
      .map(c => Buffer.from(c.data, 'base64'))
      .reduce((acc, buf) => Buffer.concat([acc, buf]), Buffer.alloc(0));

    try {
      results.push(JSON.parse(fullData.toString()));
    } catch {
      // Invalid JSON after reassembly
    }
  }

  return results.length === 1 ? results[0] : results.length > 0 ? results : null;
}

// ============================================================================
// Chunk Tracking
// ============================================================================

/**
 * Track incomplete chunk sets for streaming reassembly
 */
export class ChunkTracker {
  private chunks = new Map<string, ChunkMessage[]>();

  /**
   * Add a chunk, returns assembled payload if complete
   */
  add(message: ChunkMessage): unknown | null {
    const existing = this.chunks.get(message.id) || [];

    // Avoid duplicates
    if (existing.some(c => c.part === message.part)) {
      return null;
    }

    existing.push(message);
    this.chunks.set(message.id, existing);

    // Check if complete
    if (existing.length === message.total) {
      const result = reassembleChunks(existing);
      if (result !== null) {
        this.chunks.delete(message.id); // Clean up
        return result;
      }
    }

    return null;
  }

  /**
   * Get incomplete message IDs
   */
  getIncomplete(): Array<{ id: string; have: number; need: number }> {
    const result: Array<{ id: string; have: number; need: number }> = [];
    for (const [id, chunks] of this.chunks) {
      result.push({
        id,
        have: chunks.length,
        need: chunks[0].total,
      });
    }
    return result;
  }

  /**
   * Clear tracker
   */
  clear(): void {
    this.chunks.clear();
  }
}

// ============================================================================
// Size Estimation
// ============================================================================

/**
 * Estimate number of chunks needed for a payload
 */
export function estimateChunks(payload: unknown): number {
  const size = Buffer.from(JSON.stringify(payload)).length;
  return Math.ceil(size / MAX_CHUNK_SIZE);
}

/**
 * Estimate wrapped size for a payload (rough approximation)
 * Actual size depends on number of recipients
 */
export function estimateWrappedSize(payloadSize: number, recipientCount: number): number {
  // Per-recipient overhead: ~354 bytes
  // Base overhead: ~200 bytes
  // Base64 expansion: ~1.37x
  const perRecipient = 354;
  const baseOverhead = 200;
  const base64Factor = 1.37;

  return Math.ceil((payloadSize + baseOverhead + (perRecipient * (recipientCount + 1))) * base64Factor);
}
