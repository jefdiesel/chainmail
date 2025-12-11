/**
 * Wrap Protocol Tests
 */

import {
  generateFullKeyPair,
  wrap,
  unwrap,
  isWrap,
  getSender,
  getRecipients,
  wrapAndChunk,
  unwrapChunk,
  reassembleChunks,
  ChunkTracker,
  toHex,
  bundleToHex,
  registerAddress,
  getAddressBundle,
  exportRegistry,
  importRegistry,
  clearRegistry,
} from '../dist/index.js';

const assert = (condition, message) => {
  if (!condition) throw new Error(`FAIL: ${message}`);
  console.log(`  ✓ ${message}`);
};

async function testBasicWrap() {
  console.log('\n=== Basic Wrap/Unwrap ===');

  const alice = generateFullKeyPair();
  const bob = generateFullKeyPair();

  const message = Buffer.from('Hello, Bob!');
  const calldata = wrap(alice, [{ id: 'bob', bundle: bob.bundle }], message);

  assert(isWrap(calldata), 'calldata has wrap prefix');
  assert(calldata.startsWith('data:wrap,'), 'prefix is data:wrap,');

  // Bob can decrypt
  const decrypted = unwrap('bob', bob, calldata);
  assert(decrypted !== null, 'Bob can decrypt');
  assert(Buffer.from(decrypted).toString() === 'Hello, Bob!', 'message matches');

  // Alice (sender) can also decrypt
  const senderDecrypted = unwrap('sender', alice, calldata);
  assert(senderDecrypted !== null, 'sender can decrypt own message');
  assert(Buffer.from(senderDecrypted).toString() === 'Hello, Bob!', 'sender message matches');

  // Carol cannot decrypt
  const carol = generateFullKeyPair();
  const carolDecrypted = unwrap('carol', carol, calldata);
  assert(carolDecrypted === null, 'unauthorized cannot decrypt');

  console.log('Basic wrap/unwrap: PASSED');
}

async function testMetadata() {
  console.log('\n=== Metadata Extraction ===');

  const alice = generateFullKeyPair();
  const bob = generateFullKeyPair();
  const carol = generateFullKeyPair();

  const calldata = wrap(
    alice,
    [
      { id: 'bob', bundle: bob.bundle },
      { id: 'carol', bundle: carol.bundle },
    ],
    Buffer.from('test')
  );

  const sender = getSender(calldata);
  assert(sender === toHex(alice.identity.publicKey), 'sender identity key matches');

  const recipients = getRecipients(calldata);
  assert(recipients.length === 3, '3 recipients (sender + bob + carol)');
  assert(recipients.includes(toHex(bob.bundle.identityKey)), 'bob in recipients');
  assert(recipients.includes(toHex(carol.bundle.identityKey)), 'carol in recipients');

  console.log('Metadata extraction: PASSED');
}

async function testChunking() {
  console.log('\n=== Chunking ===');

  const alice = generateFullKeyPair();
  const bob = generateFullKeyPair();

  // Create large payload (100KB+)
  const largePayload = {
    data: 'x'.repeat(100000),
    metadata: { test: true },
  };

  const chunks = wrapAndChunk(alice, [{ id: 'bob', bundle: bob.bundle }], largePayload);

  assert(chunks.length > 1, `payload chunked (${chunks.length} chunks)`);
  assert(chunks[0].part === 1, 'first chunk is part 1');
  assert(chunks[chunks.length - 1].total === chunks.length, 'total matches chunk count');

  // Decrypt all chunks
  const decryptedChunks = chunks.map(c => unwrapChunk('bob', bob, c.calldata));
  assert(decryptedChunks.every(c => c !== null), 'all chunks decryptable');

  // Reassemble
  const reassembled = reassembleChunks(decryptedChunks);
  assert(reassembled !== null, 'reassembly successful');
  assert(reassembled.data === largePayload.data, 'data matches');
  assert(reassembled.metadata.test === true, 'metadata matches');

  console.log('Chunking: PASSED');
}

async function testChunkTracker() {
  console.log('\n=== Chunk Tracker (streaming) ===');

  const alice = generateFullKeyPair();
  const bob = generateFullKeyPair();

  const payload = { data: 'y'.repeat(80000) };
  const chunks = wrapAndChunk(alice, [{ id: 'bob', bundle: bob.bundle }], payload);

  const tracker = new ChunkTracker();

  // Add chunks one by one (out of order)
  const shuffled = [...chunks].sort(() => Math.random() - 0.5);
  let result = null;

  for (const chunk of shuffled) {
    const decrypted = unwrapChunk('bob', bob, chunk.calldata);
    result = tracker.add(decrypted);
    if (result) break;
  }

  assert(result !== null, 'tracker assembled payload');
  assert(result.data === payload.data, 'tracker data matches');

  console.log('Chunk tracker: PASSED');
}

async function testAddressRegistry() {
  console.log('\n=== Address Registry ===');

  clearRegistry();

  const alice = generateFullKeyPair();
  const address = '0x1234567890123456789012345678901234567890';

  registerAddress(address, alice.bundle);

  const retrieved = getAddressBundle(address);
  assert(retrieved !== null, 'bundle retrieved');
  assert(toHex(retrieved.identityKey) === toHex(alice.bundle.identityKey), 'identity key matches');

  // Export/import
  const exported = exportRegistry();
  clearRegistry();
  assert(getAddressBundle(address) === null, 'registry cleared');

  importRegistry(exported);
  const reimported = getAddressBundle(address);
  assert(reimported !== null, 'registry imported');
  assert(toHex(reimported.identityKey) === toHex(alice.bundle.identityKey), 'reimported key matches');

  console.log('Address registry: PASSED');
}

async function main() {
  console.log('=================================');
  console.log('  Wrap Protocol Test Suite');
  console.log('=================================');

  try {
    await testBasicWrap();
    await testMetadata();
    await testChunking();
    await testChunkTracker();
    await testAddressRegistry();

    console.log('\n=================================');
    console.log('  ALL TESTS PASSED');
    console.log('=================================\n');
  } catch (error) {
    console.error('\n❌ TEST FAILED:', error.message);
    process.exit(1);
  }
}

main();
