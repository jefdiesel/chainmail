// Browser-Compatible Signal Protocol Implementation
// X3DH + Double Ratchet using @noble/curves and Web Crypto API

import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

// ============================================================================
// Core Cryptographic Primitives
// ============================================================================

/**
 * Generate a random X25519 keypair
 * @returns {object} { privateKey: Uint8Array(32), publicKey: Uint8Array(32) }
 */
export function generateKeyPair() {
    const privateKey = x25519.utils.randomSecretKey();
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
}

/**
 * Perform X25519 Diffie-Hellman
 * @param {Uint8Array} privateKey - 32 bytes
 * @param {Uint8Array} publicKey - 32 bytes
 * @returns {Uint8Array} Shared secret (32 bytes)
 */
export function dh(privateKey, publicKey) {
    return x25519.getSharedSecret(privateKey, publicKey);
}

/**
 * HKDF key derivation (RFC 5869)
 * @param {Uint8Array} inputKeyMaterial - Input key material
 * @param {Uint8Array|string} salt - Salt (optional)
 * @param {Uint8Array|string} info - Context info
 * @param {number} length - Output length in bytes
 * @returns {Uint8Array} Derived key
 */
export function deriveKey(inputKeyMaterial, salt, info, length = 32) {
    const saltBytes = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;
    const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;

    return hkdf(sha256, inputKeyMaterial, saltBytes, infoBytes, length);
}

/**
 * Encrypt data using AES-256-GCM (Web Crypto API)
 * @param {Uint8Array} key - 32-byte encryption key
 * @param {Uint8Array} plaintext - Data to encrypt
 * @param {Uint8Array} associatedData - Additional authenticated data (optional)
 * @returns {Promise<object>} { iv, ciphertext, authTag }
 */
export async function encrypt(key, plaintext, associatedData = null) {
    // Generate random IV (12 bytes for GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Import key for Web Crypto API
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );

    // Encrypt
    const encryptParams = {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
    };

    // Only include additionalData if provided
    if (associatedData) {
        encryptParams.additionalData = associatedData;
    }

    const ciphertextBuffer = await crypto.subtle.encrypt(
        encryptParams,
        cryptoKey,
        plaintext
    );

    // Extract ciphertext and auth tag (last 16 bytes)
    const ciphertext = new Uint8Array(ciphertextBuffer);

    return { iv, ciphertext };
}

/**
 * Decrypt data using AES-256-GCM
 * @param {Uint8Array} key - 32-byte decryption key
 * @param {Uint8Array} iv - Initialization vector
 * @param {Uint8Array} ciphertext - Encrypted data (includes auth tag)
 * @param {Uint8Array} associatedData - Additional authenticated data (optional)
 * @returns {Promise<Uint8Array>} Decrypted plaintext
 */
export async function decrypt(key, iv, ciphertext, associatedData = null) {
    // Import key for Web Crypto API
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );

    // Decrypt
    const decryptParams = {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
    };

    // Only include additionalData if provided
    if (associatedData) {
        decryptParams.additionalData = associatedData;
    }

    try {
        const plaintextBuffer = await crypto.subtle.decrypt(
            decryptParams,
            cryptoKey,
            ciphertext
        );

        return new Uint8Array(plaintextBuffer);
    } catch (error) {
        console.error('❌ AES-GCM decrypt failed:', error);
        console.error('Key length:', key.length, 'IV length:', iv.length, 'Ciphertext length:', ciphertext.length);
        console.error('Has additionalData:', !!associatedData);
        throw error;
    }
}

// ============================================================================
// X3DH (Extended Triple Diffie-Hellman) - Initial Key Agreement
// ============================================================================

/**
 * Perform X3DH handshake as sender (Alice)
 * @param {object} senderIdentity - Sender's identity keypair
 * @param {Uint8Array} recipientIdentityKey - Recipient's identity public key
 * @param {Uint8Array} recipientSignedPreKey - Recipient's signed prekey public key
 * @param {Uint8Array} recipientOneTimePreKey - Recipient's one-time prekey (optional)
 * @returns {object} { sharedSecret, ephemeralPublicKey }
 */
export function x3dhSender(senderIdentity, recipientIdentityKey, recipientSignedPreKey, recipientOneTimePreKey = null) {
    // Generate ephemeral keypair
    const ephemeral = generateKeyPair();

    // Perform 4 DH operations
    const dh1 = dh(senderIdentity.privateKey, recipientSignedPreKey);
    const dh2 = dh(ephemeral.privateKey, recipientIdentityKey);
    const dh3 = dh(ephemeral.privateKey, recipientSignedPreKey);
    const dh4 = recipientOneTimePreKey
        ? dh(ephemeral.privateKey, recipientOneTimePreKey)
        : new Uint8Array(32); // Zero bytes if no one-time prekey

    // Concatenate DH outputs
    const dhConcat = new Uint8Array(dh1.length + dh2.length + dh3.length + dh4.length);
    dhConcat.set(dh1, 0);
    dhConcat.set(dh2, dh1.length);
    dhConcat.set(dh3, dh1.length + dh2.length);
    dhConcat.set(dh4, dh1.length + dh2.length + dh3.length);

    // Derive shared secret using HKDF
    const sharedSecret = deriveKey(
        dhConcat,
        new Uint8Array(32), // Zero salt
        'ChainmailX3DH',
        32
    );

    return {
        sharedSecret,
        ephemeralPublicKey: ephemeral.publicKey
    };
}

/**
 * Perform X3DH handshake as recipient (Bob)
 * @param {object} recipientIdentity - Recipient's identity keypair
 * @param {object} recipientSignedPreKey - Recipient's signed prekey keypair
 * @param {object} recipientOneTimePreKey - Recipient's one-time prekey keypair (optional)
 * @param {Uint8Array} senderIdentityKey - Sender's identity public key
 * @param {Uint8Array} senderEphemeralKey - Sender's ephemeral public key
 * @returns {Uint8Array} Shared secret
 */
export function x3dhRecipient(recipientIdentity, recipientSignedPreKey, recipientOneTimePreKey, senderIdentityKey, senderEphemeralKey) {
    // Perform 4 DH operations (same as sender but with roles reversed)
    const dh1 = dh(recipientSignedPreKey.privateKey, senderIdentityKey);
    const dh2 = dh(recipientIdentity.privateKey, senderEphemeralKey);
    const dh3 = dh(recipientSignedPreKey.privateKey, senderEphemeralKey);
    const dh4 = recipientOneTimePreKey
        ? dh(recipientOneTimePreKey.privateKey, senderEphemeralKey)
        : new Uint8Array(32); // Zero bytes if no one-time prekey

    // Concatenate DH outputs
    const dhConcat = new Uint8Array(dh1.length + dh2.length + dh3.length + dh4.length);
    dhConcat.set(dh1, 0);
    dhConcat.set(dh2, dh1.length);
    dhConcat.set(dh3, dh1.length + dh2.length);
    dhConcat.set(dh4, dh1.length + dh2.length + dh3.length);

    // Derive shared secret using HKDF
    const sharedSecret = deriveKey(
        dhConcat,
        new Uint8Array(32), // Zero salt
        'ChainmailX3DH',
        32
    );

    return sharedSecret;
}

// ============================================================================
// Double Ratchet - Ongoing Message Encryption
// ============================================================================

/**
 * Initialize a Double Ratchet session as sender
 * @param {Uint8Array} sharedSecret - Shared secret from X3DH
 * @param {Uint8Array} recipientRatchetKey - Recipient's initial ratchet public key
 * @returns {object} Ratchet state
 */
export function initializeRatchetSender(sharedSecret, recipientRatchetKey) {
    console.log('📤 initializeRatchetSender: recipientRatchetKey:', toHex(recipientRatchetKey).slice(0, 32));
    console.log('📤 initializeRatchetSender: sharedSecret:', toHex(sharedSecret).slice(0, 32));

    // Generate initial DH ratchet keypair
    const dhRatchet = generateKeyPair();
    console.log('📤 initializeRatchetSender: my DH private:', toHex(dhRatchet.privateKey).slice(0, 32));
    console.log('📤 initializeRatchetSender: my DH public:', toHex(dhRatchet.publicKey).slice(0, 32));

    // Perform DH and derive root key and chain key
    const dhOutput = dh(dhRatchet.privateKey, recipientRatchetKey);
    console.log('📤 initializeRatchetSender: DH output:', toHex(dhOutput).slice(0, 32));
    const derivedKeys = deriveKey(sharedSecret, dhOutput, 'ChainmailRatchet', 64);
    console.log('📤 initializeRatchetSender: Derived sendChainKey:', toHex(derivedKeys.slice(32, 64)).slice(0, 32));

    const rootKey = derivedKeys.slice(0, 32);
    const sendChainKey = derivedKeys.slice(32, 64);

    return {
        rootKey,
        sendChainKey,
        receiveChainKey: null,
        dhRatchet,
        dhRemote: recipientRatchetKey,
        sendCount: 0,
        receiveCount: 0,
        previousSendCount: 0
    };
}

/**
 * Initialize a Double Ratchet session as recipient
 * @param {Uint8Array} sharedSecret - Shared secret from X3DH
 * @param {object} dhRatchet - Recipient's DH ratchet keypair
 * @returns {object} Ratchet state
 */
export function initializeRatchetRecipient(sharedSecret, dhRatchet) {
    console.log('📥 initializeRatchetRecipient: sharedSecret:', toHex(sharedSecret).slice(0, 32));
    console.log('📥 initializeRatchetRecipient: my ratchet private:', toHex(dhRatchet.privateKey).slice(0, 32));
    console.log('📥 initializeRatchetRecipient: my ratchet public:', toHex(dhRatchet.publicKey).slice(0, 32));

    // Recipient starts with just the shared secret as root key
    // The receive chain will be derived when the first message arrives (in ratchetDecrypt)
    return {
        rootKey: sharedSecret,
        sendChainKey: null,
        receiveChainKey: null,
        dhRatchet,
        dhRemote: null,
        sendCount: 0,
        receiveCount: 0,
        previousSendCount: 0
    };
}

/**
 * Advance the DH ratchet (used when receiving a new ratchet key)
 * @param {object} state - Ratchet state
 * @param {Uint8Array} remoteRatchetKey - Remote party's new ratchet public key
 * @returns {object} Updated state
 */
export function ratchetStep(state, remoteRatchetKey) {
    console.log('🔄 ratchetStep: remote key:', toHex(remoteRatchetKey).slice(0, 32));
    console.log('🔄 ratchetStep: my DH private:', toHex(state.dhRatchet.privateKey).slice(0, 32));
    console.log('🔄 ratchetStep: rootKey:', toHex(state.rootKey).slice(0, 32));

    // Save previous send count
    state.previousSendCount = state.sendCount;

    // Derive new receive chain key
    if (remoteRatchetKey) {
        const dhOutput = dh(state.dhRatchet.privateKey, remoteRatchetKey);
        console.log('🔄 ratchetStep: DH output:', toHex(dhOutput).slice(0, 32));
        const derivedKeys = deriveKey(state.rootKey, dhOutput, 'ChainmailRatchet', 64);
        console.log('🔄 ratchetStep: Derived receiveChainKey:', toHex(derivedKeys.slice(32, 64)).slice(0, 32));

        state.rootKey = derivedKeys.slice(0, 32);
        state.receiveChainKey = derivedKeys.slice(32, 64);
        state.dhRemote = remoteRatchetKey;
        state.receiveCount = 0;
    }

    // Generate new DH ratchet keypair for sending
    const newDhRatchet = generateKeyPair();
    const dhOutput = dh(newDhRatchet.privateKey, state.dhRemote);
    const derivedKeys = deriveKey(state.rootKey, dhOutput, 'ChainmailRatchet', 64);

    state.rootKey = derivedKeys.slice(0, 32);
    state.sendChainKey = derivedKeys.slice(32, 64);
    state.dhRatchet = newDhRatchet;
    state.sendCount = 0;

    return state;
}

/**
 * Derive message key from chain key
 * @param {Uint8Array} chainKey - Current chain key
 * @returns {object} { messageKey, nextChainKey }
 */
export function deriveMessageKey(chainKey) {
    const messageKey = deriveKey(chainKey, 'MessageKey', 'ChainmailMessage', 32);
    const nextChainKey = deriveKey(chainKey, 'ChainKey', 'ChainmailChain', 32);

    return { messageKey, nextChainKey };
}

/**
 * Encrypt message using Double Ratchet
 * @param {object} state - Ratchet state
 * @param {Uint8Array} plaintext - Message to encrypt
 * @returns {Promise<object>} { ciphertext, header, newState }
 */
export async function ratchetEncrypt(state, plaintext) {
    console.log('🔐 ratchetEncrypt: sendChainKey:', toHex(state.sendChainKey).slice(0, 32));
    console.log('🔐 ratchetEncrypt: sendCount:', state.sendCount);

    // Derive message key from send chain
    const { messageKey, nextChainKey } = deriveMessageKey(state.sendChainKey);
    console.log('🔐 ratchetEncrypt: messageKey:', toHex(messageKey).slice(0, 32));

    // Encrypt message
    const { iv, ciphertext } = await encrypt(messageKey, plaintext);
    console.log('🔐 ratchetEncrypt: iv:', toHex(iv).slice(0, 24));
    console.log('🔐 ratchetEncrypt: ciphertext length:', ciphertext.length);

    // Create message header
    const header = {
        dhPublicKey: state.dhRatchet.publicKey,
        sendCount: state.sendCount,
        previousSendCount: state.previousSendCount
    };

    // Update state
    const newState = {
        ...state,
        sendChainKey: nextChainKey,
        sendCount: state.sendCount + 1
    };

    return {
        iv,
        ciphertext,
        header,
        newState
    };
}

/**
 * Decrypt message using Double Ratchet
 * @param {object} state - Ratchet state
 * @param {object} header - Message header
 * @param {Uint8Array} iv - Initialization vector
 * @param {Uint8Array} ciphertext - Encrypted message
 * @returns {Promise<object>} { plaintext, newState }
 */
export async function ratchetDecrypt(state, header, iv, ciphertext) {
    console.log('🔓 ratchetDecrypt: header.dhPublicKey:', toHex(header.dhPublicKey).slice(0, 32));
    console.log('🔓 ratchetDecrypt: header.sendCount:', header.sendCount);
    console.log('🔓 ratchetDecrypt: iv:', toHex(iv).slice(0, 24));
    console.log('🔓 ratchetDecrypt: ciphertext length:', ciphertext.length);

    let currentState = { ...state };

    // Check if we need to perform a DH ratchet step
    if (!buffersEqual(header.dhPublicKey, currentState.dhRemote)) {
        console.log('🔓 ratchetDecrypt: DH public key changed, performing ratchet step');
        currentState = ratchetStep(currentState, header.dhPublicKey);
    } else {
        console.log('🔓 ratchetDecrypt: DH public key unchanged, no ratchet step needed');
    }

    console.log('🔓 ratchetDecrypt: receiveChainKey:', currentState.receiveChainKey ? toHex(currentState.receiveChainKey).slice(0, 32) : 'null');
    console.log('🔓 ratchetDecrypt: receiveCount:', currentState.receiveCount);

    // Derive message key from receive chain
    let chainKey = currentState.receiveChainKey;
    for (let i = currentState.receiveCount; i < header.sendCount; i++) {
        const { nextChainKey } = deriveMessageKey(chainKey);
        chainKey = nextChainKey;
    }

    const { messageKey, nextChainKey } = deriveMessageKey(chainKey);
    console.log('🔓 ratchetDecrypt: messageKey:', toHex(messageKey).slice(0, 32));

    // Decrypt message
    const plaintext = await decrypt(messageKey, iv, ciphertext);

    // Update state
    currentState.receiveChainKey = nextChainKey;
    currentState.receiveCount = header.sendCount + 1;

    return {
        plaintext,
        newState: currentState
    };
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Compare two Uint8Arrays for equality
 */
function buffersEqual(a, b) {
    if (!a || !b) return false;
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

/**
 * Convert Uint8Array to hex string
 */
export function toHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Convert hex string to Uint8Array
 */
export function fromHex(hex) {
    if (!hex || typeof hex !== 'string') {
        throw new Error(`fromHex: invalid input: ${hex}`);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Convert Uint8Array to base64 string
 */
export function toBase64(bytes) {
    return btoa(String.fromCharCode(...bytes));
}

/**
 * Convert base64 string to Uint8Array
 */
export function fromBase64(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
