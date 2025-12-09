// Signal Protocol Store - Browser-Compatible Implementation
// Uses custom X3DH + Double Ratchet implementation

import {
    generateKeyPair,
    x3dhSender,
    x3dhRecipient,
    initializeRatchetSender,
    initializeRatchetRecipient,
    ratchetEncrypt,
    ratchetDecrypt,
    toHex,
    fromHex,
    toBase64,
    fromBase64
} from './signalProtocol.js';
import { ethers } from 'ethers';

/**
 * Signal Protocol Store - manages identity, sessions, and prekeys
 */
class ChainmailSignalStore {
    constructor() {
        this.identityKeyPair = null;
        this.registrationId = null;
        this.sessions = new Map(); // address -> ratchet state
        this.preKeys = new Map(); // keyId -> keypair
        this.signedPreKey = null;
    }

    /**
     * Initialize the store - generates or loads identity key
     * @param {string} address - User's Ethereum address (for storage key)
     */
    async initialize(address) {
        const normalizedAddress = address.toLowerCase();
        const storageKey = `chainmail_signal_identity_${normalizedAddress}`;

        // Try to load existing identity
        const stored = localStorage.getItem(storageKey);
        if (stored) {
            const data = JSON.parse(stored);

            // Validate that stored identity is for this address
            if (!data.address) {
                console.warn('⚠️ Old identity format detected (no address), regenerating to ensure uniqueness...');
                localStorage.removeItem(storageKey);
                // Fall through to generate new identity
            } else if (data.address !== normalizedAddress) {
                console.warn('⚠️ Stored identity is for different address, regenerating...');
                localStorage.removeItem(storageKey);
                // Fall through to generate new identity
            } else {
                this.identityKeyPair = {
                    privateKey: fromHex(data.privateKey),
                    publicKey: fromHex(data.publicKey)
                };
                this.registrationId = data.registrationId;

                // Load prekeys if they exist
                if (data.signedPreKey) {
                    this.signedPreKey = {
                        keyId: data.signedPreKey.keyId,
                        keyPair: {
                            privateKey: fromHex(data.signedPreKey.privateKey),
                            publicKey: fromHex(data.signedPreKey.publicKey)
                        },
                        publicKey: fromHex(data.signedPreKey.publicKey),
                        signature: data.signedPreKey.signature,
                        timestamp: data.signedPreKey.timestamp
                    };
                }

                if (data.initialRatchetKey) {
                    this.initialRatchetKey = {
                        privateKey: fromHex(data.initialRatchetKey.privateKey),
                        publicKey: fromHex(data.initialRatchetKey.publicKey)
                    };
                }

                if (data.preKeys) {
                    for (const pk of data.preKeys) {
                        this.preKeys.set(pk.keyId, {
                            keyId: pk.keyId,
                            keyPair: {
                                privateKey: fromHex(pk.privateKey),
                                publicKey: fromHex(pk.publicKey)
                            },
                            publicKey: fromHex(pk.publicKey)
                        });
                    }
                }

                console.log('📱 Loaded existing Signal identity for', normalizedAddress, '- RegID:', this.registrationId);
                return;
            }
        }

        // Generate new identity
        this.identityKeyPair = generateKeyPair();
        this.registrationId = this.generateRegistrationId();

        // Save to localStorage with address for validation
        const toStore = {
            address: normalizedAddress,
            privateKey: toHex(this.identityKeyPair.privateKey),
            publicKey: toHex(this.identityKeyPair.publicKey),
            registrationId: this.registrationId
        };
        localStorage.setItem(storageKey, JSON.stringify(toStore));
        console.log('✨ Generated new Signal identity for', normalizedAddress, '- RegID:', this.registrationId);
    }

    /**
     * Generate a random registration ID (1-16380)
     */
    generateRegistrationId() {
        return Math.floor(Math.random() * 16380) + 1;
    }

    /**
     * Get public identity key
     */
    getIdentityPublicKey() {
        if (!this.identityKeyPair) {
            throw new Error('Signal store not initialized');
        }
        return this.identityKeyPair.publicKey;
    }

    /**
     * Generate signed prekey (signed by wallet, not identity key for simplicity)
     * @param {number} keyId - Prekey ID
     * @param {function} signMessageFn - Wallet signature function
     */
    async generateSignedPreKey(keyId, signMessageFn) {
        const keyPair = generateKeyPair();

        // Sign the public key with wallet for address binding
        const message = `Chainmail Signal Prekey\nKey ID: ${keyId}\nPublic Key: ${toHex(keyPair.publicKey)}`;
        const signature = await signMessageFn({ message });

        this.signedPreKey = {
            keyId,
            keyPair,
            publicKey: keyPair.publicKey,
            signature,
            timestamp: Date.now()
        };

        return this.signedPreKey;
    }

    /**
     * Generate batch of one-time prekeys
     * @param {number} startId - Starting prekey ID
     * @param {number} count - Number of prekeys to generate
     */
    async generatePreKeys(startId, count) {
        const preKeys = [];

        for (let i = 0; i < count; i++) {
            const keyId = startId + i;
            const keyPair = generateKeyPair();
            const preKey = {
                keyId,
                keyPair,
                publicKey: keyPair.publicKey
            };

            this.preKeys.set(keyId, preKey);
            preKeys.push(preKey);
        }

        return preKeys;
    }

    /**
     * Get prekey bundle for publishing on-chain
     * @param {function} signMessageFn - Wallet signature function
     * @param {string} address - User's Ethereum address
     */
    async getPrekeyBundle(signMessageFn, address) {
        if (!this.identityKeyPair) {
            throw new Error('Signal store not initialized');
        }

        // Generate signed prekey
        const signedPreKey = await this.generateSignedPreKey(1, signMessageFn);

        // Generate 20 one-time prekeys
        const oneTimePreKeys = await this.generatePreKeys(1, 20);

        // Also generate initial DH ratchet key (for Double Ratchet)
        const initialRatchetKey = generateKeyPair();
        this.initialRatchetKey = initialRatchetKey;

        // Create bundle data
        const bundle = {
            address: address.toLowerCase(),
            identityKey: toHex(this.identityKeyPair.publicKey),
            registrationId: this.registrationId,
            signedPreKey: {
                keyId: signedPreKey.keyId,
                publicKey: toHex(signedPreKey.publicKey),
                signature: signedPreKey.signature,
                timestamp: signedPreKey.timestamp
            },
            initialRatchetKey: toHex(initialRatchetKey.publicKey),
            preKeys: oneTimePreKeys.map(pk => ({
                keyId: pk.keyId,
                publicKey: toHex(pk.publicKey)
            }))
        };

        // Sign the bundle with wallet (proves address ownership)
        const message = `Chainmail Signal Prekey Bundle\n\nAddress: ${address.toLowerCase()}\nIdentity Key: ${bundle.identityKey.slice(0, 16)}...\nTimestamp: ${Date.now()}`;
        const walletSignature = await signMessageFn({ message });

        // Save prekeys to localStorage for persistence
        const storageKey = `chainmail_signal_identity_${address.toLowerCase()}`;
        const stored = localStorage.getItem(storageKey);
        if (stored) {
            const data = JSON.parse(stored);
            data.signedPreKey = {
                keyId: signedPreKey.keyId,
                privateKey: toHex(signedPreKey.keyPair.privateKey),
                publicKey: toHex(signedPreKey.keyPair.publicKey),
                signature: signedPreKey.signature,
                timestamp: signedPreKey.timestamp
            };
            data.initialRatchetKey = {
                privateKey: toHex(initialRatchetKey.privateKey),
                publicKey: toHex(initialRatchetKey.publicKey)
            };
            data.preKeys = oneTimePreKeys.map(pk => ({
                keyId: pk.keyId,
                privateKey: toHex(pk.keyPair.privateKey),
                publicKey: toHex(pk.keyPair.publicKey)
            }));
            localStorage.setItem(storageKey, JSON.stringify(data));
            console.log('💾 Saved prekeys to localStorage');
        }

        return {
            ...bundle,
            walletSignature
        };
    }

    /**
     * Initialize session with recipient (X3DH handshake as sender)
     * @param {string} recipientAddress - Recipient's address
     * @param {object} bundle - Recipient's prekey bundle
     * @returns {object} Initial message data for X3DH
     */
    async initializeSession(recipientAddress, bundle) {
        // Validate bundle has required fields
        if (!bundle.identityKey || !bundle.signedPreKey?.publicKey) {
            throw new Error('Invalid prekey bundle: missing required fields');
        }

        // Parse recipient's keys
        const recipientIdentityKey = fromHex(bundle.identityKey);
        const recipientSignedPreKey = fromHex(bundle.signedPreKey.publicKey);

        // Use initial ratchet key if available, otherwise generate one (for old bundles)
        let recipientRatchetKey;
        if (bundle.initialRatchetKey) {
            recipientRatchetKey = fromHex(bundle.initialRatchetKey);
        } else {
            console.warn('⚠️ Recipient bundle missing initialRatchetKey, using signedPreKey as ratchet key');
            recipientRatchetKey = recipientSignedPreKey;
        }

        // Get one-time prekey if available
        let recipientOneTimePreKey = null;
        let usedPrekeyId = null;
        if (bundle.preKeys && bundle.preKeys.length > 0) {
            const pk = bundle.preKeys[0]; // TODO: Track which ones are used
            recipientOneTimePreKey = fromHex(pk.publicKey);
            usedPrekeyId = pk.keyId;
        }

        // Perform X3DH handshake
        const { sharedSecret, ephemeralPublicKey } = x3dhSender(
            this.identityKeyPair,
            recipientIdentityKey,
            recipientSignedPreKey,
            recipientOneTimePreKey
        );

        // Initialize Double Ratchet
        const ratchetState = initializeRatchetSender(sharedSecret, recipientRatchetKey);

        // Store session
        this.sessions.set(recipientAddress.toLowerCase(), ratchetState);

        console.log('✅ Signal session initialized with', recipientAddress);

        return {
            ephemeralPublicKey,
            usedPrekeyId
        };
    }

    /**
     * Process incoming X3DH message and initialize session (as recipient)
     * @param {string} senderAddress - Sender's address
     * @param {Uint8Array} senderIdentityKey - Sender's identity public key
     * @param {Uint8Array} senderEphemeralKey - Sender's ephemeral public key
     * @param {number} usedPrekeyId - Which one-time prekey was used
     */
    async processX3DHMessage(senderAddress, senderIdentityKey, senderEphemeralKey, usedPrekeyId) {
        // Get our keys
        const recipientOneTimePreKey = usedPrekeyId ? this.preKeys.get(usedPrekeyId) : null;

        // Perform X3DH handshake as recipient
        // x3dhRecipient expects keypair objects with .privateKey and .publicKey directly
        const sharedSecret = x3dhRecipient(
            this.identityKeyPair,
            this.signedPreKey?.keyPair || this.signedPreKey, // Handle both old and new format
            recipientOneTimePreKey?.keyPair || recipientOneTimePreKey, // Handle both old and new format
            senderIdentityKey,
            senderEphemeralKey
        );

        // Initialize Double Ratchet
        const ratchetState = initializeRatchetRecipient(sharedSecret, this.initialRatchetKey);

        // Store session
        this.sessions.set(senderAddress.toLowerCase(), ratchetState);

        // Remove used one-time prekey
        if (usedPrekeyId) {
            this.preKeys.delete(usedPrekeyId);
            console.log('🗑️ Removed used one-time prekey:', usedPrekeyId);
        }

        console.log('✅ Signal session initialized from', senderAddress);
    }

    /**
     * Encrypt message using Double Ratchet
     * @param {string} recipientAddress - Recipient's address
     * @param {string} message - Plain text message
     * @returns {Promise<object>} Encrypted message data
     */
    async encryptMessage(recipientAddress, message) {
        const sessionKey = recipientAddress.toLowerCase();
        let ratchetState = this.sessions.get(sessionKey);

        if (!ratchetState) {
            throw new Error('No session found for ' + recipientAddress);
        }

        const plaintext = new TextEncoder().encode(message);

        // Encrypt using Double Ratchet
        const { iv, ciphertext, header, newState } = await ratchetEncrypt(ratchetState, plaintext);

        // Update session state
        this.sessions.set(sessionKey, newState);

        return {
            header: {
                dhPublicKey: toHex(header.dhPublicKey),
                sendCount: header.sendCount,
                previousSendCount: header.previousSendCount
            },
            iv: toBase64(iv),
            ciphertext: toBase64(ciphertext)
        };
    }

    /**
     * Decrypt message using Double Ratchet
     * @param {string} senderAddress - Sender's address
     * @param {object} encryptedMessage - Encrypted message data
     * @returns {Promise<string>} Decrypted message
     */
    async decryptMessage(senderAddress, encryptedMessage) {
        const sessionKey = senderAddress.toLowerCase();
        let ratchetState = this.sessions.get(sessionKey);

        if (!ratchetState) {
            throw new Error('No session found for ' + senderAddress);
        }

        const header = {
            dhPublicKey: fromHex(encryptedMessage.header.dhPublicKey),
            sendCount: encryptedMessage.header.sendCount,
            previousSendCount: encryptedMessage.header.previousSendCount
        };
        const iv = fromBase64(encryptedMessage.iv);
        const ciphertext = fromBase64(encryptedMessage.ciphertext);

        // Decrypt using Double Ratchet
        const { plaintext, newState } = await ratchetDecrypt(ratchetState, header, iv, ciphertext);

        // Update session state
        this.sessions.set(sessionKey, newState);

        return new TextDecoder().decode(plaintext);
    }
}

// Store instances per address (one identity per wallet)
const signalStores = new Map();

/**
 * Get or create Signal store instance for a specific address
 */
export async function getSignalStore(address) {
    const normalizedAddress = address.toLowerCase();

    if (!signalStores.has(normalizedAddress)) {
        const store = new ChainmailSignalStore();
        await store.initialize(normalizedAddress);
        signalStores.set(normalizedAddress, store);
        console.log('📱 Created Signal store for', normalizedAddress);
    }

    return signalStores.get(normalizedAddress);
}

/**
 * Export prekey bundle for publishing on-chain
 */
export async function exportPrekeyBundle(signMessageFn, address) {
    const store = await getSignalStore(address);
    return await store.getPrekeyBundle(signMessageFn, address);
}

/**
 * Encrypt message using Signal protocol
 * @param {string} senderAddress - Sender's address
 * @param {string} recipientAddress - Recipient's address
 * @param {object} recipientBundle - Recipient's prekey bundle
 * @param {string} message - Plain text message
 * @returns {Promise<object>} Encrypted message with X3DH data
 */
export async function signalEncryptMessage(senderAddress, recipientAddress, recipientBundle, message) {
    const store = await getSignalStore(senderAddress);
    if (!store) {
        throw new Error('Signal store not initialized');
    }

    // Check if session exists
    const sessionKey = recipientAddress.toLowerCase();
    let isNewSession = !store.sessions.has(sessionKey);

    let x3dhData = null;
    if (isNewSession) {
        // Initialize session with X3DH
        x3dhData = await store.initializeSession(recipientAddress, recipientBundle);
    }

    // Encrypt message
    const encrypted = await store.encryptMessage(recipientAddress, message);

    return {
        isPreKeyMessage: isNewSession,
        x3dh: isNewSession ? {
            senderIdentityKey: toHex(store.identityKeyPair.publicKey),
            ephemeralKey: toHex(x3dhData.ephemeralPublicKey),
            usedPrekeyId: x3dhData.usedPrekeyId
        } : null,
        ...encrypted
    };
}

/**
 * Decrypt message using Signal protocol
 * @param {string} recipientAddress - Recipient's address (who is decrypting)
 * @param {string} senderAddress - Sender's address
 * @param {object} encryptedMessage - Encrypted message data
 * @returns {Promise<string>} Decrypted message
 */
export async function signalDecryptMessage(recipientAddress, senderAddress, encryptedMessage) {
    console.log('🔐 signalDecryptMessage: Getting store');
    const store = await getSignalStore(recipientAddress);
    if (!store) {
        throw new Error('Signal store not initialized');
    }

    console.log('🔐 signalDecryptMessage: isPreKeyMessage:', encryptedMessage.isPreKeyMessage);
    // Check if this is a prekey message (new session)
    if (encryptedMessage.isPreKeyMessage && encryptedMessage.x3dh) {
        console.log('🔐 signalDecryptMessage: Processing X3DH...');
        const senderIdentityKey = fromHex(encryptedMessage.x3dh.senderIdentityKey);
        const ephemeralKey = fromHex(encryptedMessage.x3dh.ephemeralKey);
        const usedPrekeyId = encryptedMessage.x3dh.usedPrekeyId;

        await store.processX3DHMessage(senderAddress, senderIdentityKey, ephemeralKey, usedPrekeyId);
        console.log('🔐 signalDecryptMessage: X3DH complete');
    }

    console.log('🔐 signalDecryptMessage: Calling decryptMessage...');
    // Decrypt message
    const result = await store.decryptMessage(senderAddress, encryptedMessage);
    console.log('🔐 signalDecryptMessage: Done');
    return result;
}
