// Chainmail Backup & Restore System
// BIP39 mnemonic + AES-256-GCM encryption for Signal Protocol state

import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';

// ============================================================================
// Mnemonic Generation & Key Derivation
// ============================================================================

/**
 * Generate a 12-word BIP39 mnemonic
 * @returns {string} 12-word mnemonic phrase
 */
export function generateBackupMnemonic() {
    return bip39.generateMnemonic(wordlist, 128); // 128 bits = 12 words
}

/**
 * Validate a BIP39 mnemonic
 * @param {string} mnemonic - The mnemonic to validate
 * @returns {boolean} True if valid
 */
export function validateBackupMnemonic(mnemonic) {
    try {
        return bip39.validateMnemonic(mnemonic, wordlist);
    } catch {
        return false;
    }
}

/**
 * Derive AES-256 key from mnemonic using PBKDF2
 * @param {string} mnemonic - 12-word mnemonic
 * @param {string} salt - Salt (defaults to 'chainmail-backup')
 * @returns {Uint8Array} 32-byte encryption key
 */
export function deriveKeyFromMnemonic(mnemonic, salt = 'chainmail-backup') {
    const mnemonicBytes = new TextEncoder().encode(mnemonic);
    const saltBytes = new TextEncoder().encode(salt);

    // PBKDF2 with 100,000 iterations (recommended for password-based key derivation)
    return pbkdf2(sha256, mnemonicBytes, saltBytes, {
        c: 100000,
        dkLen: 32
    });
}

// ============================================================================
// Backup Encryption
// ============================================================================

/**
 * Create encrypted backup of Signal store data
 * @param {string} address - User's Ethereum address
 * @returns {Promise<object>} { backupData, mnemonic } - Encrypted backup and mnemonic to save
 */
export async function createBackup(address) {
    const normalizedAddress = address.toLowerCase();

    // Generate mnemonic
    const mnemonic = generateBackupMnemonic();

    // Derive encryption key
    const encryptionKey = deriveKeyFromMnemonic(mnemonic);

    // Gather all Signal store data from localStorage
    const storageKey = `chainmail_signal_identity_${normalizedAddress}`;
    const identityData = localStorage.getItem(storageKey);

    if (!identityData) {
        throw new Error('No Signal identity found for this address');
    }

    // Create backup payload
    const backupPayload = {
        version: 'v1.0',
        timestamp: Date.now(),
        address: normalizedAddress,
        identity: JSON.parse(identityData)
    };

    // Encrypt the payload
    const plaintext = new TextEncoder().encode(JSON.stringify(backupPayload));

    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Import key for Web Crypto API
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        encryptionKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );

    // Encrypt
    const ciphertextBuffer = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        },
        cryptoKey,
        plaintext
    );

    const ciphertext = new Uint8Array(ciphertextBuffer);

    // Create backup file structure
    const backupData = {
        version: 'v1.0',
        created: new Date().toISOString(),
        address: normalizedAddress,
        iv: Array.from(iv),
        ciphertext: Array.from(ciphertext)
    };

    return {
        backupData,
        mnemonic
    };
}

/**
 * Restore from encrypted backup
 * @param {object} backupData - Encrypted backup data
 * @param {string} mnemonic - 12-word mnemonic phrase
 * @returns {Promise<string>} Restored address
 */
export async function restoreBackup(backupData, mnemonic) {
    // Validate mnemonic
    if (!validateBackupMnemonic(mnemonic)) {
        throw new Error('Invalid mnemonic phrase');
    }

    // Validate backup format
    if (!backupData.version || !backupData.iv || !backupData.ciphertext) {
        throw new Error('Invalid backup file format');
    }

    // Derive decryption key
    const decryptionKey = deriveKeyFromMnemonic(mnemonic);

    // Convert arrays back to Uint8Arrays
    const iv = new Uint8Array(backupData.iv);
    const ciphertext = new Uint8Array(backupData.ciphertext);

    // Import key for Web Crypto API
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        decryptionKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );

    // Decrypt
    let plaintextBuffer;
    try {
        plaintextBuffer = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            cryptoKey,
            ciphertext
        );
    } catch (error) {
        throw new Error('Decryption failed - incorrect mnemonic or corrupted backup');
    }

    // Parse decrypted payload
    const plaintext = new TextDecoder().decode(plaintextBuffer);
    const backupPayload = JSON.parse(plaintext);

    // Validate payload
    if (!backupPayload.identity || !backupPayload.address) {
        throw new Error('Invalid backup payload');
    }

    // Restore to localStorage
    const storageKey = `chainmail_signal_identity_${backupPayload.address}`;
    localStorage.setItem(storageKey, JSON.stringify(backupPayload.identity));

    console.log('✅ Backup restored successfully for', backupPayload.address);

    return backupPayload.address;
}

// ============================================================================
// Backup File Management
// ============================================================================

/**
 * Download backup as JSON file
 * @param {object} backupData - Encrypted backup data
 * @param {string} address - User's address (for filename)
 */
export function downloadBackup(backupData, address) {
    const filename = `chainmail-backup-${address.slice(0, 8)}.json`;
    const jsonString = JSON.stringify(backupData, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Read backup file
 * @param {File} file - Backup file from file input
 * @returns {Promise<object>} Parsed backup data
 */
export async function readBackupFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = (e) => {
            try {
                const backupData = JSON.parse(e.target.result);
                resolve(backupData);
            } catch (error) {
                reject(new Error('Invalid backup file format'));
            }
        };

        reader.onerror = () => {
            reject(new Error('Failed to read backup file'));
        };

        reader.readAsText(file);
    });
}
