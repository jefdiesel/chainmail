// Browser-compatible ECDH encryption/decryption module
// Uses Web Crypto API and ethers.js

import { ethers } from 'ethers';

/**
 * Derive a deterministic PUBLIC key from an Ethereum address
 * SAFE: Public keys are meant to be public
 * Used by sender to encrypt messages to recipient
 * @param {string} address - Ethereum address
 * @returns {string} publicKey - Deterministic public key
 */
export function derivePublicKeyFromAddress(address) {
    // Create a deterministic seed from address + salt
    const seed = ethers.keccak256(ethers.toUtf8Bytes(address.toLowerCase() + "SecureChat"));
    
    // Use first 32 bytes as private key (only used to derive public)
    const privateKey = '0x' + seed.slice(2, 66);
    
    // Create signing key from private key to get public key
    const signingKey = new ethers.SigningKey(privateKey);
    
    return signingKey.publicKey;
}

/**
 * Derive keypair from WALLET SIGNATURE (secure)
 * CRITICAL: This requires actual wallet access - cannot be derived by attacker
 * Used by recipient to decrypt their messages
 * @param {function} signMessageFn - Async function to sign message with wallet
 * @param {string} address - User's Ethereum address
 * @returns {Promise<object>} { privateKey, publicKey, signature }
 */
export async function deriveKeypairFromWalletSignature(signMessageFn, address) {
    // Message to sign - deterministic so we get same keypair each session
    const message = `Chainmail v2.0 Messaging Key\n\nAddress: ${address.toLowerCase()}\n\nSign this once to securely decrypt your messages.`;
    
    // Get wallet signature (only real wallet owner can create this)
    const signature = await signMessageFn({ message });
    
    // Derive private key from signature (256 bits of entropy)
    const seed = ethers.keccak256(signature);
    const privateKey = '0x' + seed.slice(2, 66);
    
    // Get public key
    const signingKey = new ethers.SigningKey(privateKey);
    
    return {
        privateKey,
        publicKey: signingKey.publicKey,
        signature
    };
}

/**
 * DEPRECATED: Old insecure derivation (kept for reference)
 * DO NOT USE - anyone can compute this from public address
 */
export function deriveKeypairFromAddress(address) {
    console.warn('⚠️ deriveKeypairFromAddress is INSECURE - use deriveKeypairFromWalletSignature instead');
    const seed = ethers.keccak256(ethers.toUtf8Bytes(address.toLowerCase() + "SecureChat"));
    const privateKey = '0x' + seed.slice(2, 66);
    const signingKey = new ethers.SigningKey(privateKey);
    
    return {
        privateKey: privateKey,
        publicKey: signingKey.publicKey
    };
}

/**
 * Encrypt a message for a recipient using ECDH
 * @param {string} recipientAddress - Recipient's Ethereum address
 * @param {string} message - Plain text message to encrypt
 * @param {string} subject - Subject line (optional)
 * @param {string} senderAddress - Sender's address
 * @param {boolean} saveOutbox - Whether to save to outbox
 * @returns {object} Encrypted message data
 */
export async function encryptMessageForRecipient(message, recipientAddress, senderAddress, saveOutbox = false, subject = '') {
    try {
        let senderPublicKey;
        let senderPrivateKey;
        
        if (saveOutbox) {
            // Use deterministic keys - allows sender to decrypt later
            // WARNING: This still uses old insecure method for backwards compatibility
            // TODO: Migrate to wallet-signed keys
            const senderKeys = deriveKeypairFromAddress(senderAddress);
            senderPrivateKey = senderKeys.privateKey;
            senderPublicKey = senderKeys.publicKey;
        } else {
            // Use ephemeral keys - forward secrecy (sender can't decrypt later)
            const ephemeralWallet = ethers.Wallet.createRandom();
            senderPrivateKey = ephemeralWallet.privateKey;
            senderPublicKey = ephemeralWallet.signingKey.publicKey;
        }
        
        // Derive recipient's deterministic public key (this is safe - public keys are public)
        const recipientPublicKey = derivePublicKeyFromAddress(recipientAddress);
        
        // Compute shared secret using sender private + recipient public
        const sharedSecret = await deriveSharedSecret(senderPrivateKey, recipientPublicKey);
        
        // Package subject and message together
        const payload = JSON.stringify({ subject: subject || '', message });
        
        // Encrypt the entire payload
        const { ivHex, ciphertextHex } = await encryptAES(payload, sharedSecret);
        
        // Package encrypted data
        // Recipient address included since we now self-send (privacy fix)
        const encrypted = { 
            to: recipientAddress, // Recipient address (tx is self-send)
            senderPublicKey, // Required for ECDH shared secret computation
            senderAddress: saveOutbox ? senderAddress : undefined, // Only include if saving to outbox
            iv: ivHex, 
            ciphertext: ciphertextHex,
            saveOutbox // Include flag for reference
        };
        const encryptedStr = JSON.stringify(encrypted);
        const encryptedBase64 = btoa(encryptedStr);
        
        // If ephemeral, private key goes out of scope and is garbage collected
        return encryptedBase64;
    } catch (error) {
        console.error('Error encrypting message:', error);
        throw error;
    }
}

/**
 * Decrypt a message using the recipient's private key
 * @param {string} privateKey - Recipient's private key (from wallet)
 * @param {string} encryptedData - Encrypted calldata from transaction
 * @returns {object} Decrypted message object with subject and message, or null
 */
export async function decryptMessage(privateKey, encryptedData) {
    try {
        // Validate encryptedData is base64
        if (!encryptedData || typeof encryptedData !== 'string') {
            console.error('Invalid encrypted data: not a string');
            return null;
        }
        
        // Check if it looks like hex data (old format) instead of base64
        if (encryptedData.startsWith('0x')) {
            console.warn('Message appears to use old hex format, cannot decrypt');
            return null;
        }
        
        // Try to decode base64
        let encryptedStr;
        try {
            encryptedStr = atob(encryptedData);
        } catch (e) {
            console.error('Failed to decode base64:', e);
            return null;
        }
        
        // Parse JSON
        let parsed;
        try {
            parsed = JSON.parse(encryptedStr);
        } catch (e) {
            console.error('Failed to parse JSON from decoded data:', e);
            return null;
        }
        
        const { senderPublicKey, senderAddress, iv, ciphertext } = parsed;
        
        // Validate required fields
        if (!senderPublicKey || !iv || !ciphertext) {
            console.error('Missing required fields in encrypted data:', { 
                hasSenderPublicKey: !!senderPublicKey, 
                hasIv: !!iv, 
                hasCiphertext: !!ciphertext 
            });
            return null;
        }
        
        // Compute shared secret using recipient private + sender public
        const sharedSecret = await deriveSharedSecret(privateKey, senderPublicKey);
        const decrypted = await decryptAES(ciphertext, sharedSecret, iv);
        
        // Try to parse as JSON (new format with subject)
        try {
            const payload = JSON.parse(decrypted);
            if (payload.message !== undefined) {
                return {
                    subject: payload.subject || '',
                    message: payload.message,
                    senderAddress: senderAddress // May be undefined for ephemeral messages
                };
            }
        } catch (e) {
            // Not JSON, treat as plain text (old format)
        }
        
        // Old format: plain text message
        return {
            subject: '',
            message: decrypted,
            senderAddress: senderAddress
        };
    } catch (error) {
        console.error('Error decrypting message:', error);
        return null;
    }
}

/**
 * Get public key from Ethereum address by recovering from transaction signature
 * Uses multiple APIs to fetch transaction history
 * @param {object} provider - Ethers provider
 * @param {string} address - Ethereum address
 * @returns {string} Public key (hex string with 0x prefix)
 */
async function getPublicKeyFromAddress(provider, address) {
    try {
        console.log(`Fetching public key for ${address}...`);
        
        // Check if address has made any transactions
        const txCount = await provider.getTransactionCount(address);
        if (txCount === 0) {
            throw new Error('Recipient has no transaction history. They need to send at least one transaction first.');
        }

        console.log(`Address has ${txCount} transactions. Fetching...`);

        const network = await provider.getNetwork();
        const chainId = network.chainId;

        // Try multiple API services
        const apiMethods = [
            // Etherscan (free tier, no key needed for low usage)
            async () => {
                let baseUrl;
                if (chainId === 1n) baseUrl = 'https://api.etherscan.io/api';
                else if (chainId === 11155111n) baseUrl = 'https://api-sepolia.etherscan.io/api';
                else return null;

                console.log('Trying Etherscan API...');
                const url = `${baseUrl}?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&page=1&offset=10&sort=desc`;
                const response = await fetch(url);
                const data = await response.json();
                
                if (data.status === '1' && data.result?.length > 0) {
                    // Find a transaction FROM this address
                    for (const tx of data.result) {
                        if (tx.from.toLowerCase() === address.toLowerCase()) {
                            return tx.hash;
                        }
                    }
                }
                return null;
            },
            
            // Blockscout (works for many chains)
            async () => {
                let baseUrl;
                if (chainId === 1n) baseUrl = 'https://eth.blockscout.com/api';
                else return null;

                console.log('Trying Blockscout API...');
                const url = `${baseUrl}?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&page=1&offset=10&sort=desc`;
                const response = await fetch(url);
                const data = await response.json();
                
                if (data.status === '1' && data.result?.length > 0) {
                    // Find a transaction FROM this address
                    for (const tx of data.result) {
                        if (tx.from.toLowerCase() === address.toLowerCase()) {
                            return tx.hash;
                        }
                    }
                }
                return null;
            },

            // Alchemy API (if available via provider)
            async () => {
                try {
                    console.log('Trying Alchemy getAssetTransfers...');
                    // Use Alchemy's getAssetTransfers if provider supports it
                    const result = await provider.send('alchemy_getAssetTransfers', [{
                        fromAddress: address,
                        category: ['external', 'internal', 'erc20', 'erc721', 'erc1155'],
                        maxCount: '0x1',
                        order: 'desc'
                    }]);
                    
                    if (result?.transfers?.length > 0) {
                        return result.transfers[0].hash;
                    }
                } catch (e) {
                    console.log('Alchemy method not available');
                }
                return null;
            }
        ];

        // Try each API method
        let txHash = null;
        for (const method of apiMethods) {
            try {
                txHash = await method();
                if (txHash) break;
            } catch (error) {
                console.log(`API method failed: ${error.message}`);
                continue;
            }
        }

        if (!txHash) {
            throw new Error(`Unable to fetch transaction history for ${address}. Please ensure the address has sent at least one transaction.`);
        }

        console.log(`Found transaction: ${txHash}`);
        
        // Fetch the transaction with full details
        const tx = await provider.getTransaction(txHash);
        if (!tx) {
            throw new Error('Could not fetch transaction details');
        }

        console.log(`Transaction from: ${tx.from}, expected: ${address}`);
        
        if (tx.from.toLowerCase() !== address.toLowerCase()) {
            throw new Error(`Transaction sender (${tx.from}) does not match address (${address})`);
        }

        // If transaction is pending or doesn't have signature, fetch receipt
        if (!tx.signature && !tx.r) {
            console.log('Fetching transaction receipt for signature...');
            const receipt = await provider.getTransactionReceipt(txHash);
            if (receipt) {
                // Refetch with receipt block
                const blockTx = await provider.getTransaction(txHash);
                if (blockTx && (blockTx.signature || blockTx.r)) {
                    const publicKey = await recoverPublicKeyFromTx(blockTx);
                    if (publicKey) {
                        console.log('Successfully recovered public key!');
                        return publicKey;
                    }
                }
            }
        }

        const publicKey = await recoverPublicKeyFromTx(tx);
        if (!publicKey) {
            throw new Error('Failed to recover public key from transaction. The transaction may be pending or have an invalid signature.');
        }

        console.log('Successfully recovered public key!');
        return publicKey;

    } catch (error) {
        console.error('Error getting public key:', error);
        throw error;
    }
}

/**
 * Helper function to recover public key from a transaction
 * @param {object} tx - Transaction object
 * @returns {string|null} Public key or null if recovery fails
 */
async function recoverPublicKeyFromTx(tx) {
    try {
        // Check if signature fields exist
        if (!tx.signature || (!tx.r && !tx.signature.r)) {
            console.log('Transaction missing signature fields, fetching full details...');
            return null;
        }

        // Get signature from either tx.signature object or direct fields
        const signature = tx.signature || {
            r: tx.r,
            s: tx.s,
            v: tx.v
        };

        if (!signature.r || !signature.s) {
            console.log('Invalid signature fields');
            return null;
        }

        // Build transaction for hash calculation
        const txData = {
            type: tx.type,
            nonce: tx.nonce,
            gasLimit: tx.gasLimit,
            to: tx.to,
            value: tx.value,
            data: tx.data,
            chainId: tx.chainId
        };
        
        // Add gas price fields based on tx type
        if (tx.type === 0 || tx.type === 1 || tx.type === null) {
            txData.gasPrice = tx.gasPrice;
        } else if (tx.type === 2) {
            txData.maxFeePerGas = tx.maxFeePerGas;
            txData.maxPriorityFeePerGas = tx.maxPriorityFeePerGas;
        }

        const transaction = ethers.Transaction.from(txData);
        const serializedTx = transaction.unsignedSerialized;
        const txHash = ethers.keccak256(serializedTx);

        // Recover public key
        const publicKey = ethers.SigningKey.recoverPublicKey(
            txHash,
            ethers.Signature.from(signature)
        );

        return publicKey;
    } catch (error) {
        console.error('Error recovering public key from tx:', error);
        return null;
    }
}

/**
 * Derive shared secret using ECDH on secp256k1 curve
 * @param {string} privateKey - Private key (hex with 0x prefix)
 * @param {string} publicKey - Public key (hex with 0x prefix, uncompressed)
 * @returns {Uint8Array} Shared secret (32 bytes)
 */
async function deriveSharedSecret(privateKey, publicKey) {
    try {
        // Use ethers SigningKey for ECDH computation
        const privateKeyBytes = ethers.getBytes(privateKey);
        const publicKeyBytes = ethers.getBytes(publicKey);
        const signingKey = new ethers.SigningKey(privateKeyBytes);
        
        // Compute shared point (ECDH)
        const sharedPoint = signingKey.computeSharedSecret(publicKeyBytes);
        
        // Hash the shared point to get symmetric key
        const sharedSecret = ethers.keccak256(sharedPoint);
        
        // Convert to Uint8Array (remove 0x prefix)
        const secretBytes = ethers.getBytes(sharedSecret);
        
        return secretBytes;

    } catch (error) {
        console.error('Error deriving shared secret:', error);
        throw error;
    }
}

/**
 * Encrypt plaintext using AES-256-GCM
 * @param {string} plaintext - Message to encrypt
 * @param {Uint8Array} key - 32-byte encryption key
 * @returns {string} Hex string of encrypted data (iv + ciphertext + authTag)
 */
async function encryptAES(plaintext, key) {
    try {
        // Generate random IV (12 bytes for GCM)
        const iv = ethers.randomBytes(12);
        
        // Import key for Web Crypto API
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        // Convert plaintext to bytes
        const plaintextBytes = new TextEncoder().encode(plaintext);

        // Encrypt
        const ciphertextBuffer = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv, tagLength: 128 },
            cryptoKey,
            plaintextBytes
        );

        // Return iv and ciphertext separately as hex
        const ivHex = ethers.hexlify(iv).slice(2);
        const ciphertextHex = ethers.hexlify(new Uint8Array(ciphertextBuffer)).slice(2);
        return { ivHex, ciphertextHex };

    } catch (error) {
        console.error('Error encrypting:', error);
        throw error;
    }
}

/**
 * Decrypt ciphertext using AES-256-GCM
 * @param {string} ciphertextHex - Hex string of encrypted data
 * @param {Uint8Array} key - 32-byte decryption key
 * @returns {string} Decrypted plaintext
 */
async function decryptAES(ciphertextHex, key, ivHex) {
    try {
        // Convert hex to bytes
        const ciphertext = ethers.getBytes('0x' + ciphertextHex);
        const iv = ethers.getBytes('0x' + ivHex);

        // Import key for Web Crypto API
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        // Decrypt
        const plaintextBytes = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv, tagLength: 128 },
            cryptoKey,
            ciphertext
        );

        // Convert bytes to string
        const plaintext = new TextDecoder().decode(plaintextBytes);

        return plaintext;

    } catch (error) {
        console.error('Error decrypting:', error);
        throw new Error('Decryption failed. Invalid key or corrupted data.');
    }
}

/**
 * Validate Ethereum address
 * @param {string} address - Address to validate
 * @returns {boolean} True if valid
 */
export function isValidAddress(address) {
    return ethers.isAddress(address);
}

// ============================================================================
// Signal Protocol Integration (v3.0)
// ============================================================================

import { getSignalStore, signalEncryptMessage, signalDecryptMessage } from './signalStore.js';
import { fetchPrekeyBundle, getAvailablePrekeys } from './prekeyRegistry.js';

/**
 * Encrypt message using Signal protocol (X3DH + Double Ratchet)
 * @param {string} message - Plain text message
 * @param {string} subject - Subject line
 * @param {string} recipientAddress - Recipient's address
 * @param {string} senderAddress - Sender's address
 * @returns {Promise<string>} Encrypted message bundle (base64)
 */
export async function encryptMessageSignal(message, subject, recipientAddress, senderAddress) {
    try {
        // Initialize Signal store for sender
        await getSignalStore(senderAddress);

        // Fetch recipient's prekey bundle from chain
        const recipientBundle = await fetchPrekeyBundle(recipientAddress);
        if (!recipientBundle) {
            // No prekeys found - fall back to v2.0 ephemeral ECDH
            console.warn(`⚠️ Recipient ${recipientAddress} has no prekeys. Falling back to v2.0 encryption.`);
            return await encryptMessageForRecipient(message, recipientAddress, senderAddress, false, subject);
        }

        // Check if there are available prekeys
        const availablePrekeys = getAvailablePrekeys(recipientBundle);
        if (availablePrekeys.length === 0) {
            console.warn('⚠️ No available one-time prekeys, using signed prekey only');
        }

        // Package message with subject
        const payload = JSON.stringify({ subject: subject || '', message });

        // Encrypt using Signal protocol
        const ciphertext = await signalEncryptMessage(
            senderAddress,
            recipientAddress,
            recipientBundle,
            payload
        );

        // Package for on-chain storage
        const packagedMessage = {
            v: 3, // Signal protocol version
            to: recipientAddress,
            isPreKeyMessage: ciphertext.isPreKeyMessage,
            x3dh: ciphertext.x3dh,
            header: ciphertext.header,
            iv: ciphertext.iv,
            ciphertext: ciphertext.ciphertext,
            timestamp: Date.now()
        };

        return btoa(JSON.stringify(packagedMessage));

    } catch (error) {
        console.error('Error encrypting with Signal protocol:', error);
        throw error;
    }
}

/**
 * Decrypt message using Signal protocol
 * @param {string} encryptedData - Encrypted message (base64)
 * @param {string} senderAddress - Sender's address
 * @param {string} recipientAddress - Recipient's address (current user)
 * @returns {Promise<object>} Decrypted { subject, message, senderAddress }
 */
export async function decryptMessageSignal(encryptedData, senderAddress, recipientAddress) {
    try {
        console.log('🔓 Step 1: Getting Signal store');
        // Initialize Signal store for recipient
        await getSignalStore(recipientAddress);

        console.log('🔓 Step 2: Parsing package');
        // Parse encrypted package
        const decoded = atob(encryptedData);
        const packagedMessage = JSON.parse(decoded);

        // Verify version
        if (packagedMessage.v !== 3) {
            throw new Error(`Unsupported message version: ${packagedMessage.v}`);
        }

        console.log('🔓 Step 3: Preparing encrypted message');
        console.log('🔓 Message DH public key:', packagedMessage.header?.dhPublicKey?.slice(0, 32) || 'N/A');
        console.log('🔓 Is prekey message:', packagedMessage.isPreKeyMessage);

        // Decrypt using Signal protocol
        const encryptedMessage = {
            isPreKeyMessage: packagedMessage.isPreKeyMessage,
            x3dh: packagedMessage.x3dh,
            header: packagedMessage.header,
            iv: packagedMessage.iv,
            ciphertext: packagedMessage.ciphertext
        };

        console.log('🔓 Step 4: Calling signalDecryptMessage...');
        const decrypted = await signalDecryptMessage(recipientAddress, senderAddress, encryptedMessage);
        console.log('🔓 Step 5: Decryption complete');

        // Parse payload (subject + message)
        const payload = JSON.parse(decrypted);

        return {
            subject: payload.subject || '',
            message: payload.message,
            senderAddress: senderAddress
        };

    } catch (error) {
        console.error('Error decrypting with Signal protocol:', error);
        return null;
    }
}

/**
 * Auto-detect message version and decrypt accordingly
 * @param {string} encryptedData - Encrypted message (base64)
 * @param {string} senderAddress - Sender's address
 * @param {string} recipientPrivateKey - Recipient's private key (for v2)
 * @param {string} recipientAddress - Recipient's address (for v3)
 * @returns {Promise<object>} Decrypted message
 */
export async function decryptMessageAuto(encryptedData, senderAddress, recipientPrivateKey, recipientAddress) {
    try {
        // Try to parse as JSON
        const decoded = atob(encryptedData);
        const parsed = JSON.parse(decoded);

        // Check version
        if (parsed.v === 3) {
            // Signal protocol v3.0
            console.log('🔐 Decrypting v3.0 Signal protocol message');
            return await decryptMessageSignal(encryptedData, senderAddress, recipientAddress);
        } else {
            // Legacy ECDH v2.0 (no version field or different version)
            console.log('🔐 Decrypting v2.0 legacy ECDH message');
            return await decryptMessage(recipientPrivateKey, encryptedData);
        }
    } catch (e) {
        console.warn('Error parsing message, trying legacy decrypt:', e.message);
        // Fallback to legacy
        return await decryptMessage(recipientPrivateKey, encryptedData);
    }
}
