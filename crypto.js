// Browser-compatible ECDH encryption/decryption module
// Uses Web Crypto API and ethers.js

import { ethers } from 'ethers';

/**
 * Derive a deterministic keypair from an Ethereum address
 * @param {string} address - Ethereum address
 * @returns {object} { privateKey, publicKey }
 */
export function deriveKeypairFromAddress(address) {
    // Create a deterministic seed from address + salt
    const seed = ethers.keccak256(ethers.toUtf8Bytes(address.toLowerCase() + "SecureChat"));
    
    // Use first 32 bytes as private key
    const privateKey = '0x' + seed.slice(2, 66);
    
    // Create signing key from private key to get public key
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
            const senderKeys = deriveKeypairFromAddress(senderAddress);
            senderPrivateKey = senderKeys.privateKey;
            senderPublicKey = senderKeys.publicKey;
        } else {
            // Use ephemeral keys - forward secrecy (sender can't decrypt later)
            const ephemeralWallet = ethers.Wallet.createRandom();
            senderPrivateKey = ephemeralWallet.privateKey;
            senderPublicKey = ephemeralWallet.signingKey.publicKey;
        }
        
        // Derive recipient's deterministic public key
        const { publicKey: recipientPublicKey } = deriveKeypairFromAddress(recipientAddress);
        
        // Compute shared secret using sender private + recipient public
        const sharedSecret = await deriveSharedSecret(senderPrivateKey, recipientPublicKey);
        
        // Package subject and message together
        const payload = JSON.stringify({ subject: subject || '', message });
        
        // Encrypt the entire payload
        const { ivHex, ciphertextHex } = await encryptAES(payload, sharedSecret);
        
        // Package with sender's public key and sender address (for ephemeral messages)
        const encrypted = { 
            senderPublicKey,
            senderAddress: saveOutbox ? senderAddress : undefined, // Only include if not ephemeral
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
