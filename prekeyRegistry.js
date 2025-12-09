// On-chain Prekey Bundle Registry for Signal Protocol
// Publishes and fetches prekey bundles as ethscriptions

import { ethers } from 'ethers';

const PREKEY_PROTOCOL = 'data:,{"p":"chainfeed.online","op":"prekeys"}';
const PREKEY_USE_PROTOCOL = 'data:,{"p":"chainfeed.online","op":"prekey_use"}';
const ETHSCRIPTION_ENDPOINT = 'https://api.ethscriptions.com/api/ethscriptions';

// Cache for prekey bundles
const prekeyCache = new Map();
const usedPrekeysCache = new Map();

/**
 * Publish prekey bundle on-chain as ethscription
 * @param {object} bundle - Prekey bundle from Signal store
 * @param {object} signer - Ethers signer
 * @returns {object} Transaction details
 */
export async function publishPrekeyBundle(bundle, signer) {
    try {
        // Create prekey bundle payload
        const payload = {
            p: "chainfeed.online",
            op: "prekeys",
            v: "3.0", // Signal protocol version
            address: bundle.address,
            identityKey: bundle.identityKey,
            registrationId: bundle.registrationId,
            signedPreKey: bundle.signedPreKey,
            initialRatchetKey: bundle.initialRatchetKey, // CRITICAL: needed for Double Ratchet
            preKeys: bundle.preKeys,
            walletSignature: bundle.walletSignature,
            timestamp: Date.now()
        };

        // Convert to calldata format
        const calldataString = 'data:,' + JSON.stringify(payload);
        const calldataHex = ethers.hexlify(ethers.toUtf8Bytes(calldataString));

        // Build transaction - self-send
        const tx = {
            to: bundle.address, // Send to self
            value: 0,
            data: calldataHex
        };

        console.log('📤 Publishing prekey bundle on-chain...');
        const txResponse = await signer.sendTransaction(tx);

        console.log('Transaction sent:', txResponse.hash);

        // Wait for confirmation
        const receipt = await txResponse.wait();

        console.log('✅ Prekey bundle published:', receipt.hash);

        // Cache the bundle
        prekeyCache.set(bundle.address.toLowerCase(), {
            bundle: payload,
            txHash: receipt.hash,
            timestamp: Date.now()
        });

        return {
            success: true,
            txHash: receipt.hash,
            blockNumber: receipt.blockNumber
        };

    } catch (error) {
        console.error('❌ Error publishing prekey bundle:', error);
        throw error;
    }
}

/**
 * Fetch prekey bundle for a specific address
 * @param {string} address - Address to fetch bundle for
 * @returns {object|null} Prekey bundle or null if not found
 */
export async function fetchPrekeyBundle(address) {
    const normalizedAddress = address.toLowerCase();

    // Check cache first (5 minute TTL)
    const cached = prekeyCache.get(normalizedAddress);
    if (cached && (Date.now() - cached.timestamp) < 5 * 60 * 1000) {
        console.log('📦 Using cached prekey bundle for', address);
        return cached.bundle;
    }

    try {
        console.log('🔍 Fetching prekey bundle from chain for', address);

        // Fetch all ethscriptions from this address
        const url = `${ETHSCRIPTION_ENDPOINT}?creator=${address}&page=1&per_page=50`;
        const response = await fetch(url);
        const data = await response.json();

        // Handle different response formats
        const ethscriptions = Array.isArray(data) ? data : (data.ethscriptions || []);

        // Find the most recent prekey bundle
        let latestBundle = null;
        let latestTimestamp = 0;

        console.log(`🔎 Checking ${ethscriptions.length} ethscriptions for prekey bundles`);

        for (const eth of ethscriptions) {
            try {
                // Parse calldata
                const calldata = eth.calldata || eth.content_uri;
                if (!calldata) continue;

                // Convert to string (handle both hex and plain text)
                let dataString;
                if (typeof calldata === 'string' && calldata.startsWith('0x')) {
                    dataString = ethers.toUtf8String(calldata);
                } else {
                    dataString = calldata; // Already a string
                }

                // Debug: show what we found
                if (dataString.includes('chainfeed') || dataString.includes('prekey')) {
                    console.log('Found chainfeed ethscription:', eth.transaction_hash?.slice(0, 10), dataString.slice(0, 150));
                }

                // Check if it's a prekey bundle
                if (!dataString.includes('"op":"prekeys"')) continue;

                // Extract JSON from data URI
                const jsonStr = dataString.replace(/^data:,/, '');
                const payload = JSON.parse(jsonStr);

                // Verify it's the right protocol and address
                if (payload.p !== 'chainfeed.online' || payload.op !== 'prekeys') continue;
                if (payload.address.toLowerCase() !== normalizedAddress) continue;

                // Keep the most recent one
                if (payload.timestamp > latestTimestamp) {
                    latestTimestamp = payload.timestamp;
                    latestBundle = payload;
                }
            } catch (e) {
                // Skip invalid entries
                continue;
            }
        }

        if (latestBundle) {
            // Cache it
            prekeyCache.set(normalizedAddress, {
                bundle: latestBundle,
                timestamp: Date.now()
            });

            console.log('✅ Found prekey bundle for', address);
            return latestBundle;
        }

        console.log('⚠️ No prekey bundle found for', address);
        return null;

    } catch (error) {
        console.error('❌ Error fetching prekey bundle:', error);
        return null;
    }
}

/**
 * Mark a one-time prekey as used (optional on-chain tracking)
 * This prevents replay attacks and tracks prekey consumption
 * @param {string} recipientAddress - Address whose prekey was used
 * @param {number} prekeyId - ID of the used prekey
 * @param {object} signer - Ethers signer
 */
export async function markPrekeyAsUsed(recipientAddress, prekeyId, signer) {
    try {
        const payload = {
            p: "chainfeed.online",
            op: "prekey_use",
            recipient: recipientAddress.toLowerCase(),
            prekeyId,
            timestamp: Date.now()
        };

        const calldataString = 'data:,' + JSON.stringify(payload);
        const calldataHex = ethers.hexlify(ethers.toUtf8Bytes(calldataString));

        const address = await signer.getAddress();
        const tx = {
            to: address, // Self-send
            value: 0,
            data: calldataHex
        };

        console.log('📝 Marking prekey as used:', prekeyId);
        const txResponse = await signer.sendTransaction(tx);
        await txResponse.wait();

        // Update local cache
        const key = `${recipientAddress.toLowerCase()}_${prekeyId}`;
        usedPrekeysCache.set(key, Date.now());

        return { success: true, txHash: txResponse.hash };

    } catch (error) {
        console.error('Error marking prekey as used:', error);
        // Non-critical error - don't throw
        return { success: false };
    }
}

/**
 * Get available (unused) prekeys from a bundle
 * @param {object} bundle - Prekey bundle
 * @returns {array} Array of available prekeys
 */
export function getAvailablePrekeys(bundle) {
    if (!bundle || !bundle.preKeys) return [];

    return bundle.preKeys.filter(pk => {
        const key = `${bundle.address}_${pk.keyId}`;
        return !usedPrekeysCache.has(key);
    });
}

/**
 * Check if a user has published their prekey bundle
 * @param {string} address - Address to check
 * @param {number} maxRetries - Maximum number of retries if not found
 * @returns {boolean} True if bundle exists
 */
export async function hasPrekeyBundle(address, maxRetries = 3) {
    // Check cache first
    const cached = prekeyCache.get(address.toLowerCase());
    if (cached && (Date.now() - cached.timestamp) < 5 * 60 * 1000) {
        console.log('✅ Found prekey bundle in cache for', address);
        return true;
    }

    // Try fetching from chain with retries
    for (let i = 0; i < maxRetries; i++) {
        const bundle = await fetchPrekeyBundle(address);
        if (bundle !== null) {
            return true;
        }

        if (i < maxRetries - 1) {
            const delay = 3000 + (i * 2000); // Exponential backoff: 3s, 5s, 7s
            console.log(`⏳ Prekey bundle not found, retrying in ${delay/1000}s... (${i + 1}/${maxRetries})`);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }

    return false;
}

/**
 * Clear prekey cache for testing/debugging
 */
export function clearPrekeyCache() {
    prekeyCache.clear();
    usedPrekeysCache.clear();
    console.log('Prekey cache cleared');
}

/**
 * Debug: Fetch a specific ethscription by transaction hash
 * @param {string} txHash - Transaction hash
 * @returns {object|null} Ethscription data
 */
export async function debugFetchByTxHash(txHash) {
    try {
        const url = `${ETHSCRIPTION_ENDPOINT}/${txHash}`;
        console.log('🔍 Fetching ethscription:', url);

        const response = await fetch(url);
        const data = await response.json();

        console.log('📦 Ethscription data:', JSON.stringify(data, null, 2));

        if (data.calldata) {
            try {
                const dataString = ethers.toUtf8String(data.calldata);
                console.log('📝 Decoded calldata:', dataString.substring(0, 500));

                if (dataString.includes('prekeys')) {
                    const jsonStr = dataString.replace(/^data:,/, '');
                    const payload = JSON.parse(jsonStr);
                    console.log('✅ Parsed prekey bundle:', payload);
                }
            } catch (e) {
                console.error('Error decoding:', e);
            }
        }

        return data;
    } catch (error) {
        console.error('❌ Error fetching by hash:', error);
        return null;
    }
}
