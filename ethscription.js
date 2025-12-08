import { ethers } from 'ethers';

// Constants
const MESSAGE_PROTOCOL = 'data:,{"p":"chainfeed.online","op":"msg"}';
const ETHSCRIPTION_ENDPOINT = 'https://api.ethscriptions.com/api/ethscriptions';

// Cache for API responses (5 minute TTL)
const apiCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Prevent concurrent fetches for the same address
const ongoingFetches = new Map();

/**
 * Clear the API cache for an address
 */
export function clearCache(address) {
    if (address) {
        apiCache.delete(address);
        console.log('Cache cleared for', address);
    } else {
        apiCache.clear();
        console.log('All cache cleared');
    }
}

/**
 * Send an encrypted message as an ethscription transaction
 * @param {string} recipientAddress - Recipient's Ethereum address (stored in calldata)
 * @param {string} encryptedCalldata - Encrypted message calldata with recipient info
 * @param {string} senderAddress - Sender's address (transaction sent to self)
 * @param {object} provider - Ethers provider
 * @param {object} signer - Ethers signer
 * @returns {object} Transaction details
 */
export async function sendEncryptedMessage(recipientAddress, encryptedCalldata, senderAddress, provider, signer) {
    try {
        // Validate recipient address
        if (!ethers.isAddress(recipientAddress)) {
            throw new Error('Invalid recipient address');
        }

        // Simple text format - much cheaper gas
        const calldataString = MESSAGE_PROTOCOL + (typeof encryptedCalldata === 'string' ? encryptedCalldata : encryptedCalldata.calldata);
        
        // Convert to hex for calldata
        const calldataHex = ethers.hexlify(ethers.toUtf8Bytes(calldataString));

        // Build transaction - SELF-SEND for privacy
        // Recipient address is in the calldata, not in 'to' field
        const tx = {
            to: senderAddress, // Send to self - keeps wallet history clean
            value: 0,
            data: calldataHex
        };

        // Send transaction
        console.log('Sending encrypted message transaction...');
        const txResponse = await signer.sendTransaction(tx);
        
        console.log('Transaction sent:', txResponse.hash);
        
        // Wait for confirmation
        const receipt = await txResponse.wait();
        
        console.log('Transaction confirmed:', receipt ? receipt.hash : txResponse.hash);

        return {
            success: true,
            txHash: receipt ? receipt.hash : txResponse.hash,
            blockNumber: receipt ? receipt.blockNumber : null,
            from: txResponse.from,
            to: txResponse.to
        };

    } catch (error) {
        console.error('Error sending encrypted message:', error);
        throw error;
    }
}



/**
 * No longer needed - notification is combined with message
 * @deprecated
 */
export async function sendNotification(recipientAddress, messageTxHash, signer) {
    console.log('Notification now combined with message ethscription');
    return { success: true };
}

/**
 * Fetch all messages sent to a specific address
 * @param {string} address - Address to fetch messages for
 * @returns {array} Array of message transactions
 */
export async function fetchMessagesForAddress(address) {
    // Check if there's an ongoing fetch for this address
    if (ongoingFetches.has(address)) {
        console.log('Fetch already in progress for', address);
        return ongoingFetches.get(address);
    }
    
    // Check cache first
    const cached = apiCache.get(address);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
        console.log('Returning cached messages for', address);
        return cached.messages;
    }
    
    // Create fetch promise
    const fetchPromise = (async () => {
        try {
            console.log(`Fetching messages for ${address}...`);
            
            // Query ALL text/plain ethscriptions (includes chainfeed.online messages)
            // We'll filter for chainfeed.online client-side
            const url = `https://api.ethscriptions.com/api/ethscriptions?mimetype=text/plain&sort_order=desc&per_page=500`;
            
            console.log(`Querying: ${url}`);
            const response = await fetch(url);
            
            if (!response.ok) {
                throw new Error(`API returned ${response.status}`);
            }
            
            const data = await response.json();
            // API returns array directly, not {ethscriptions: []}
            const allEthscriptions = Array.isArray(data) ? data : (data.ethscriptions || []);
            console.log(`Found ${allEthscriptions.length} total ethscriptions`);
            
            // Client-side filter: only chainfeed.online messages addressed to this user
            const messages = allEthscriptions.filter(ethscription => {
                try {
                    const content = ethscription.content_uri || '';
                    
                    // Must be chainfeed.online protocol (not old secrechat)
                    if (!content.includes('"p":"chainfeed.online"') || !content.includes('"op":"msg"')) {
                        return false;
                    }
                    
                    // Skip old secrechat messages
                    if (content.includes('"p":"secrechat"')) {
                        return false;
                    }
                    
                    // Parse the payload to check recipient
                    try {
                        // Split by data:, to get the JSON part
                        const jsonStr = content.split('data:,')[1];
                        if (!jsonStr) return false;
                        
                        // Extract just the base64 part after the protocol marker
                        const protocolMarker = '{"p":"chainfeed.online","op":"msg"}';
                        const markerIdx = jsonStr.indexOf(protocolMarker);
                        if (markerIdx === -1) return false;
                        
                        const base64Data = jsonStr.substring(markerIdx + protocolMarker.length);
                        const encryptedData = JSON.parse(atob(base64Data));
                        
                        // Message is for me if I'm the recipient in the payload
                        const isRecipient = encryptedData.to?.toLowerCase() === address.toLowerCase();
                        
                        if (isRecipient) {
                            console.log('✓ Found message for you:', ethscription.transaction_hash);
                            return true;
                        }
                    } catch (parseError) {
                        // Skip messages we can't parse
                        return false;
                    }
                    
                    return false;
                } catch (e) {
                    return false;
                }
            });

            console.log(`Found ${messages.length} messages addressed to you`);
            
            // Return messages with clean structure
            const normalizedMessages = messages.map(msg => ({
                txHash: msg.transaction_hash,
                from: msg.creator,
                to: msg.current_owner,
                blockNumber: msg.block_number,
                timestamp: new Date(msg.creation_timestamp).getTime() / 1000,
                calldata: msg.content_uri
            }));
            
            // Cache the result
            apiCache.set(address, {
                messages: normalizedMessages,
                timestamp: Date.now()
            });
            
            return normalizedMessages;

        } catch (error) {
            console.error('Error fetching messages:', error);
            return [];
        } finally {
            // Remove from ongoing fetches
            ongoingFetches.delete(address);
        }
    })();
    
    // Store the promise to prevent concurrent fetches
    ongoingFetches.set(address, fetchPromise);
    
    return fetchPromise;
}

/**
 * Fetch recent transactions for an address using Alchemy
 * @param {string} address - Address to fetch messages for
 * @returns {array} Array of message transactions
 */
async function fetchMessagesFromBlockchainDirect(address) {
    try {
        console.log('Fetching recent transactions for', address);
        
        const apiKey = import.meta.env.VITE_ALCHEMY_API_KEY;
        
        if (!apiKey) {
            console.warn('Alchemy API key not configured, skipping blockchain scan');
            return [];
        }
        
        const alchemyUrl = `https://eth-mainnet.g.alchemy.com/v2/${apiKey}`;
        
        // Get current block
        const blockResp = await fetch(alchemyUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'eth_blockNumber',
                params: []
            })
        });
        const blockData = await blockResp.json();
        const currentBlock = parseInt(blockData.result, 16);
        const fromBlock = '0x' + Math.max(0, currentBlock - 10000).toString(16);
        
        console.log(`Getting transaction count from block ${fromBlock} to latest...`);
        
        // Get transaction count
        const countResp = await fetch(alchemyUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'eth_getTransactionCount',
                params: [address, 'latest']
            })
        });
        const countData = await countResp.json();
        const txCount = parseInt(countData.result, 16);
        
        console.log(`Address has ${txCount} total transactions - getting transaction history...`);
        
        // Use Alchemy's alchemy_getAssetTransfers to get transaction history
        const historyResp = await fetch(alchemyUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'alchemy_getAssetTransfers',
                params: [{
                    fromBlock: fromBlock,
                    toBlock: 'latest',
                    toAddress: address,
                    category: ['external', 'internal'],
                    withMetadata: true,
                    excludeZeroValue: false,
                    maxCount: '0x64'
                }]
            })
        });
        
        const historyData = await historyResp.json();
        const transfers = historyData.result?.transfers || [];
        
        console.log(`Got ${transfers.length} transfers to this address`);
        
        const messages = [];
        
        // Check each transaction for calldata
        for (const transfer of transfers) {
            const txHash = transfer.hash;
            
            // Fetch full transaction data
            const txResp = await fetch(alchemyUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_getTransactionByHash',
                    params: [txHash]
                })
            });
            
            const txData = await txResp.json();
            const tx = txData.result;
            
            if (!tx || !tx.input || tx.input === '0x') continue;
            
            try {
                const dataStr = ethers.toUtf8String(tx.input);
                
                // Only include chainfeed.online protocol messages
                const isChainfeed = dataStr.includes('"p":"chainfeed.online"') && dataStr.includes('"op":"msg"');
                
                if (isChainfeed) {
                    // Check if this message is for the queried address
                    let isForMe = false;
                    try {
                        const parsed = parseCalldata(dataStr);
                        if (parsed) {
                            const encryptedData = JSON.parse(atob(parsed));
                            // Message is for me if: I'm the recipient in payload
                            isForMe = encryptedData.to?.toLowerCase() === address.toLowerCase();
                        }
                    } catch {
                        // If parsing fails, include it (might be old format or sent to me)
                        isForMe = tx.to?.toLowerCase() === address.toLowerCase();
                    }
                    
                    if (isForMe) {
                        messages.push({
                            transaction_hash: txHash,
                            from_address: tx.from,
                            to_address: tx.to,
                            block_number: parseInt(tx.blockNumber, 16),
                            block_timestamp: transfer.metadata?.blockTimestamp ? new Date(transfer.metadata.blockTimestamp).getTime() / 1000 : Date.now() / 1000,
                            content_uri: dataStr,
                            calldata: tx.input
                        });
                    }
                }
            } catch (e) {
                console.warn('Error decoding TX:', txHash, e);
            }
        }
        
        console.log(`Found ${messages.length} chainfeed.online messages`);
        return messages;
        
    } catch (error) {
        console.error('Error fetching from Alchemy:', error);
        return [];
    }
}

/**
 * Fallback method to fetch messages directly from blockchain
 * @param {string} address - Address to fetch messages for
 * @returns {array} Array of message transactions
 */
async function fetchMessagesFromBlockchain(address) {
    try {
        const provider = new ethers.JsonRpcProvider('https://eth.llamarpc.com');
        const latestBlock = await provider.getBlockNumber();
        const messages = [];

        // Scan recent blocks (last ~1000 blocks, adjust as needed)
        const blocksToScan = 1000;
        const startBlock = Math.max(0, latestBlock - blocksToScan);

        console.log(`Scanning blocks ${startBlock} to ${latestBlock}...`);

        for (let i = latestBlock; i >= startBlock; i--) {
            try {
                const block = await provider.getBlock(i, true);
                
                if (!block || !block.transactions) continue;

                for (const tx of block.transactions) {
                    if (tx.to?.toLowerCase() === address.toLowerCase() && tx.data && tx.data !== '0x') {
                        try {
                            const dataStr = ethers.toUtf8String(tx.data);
                            if (dataStr.includes('"p":"chainfeed.online"') && dataStr.includes('"op":"msg"')) {
                                messages.push({
                                    transaction_hash: tx.hash,
                                    from_address: tx.from,
                                    to_address: tx.to,
                                    block_number: tx.blockNumber,
                                    block_timestamp: block.timestamp,
                                    content_uri: dataStr,
                                    calldata: tx.data
                                });
                            }
                        } catch (e) {
                            // Skip non-UTF8 data
                        }
                    }
                }
            } catch (blockError) {
                console.error(`Error processing block ${i}:`, blockError);
            }
        }

        return messages;

    } catch (error) {
        console.error('Error fetching from blockchain:', error);
        return [];
    }
}

/**
 * Extract encrypted calldata from ethscription content
 * @param {string} contentUri - The ethscription content URI
 * @returns {string} Encrypted calldata
 */
export function extractEncryptedData(contentUri) {
    try {
        // Remove 'data:,' prefix
        const jsonStr = contentUri.replace(/^data:,/, '');
        
        // The encrypted data follows the protocol identifier
        const protocolEnd = jsonStr.indexOf('}') + 1;
        const encryptedData = jsonStr.substring(protocolEnd);
        
        return encryptedData;

    } catch (error) {
        console.error('Error extracting encrypted data:', error);
        return null;
    }
}

/**
 * Parse transaction data to extract encrypted calldata
 * @param {string} calldata - Raw transaction calldata
 * @returns {string} Encrypted calldata for decryption
 */
export function parseCalldata(calldata) {
    try {
        let dataStr;
        
        // Check if it's already a UTF-8 string (from content_uri) or hex (from calldata)
        if (calldata.startsWith('data:')) {
            // Already decoded UTF-8 string from content_uri
            dataStr = calldata;
        } else {
            // Hex-encoded calldata - need to decode
            const hexData = calldata.startsWith('0x') ? calldata.slice(2) : calldata;
            dataStr = ethers.toUtf8String('0x' + hexData);
        }
        
        // Check if it's HTML format (new format)
        if (dataStr.includes('data:text/html')) {
            // Extract from hidden div
            const match = dataStr.match(/<div[^>]*id="encrypted"[^>]*>(.*?)<\/div>/);
            if (match && match[1]) {
                const content = match[1];
                const protocolMarker = MESSAGE_PROTOCOL;
                const startIdx = content.indexOf(protocolMarker);
                if (startIdx !== -1) {
                    return content.substring(startIdx + protocolMarker.length);
                }
            }
        }
        
        // Support both formats:
        // 1. Full protocol: data:,{"p":"chainfeed.online","op":"msg"}base64data
        // 2. Just the JSON: {"p":"chainfeed.online","op":"msg"}base64data
        
        let protocolMarker = MESSAGE_PROTOCOL;
        let startIdx = dataStr.indexOf(protocolMarker);
        
        // If full protocol not found, try without the data:, prefix
        if (startIdx === -1) {
            protocolMarker = '{"p":"chainfeed.online","op":"msg"}';
            startIdx = dataStr.indexOf(protocolMarker);
        }
        
        if (startIdx === -1) {
            console.warn('Protocol marker not found in calldata. Data preview:', dataStr.substring(0, 100));
            return null;
        }
        
        const encryptedData = dataStr.substring(startIdx + protocolMarker.length);
        return encryptedData;

    } catch (error) {
        console.error('Error parsing calldata:', error);
        return null;
    }
}
