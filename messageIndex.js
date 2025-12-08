/**
 * Message indexer for SecureChat
 * Caches and indexes messages for faster retrieval
 * Can be used as a backend service or run in browser with IndexedDB
 */

const DB_NAME = 'SecureChatDB';
const DB_VERSION = 1;
const MESSAGES_STORE = 'messages';

/**
 * Initialize IndexedDB for message caching
 */
export async function initDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);

        request.onupgradeneeded = (event) => {
            const db = event.target.result;

            // Create messages store if it doesn't exist
            if (!db.objectStoreNames.contains(MESSAGES_STORE)) {
                const objectStore = db.createObjectStore(MESSAGES_STORE, { keyPath: 'txHash' });
                
                // Create indexes for efficient queries
                objectStore.createIndex('to', 'to', { unique: false });
                objectStore.createIndex('from', 'from', { unique: false });
                objectStore.createIndex('timestamp', 'timestamp', { unique: false });
                objectStore.createIndex('blockNumber', 'blockNumber', { unique: false });
            }
        };
    });
}

/**
 * Store a message in IndexedDB
 * @param {object} message - Message object to store
 */
export async function storeMessage(message) {
    try {
        const db = await initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([MESSAGES_STORE], 'readwrite');
            const store = transaction.objectStore(MESSAGES_STORE);
            
            const request = store.put(message);
            
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error storing message:', error);
        throw error;
    }
}

/**
 * Get all messages for a specific address
 * @param {string} address - Ethereum address
 * @returns {array} Array of messages
 */
export async function getMessagesForAddress(address) {
    try {
        const db = await initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([MESSAGES_STORE], 'readonly');
            const store = transaction.objectStore(MESSAGES_STORE);
            const index = store.index('to');
            
            const request = index.getAll(address.toLowerCase());
            
            request.onsuccess = () => {
                const messages = request.result || [];
                // Sort by timestamp descending
                messages.sort((a, b) => b.timestamp - a.timestamp);
                resolve(messages);
            };
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error getting messages:', error);
        return [];
    }
}

/**
 * Get a specific message by transaction hash
 * @param {string} txHash - Transaction hash
 * @returns {object} Message object
 */
export async function getMessageByTxHash(txHash) {
    try {
        const db = await initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([MESSAGES_STORE], 'readonly');
            const store = transaction.objectStore(MESSAGES_STORE);
            
            const request = store.get(txHash);
            
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error getting message:', error);
        return null;
    }
}

/**
 * Delete a message
 * @param {string} txHash - Transaction hash
 */
export async function deleteMessage(txHash) {
    try {
        const db = await initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([MESSAGES_STORE], 'readwrite');
            const store = transaction.objectStore(MESSAGES_STORE);
            
            const request = store.delete(txHash);
            
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error deleting message:', error);
        throw error;
    }
}

/**
 * Clear all cached messages
 */
export async function clearAllMessages() {
    try {
        const db = await initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([MESSAGES_STORE], 'readwrite');
            const store = transaction.objectStore(MESSAGES_STORE);
            
            const request = store.clear();
            
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error clearing messages:', error);
        throw error;
    }
}

/**
 * Check if a message exists in cache
 * @param {string} txHash - Transaction hash
 * @returns {boolean} True if message exists
 */
export async function messageExists(txHash) {
    const message = await getMessageByTxHash(txHash);
    return message !== null && message !== undefined;
}

/**
 * Get message count for an address
 * @param {string} address - Ethereum address
 * @returns {number} Count of messages
 */
export async function getMessageCount(address) {
    try {
        const db = await initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([MESSAGES_STORE], 'readonly');
            const store = transaction.objectStore(MESSAGES_STORE);
            const index = store.index('to');
            
            const request = index.count(address.toLowerCase());
            
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error getting message count:', error);
        return 0;
    }
}

/**
 * Batch store multiple messages
 * @param {array} messages - Array of message objects
 */
export async function batchStoreMessages(messages) {
    try {
        const db = await initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([MESSAGES_STORE], 'readwrite');
            const store = transaction.objectStore(MESSAGES_STORE);
            
            let completed = 0;
            const total = messages.length;
            
            messages.forEach(message => {
                const request = store.put(message);
                request.onsuccess = () => {
                    completed++;
                    if (completed === total) {
                        resolve(completed);
                    }
                };
                request.onerror = () => {
                    console.error('Error storing message:', request.error);
                };
            });
            
            if (total === 0) {
                resolve(0);
            }
        });
    } catch (error) {
        console.error('Error batch storing messages:', error);
        throw error;
    }
}

/**
 * Get messages sent from a specific address
 * @param {string} address - Ethereum address
 * @returns {array} Array of messages
 */
export async function getMessagesSentByAddress(address) {
    try {
        const db = await initDB();
        
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([MESSAGES_STORE], 'readonly');
            const store = transaction.objectStore(MESSAGES_STORE);
            const index = store.index('from');
            
            const request = index.getAll(address.toLowerCase());
            
            request.onsuccess = () => {
                const messages = request.result || [];
                messages.sort((a, b) => b.timestamp - a.timestamp);
                resolve(messages);
            };
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error getting sent messages:', error);
        return [];
    }
}
