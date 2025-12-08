import { ethers } from 'ethers';
import { 
    encryptMessageForRecipient, 
    decryptMessage, 
    isValidAddress 
} from './crypto.js';
import { 
    sendEncryptedMessage, 
    sendNotification,
    fetchMessagesForAddress,
    parseCalldata 
} from './ethscription.js';
import { 
    showNotificationModal, 
    hideNotificationModal,
    checkUrlForMessage,
    showToast,
    sendBrowserNotification 
} from './notifications.js';
import { 
    initDB,
    storeMessage,
    getMessagesForAddress as getCachedMessages,
    batchStoreMessages 
} from './messageIndex.js';

// Global state
let provider = null;
let signer = null;
let userAddress = null;
let messageCheckInterval = null;

/**
 * Initialize the application
 */
async function init() {
    console.log('🚀 Initializing SecureChat...');
    
    // Initialize IndexedDB
    await initDB();
    
    // Check for incoming message notification in URL
    checkUrlForMessage();
    
    // Set up event listeners
    setupEventListeners();
    
    // Check if wallet was previously connected
    await checkPreviousConnection();
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    // Wallet connection
    document.getElementById('connect-wallet').addEventListener('click', connectWallet);
    document.getElementById('disconnect-wallet').addEventListener('click', disconnectWallet);
    
    // Send message form
    document.getElementById('send-message-form').addEventListener('submit', handleSendMessage);
    
    // Refresh messages
    document.getElementById('refresh-messages').addEventListener('click', loadMessages);
    
    // Close modal
    document.querySelector('.close-modal')?.addEventListener('click', hideNotificationModal);
    
    // Close modal on background click
    document.getElementById('notification-modal')?.addEventListener('click', (e) => {
        if (e.target.id === 'notification-modal') {
            hideNotificationModal();
        }
    });
}

/**
 * Check if wallet was previously connected
 */
async function checkPreviousConnection() {
    if (typeof window.ethereum !== 'undefined') {
        try {
            const accounts = await window.ethereum.request({ 
                method: 'eth_accounts' 
            });
            
            if (accounts.length > 0) {
                await connectWallet();
            }
        } catch (error) {
            console.error('Error checking previous connection:', error);
        }
    }
}

/**
 * Connect to MetaMask wallet
 */
async function connectWallet() {
    try {
        if (typeof window.ethereum === 'undefined') {
            showToast('Please install MetaMask to use this app', 'error');
            return;
        }

        // Request account access
        const accounts = await window.ethereum.request({ 
            method: 'eth_requestAccounts' 
        });
        
        if (accounts.length === 0) {
            throw new Error('No accounts found');
        }

        // Set up provider and signer
        provider = new ethers.BrowserProvider(window.ethereum);
        signer = await provider.getSigner();
        userAddress = accounts[0];

        // Update UI
        document.getElementById('connect-wallet').classList.add('hidden');
        document.getElementById('wallet-info').classList.remove('hidden');
        document.getElementById('wallet-address').textContent = 
            `${userAddress.slice(0, 6)}...${userAddress.slice(-4)}`;
        document.getElementById('app-content').classList.remove('hidden');

        showToast('Wallet connected successfully! 🎉', 'success');

        // Load messages
        await loadMessages();

        // Start periodic message checking
        startMessageChecking();

        // Listen for account changes
        window.ethereum.on('accountsChanged', handleAccountsChanged);
        window.ethereum.on('chainChanged', handleChainChanged);

    } catch (error) {
        console.error('Error connecting wallet:', error);
        showToast('Failed to connect wallet: ' + error.message, 'error');
    }
}

/**
 * Disconnect wallet
 */
function disconnectWallet() {
    // Clear state
    provider = null;
    signer = null;
    userAddress = null;

    // Stop message checking
    if (messageCheckInterval) {
        clearInterval(messageCheckInterval);
        messageCheckInterval = null;
    }

    // Update UI
    document.getElementById('connect-wallet').classList.remove('hidden');
    document.getElementById('wallet-info').classList.add('hidden');
    document.getElementById('app-content').classList.add('hidden');
    document.getElementById('messages-container').innerHTML = 
        '<p class="empty-state">No messages yet. Messages sent to your address will appear here.</p>';

    showToast('Wallet disconnected', 'info');
}

/**
 * Handle account changes
 */
function handleAccountsChanged(accounts) {
    if (accounts.length === 0) {
        disconnectWallet();
    } else {
        location.reload();
    }
}

/**
 * Handle chain changes
 */
function handleChainChanged() {
    location.reload();
}

/**
 * Handle send message form submission
 */
async function handleSendMessage(e) {
    e.preventDefault();

    const recipientAddress = document.getElementById('recipient-address').value.trim();
    const messageText = document.getElementById('message-text').value.trim();
    const statusEl = document.getElementById('send-status');

    // Validate inputs
    if (!isValidAddress(recipientAddress)) {
        statusEl.textContent = '❌ Invalid recipient address';
        statusEl.className = 'status-message error';
        return;
    }

    if (!messageText) {
        statusEl.textContent = '❌ Message cannot be empty';
        statusEl.className = 'status-message error';
        return;
    }

    try {
        statusEl.textContent = '⏳ Step 1/3: Fetching recipient public key from blockchain...';
        statusEl.className = 'status-message info';

        // Encrypt the message
        const encrypted = await encryptMessageForRecipient(
            recipientAddress,
            messageText,
            provider
        );

        statusEl.textContent = '⏳ Step 2/3: Encrypting message with ECDH...';
        
        // Small delay to show status
        await new Promise(resolve => setTimeout(resolve, 500));

        statusEl.textContent = '⏳ Step 3/3: Sending encrypted message to blockchain...';

        // Get sender address
        const senderAddress = await signer.getAddress();

        // Send as ethscription with image
        const result = await sendEncryptedMessage(
            recipientAddress,
            encrypted.calldata,
            senderAddress,
            provider,
            signer
        );

        if (result.success) {
            const txHashShort = result.txHash ? result.txHash.slice(0, 10) : 'pending';
            
            statusEl.textContent = `✅ Message sent! TX: ${txHashShort}... 📬`;
            statusEl.className = 'status-message success';

            // Add transaction links
            const linksDiv = document.createElement('div');
            linksDiv.style.marginTop = '12px';
            linksDiv.innerHTML = `
                <a href="https://etherscan.io/tx/${result.txHash}" target="_blank" style="color: #CEFF00; margin-right: 15px;">View TX →</a>
                <a href="https://ethscriptions.com/ethscriptions/${result.txHash}" target="_blank" style="color: #CEFF00;">View Ethscription →</a>
            `;
            statusEl.appendChild(linksDiv);

            // Clear form
            document.getElementById('send-message-form').reset();

            showToast('Message sent successfully! 📬', 'success');
        }

    } catch (error) {
        console.error('Error sending message:', error);
        statusEl.textContent = '❌ Error: ' + error.message;
        statusEl.className = 'status-message error';
        showToast('Failed to send message', 'error');
    }
}

/**
 * Load messages for connected wallet
 */
async function loadMessages() {
    if (!userAddress) {
        console.warn('No wallet connected');
        return;
    }

    const loadingEl = document.getElementById('messages-loading');
    const containerEl = document.getElementById('messages-container');

    try {
        loadingEl.classList.remove('hidden');

        // Try to get cached messages first
        let messages = await getCachedMessages(userAddress);

        // Fetch new messages from blockchain
        const freshMessages = await fetchMessagesForAddress(userAddress);

        console.log(`Fetched ${freshMessages.length} fresh messages from blockchain`);

        // Merge and cache new messages
        if (freshMessages.length > 0) {
            const messagesToStore = freshMessages.map(msg => ({
                txHash: msg.transaction_hash,
                from: msg.from_address || msg.creator,
                to: msg.to_address || msg.initial_owner,
                timestamp: msg.block_timestamp || msg.creation_timestamp || Date.now() / 1000,
                blockNumber: msg.block_number,
                calldata: msg.content_uri,
                decrypted: null
            }));
            
            console.log('Storing messages:', messagesToStore);
            await batchStoreMessages(messagesToStore);

            // Reload from cache
            messages = await getCachedMessages(userAddress);
        }

        console.log(`Displaying ${messages.length} total messages`);
        // Display messages
        displayMessages(messages);

    } catch (error) {
        console.error('Error loading messages:', error);
        showToast('Error loading messages', 'error');
        containerEl.innerHTML = 
            '<p class="empty-state">Error loading messages. Please try again.</p>';
    } finally {
        loadingEl.classList.add('hidden');
    }
}

/**
 * Display messages in UI
 */
async function displayMessages(messages) {
    const containerEl = document.getElementById('messages-container');

    if (!messages || messages.length === 0) {
        containerEl.innerHTML = 
            '<p class="empty-state">No messages yet. Messages sent to your address will appear here.</p>';
        return;
    }

    // Get private key for decryption
    let privateKey;
    try {
        console.log('Requesting signature for decryption key...');
        privateKey = await signer.signMessage('Get private key for SecureChat decryption');
        // Hash it to get a deterministic private key (not the actual wallet key)
        privateKey = ethers.keccak256(ethers.toUtf8Bytes(privateKey));
        console.log('Got decryption key');
    } catch (error) {
        console.error('Could not get private key for decryption:', error);
        containerEl.innerHTML = 
            '<p class="empty-state">Please sign the message to decrypt your messages.</p>';
        return;
    }

    let html = '';

    for (const msg of messages) {
        console.log('Processing message:', msg.txHash);
        let decryptedText = msg.decrypted;

        // Try to decrypt if not already decrypted
        if (!decryptedText && msg.calldata) {
            try {
                console.log('Parsing calldata...');
                const encryptedData = parseCalldata(msg.calldata);
                console.log('Encrypted data extracted:', encryptedData ? 'yes' : 'no');
                
                if (encryptedData) {
                    console.log('Decrypting message...');
                    decryptedText = await decryptMessage(privateKey, encryptedData);
                    console.log('Decrypted successfully!');
                    
                    // Update cache with decrypted message
                    msg.decrypted = decryptedText;
                    await storeMessage(msg);
                }
            } catch (decryptError) {
                console.error('Error decrypting message:', decryptError);
                decryptedText = '[Unable to decrypt message]';
            }
        }

        const timestamp = new Date(msg.timestamp * 1000).toLocaleString();
        const fromAddress = `${msg.from.slice(0, 6)}...${msg.from.slice(-4)}`;

        html += `
            <div class="message-item" data-tx-hash="${msg.txHash}">
                <div class="message-header">
                    <span class="message-from">From: ${fromAddress}</span>
                    <span class="message-time">${timestamp}</span>
                </div>
                <div class="message-content">
                    ${escapeHtml(decryptedText || '[Decrypting...]')}
                </div>
                <div class="message-tx">
                    <a href="https://etherscan.io/tx/${msg.txHash}" target="_blank" rel="noopener">
                        View TX: ${msg.txHash.slice(0, 10)}...
                    </a>
                </div>
            </div>
        `;
    }

    containerEl.innerHTML = html;
}

/**
 * Start periodic message checking
 */
function startMessageChecking() {
    // Clear any existing interval
    if (messageCheckInterval) {
        clearInterval(messageCheckInterval);
    }
    
    // Check for new messages every 2 minutes (reduced API load)
    messageCheckInterval = setInterval(async () => {
        await loadMessages();
    }, 120000);
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize app when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
