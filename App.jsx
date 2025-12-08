import React, { useState, useEffect } from 'react';
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { BrowserProvider } from 'ethers';
import { 
    encryptMessageForRecipient, 
    decryptMessage,
    deriveKeypairFromAddress
} from './crypto.js';
import { 
    sendEncryptedMessage, 
    fetchMessagesForAddress,
    parseCalldata,
    clearCache 
} from './ethscription.js';
import { 
    showToast 
} from './notifications.js';
import { 
    initDB,
    storeMessage,
    getMessagesForAddress as getCachedMessages,
    batchStoreMessages 
} from './messageIndex.js';

function App() {
    const { address, isConnected } = useAccount();
    const { data: walletClient } = useWalletClient();
    
    const [recipientAddress, setRecipientAddress] = useState('');
    const [messageText, setMessageText] = useState('');
    const [messages, setMessages] = useState([]);
    const [loading, setLoading] = useState(false);
    const [sendStatus, setSendStatus] = useState('');
    const [saveOutbox, setSaveOutbox] = useState(false);

    useEffect(() => {
        initDB();
    }, []);

    useEffect(() => {
        if (isConnected && address) {
            loadMessages();
            
            // Poll for new messages every 2 minutes
            const interval = setInterval(loadMessages, 120000);
            return () => clearInterval(interval);
        }
    }, [isConnected, address]);

    const loadMessages = async () => {
        if (!address) return;

        setLoading(true);
        try {
            // Clear API cache to force fresh fetch
            clearCache(address);
            
            // Get cached messages
            let cachedMessages = await getCachedMessages(address);

            // Fetch fresh messages
            const freshMessages = await fetchMessagesForAddress(address);

            if (freshMessages.length > 0) {
                const messagesToStore = freshMessages.map(msg => ({
                    txHash: msg.transaction_hash,
                    from: msg.from_address || msg.creator,
                    to: msg.to_address || msg.initial_owner || msg.current_owner,
                    timestamp: msg.block_timestamp || msg.creation_timestamp || Date.now() / 1000,
                    blockNumber: msg.block_number,
                    calldata: msg.content_uri,
                    decrypted: null
                }));
                
                await batchStoreMessages(messagesToStore);
                cachedMessages = await getCachedMessages(address);
            }

            setMessages(cachedMessages);
        } catch (error) {
            console.error('Error loading messages:', error);
            showToast('Error loading messages', 'error');
        } finally {
            setLoading(false);
        }
    };

    const handleSendMessage = async (e) => {
        e.preventDefault();
        
        if (!walletClient || !address) {
            showToast('Please connect your wallet', 'error');
            return;
        }

        setSendStatus('Encrypting message...');

        try {
            // Get ethers provider and signer from walletClient
            const provider = new BrowserProvider(walletClient);
            const signer = await provider.getSigner();

            // Encrypt message
            const encryptedData = await encryptMessageForRecipient(
                messageText,
                recipientAddress,
                address,
                saveOutbox
            );

            setSendStatus('Sending transaction...');

            // Send as ethscription
            const result = await sendEncryptedMessage(
                recipientAddress,
                encryptedData,
                address,
                provider,
                signer
            );

            setSendStatus(`✅ Message sent! TX: ${result.txHash}`);
            showToast('Message sent successfully! 📬', 'success');
            
            // Clear form
            setRecipientAddress('');
            setMessageText('');

        } catch (error) {
            console.error('Error sending message:', error);
            setSendStatus('❌ Error: ' + error.message);
            showToast('Failed to send message', 'error');
        }
    };

    const decryptMessages = async () => {
        if (!walletClient || messages.length === 0) return;

        try {
            const provider = new BrowserProvider(walletClient);
            const signer = await provider.getSigner();
            
            // Derive deterministic private key from address
            const { privateKey } = deriveKeypairFromAddress(address);

            const decryptedMessages = await Promise.all(
                messages
                    .filter(msg => msg.blockNumber >= 23969000) // Only process recent messages
                    .map(async (msg) => {
                    if (msg.decrypted) return msg;

                    try {
                        const encryptedData = parseCalldata(msg.calldata);
                        if (encryptedData) {
                            const decryptedText = await decryptMessage(privateKey, encryptedData);
                            const updatedMsg = { ...msg, decrypted: decryptedText };
                            await storeMessage(updatedMsg);
                            return updatedMsg;
                        }
                    } catch (error) {
                        console.error('Error decrypting:', error);
                        return { ...msg, decrypted: '[Unable to decrypt]' };
                    }
                    return msg;
                })
            );

            setMessages(decryptedMessages);
        } catch (error) {
            console.error('Error decrypting messages:', error);
        }
    };

    useEffect(() => {
        if (messages.length > 0 && walletClient) {
            decryptMessages();
        }
    }, [messages.length, walletClient]);

    return (
        <div className="container">
            <header>
                <h1>📬 SecureChat</h1>
                <p className="subtitle">End-to-end encrypted on-chain messaging</p>
            </header>

            <div className="section" style={{ display: 'flex', justifyContent: 'center', padding: '20px' }}>
                <ConnectButton />
            </div>

            {isConnected && (
                <div>
                    {/* Send Message Section */}
                    <div className="section card">
                        <h2>✉️ Send Encrypted Message</h2>
                        <form onSubmit={handleSendMessage}>
                            <div className="form-group">
                                <label htmlFor="recipient-address">Recipient Address:</label>
                                <input 
                                    type="text" 
                                    id="recipient-address" 
                                    placeholder="0x..." 
                                    value={recipientAddress}
                                    onChange={(e) => setRecipientAddress(e.target.value)}
                                    required
                                    pattern="^0x[a-fA-F0-9]{40}$"
                                />
                            </div>
                            <div className="form-group">
                                <label htmlFor="message-text">Message:</label>
                                <textarea 
                                    id="message-text" 
                                    rows="4" 
                                    placeholder="Type your encrypted message here..."
                                    value={messageText}
                                    onChange={(e) => setMessageText(e.target.value)}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                                    <input 
                                        type="checkbox" 
                                        checked={saveOutbox}
                                        onChange={(e) => setSaveOutbox(e.target.checked)}
                                    />
                                    <span style={{ fontSize: '14px' }}>Save copy in outbox (allows you to decrypt later, no forward secrecy)</span>
                                </label>
                            </div>
                            <button type="submit" className="btn btn-primary">
                                Send Encrypted Message
                            </button>
                        </form>
                        {sendStatus && <div className="status-message">{sendStatus}</div>}
                    </div>

                    {/* Received Messages Section */}
                    <div className="section card">
                        <h2>📥 Your Messages</h2>
                        <button onClick={loadMessages} className="btn btn-secondary">
                            Refresh Messages
                        </button>
                        
                        {loading && <div className="loading">Loading messages...</div>}
                        
                        <div className="messages-container">
                            {messages.length === 0 ? (
                                <p className="empty-state">
                                    No messages yet. Messages sent to your address will appear here.
                                </p>
                            ) : (
                                messages.map((msg) => (
                                    <div key={msg.txHash} className="message-item">
                                        <div className="message-header">
                                            <span className="message-from">
                                                From: {msg.from.slice(0, 6)}...{msg.from.slice(-4)}
                                            </span>
                                            <span className="message-time">
                                                {new Date(msg.timestamp * 1000).toLocaleString()}
                                            </span>
                                        </div>
                                        <div className="message-content">
                                            {msg.decrypted || '[Decrypting...]'}
                                        </div>
                                        <div className="message-tx">
                                            <a 
                                                href={`https://etherscan.io/tx/${msg.txHash}`} 
                                                target="_blank" 
                                                rel="noopener noreferrer"
                                            >
                                                View TX: {msg.txHash.slice(0, 10)}...
                                            </a>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default App;
