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
    const [subjectText, setSubjectText] = useState('');
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
                    calldata: msg.calldata || msg.content_uri, // Use hex calldata, fallback to content_uri
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

            // Encrypt message with subject
            const encryptedData = await encryptMessageForRecipient(
                messageText,
                recipientAddress,
                address,
                saveOutbox,
                subjectText
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
            setSubjectText('');
            setMessageText('');

        } catch (error) {
            console.error('Error sending message:', error);
            setSendStatus('❌ Error: ' + error.message);
            showToast('Failed to send message', 'error');
        }
    };

    const handleReply = (msg) => {
        setRecipientAddress(msg.senderAddress || msg.from);
        const replySubject = msg.subject 
            ? (msg.subject.startsWith('Re: ') ? msg.subject : `Re: ${msg.subject}`)
            : 'Re: Your message';
        setSubjectText(replySubject);
        
        // Scroll to form
        window.scrollTo({ top: 0, behavior: 'smooth' });
        
        showToast('Reply form populated', 'success');
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
                        // Try calldata first, fallback to content_uri
                        const dataSource = msg.calldata || msg.content_uri;
                        if (!dataSource) {
                            return { ...msg, decrypted: '[No data available]' };
                        }
                        
                        const encryptedData = parseCalldata(dataSource);
                        if (!encryptedData) {
                            return { ...msg, decrypted: '[Invalid message format]' };
                        }
                        
                        // Check if it's old hex format
                        if (encryptedData.startsWith('0x')) {
                            return { ...msg, decrypted: '[Old format - cannot decrypt]' };
                        }
                        
                        const decryptedData = await decryptMessage(privateKey, encryptedData);
                        if (decryptedData) {
                            const updatedMsg = { 
                                ...msg, 
                                subject: decryptedData.subject,
                                decrypted: decryptedData.message,
                                senderAddress: decryptedData.senderAddress || msg.from
                            };
                            await storeMessage(updatedMsg);
                            return updatedMsg;
                        } else {
                            return { ...msg, decrypted: '[Decryption failed]' };
                        }
                    } catch (error) {
                        console.error('Error decrypting TX:', msg.transaction_hash, error);
                        return { ...msg, decrypted: '[Error]' };
                    }
                })
            );

            // Only update if there are actual changes (new decryptions)
            const hasNewDecryptions = decryptedMessages.some((msg, idx) => 
                msg.decrypted !== messages[idx]?.decrypted
            );
            
            if (hasNewDecryptions) {
                setMessages(decryptedMessages);
            }
        } catch (error) {
            console.error('Error decrypting messages:', error);
        }
    };

    useEffect(() => {
        // Only decrypt if there are undecrypted messages
        const hasUndecrypted = messages.some(msg => 
            !msg.decrypted && msg.blockNumber >= 23969000
        );
        
        if (hasUndecrypted && walletClient) {
            decryptMessages();
        }
    }, [messages.length, walletClient]);

    return (
        <div className="container">
            <header className="app-header">
                <div className="header-left">
                    <h1 className="logo">
                        <span className="logo-chain">Chain</span><span className="logo-mail">mail</span>
                    </h1>
                </div>
                <div className="header-right">
                    <ConnectButton />
                </div>
            </header>

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
                                <label htmlFor="subject-text">Subject: (optional, encrypted)</label>
                                <input 
                                    type="text" 
                                    id="subject-text" 
                                    placeholder="Message subject..."
                                    value={subjectText}
                                    onChange={(e) => setSubjectText(e.target.value)}
                                    maxLength="100"
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
                            <div className="checkbox-group">
                                <label className="checkbox-label">
                                    <input 
                                        type="checkbox" 
                                        checked={saveOutbox}
                                        onChange={(e) => setSaveOutbox(e.target.checked)}
                                    />
                                    <span className="checkbox-text">
                                        <strong>Save to Outbox</strong>
                                        <small>Keep a copy you can decrypt later (disables forward secrecy)</small>
                                    </span>
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
                                                From: {(msg.senderAddress || msg.from).slice(0, 6)}...{(msg.senderAddress || msg.from).slice(-4)}
                                                {!msg.senderAddress && msg.decrypted && !msg.decrypted.startsWith('[') && (
                                                    <span className="ephemeral-badge" title="Ephemeral message - sender cannot decrypt">🔒</span>
                                                )}
                                            </span>
                                            <span className="message-time">
                                                {new Date(msg.timestamp * 1000).toLocaleString()}
                                            </span>
                                        </div>
                                        {msg.subject && (
                                            <div className="message-subject">
                                                <strong>Subject:</strong> {msg.subject}
                                            </div>
                                        )}
                                        <div className="message-content">
                                            {msg.decrypted || '[Decrypting...]'}
                                        </div>
                                        <div className="message-footer">
                                            <a 
                                                href={`https://etherscan.io/tx/${msg.txHash}`} 
                                                target="_blank" 
                                                rel="noopener noreferrer"
                                                className="message-tx-link"
                                            >
                                                View TX: {msg.txHash.slice(0, 10)}...
                                            </a>
                                            {msg.decrypted && !msg.decrypted.startsWith('[') && (
                                                <button 
                                                    onClick={() => handleReply(msg)}
                                                    className="btn-reply"
                                                >
                                                    ↩️ Reply
                                                </button>
                                            )}
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
