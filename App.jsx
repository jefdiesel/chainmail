import React, { useState, useEffect } from 'react';
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient } from 'wagmi';
import { BrowserProvider } from 'ethers';
import {
    encryptMessageForRecipient,
    decryptMessage,
    deriveKeypairFromAddress,
    encryptMessageSignal,
    decryptMessageAuto
} from './crypto.js';
import {
    getSignalStore,
    exportPrekeyBundle
} from './signalStore.js';
import {
    publishPrekeyBundle,
    hasPrekeyBundle,
    fetchPrekeyBundle
} from './prekeyRegistry.js';
import { toHex } from './signalProtocol.js';
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
import {
    createBackup,
    restoreBackup,
    downloadBackup,
    readBackupFile
} from './backup.js';
import About from './About.jsx';

function App() {
    const { address, isConnected } = useAccount();
    const { data: walletClient } = useWalletClient();
    
    const [recipientAddress, setRecipientAddress] = useState('');
    const [recipientENS, setRecipientENS] = useState('');
    const [subjectText, setSubjectText] = useState('');
    const [messageText, setMessageText] = useState('');
    const [messages, setMessages] = useState([]);
    const [loading, setLoading] = useState(false);
    const [sendStatus, setSendStatus] = useState('');
    const [saveOutbox, setSaveOutbox] = useState(false);
    const [ensCache, setEnsCache] = useState(new Map());
    const [cachedPrivateKey, setCachedPrivateKey] = useState(null); // Session cache for derived key
    const [hasPrekeys, setHasPrekeys] = useState(false);
    const [isPublishingPrekeys, setIsPublishingPrekeys] = useState(false);
    const [prekeyStatus, setPrekeyStatus] = useState('');

    // Backup/Restore state
    const [showBackupModal, setShowBackupModal] = useState(false);
    const [showRestoreModal, setShowRestoreModal] = useState(false);
    const [backupMnemonic, setBackupMnemonic] = useState('');
    const [restoreMnemonic, setRestoreMnemonic] = useState('');
    const [restoreFile, setRestoreFile] = useState(null);
    const [backupStatus, setBackupStatus] = useState('');

    useEffect(() => {
        initDB();
    }, []);

    useEffect(() => {
        if (isConnected && address) {
            checkPrekeySetup();
            loadMessages();

            // Poll for new messages every 2 minutes
            const interval = setInterval(loadMessages, 120000);
            return () => clearInterval(interval);
        } else {
            // Clear cached key when wallet disconnects
            setCachedPrivateKey(null);
            setHasPrekeys(false);
        }
    }, [isConnected, address]);

    const checkPrekeySetup = async () => {
        if (!address) return;

        try {
            // Initialize Signal store
            const store = await getSignalStore(address);
            const localIdentityKey = toHex(store.getIdentityPublicKey());

            // Check if prekeys published on-chain
            const onChainBundle = await fetchPrekeyBundle(address);

            if (!onChainBundle) {
                setHasPrekeys(false);
                setPrekeyStatus('⚠️ Prekey setup required to receive messages');
            } else {
                // Check if on-chain bundle matches local identity
                if (onChainBundle.identityKey !== localIdentityKey) {
                    console.warn('⚠️ Identity mismatch! On-chain:', onChainBundle.identityKey.slice(0, 16), 'Local:', localIdentityKey.slice(0, 16));
                    setHasPrekeys(false);
                    setPrekeyStatus('⚠️ Identity changed - republish prekeys required');
                } else if (!store.signedPreKey || !store.initialRatchetKey) {
                    console.warn('⚠️ Missing local prekeys (signedPreKey or initialRatchetKey)');
                    setHasPrekeys(false);
                    setPrekeyStatus('⚠️ Missing local prekeys - republish required');
                } else {
                    setHasPrekeys(true);
                    setPrekeyStatus('✅ Ready to send and receive encrypted messages');
                }
            }
        } catch (error) {
            console.error('Error checking prekey setup:', error);
            setPrekeyStatus('❌ Error checking prekey setup');
        }
    };

    const handlePublishPrekeys = async () => {
        if (!walletClient || !address) {
            showToast('Please connect your wallet', 'error');
            return;
        }

        setIsPublishingPrekeys(true);
        setPrekeyStatus('Generating prekey bundle...');

        try {
            const provider = new BrowserProvider(walletClient);
            const signer = await provider.getSigner();

            // Generate prekey bundle
            setPrekeyStatus('Generating Signal protocol keys...');
            const signMessageFn = async ({ message }) => {
                return await signer.signMessage(message);
            };

            const bundle = await exportPrekeyBundle(signMessageFn, address);

            // Publish on-chain
            setPrekeyStatus('Publishing prekey bundle on-chain...');
            const result = await publishPrekeyBundle(bundle, signer);

            setPrekeyStatus('✅ Prekey bundle published! You can now receive messages.');
            setHasPrekeys(true);
            showToast('Prekey bundle published successfully! 🔐', 'success');

        } catch (error) {
            console.error('Error publishing prekeys:', error);
            setPrekeyStatus('❌ Error: ' + error.message);
            showToast('Failed to publish prekeys', 'error');
        } finally {
            setIsPublishingPrekeys(false);
        }
    };

    const handleExportBackup = async () => {
        if (!address) {
            showToast('Please connect your wallet', 'error');
            return;
        }

        setBackupStatus('Creating encrypted backup...');

        try {
            const { backupData, mnemonic } = await createBackup(address);

            // Download the backup file
            downloadBackup(backupData, address);

            // Show the mnemonic to the user
            setBackupMnemonic(mnemonic);
            setShowBackupModal(true);
            setBackupStatus('');

            showToast('Backup created! Save your recovery phrase!', 'success');
        } catch (error) {
            console.error('Error creating backup:', error);
            setBackupStatus('❌ Error: ' + error.message);
            showToast('Failed to create backup', 'error');
        }
    };

    const handleImportBackup = async () => {
        if (!restoreFile || !restoreMnemonic.trim()) {
            showToast('Please select a backup file and enter your recovery phrase', 'error');
            return;
        }

        setBackupStatus('Restoring from backup...');

        try {
            // Read the backup file
            const backupData = await readBackupFile(restoreFile);

            // Restore the backup
            const restoredAddress = await restoreBackup(backupData, restoreMnemonic.trim());

            setBackupStatus('✅ Backup restored successfully!');
            showToast(`Backup restored for ${restoredAddress}`, 'success');

            // Close modal and clear form
            setShowRestoreModal(false);
            setRestoreFile(null);
            setRestoreMnemonic('');

            // Reload the page to reinitialize with restored data
            setTimeout(() => {
                window.location.reload();
            }, 2000);

        } catch (error) {
            console.error('Error restoring backup:', error);
            setBackupStatus('❌ Error: ' + error.message);
            showToast('Failed to restore backup', 'error');
        }
    };

    const loadMessages = async () => {
        if (!address) return;

        setLoading(true);
        try {
            // Clear API cache to force fresh fetch
            clearCache(address);

            // Get cached decrypted messages from IndexedDB
            const cachedMessages = await getCachedMessages(address);
            const cachedMap = new Map(cachedMessages.map(msg => [msg.txHash, msg]));

            // Fetch fresh messages from blockchain
            const freshMessages = await fetchMessagesForAddress(address);

            // Merge: use cached decrypted content if available, otherwise use fresh message
            const mergedMessages = freshMessages.map(freshMsg => {
                const cached = cachedMap.get(freshMsg.txHash);
                if (cached && cached.decrypted) {
                    // Use cached message with decrypted content to prevent re-decryption
                    return cached;
                }
                // New message or not yet decrypted
                return freshMsg;
            });

            setMessages(mergedMessages);
        } catch (error) {
            console.error('Error loading messages:', error);
            showToast('Error loading messages', 'error');
        } finally {
            setLoading(false);
        }
    };

    const resolveENSOrAddress = async (input, provider) => {
        if (!input) return null;
        
        // If it's already an address, return it
        if (input.match(/^0x[a-fA-F0-9]{40}$/)) {
            return input;
        }
        
        // If it ends with .eth, resolve ENS
        if (input.endsWith('.eth')) {
            try {
                const resolvedAddress = await provider.resolveName(input);
                if (resolvedAddress) {
                    return resolvedAddress;
                }
                throw new Error('ENS name not found');
            } catch (error) {
                throw new Error(`Failed to resolve ENS name: ${input}`);
            }
        }
        
        throw new Error('Invalid address or ENS name');
    };

    const lookupENS = async (address, provider) => {
        // Check cache first
        if (ensCache.has(address)) {
            return ensCache.get(address);
        }
        
        try {
            const ensName = await provider.lookupAddress(address);
            if (ensName) {
                setEnsCache(prev => new Map(prev).set(address, ensName));
                return ensName;
            }
        } catch (error) {
            console.log('No ENS found for', address);
        }
        return null;
    };

    const handleRecipientChange = async (e) => {
        const input = e.target.value;
        setRecipientAddress(input);
        
        // Clear ENS display
        setRecipientENS('');
        
        // If input ends with .eth, try to resolve it
        if (input.endsWith('.eth') && walletClient) {
            try {
                const provider = new BrowserProvider(walletClient);
                const resolved = await provider.resolveName(input);
                if (resolved) {
                    setRecipientENS(`→ ${resolved.slice(0, 6)}...${resolved.slice(-4)}`);
                }
            } catch (error) {
                setRecipientENS('❌ Not found');
            }
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

            // Resolve ENS if needed
            const resolvedAddress = await resolveENSOrAddress(recipientAddress, provider);
            if (!resolvedAddress) {
                throw new Error('Invalid recipient address or ENS name');
            }

            // Check if recipient has prekeys
            // Note: Don't clear cache here - it might have just been published
            const recipientHasPrekeys = await hasPrekeyBundle(resolvedAddress);
            if (!recipientHasPrekeys) {
                showToast('⚠️ Recipient has not set up Chainmail. Using fallback encryption.', 'warning');
                console.warn('Recipient missing prekeys, using v2.0 encryption');
            } else {
                console.log('✅ Recipient has prekeys, using Signal protocol');
            }

            // Encrypt message with subject using Signal protocol (falls back to v2.0 if needed)
            const encryptedData = await encryptMessageSignal(
                messageText,
                subjectText,
                resolvedAddress,
                address
            );

            setSendStatus('Sending transaction...');

            // Send as ethscription
            const result = await sendEncryptedMessage(
                resolvedAddress,
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
            
            // For now, use deterministic key derivation (matches encryption)
            // TODO: Implement proper key exchange for wallet-signature keys
            const { privateKey } = deriveKeypairFromAddress(address);

            // Process messages SEQUENTIALLY to avoid session overwriting with prekey messages
            const filteredMessages = messages.filter(msg => msg.blockNumber >= 23969000);
            const decryptedMessages = [];

            for (const msg of filteredMessages) {
                if (msg.decrypted) {
                    decryptedMessages.push(msg);
                    continue;
                }

                try {
                    // Try calldata first, fallback to content_uri
                    const dataSource = msg.calldata || msg.content_uri;
                    if (!dataSource) {
                        decryptedMessages.push({ ...msg, decrypted: '[No data available]' });
                        continue;
                    }

                    const encryptedData = parseCalldata(dataSource);
                    if (!encryptedData) {
                        decryptedMessages.push({ ...msg, decrypted: '[Invalid message format]' });
                        continue;
                    }

                    // Check if it's old hex format
                    if (encryptedData.startsWith('0x')) {
                        decryptedMessages.push({ ...msg, decrypted: '[Old format - cannot decrypt]' });
                        continue;
                    }

                    // Auto-detect version and decrypt (handles both v2.0 and v3.0)
                    const decryptedData = await decryptMessageAuto(
                        encryptedData,
                        msg.from,
                        privateKey,
                        address
                    );
                    if (decryptedData) {
                        const senderAddr = decryptedData.senderAddress || msg.from;

                        // Lookup ENS for sender
                        const ensName = await lookupENS(senderAddr, provider);

                        const updatedMsg = {
                            ...msg,
                            subject: decryptedData.subject,
                            decrypted: decryptedData.message,
                            senderAddress: senderAddr,
                            senderENS: ensName
                        };
                        await storeMessage(updatedMsg);
                        decryptedMessages.push(updatedMsg);
                    } else {
                        decryptedMessages.push({ ...msg, decrypted: '[Decryption failed]' });
                    }
                } catch (error) {
                    console.error('Error decrypting TX:', msg.transaction_hash, error);
                    decryptedMessages.push({ ...msg, decrypted: '[Error]' });
                }
            }

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

    // State for showing send message section
    const [showSendMessage, setShowSendMessage] = useState(false);
    const [currentPage, setCurrentPage] = useState('main'); // 'main' or 'about'

    // If showing About page, render it instead of main app
    if (currentPage === 'about') {
        return <About onBack={() => setCurrentPage('main')} />;
    }

    return (
        <div className="container">
            <header className="app-header">
                <div className="header-left">
                    <h1 className="logo">
                        <span className="logo-emoji">⛓️</span>
                        <span className="logo-chain">Chain</span><span className="logo-mail">mail</span>
                    </h1>
                    <div className="header-links">
                        <button className="header-link" onClick={() => setCurrentPage('about')}>About</button>
                        <a className="header-link" href="https://github.com/jefdiesel/chainmail" target="_blank" rel="noopener noreferrer">GitHub</a>
                        <button onClick={handleExportBackup} className="header-link">Backup</button>
                        <button onClick={() => setShowRestoreModal(true)} className="header-link">Restore</button>
                        {isConnected && hasPrekeys && (
                            <span className="header-status-check" title="Prekey setup ready">✓</span>
                        )}
                    </div>
                </div>
                <div className="header-right">
                    <ConnectButton />
                </div>
            </header>

            {isConnected && (
                <>
                    {/* Prekey Setup Status */}
                    {!hasPrekeys && (
                        <div className="status-badge status-warning" style={{marginBottom: '30px'}}>
                            <strong>⚠️ Setup Required</strong>
                            <p>Publish prekey bundle to receive messages (one-time, ~$0.25-1 gas)</p>
                            <button
                                onClick={handlePublishPrekeys}
                                disabled={isPublishingPrekeys}
                                className="btn btn-primary btn-sm"
                                style={{marginTop: '8px'}}
                            >
                                {isPublishingPrekeys ? 'Publishing...' : 'Publish Prekey Bundle'}
                            </button>
                            {prekeyStatus && <div style={{marginTop: '8px', fontSize: '0.85rem'}}>{prekeyStatus}</div>}
                        </div>
                    )}

                    {/* Action Bar */}
                    <div className="action-bar">
                        <h2 className="inbox-title" onClick={loadMessages} style={{cursor: 'pointer', margin: 0}} title="Click to refresh">
                            📥 Inbox
                        </h2>
                        <button
                            onClick={() => setShowSendMessage(!showSendMessage)}
                            className="btn btn-primary"
                        >
                            ✉️ Send Encrypted Message
                        </button>
                    </div>

                    {/* Send Message Section - Collapsible */}
                    {showSendMessage && (
                        <div className="section send-message-section">
                            <h2>✉️ Send Encrypted Message</h2>
                            <form onSubmit={handleSendMessage}>
                            <div className="form-group">
                                <label htmlFor="recipient-address">Recipient Address or ENS:</label>
                                <input 
                                    type="text" 
                                    id="recipient-address" 
                                    placeholder="0x... or name.eth" 
                                    value={recipientAddress}
                                    onChange={handleRecipientChange}
                                    required
                                />
                                {recipientENS && <small className="ens-helper">{recipientENS}</small>}
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
                            {/* Signal protocol automatically handles ratcheting */}
                            <button type="submit" className="btn btn-primary">
                                Send Encrypted Message
                            </button>
                        </form>
                        {sendStatus && <div className="status-message">{sendStatus}</div>}
                        </div>
                    )}

                    {/* Inbox Section */}
                    <div className="section inbox-section">
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
                                                From: {msg.senderENS || `${(msg.senderAddress || msg.from).slice(0, 6)}...${(msg.senderAddress || msg.from).slice(-4)}`}
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
                </>
            )}

            {/* Backup Mnemonic Modal */}
            {showBackupModal && (
                <div className="modal-overlay" onClick={() => setShowBackupModal(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{maxWidth: '650px'}}>
                        <h2 style={{color: '#ff9800'}}>✅ Backup Created Successfully</h2>

                        <div style={{backgroundColor: '#e3f2fd', padding: '15px', borderRadius: '8px', marginBottom: '20px', border: '1px solid #2196F3'}}>
                            <p style={{margin: '0 0 10px 0', fontWeight: 'bold', color: '#1976d2'}}>
                                📦 Two Components Created:
                            </p>
                            <ol style={{margin: '8px 0', paddingLeft: '20px', color: '#424242', fontSize: '14px'}}>
                                <li style={{marginBottom: '8px'}}>
                                    <strong>JSON Backup File</strong> - Downloaded to your computer (chainmail-backup-{address?.slice(0, 8)}.json)
                                    <br/>
                                    <span style={{color: '#666', fontSize: '13px'}}>Contains your encrypted Signal Protocol identity and sessions</span>
                                </li>
                                <li style={{marginBottom: '0'}}>
                                    <strong>12-Word Recovery Phrase</strong> - Shown below
                                    <br/>
                                    <span style={{color: '#666', fontSize: '13px'}}>The encryption key to decrypt your backup file</span>
                                </li>
                            </ol>
                        </div>

                        <div style={{backgroundColor: '#fff3cd', padding: '15px', borderRadius: '8px', marginBottom: '20px'}}>
                            <p style={{margin: '0 0 10px 0', fontWeight: 'bold'}}>
                                ⚠️ IMPORTANT: You Need BOTH to Restore
                            </p>
                            <ul style={{margin: '8px 0', paddingLeft: '20px', fontSize: '14px'}}>
                                <li style={{marginBottom: '6px'}}>Write down these 12 words in order and store them safely</li>
                                <li style={{marginBottom: '6px'}}>Keep the JSON file and recovery phrase in separate secure locations</li>
                                <li style={{marginBottom: '0'}}>Never share your recovery phrase with anyone - it can decrypt your backup</li>
                            </ul>
                        </div>

                        <div style={{
                            backgroundColor: '#1a1a1a',
                            padding: '20px',
                            borderRadius: '8px',
                            marginBottom: '20px',
                            border: '2px solid #2196F3'
                        }}>
                            <div style={{
                                display: 'grid',
                                gridTemplateColumns: 'repeat(3, 1fr)',
                                gap: '10px',
                                fontFamily: 'monospace',
                                fontSize: '16px'
                            }}>
                                {backupMnemonic.split(' ').map((word, idx) => (
                                    <div key={idx} style={{
                                        padding: '8px 12px',
                                        backgroundColor: '#0a0a0a',
                                        borderRadius: '4px',
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '8px'
                                    }}>
                                        <span style={{color: '#666', fontSize: '12px', minWidth: '20px', textAlign: 'left'}}>{idx + 1}.</span>
                                        <span style={{color: '#CEFF00', fontWeight: '600', flex: 1, textAlign: 'center'}}>{word}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div style={{display: 'flex', gap: '10px', justifyContent: 'flex-end'}}>
                            <button
                                onClick={() => {
                                    navigator.clipboard.writeText(backupMnemonic);
                                    showToast('Recovery phrase copied to clipboard', 'success');
                                }}
                                className="btn btn-secondary"
                            >
                                📋 Copy to Clipboard
                            </button>
                            <button
                                onClick={() => {
                                    setShowBackupModal(false);
                                    setBackupMnemonic('');
                                }}
                                className="btn btn-primary"
                            >
                                I've Saved It
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Restore Backup Modal */}
            {showRestoreModal && (
                <div className="modal-overlay" onClick={() => setShowRestoreModal(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{maxWidth: '500px'}}>
                        <h2>📤 Restore from Backup</h2>
                        <p style={{color: '#666', marginBottom: '20px'}}>
                            Upload your backup file and enter your 12-word recovery phrase.
                        </p>

                        <div className="form-group">
                            <label htmlFor="backup-file">Backup File:</label>
                            <input
                                type="file"
                                id="backup-file"
                                accept=".json"
                                onChange={(e) => setRestoreFile(e.target.files[0])}
                            />
                            {restoreFile && (
                                <small style={{color: '#4caf50'}}>
                                    Selected: {restoreFile.name}
                                </small>
                            )}
                        </div>

                        <div className="form-group">
                            <label htmlFor="restore-mnemonic">Recovery Phrase (12 words):</label>
                            <textarea
                                id="restore-mnemonic"
                                rows="3"
                                placeholder="Enter your 12-word recovery phrase separated by spaces..."
                                value={restoreMnemonic}
                                onChange={(e) => setRestoreMnemonic(e.target.value)}
                            />
                        </div>

                        {backupStatus && <div className="status-message">{backupStatus}</div>}

                        <div style={{display: 'flex', gap: '10px', justifyContent: 'flex-end', marginTop: '20px'}}>
                            <button
                                onClick={() => {
                                    setShowRestoreModal(false);
                                    setRestoreFile(null);
                                    setRestoreMnemonic('');
                                    setBackupStatus('');
                                }}
                                className="btn btn-secondary"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleImportBackup}
                                className="btn btn-primary"
                                disabled={!restoreFile || !restoreMnemonic.trim()}
                            >
                                Restore Backup
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default App;
