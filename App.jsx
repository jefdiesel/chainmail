import React, { useState, useEffect, useRef } from 'react';
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
    const [recipientPrekeyStatus, setRecipientPrekeyStatus] = useState(null); // null = unchecked, true = has prekeys, false = no prekeys
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
    const [showSecurityWarning, setShowSecurityWarning] = useState(false);
    const [pendingSendData, setPendingSendData] = useState(null);
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

    // Backup/Restore state
    const [showBackupModal, setShowBackupModal] = useState(false);
    const [showRestoreModal, setShowRestoreModal] = useState(false);
    const [backupMnemonic, setBackupMnemonic] = useState('');
    const [backupData, setBackupData] = useState(null);
    const [backupStep, setBackupStep] = useState(1); // 1 = show mnemonic, 2 = download JSON
    const [restoreMnemonic, setRestoreMnemonic] = useState('');
    const [restoreFile, setRestoreFile] = useState(null);
    const [backupStatus, setBackupStatus] = useState('');

    // Ref to track if we just loaded messages from cache (prevents immediate re-decryption)
    const justLoadedFromCache = useRef(false);

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

            // Store backup data and mnemonic (don't auto-download yet)
            setBackupData(backupData);
            setBackupMnemonic(mnemonic);
            setBackupStep(1);
            setShowBackupModal(true);
            setBackupStatus('');

            showToast('Backup created! Save your recovery phrase!', 'success');
        } catch (error) {
            console.error('Error creating backup:', error);
            setBackupStatus('❌ Error: ' + error.message);
            showToast('Failed to create backup', 'error');
        }
    };

    const handleDownloadBackup = () => {
        if (backupData && address) {
            downloadBackup(backupData, address);
            showToast('Backup JSON downloaded!', 'success');
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
            console.log(`📦 Loaded ${cachedMessages.length} cached messages from IndexedDB`);
            const cachedMap = new Map(cachedMessages.map(msg => [msg.txHash, msg]));

            // Fetch fresh messages from blockchain
            const freshMessages = await fetchMessagesForAddress(address);
            console.log(`⛓️ Fetched ${freshMessages.length} messages from blockchain`);

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

            const alreadyDecrypted = mergedMessages.filter(m => m.decrypted).length;
            console.log(`🔀 Merged ${mergedMessages.length} messages (${alreadyDecrypted} from cache, ${mergedMessages.length - alreadyDecrypted} need decryption)`);

            // Set flag to prevent immediate decryption after loading from cache
            justLoadedFromCache.current = true;
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

        // Clear previous status
        setRecipientENS('');
        setRecipientPrekeyStatus(null);

        if (!input) return;

        let resolvedAddress = input;

        // If input ends with .eth, try to resolve it
        if (input.endsWith('.eth') && walletClient) {
            try {
                const provider = new BrowserProvider(walletClient);
                const resolved = await provider.resolveName(input);
                if (resolved) {
                    setRecipientENS(`→ ${resolved.slice(0, 6)}...${resolved.slice(-4)}`);
                    resolvedAddress = resolved;
                } else {
                    setRecipientENS('❌ Not found');
                    return;
                }
            } catch (error) {
                setRecipientENS('❌ Not found');
                return;
            }
        }

        // Check for prekeys if we have a valid address
        if (resolvedAddress?.match(/^0x[a-fA-F0-9]{40}$/)) {
            try {
                const hasPrekeys = await hasPrekeyBundle(resolvedAddress);
                setRecipientPrekeyStatus(hasPrekeys);
            } catch (error) {
                console.error('Error checking prekeys:', error);
                setRecipientPrekeyStatus(null);
            }
        }
    };

    const handleSendMessage = async (e) => {
        e.preventDefault();

        if (!walletClient || !address) {
            showToast('Please connect your wallet', 'error');
            return;
        }

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
            const recipientHasPrekeys = await hasPrekeyBundle(resolvedAddress);

            // If no prekeys, show warning modal and wait for confirmation
            if (!recipientHasPrekeys) {
                setPendingSendData({ resolvedAddress, provider, signer });
                setShowSecurityWarning(true);
                return; // Wait for user confirmation
            }

            // Proceed with sending (has prekeys)
            await proceedWithSend(resolvedAddress, provider, signer);

        } catch (error) {
            console.error('Error sending message:', error);
            setSendStatus('❌ Error: ' + error.message);
            showToast('Failed to send message', 'error');
        }
    };

    const proceedWithSend = async (resolvedAddress, provider, signer) => {
        try {
            setSendStatus('Encrypting message...');

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
            setRecipientENS('');
            setRecipientPrekeyStatus(null);
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

        const alreadyDecrypted = messages.filter(m => m.decrypted).length;
        console.log(`🔓 decryptMessages() called: ${messages.length} total, ${alreadyDecrypted} already decrypted`);

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

        // If we just loaded from cache, skip immediate decryption to prevent overwriting merged data
        if (justLoadedFromCache.current) {
            console.log(`⏭️ Skipping immediate decryption (just loaded from cache)`);
            justLoadedFromCache.current = false; // Reset for next time

            // But schedule decryption for any truly new messages after a short delay
            if (hasUndecrypted && walletClient) {
                console.log(`⏰ Scheduling delayed decryption for ${messages.length - messages.filter(m => m.decrypted).length} new messages`);
                setTimeout(() => {
                    decryptMessages();
                }, 500); // 500ms delay to let React state fully update
            }
            return;
        }

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
                    <button
                        className="hamburger-menu"
                        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                        aria-label="Toggle menu"
                    >
                        <span></span>
                        <span></span>
                        <span></span>
                    </button>
                    <div className={`header-links ${mobileMenuOpen ? 'mobile-open' : ''}`}>
                        <button className="header-link" onClick={() => { setCurrentPage('about'); setMobileMenuOpen(false); }}>Get Started</button>
                        <a className="header-link" href="https://github.com/jefdiesel/chainmail" target="_blank" rel="noopener noreferrer">GitHub</a>
                        <button onClick={() => { handleExportBackup(); setMobileMenuOpen(false); }} className="header-link">Backup</button>
                        <button onClick={() => { setShowRestoreModal(true); setMobileMenuOpen(false); }} className="header-link">Restore</button>
                        <a className="header-link" href="https://chainfeed.online" target="_blank" rel="noopener noreferrer">Ethscriptions</a>
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
                        <div className="status-badge status-warning">
                            <div className="status-badge-header">
                                <strong>⚠️ Setup Required</strong>
                            </div>
                            <div className="status-badge-content">
                                <p className="status-badge-text">
                                    Publish prekey bundle to receive <strong>SECURE</strong> messages
                                </p>
                                <p className="status-badge-meta">
                                    One-time setup · ~$0.03-0.10 gas ·{' '}
                                    <a
                                        href="https://github.com/jefdiesel/chainmail#i-received-a-message---whats-this-prekey-setup-about"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="status-badge-link"
                                    >
                                        Why?
                                    </a>
                                </p>
                            </div>
                            <button
                                onClick={handlePublishPrekeys}
                                disabled={isPublishingPrekeys}
                                className="btn btn-primary"
                            >
                                {isPublishingPrekeys ? 'Publishing...' : 'Publish Prekey Bundle'}
                            </button>
                            {prekeyStatus && <div className="status-badge-status">{prekeyStatus}</div>}
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

                                {/* Prekey status indicators */}
                                {recipientPrekeyStatus === true && (
                                    <small className="prekey-status prekey-ok">
                                        ✅ Full Signal Protocol encryption available
                                    </small>
                                )}

                                {recipientPrekeyStatus === false && (
                                    <small className="prekey-status prekey-warning">
                                        ⚠️ No prekeys found - fallback encryption only
                                        <br/>
                                        <strong>Do not send sensitive information</strong>
                                    </small>
                                )}

                                {recipientPrekeyStatus === null && recipientAddress && recipientAddress.length > 10 && (
                                    <small className="prekey-status prekey-checking">
                                        🔍 Checking encryption status...
                                    </small>
                                )}
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
            {showBackupModal && backupStep === 1 && (
                <div className="modal-overlay" onClick={() => {
                    setShowBackupModal(false);
                    setBackupStep(1);
                    setBackupMnemonic('');
                    setBackupData(null);
                }}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{maxWidth: '650px', backgroundColor: '#000', color: '#fff'}}>
                        <h2 style={{color: '#fff', marginBottom: '20px'}}>🔐 Step 1: Save Your Recovery Phrase</h2>

                        <div style={{backgroundColor: '#1a1a1a', padding: '15px', borderRadius: '8px', marginBottom: '20px', border: '1px solid #333'}}>
                            <p style={{margin: '0 0 10px 0', color: '#fff', fontSize: '14px'}}>
                                Write down these 12 words in order. You'll need this phrase to decrypt your backup.
                            </p>
                            <p style={{margin: '0', color: '#CEFF00', fontSize: '13px', fontWeight: 'bold'}}>
                                ⚠️ Never share this phrase with anyone
                            </p>
                        </div>

                        <div style={{
                            backgroundColor: '#0a0a0a',
                            padding: '20px',
                            borderRadius: '8px',
                            marginBottom: '20px',
                            border: '2px solid #CEFF00'
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
                                        backgroundColor: '#1a1a1a',
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
                                    setBackupStep(2);
                                }}
                                className="btn btn-primary"
                            >
                                I've Saved It →
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Backup Download JSON Step */}
            {showBackupModal && backupStep === 2 && (
                <div className="modal-overlay" onClick={() => {
                    setShowBackupModal(false);
                    setBackupStep(1);
                    setBackupMnemonic('');
                    setBackupData(null);
                }}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{maxWidth: '600px', backgroundColor: '#000', color: '#fff'}}>
                        <h2 style={{color: '#fff', marginBottom: '20px'}}>📦 Step 2: Download Backup File</h2>

                        <div style={{backgroundColor: '#1a1a1a', padding: '20px', borderRadius: '8px', marginBottom: '20px', border: '1px solid #333'}}>
                            <p style={{margin: '0 0 15px 0', color: '#fff', fontSize: '15px'}}>
                                Click below to download your encrypted backup JSON file.
                            </p>
                            <p style={{margin: '0 0 15px 0', color: '#CEFF00', fontSize: '14px', fontWeight: 'bold'}}>
                                ⚠️ You need BOTH the recovery phrase AND this JSON file to restore
                            </p>
                            <ul style={{margin: '0', paddingLeft: '20px', color: '#aaa', fontSize: '13px'}}>
                                <li style={{marginBottom: '8px'}}>Use this backup to log into multiple devices</li>
                                <li style={{marginBottom: '8px'}}>Store the JSON file and recovery phrase in separate secure locations</li>
                                <li style={{marginBottom: '0'}}>The JSON file is encrypted - useless without your recovery phrase</li>
                            </ul>
                        </div>

                        <div style={{
                            backgroundColor: '#0a0a0a',
                            padding: '15px',
                            borderRadius: '8px',
                            marginBottom: '20px',
                            border: '1px solid #CEFF00',
                            textAlign: 'center'
                        }}>
                            <p style={{margin: '0 0 10px 0', color: '#CEFF00', fontSize: '13px', fontFamily: 'monospace'}}>
                                chainmail-backup-{address?.slice(0, 8)}.json
                            </p>
                            <button
                                onClick={handleDownloadBackup}
                                className="btn btn-primary"
                                style={{width: '100%', fontSize: '16px'}}
                            >
                                ⬇️ Download Backup JSON
                            </button>
                        </div>

                        <div style={{display: 'flex', gap: '10px', justifyContent: 'flex-end'}}>
                            <button
                                onClick={() => {
                                    setShowBackupModal(false);
                                    setBackupStep(1);
                                    setBackupMnemonic('');
                                    setBackupData(null);
                                }}
                                className="btn btn-secondary"
                            >
                                Done
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

            {/* Security Warning Modal - No Prekeys */}
            {showSecurityWarning && (
                <div className="modal-overlay" onClick={() => setShowSecurityWarning(false)}>
                    <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{maxWidth: '550px', backgroundColor: '#000', color: '#fff'}}>
                        <h2 style={{color: '#ff9800', marginBottom: '20px'}}>
                            ⚠️ Limited Encryption Warning
                        </h2>

                        <div style={{backgroundColor: '#1a1a1a', padding: '18px', borderRadius: '8px', marginBottom: '20px', border: '1px solid #333'}}>
                            <p style={{margin: '0 0 15px 0', color: '#fff', fontSize: '15px'}}>
                                <strong>{recipientAddress}</strong> has not published encryption keys yet.
                            </p>
                            <p style={{margin: '0 0 15px 0', color: '#aaa', fontSize: '14px'}}>
                                Your message will use <strong>fallback encryption</strong> without forward secrecy.
                            </p>
                            <p style={{margin: '0', color: '#CEFF00', fontSize: '14px', fontWeight: 'bold'}}>
                                ⚠️ Do not send sensitive information
                            </p>
                        </div>

                        <div style={{backgroundColor: '#0a0a0a', padding: '18px', borderRadius: '8px', marginBottom: '20px', border: '1px solid #333'}}>
                            <p style={{margin: '0 0 12px 0', color: '#fff', fontSize: '14px'}}>
                                Share Chainmail with them to enable full Signal Protocol encryption:
                            </p>
                            <button
                                onClick={() => {
                                    const inviteMessage = `Try Chainmail for encrypted on-chain messaging!\n\nhttps://chainmail.app\n\nMy address: ${address}`;
                                    navigator.clipboard.writeText(inviteMessage);
                                    showToast('Invite link copied to clipboard!', 'success');
                                }}
                                className="btn btn-secondary"
                                style={{width: '100%'}}
                            >
                                📋 Copy Invite Link
                            </button>
                        </div>

                        <div style={{display: 'flex', gap: '10px', justifyContent: 'flex-end'}}>
                            <button
                                onClick={() => {
                                    setShowSecurityWarning(false);
                                    setPendingSendData(null);
                                }}
                                className="btn btn-secondary"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={async () => {
                                    setShowSecurityWarning(false);
                                    if (pendingSendData) {
                                        const { resolvedAddress, provider, signer } = pendingSendData;
                                        await proceedWithSend(resolvedAddress, provider, signer);
                                        setPendingSendData(null);
                                    }
                                }}
                                className="btn btn-primary"
                            >
                                I Understand, Send Anyway
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default App;
