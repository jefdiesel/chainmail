import React from 'react';

function About({ onBack }) {
    return (
        <div className="about-page">
            <div className="about-header">
                <h1>
                    <span className="logo-emoji">⛓️</span>
                    <span className="logo-chain">Chain</span><span className="logo-mail">mail</span>
                </h1>
                <p className="tagline">Get Started with Encrypted On-Chain Messaging</p>
                <button onClick={onBack} className="btn btn-secondary" style={{marginTop: '20px'}}>
                    ← Back to App
                </button>
            </div>

            <section className="about-section" style={{backgroundColor: '#0a0a0a', border: '2px solid #CEFF00', padding: '25px'}}>
                <h2 style={{color: '#CEFF00', marginTop: '0'}}>Free • Decentralized • Contractless</h2>
                <p style={{fontSize: '16px', lineHeight: '1.6'}}>
                    Chainmail is end-to-end encrypted messaging that runs entirely in your browser.
                    No servers, no accounts, no tracking. Just connect your wallet and start messaging.
                </p>
                <ul style={{fontSize: '15px', lineHeight: '1.8', marginTop: '15px'}}>
                    <li><strong>Free to use</strong> - only pay Ethereum network fees (a few cents per message)</li>
                    <li><strong>Signal Protocol encryption</strong> - the same security used by Signal and WhatsApp</li>
                    <li><strong>No contracts</strong> - messages stored as ethscriptions (transaction data)</li>
                    <li><strong>Your keys, your messages</strong> - nobody can read your conversations but you</li>
                </ul>
            </section>

            <section className="about-section">
                <h2>Quick Start</h2>

                <h3>1. Connect Your Wallet</h3>
                <p>
                    Click "Connect Wallet" in the top right. Any Ethereum wallet works (MetaMask, Coinbase Wallet, Rainbow, etc.).
                    Your wallet address becomes your messaging identity.
                </p>

                <h3>2. Set Up Encryption Keys (One-Time)</h3>
                <p>
                    Click "Publish Prekey Bundle" to set up your encryption keys. This costs a few cents in gas and
                    only needs to be done once. These keys let others send you encrypted messages.
                </p>

                <h3>3. Send a Message</h3>
                <p>
                    Enter a recipient's address or ENS name (like vitalik.eth), type your message, and hit send.
                    Your message is encrypted and stored permanently on Ethereum. Cost: ~$0.03-0.10 depending on network congestion.
                </p>

                <h3>4. Receive Messages</h3>
                <p>
                    Click "Inbox" to check for new messages. They'll automatically decrypt if someone sent to your address.
                    The app checks for new messages every 2 minutes.
                </p>

                <h3>5. Backup Your Keys</h3>
                <p>
                    Click "Backup" to save your encryption keys with a 12-word recovery phrase. Store both the JSON file
                    and recovery phrase safely - you'll need them to access messages on other devices.
                </p>
            </section>

            <section className="about-section">
                <h2>What Makes Chainmail Different?</h2>
                <p>
                    <strong>No servers to hack.</strong> Your messages live on Ethereum, not in some company's database.
                </p>
                <p>
                    <strong>No accounts to create.</strong> Your Ethereum address is your username. No email, no phone number, no personal info.
                </p>
                <p>
                    <strong>Messages can't be deleted.</strong> Once sent, they're permanent. This is by design - true censorship resistance.
                </p>
                <p>
                    <strong>Military-grade encryption.</strong> Signal Protocol provides perfect forward secrecy and post-compromise security.
                    Even if someone steals your keys today, past messages stay secure.
                </p>
            </section>

            <section className="about-section">
                <h2>About Chainmail v3.0</h2>
                <p>
                    Chainmail is a browser-based encrypted messaging application that stores messages
                    on the Ethereum blockchain as ethscriptions. Messages are encrypted using the
                    <strong> Signal Protocol</strong> (X3DH + Double Ratchet), providing military-grade
                    end-to-end encryption with perfect forward secrecy and post-compromise security.
                </p>
                <p>
                    Unlike centralized messaging platforms, Chainmail is censorship-resistant, permanent,
                    and trustless. Messages are stored immutably on-chain and cannot be deleted, altered,
                    or censored by any third party.
                </p>
            </section>

            <section className="about-section">
                <h2>Signal Protocol v3.0</h2>

                <h3>X3DH (Extended Triple Diffie-Hellman)</h3>
                <p>
                    Session establishment uses X3DH key agreement protocol. Recipients publish prekey bundles
                    on-chain containing their identity key and signed prekeys. Senders fetch these bundles to
                    establish encrypted sessions without requiring both parties to be online simultaneously.
                </p>

                <h3>Double Ratchet Algorithm</h3>
                <p>
                    Each message advances both sending and receiving ratchets, deriving new encryption keys
                    from Diffie-Hellman outputs and key derivation functions. This provides:
                </p>
                <ul>
                    <li><strong>Perfect Forward Secrecy:</strong> Past messages remain secure even if current keys are compromised</li>
                    <li><strong>Post-Compromise Security:</strong> Future messages become secure again after key compromise</li>
                    <li><strong>Self-Healing:</strong> Security automatically restores after compromise through ratchet advancement</li>
                </ul>

                <h3>Cryptographic Primitives</h3>
                <ul>
                    <li><strong>Curve:</strong> Curve25519 (X25519 ECDH)</li>
                    <li><strong>Signing:</strong> Ed25519 signatures for identity verification</li>
                    <li><strong>Encryption:</strong> AES-256-GCM with authenticated encryption</li>
                    <li><strong>KDF:</strong> HKDF-SHA256 for key derivation</li>
                    <li><strong>RNG:</strong> Web Crypto API (CSPRNG)</li>
                </ul>
            </section>

            <section className="about-section">
                <h2>Architecture</h2>

                <h3>Wallet-Based Identity</h3>
                <p>
                    Your Ethereum wallet address serves as your messaging identity. The Signal Protocol
                    identity keypair is derived deterministically from your wallet signature, ensuring
                    consistent identity across sessions while maintaining cryptographic independence
                    from your wallet keys.
                </p>

                <h3>On-Chain Prekey Registry</h3>
                <p>
                    Prekey bundles are published to an on-chain registry contract. This eliminates the need
                    for centralized prekey servers while maintaining the asynchronous messaging capabilities
                    of the Signal Protocol. One-time prekeys are consumed and rotated as sessions are established.
                </p>

                <h3>Ethscriptions Message Transport</h3>
                <p>
                    Encrypted messages are stored as ethscriptions (transaction calldata) on Ethereum mainnet.
                    Messages are self-sent to your own address with the recipient identifier encrypted in the
                    payload, preventing wallet history pollution and spam attacks.
                </p>
            </section>

            <section className="about-section">
                <h2>Security Properties</h2>

                <h3>Confidentiality</h3>
                <p>
                    All message content is encrypted end-to-end. Only the sender and intended recipient
                    can decrypt messages. Blockchain nodes, indexers, and network observers see only
                    encrypted ciphertext.
                </p>

                <h3>Authenticity</h3>
                <p>
                    Ed25519 signatures verify message authenticity. Recipients cryptographically verify
                    that messages originated from the claimed sender's identity key.
                </p>

                <h3>Forward Secrecy</h3>
                <p>
                    Compromise of current session keys does not compromise past messages. Each message
                    is encrypted with ephemeral keys derived from the ratchet state, which are immediately
                    discarded after use.
                </p>

                <h3>Post-Compromise Security</h3>
                <p>
                    If an attacker compromises session state, security automatically restores after
                    a single message exchange completes a DH ratchet step. New keys are derived from
                    fresh Diffie-Hellman outputs unknown to the attacker.
                </p>
            </section>

            <section className="about-section">
                <h2>Protocol Flow</h2>

                <h3>Initial Setup</h3>
                <ol>
                    <li>Connect Ethereum wallet</li>
                    <li>Sign message to derive Signal Protocol identity keypair</li>
                    <li>Generate prekey bundle (identity key + signed prekeys + one-time prekeys)</li>
                    <li>Publish prekey bundle to on-chain registry (a few cents in gas, one-time)</li>
                </ol>

                <h3>Sending Messages</h3>
                <ol>
                    <li>Fetch recipient's prekey bundle from registry</li>
                    <li>Perform X3DH key agreement to establish session</li>
                    <li>Initialize Double Ratchet with shared secret</li>
                    <li>Encrypt message with current ratchet chain key</li>
                    <li>Advance sending ratchet</li>
                    <li>Publish encrypted payload as ethscription to own address</li>
                </ol>

                <h3>Receiving Messages</h3>
                <ol>
                    <li>Query blockchain for messages to your address</li>
                    <li>Load or initialize session state for sender</li>
                    <li>Advance receiving ratchet</li>
                    <li>Derive message key from ratchet chain</li>
                    <li>Decrypt and authenticate message</li>
                    <li>Store decrypted message in local IndexedDB cache</li>
                </ol>
            </section>

            <section className="about-section">
                <h2>Backup & Recovery</h2>
                <p>
                    Chainmail includes secure backup functionality to preserve your Signal Protocol identity
                    and session state across devices:
                </p>
                <ul>
                    <li><strong>BIP39 Mnemonic:</strong> 12-word recovery phrase generated for each backup</li>
                    <li><strong>AES-256-GCM:</strong> Backup encrypted with key derived from mnemonic (PBKDF2, 100k iterations)</li>
                    <li><strong>Session Preservation:</strong> All ratchet states and message keys included</li>
                    <li><strong>Offline Compatible:</strong> Backup/restore works without blockchain access</li>
                </ul>
            </section>

            <section className="about-section">
                <h2>Threat Model</h2>

                <h3>Protects Against</h3>
                <ul>
                    <li>Passive network surveillance and traffic analysis</li>
                    <li>Compromised blockchain nodes or indexers</li>
                    <li>Historical key compromise (forward secrecy)</li>
                    <li>Future key compromise (post-compromise security)</li>
                    <li>Man-in-the-middle attacks (authenticated encryption)</li>
                    <li>Message tampering (AEAD with AES-GCM)</li>
                </ul>

                <h3>Does Not Protect Against</h3>
                <ul>
                    <li>Compromised wallet private key (identity derivation depends on wallet)</li>
                    <li>Client-side malware, keyloggers, or screen capture</li>
                    <li>Metadata analysis (transaction timing, size, gas costs visible on-chain)</li>
                    <li>Coercion or physical device access</li>
                    <li>Quantum computers (Curve25519 vulnerable to Shor's algorithm)</li>
                </ul>
            </section>

            <section className="about-section">
                <h2>Technical Stack</h2>
                <ul>
                    <li><strong>Frontend:</strong> React 19.2, Vite 5.0</li>
                    <li><strong>Wallet:</strong> RainbowKit 2.2, Wagmi 2.19, Viem 2.41</li>
                    <li><strong>Cryptography:</strong> @noble/curves (Curve25519), Web Crypto API</li>
                    <li><strong>Blockchain:</strong> Ethereum Mainnet, Ethscriptions Protocol</li>
                    <li><strong>Storage:</strong> IndexedDB (local), On-chain (permanent)</li>
                    <li><strong>Indexer:</strong> Alchemy Transfers API</li>
                </ul>
            </section>

            <section className="about-section">
                <h2>Limitations</h2>
                <ul>
                    <li><strong>Network Fees:</strong> Each message requires an Ethereum transaction (typically $0.03-0.10 depending on network congestion)</li>
                    <li><strong>Latency:</strong> Message delivery requires block confirmation (~12 seconds)</li>
                    <li><strong>Metadata Leakage:</strong> Transaction timestamps, sizes, and sender addresses are public</li>
                    <li><strong>No Deniability:</strong> Messages are cryptographically signed and non-repudiable</li>
                    <li><strong>Browser Only:</strong> No mobile apps or native clients</li>
                    <li><strong>Mainnet Only:</strong> L2 support not yet implemented (multichain coming soon)</li>
                </ul>
            </section>

            <section className="about-section">
                <h2>Open Source</h2>
                <p>
                    Chainmail is MIT licensed and fully open source. The codebase is available for audit,
                    review, and contribution.
                </p>
                <p>
                    <a
                        href="https://github.com/jefdiesel/chainmail"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="github-link"
                    >
                        View Source on GitHub →
                    </a>
                </p>
            </section>

            <section className="about-section">
                <h2>Disclaimer</h2>
                <p className="disclaimer">
                    <strong>Experimental Software.</strong> Chainmail is experimental and has not undergone
                    formal security audit. Use at your own risk. Do not rely on Chainmail for life-critical
                    communications. The authors assume no liability for compromised, lost, or leaked messages.
                </p>
            </section>

            <footer className="about-footer">
                <p>Chainmail v3.0 - Signal Protocol</p>
                <p>Ethereum Mainnet • MIT License</p>
                <p>Built by <a href="https://github.com/jefdiesel" target="_blank" rel="noopener noreferrer">jefdiesel</a></p>
            </footer>
        </div>
    );
}

export default About;
