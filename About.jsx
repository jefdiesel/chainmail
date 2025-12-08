import React from 'react';

function About() {
    return (
        <div className="about-page">
            <div className="about-header">
                <h1>
                    <span className="logo-emoji">⛓️</span>
                    <span className="logo-chain">Chain</span><span className="logo-mail">mail</span>
                </h1>
                <p className="tagline">End-to-End Encrypted Messaging on Ethereum</p>
            </div>

            <section className="about-section">
                <h2>What is Chainmail?</h2>
                <p>
                    Chainmail is a browser-based encrypted messaging application that stores messages 
                    directly on the Ethereum blockchain as ethscriptions. Every message is end-to-end 
                    encrypted before being published, ensuring only you and your intended recipient can read it.
                </p>
                <p>
                    Unlike traditional messaging apps that rely on centralized servers, Chainmail is 
                    censorship-resistant, permanent, and operates entirely on-chain. Messages cannot be 
                    deleted, altered, or taken down by any third party.
                </p>
            </section>

            <section className="about-section">
                <h2>v2.0 Security Architecture</h2>
                
                <h3>🔐 Wallet-Signature Key Derivation</h3>
                <p>
                    Your private messaging key is derived from your wallet signature—not from your 
                    public address. This means only someone with access to your actual wallet can 
                    decrypt messages sent to you. Attackers cannot compute your messaging private 
                    key from your public address alone.
                </p>
                <ul>
                    <li><strong>One-time signature:</strong> Sign once per session to derive your messaging keypair</li>
                    <li><strong>Session caching:</strong> Key cached in memory—no repeated signature prompts</li>
                    <li><strong>256-bit entropy:</strong> Full cryptographic strength from wallet signature</li>
                </ul>

                <h3>🎲 Ephemeral Keys (Forward Secrecy)</h3>
                <p>
                    By default, each message uses a random ephemeral keypair generated at send time. 
                    After encryption, the private key is destroyed. This provides forward secrecy—even 
                    you cannot decrypt messages you've sent.
                </p>
                <ul>
                    <li><strong>Random per message:</strong> Fresh keypair for every sent message</li>
                    <li><strong>Cannot be recovered:</strong> Sender cannot decrypt their own sent messages</li>
                    <li><strong>Optional outbox:</strong> Disable forward secrecy to save decryptable copies</li>
                </ul>

                <h3>🕵️ Privacy-First Design</h3>
                <p>
                    Messages are self-sent to your own address, not to the recipient. The recipient's 
                    address is encrypted in the message payload. This prevents wallet history pollution 
                    and spam attacks.
                </p>
                <ul>
                    <li><strong>No recipient tracking:</strong> Wallet transactions don't reveal who you're messaging</li>
                    <li><strong>No spam attacks:</strong> Others cannot fill your wallet with junk messages</li>
                    <li><strong>Clean history:</strong> Your wallet shows only self-transactions</li>
                </ul>

                <h3>🔒 Encryption Details</h3>
                <p>
                    <strong>Algorithm:</strong> ECDH (Elliptic Curve Diffie-Hellman) + AES-256-GCM
                </p>
                <ul>
                    <li><strong>Key exchange:</strong> secp256k1 elliptic curve (same as Ethereum)</li>
                    <li><strong>Symmetric encryption:</strong> AES-256-GCM with authenticated encryption</li>
                    <li><strong>Payload format:</strong> Subject + message encrypted together as JSON</li>
                    <li><strong>Protocol marker:</strong> <code>chainfeed.online</code> in ethscription calldata</li>
                </ul>
            </section>

            <section className="about-section">
                <h2>How It Works</h2>
                
                <h3>Sending a Message</h3>
                <ol>
                    <li>Enter recipient's address or ENS name</li>
                    <li>Write your message (subject optional)</li>
                    <li>Click "Send Encrypted Message"</li>
                    <li>App generates random ephemeral keypair</li>
                    <li>Message encrypted using ECDH + AES-256-GCM</li>
                    <li>Encrypted payload sent as ethscription to your own address</li>
                    <li>Transaction confirmed on Ethereum mainnet</li>
                </ol>

                <h3>Reading Messages</h3>
                <ol>
                    <li>Connect your wallet</li>
                    <li>App queries blockchain for messages containing your address</li>
                    <li>One-time signature prompt to derive your decryption key</li>
                    <li>Messages automatically decrypted in your browser</li>
                    <li>Decrypted messages cached locally (IndexedDB)</li>
                </ol>
            </section>

            <section className="about-section">
                <h2>Technical Stack</h2>
                <div className="tech-grid">
                    <div className="tech-item">
                        <h4>Frontend</h4>
                        <ul>
                            <li>React 19.2.1</li>
                            <li>Vite 5.0.0</li>
                            <li>RainbowKit 2.2.10</li>
                        </ul>
                    </div>
                    <div className="tech-item">
                        <h4>Blockchain</h4>
                        <ul>
                            <li>Ethereum Mainnet</li>
                            <li>Wagmi 2.19.5</li>
                            <li>Viem 2.41.2</li>
                            <li>ethers.js 6.9.0</li>
                        </ul>
                    </div>
                    <div className="tech-item">
                        <h4>Crypto</h4>
                        <ul>
                            <li>Web Crypto API</li>
                            <li>secp256k1 (ECDH)</li>
                            <li>AES-256-GCM</li>
                        </ul>
                    </div>
                    <div className="tech-item">
                        <h4>Storage</h4>
                        <ul>
                            <li>IndexedDB (local cache)</li>
                            <li>Ethscriptions (on-chain)</li>
                            <li>Alchemy API (queries)</li>
                        </ul>
                    </div>
                </div>
            </section>

            <section className="about-section">
                <h2>Threat Model</h2>
                
                <h3>✅ Protection Against:</h3>
                <ul>
                    <li><strong>Passive surveillance:</strong> Encrypted payloads unreadable without private key</li>
                    <li><strong>Deterministic attacks:</strong> Keys derived from wallet signatures, not predictable</li>
                    <li><strong>Wallet history analysis:</strong> Self-send prevents recipient tracking</li>
                    <li><strong>Spam attacks:</strong> Cannot pollute recipient's wallet with messages</li>
                    <li><strong>Future compromise:</strong> Forward secrecy protects past messages</li>
                </ul>

                <h3>⚠️ Does Not Protect Against:</h3>
                <ul>
                    <li><strong>Compromised wallet private key:</strong> If attacker has wallet access, they can derive messaging key</li>
                    <li><strong>Client-side malware:</strong> Keyloggers or screen capture on your device</li>
                    <li><strong>Metadata analysis:</strong> Transaction timestamps and gas costs are public</li>
                    <li><strong>Quantum computers:</strong> secp256k1 vulnerable to Shor's algorithm (future risk)</li>
                </ul>
            </section>

            <section className="about-section">
                <h2>Ethscriptions Protocol</h2>
                <p>
                    Chainmail uses the <strong>ethscriptions</strong> protocol to store data on Ethereum. 
                    Instead of expensive smart contract storage, ethscriptions use transaction calldata 
                    with a special format that indexers recognize and parse.
                </p>
                <p>
                    <strong>Protocol format:</strong>
                </p>
                <pre><code>{`data:,{"p":"chainfeed.online","op":"msg"}`}</code></pre>
                <p>
                    Messages include encrypted payload in base64 format with ECDH public key for decryption.
                </p>
            </section>

            <section className="about-section">
                <h2>Limitations & Trade-offs</h2>
                <ul>
                    <li><strong>Gas costs:</strong> Each message requires Ethereum transaction fees (~$5-50 depending on network)</li>
                    <li><strong>Public metadata:</strong> Transaction timestamps, sender address, and message size are visible</li>
                    <li><strong>No real-time:</strong> Messages confirmed after block inclusion (~12 seconds)</li>
                    <li><strong>Breaking changes:</strong> v1.0 messages encrypted with weak keys cannot be migrated</li>
                    <li><strong>No key rotation:</strong> Messaging key tied to wallet—compromised wallet = compromised messages</li>
                    <li><strong>Browser-only:</strong> No mobile apps or native clients yet</li>
                </ul>
            </section>

            <section className="about-section">
                <h2>Roadmap</h2>
                <ul>
                    <li>✅ v1.0: Basic ECDH encryption with deterministic keys</li>
                    <li>✅ v2.0: Wallet-signature keys + self-send privacy + forward secrecy</li>
                    <li>🔄 v2.1: Group messaging support</li>
                    <li>🔄 v2.2: File attachments (IPFS + encrypted)</li>
                    <li>🔄 v3.0: X3DH + Double Ratchet (Signal protocol)</li>
                    <li>🔄 Mobile app (React Native)</li>
                    <li>🔄 L2 support (Arbitrum, Base, etc.)</li>
                </ul>
            </section>

            <section className="about-section">
                <h2>Open Source</h2>
                <p>
                    Chainmail is fully open source under the MIT license. Review the code, report issues, 
                    or contribute improvements on GitHub.
                </p>
                <p>
                    <a 
                        href="https://github.com/jefdiesel/chainmail" 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="github-link"
                    >
                        📦 View Source on GitHub
                    </a>
                </p>
            </section>

            <section className="about-section">
                <h2>Disclaimer</h2>
                <p className="disclaimer">
                    <strong>Experimental Software:</strong> Chainmail is experimental and unaudited. 
                    Use at your own risk. Do not send sensitive information without understanding 
                    the threat model and limitations. The authors assume no liability for lost, 
                    compromised, or leaked messages.
                </p>
            </section>

            <footer className="about-footer">
                <p>Built by <a href="https://github.com/jefdiesel" target="_blank" rel="noopener noreferrer">jefdiesel</a></p>
                <p>Chainmail v2.0 • Ethereum Mainnet • MIT License</p>
            </footer>
        </div>
    );
}

export default About;
