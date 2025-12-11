import React, { useState, useEffect } from 'react';
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { useAccount, useWalletClient, usePublicClient } from 'wagmi';
import {
  deriveKeysFromSignature,
  exportKeys,
  importKeys,
  announceKeys,
  wrapAsync,
  unwrapAsync,
  wrapAndChunkAsync,
  toHex,
  resolveENS,
  parseKeys,
  isWrapKeys,
} from './wrap-browser.js';
import * as indexerApi from './indexer-api.js';

// ============================================================================
// Key Management
// ============================================================================

function KeyManager({ keys, setKeys, walletClient, publicClient, address, keysPublished, setKeysPublished }) {
  const [status, setStatus] = useState('');
  const [importJson, setImportJson] = useState('');
  const [showImport, setShowImport] = useState(false);
  const [salt, setSalt] = useState('');
  const [showSaltInput, setShowSaltInput] = useState(false);
  const [publishing, setPublishing] = useState(false);

  // Validate salt: 6-12 lowercase alphanumeric only
  const validateSalt = (value) => {
    return value.replace(/[^a-z0-9]/g, '').slice(0, 12);
  };

  const deriveKeys = async (useSalt = '') => {
    if (!walletClient) return;
    const message = useSalt ? `wrap-keys-v1:${useSalt}` : 'wrap-keys-v1';
    setStatus('Sign message to derive keys...');
    try {
      const sig = await walletClient.signMessage({ message });
      const derived = deriveKeysFromSignature(sig);
      setKeys(derived);
      setSalt(useSalt);
      setShowSaltInput(false);
      // New salt = need to publish these keys
      setKeysPublished(false);
      setStatus(useSalt ? `Keys ready (salt: ${useSalt}) - publish to use` : 'Keys ready');
    } catch (err) {
      setStatus('Failed: ' + err.message);
    }
  };

  const publishKeys = async () => {
    if (!keys || !walletClient) return;
    setPublishing(true);
    setStatus('Publishing keys on chain...');
    try {
      const calldata = announceKeys(keys);
      // Convert string to hex bytes
      const hexData = '0x' + Array.from(new TextEncoder().encode(calldata))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      const tx = await walletClient.sendTransaction({
        to: address,
        value: 0n,
        data: hexData,
      });
      // Remember this key was published
      localStorage.setItem(`wrap-published-${address}`, toHex(keys.identity.publicKey));
      setKeysPublished(true);
      setStatus(`Keys published: ${tx.slice(0, 10)}...`);
    } catch (err) {
      setStatus('Publish failed: ' + err.message);
    } finally {
      setPublishing(false);
    }
  };

  const exportToJson = () => {
    if (!keys) return;
    const json = JSON.stringify(exportKeys(keys), null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wrap-keys-${address.slice(0, 8)}.json`;
    a.click();
  };

  const importFromJson = async () => {
    try {
      const parsed = JSON.parse(importJson);
      const imported = importKeys(parsed);
      setKeys(imported);
      setShowImport(false);
      setImportJson('');
      setStatus('Keys imported');
    } catch (err) {
      setStatus('Import failed: ' + err.message);
    }
  };

  // Auto-derive keys when wallet connects (no salt by default)
  useEffect(() => {
    if (address && walletClient && !keys) {
      deriveKeys('');
    }
  }, [address, walletClient]);

  // Check if keys were previously published (localStorage or indexer)
  useEffect(() => {
    if (address && keys) {
      const currentKey = toHex(keys.identity.publicKey);

      // First check localStorage
      const publishedKey = localStorage.getItem(`wrap-published-${address}`);
      if (publishedKey === currentKey) {
        setKeysPublished(true);
        return;
      }

      // Also check indexer
      indexerApi.getKeys(address).then(data => {
        if (data && data.identityKey === currentKey) {
          // Keys are on chain, save to localStorage and mark published
          localStorage.setItem(`wrap-published-${address}`, currentKey);
          setKeysPublished(true);
        }
      }).catch(() => {});
    }
  }, [address, keys]);

  // Setup flow: keys derived but not published yet
  if (keys && !keysPublished) {
    return (
      <div className="key-manager setup-flow">
        <h3>Setup Wrap</h3>
        <div className="setup-step">
          <p className="setup-instruction">
            Publish your keys on-chain so others can send you encrypted messages.
          </p>
          <p className="identity-key">
            Identity: <code>{toHex(keys.identity.publicKey).slice(0, 16)}...</code>
          </p>
          <button
            onClick={publishKeys}
            className="publish-btn large"
            disabled={publishing}
          >
            {publishing ? 'Publishing...' : 'Publish Keys'}
          </button>
        </div>
        {status && <p className="status">{status}</p>}
      </div>
    );
  }

  return (
    <div className="key-manager">
      <h3>Wrap Keys</h3>
      {keys ? (
        <div>
          <p className="identity-key">
            Identity: <code>{toHex(keys.identity.publicKey).slice(0, 16)}...</code>
            {salt && <span className="salt-badge">salt: {salt}</span>}
          </p>
          <div className="key-actions">
            <button onClick={exportToJson} className="backup-btn">Backup</button>
            <button onClick={() => setShowImport(true)}>Restore</button>
            <button onClick={() => setShowSaltInput(true)}>Use Salt</button>
          </div>

          {showSaltInput && (
            <div className="salt-input">
              <input
                type="text"
                placeholder="6-12 chars (a-z, 0-9)"
                value={salt}
                onChange={(e) => setSalt(validateSalt(e.target.value))}
                maxLength={12}
              />
              <button
                onClick={() => deriveKeys(salt)}
                disabled={salt.length < 6}
              >
                Derive
              </button>
              <button onClick={() => { setShowSaltInput(false); setSalt(''); }}>
                Cancel
              </button>
            </div>
          )}
        </div>
      ) : (
        <div>
          <p>No keys found</p>
          <button onClick={() => deriveKeys('')}>Generate from Wallet</button>
          <button onClick={() => setShowImport(true)}>Import Keys</button>
        </div>
      )}

      {showImport && (
        <div className="import-modal">
          <textarea
            placeholder="Paste exported keys JSON..."
            value={importJson}
            onChange={(e) => setImportJson(e.target.value)}
          />
          <button onClick={importFromJson}>Import</button>
          <button onClick={() => setShowImport(false)}>Cancel</button>
        </div>
      )}

      {status && <p className="status">{status}</p>}
    </div>
  );
}

// ============================================================================
// Send Form
// ============================================================================

function SendForm({ keys, walletClient, address }) {
  const [toInput, setToInput] = useState('');
  const [ccInput, setCcInput] = useState('');
  const [recipients, setRecipients] = useState([]); // [{addr, keys, type: 'to'|'cc'}]
  const [resolveStatus, setResolveStatus] = useState('');
  const [metadata, setMetadata] = useState({ name: '', subject: '', details: '' });
  const [customFields, setCustomFields] = useState([]);
  const [image, setImage] = useState(null);
  const [imagePreview, setImagePreview] = useState(null);
  const [sending, setSending] = useState(false);
  const [sendStatus, setSendStatus] = useState('');
  const [noKeysAddr, setNoKeysAddr] = useState(null);

  const resolveAndAdd = async (input, type) => {
    if (!input) return;
    setResolveStatus('Resolving...');

    // Resolve ENS if needed
    let addr = input;
    if (input.includes('.')) {
      const resolved = await resolveENS(input, { chainId: 8453 });
      if (!resolved) {
        setResolveStatus('ENS not found');
        return;
      }
      addr = resolved;
    }

    // Check if already added
    if (recipients.find(r => r.addr.toLowerCase() === addr.toLowerCase())) {
      setResolveStatus('Already added');
      return;
    }

    // Fetch wrap-keys from indexer
    try {
      const data = await indexerApi.getKeys(addr);
      const shortAddr = `${addr.slice(0, 6)}...${addr.slice(-4)}`;
      if (!data) {
        setResolveStatus(`${shortAddr} has no wrap keys`);
        setNoKeysAddr(addr);
        return;
      }
      setNoKeysAddr(null);
      setRecipients([...recipients, {
        addr,
        keys: {
          identityKey: data.identityKey,
          signedPreKey: data.signedPreKey,
        },
        type,
      }]);
      setResolveStatus(`Added ${shortAddr}`);
      if (type === 'to') setToInput('');
      else setCcInput('');
    } catch (err) {
      setResolveStatus('Failed to fetch keys: ' + err.message);
    }
  };

  const removeRecipient = (addr) => {
    setRecipients(recipients.filter(r => r.addr !== addr));
  };

  // Returns recipient object without adding to state (for auto-add on send)
  const resolveAndAddDirect = async (input, type) => {
    let addr = input;
    if (input.includes('.')) {
      const resolved = await resolveENS(input, { chainId: 8453 });
      if (!resolved) {
        setSendStatus('ENS not found: ' + input);
        return null;
      }
      addr = resolved;
    }

    // Skip if already in recipients list
    if (recipients.find(r => r.addr.toLowerCase() === addr.toLowerCase())) {
      return null;
    }

    try {
      const data = await indexerApi.getKeys(addr);
      const shortAddr = `${addr.slice(0, 6)}...${addr.slice(-4)}`;
      if (!data) {
        setSendStatus(`${shortAddr} has no wrap keys`);
        return null;
      }
      return {
        addr,
        keys: {
          identityKey: data.identityKey,
          signedPreKey: data.signedPreKey,
        },
        type,
      };
    } catch (err) {
      setSendStatus('Failed to fetch keys: ' + err.message);
      return null;
    }
  };

  const handleImageSelect = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (ev) => {
      setImage(ev.target.result);
      setImagePreview(ev.target.result);
    };
    reader.readAsDataURL(file);
  };

  const addCustomField = () => {
    setCustomFields([...customFields, { key: '', value: '' }]);
  };

  const updateCustomField = (idx, field, value) => {
    const updated = [...customFields];
    updated[idx][field] = value;
    setCustomFields(updated);
  };

  const send = async () => {
    if (!keys) {
      setSendStatus('No keys');
      return;
    }

    setSending(true);

    // Auto-add any addresses still in the input fields
    let allRecipients = [...recipients];
    if (toInput.trim()) {
      const added = await resolveAndAddDirect(toInput.trim(), 'to');
      if (added) allRecipients.push(added);
    }
    if (ccInput.trim()) {
      const added = await resolveAndAddDirect(ccInput.trim(), 'cc');
      if (added) allRecipients.push(added);
    }

    if (allRecipients.length === 0) {
      setSendStatus('Need at least one recipient');
      setSending(false);
      return;
    }

    setSendStatus('Building payload...');

    try {
      const payload = {
        ...metadata,
        customFields: customFields.filter(f => f.key && f.value),
        image,
        timestamp: Date.now(),
      };

      // Convert hex string keys to Uint8Array for the wrap library
      const hexToBytes = (hex) => {
        if (hex.startsWith('0x')) hex = hex.slice(2);
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
          bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
      };

      const recipientBundles = allRecipients.map(r => ({
        id: r.addr,
        bundle: {
          identityKey: hexToBytes(r.keys.identityKey),
          signedPreKey: hexToBytes(r.keys.signedPreKey),
        }
      }));
      const chunks = await wrapAndChunkAsync(keys, recipientBundles, payload);

      setSendStatus(`Sending ${chunks.length} chunk(s)...`);

      for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        setSendStatus(`Sending chunk ${i + 1}/${chunks.length}...`);

        // Convert calldata to hex (it's a string, use TextEncoder)
        const hexData = '0x' + Array.from(new TextEncoder().encode(chunk.calldata))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');

        await walletClient.sendTransaction({
          to: address,
          value: 0n,
          data: hexData,
        });
      }

      setSendStatus(`Sent ${chunks.length} chunk(s)`);
      // Clear form
      setMetadata({ name: '', subject: '', details: '' });
      setCustomFields([]);
      setImage(null);
      setImagePreview(null);
      setToInput('');
      setCcInput('');
      setRecipients([]);
      setResolveStatus('');
    } catch (err) {
      setSendStatus('Failed: ' + err.message);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="send-form">
      <h3>Send Wrap</h3>

      <div className="field">
        <label>To (ENS or 0x)</label>
        <div className="input-row">
          <input
            value={toInput}
            onChange={(e) => setToInput(e.target.value)}
            placeholder="alice.eth or 0x..."
            onKeyDown={(e) => e.key === 'Enter' && resolveAndAdd(toInput, 'to')}
          />
          <button onClick={() => resolveAndAdd(toInput, 'to')}>Add</button>
        </div>
      </div>

      <div className="field">
        <label>CC (optional)</label>
        <div className="input-row">
          <input
            value={ccInput}
            onChange={(e) => setCcInput(e.target.value)}
            placeholder="bob.eth or 0x..."
            onKeyDown={(e) => e.key === 'Enter' && resolveAndAdd(ccInput, 'cc')}
          />
          <button onClick={() => resolveAndAdd(ccInput, 'cc')}>Add</button>
        </div>
      </div>

      {resolveStatus && <span className="hint">{resolveStatus}</span>}

      {noKeysAddr && (
        <div className="invite-prompt">
          <span>They need to set up Wrap first:</span>
          <button
            className="invite-btn"
            onClick={() => {
              const link = `${window.location.origin}${window.location.pathname}`;
              const text = `I'm using Wrap for secure onchain messaging - ${link}`;
              navigator.clipboard.writeText(text);
              setResolveStatus('Copied to clipboard!');
              setTimeout(() => setNoKeysAddr(null), 2000);
            }}
          >
            Copy Invite
          </button>
        </div>
      )}

      {recipients.length > 0 && (
        <div className="recipients-list">
          {recipients.map((r) => (
            <span key={r.addr} className={`recipient-tag ${r.type}`}>
              <span className="type-badge">{r.type.toUpperCase()}</span>
              {r.addr.slice(0, 6)}...{r.addr.slice(-4)}
              <button className="remove-btn" onClick={() => removeRecipient(r.addr)}>×</button>
            </span>
          ))}
        </div>
      )}

      <div className="field">
        <label>Name</label>
        <input
          value={metadata.name}
          onChange={(e) => setMetadata({ ...metadata, name: e.target.value })}
        />
      </div>

      <div className="field">
        <label>Subject</label>
        <input
          value={metadata.subject}
          onChange={(e) => setMetadata({ ...metadata, subject: e.target.value })}
        />
      </div>

      <div className="field">
        <label>Details</label>
        <textarea
          value={metadata.details}
          onChange={(e) => setMetadata({ ...metadata, details: e.target.value })}
        />
      </div>

      <div className="custom-fields">
        <label>Custom Fields</label>
        {customFields.map((f, i) => (
          <div key={i} className="custom-field-row">
            <input
              placeholder="Field name"
              value={f.key}
              onChange={(e) => updateCustomField(i, 'key', e.target.value)}
            />
            <input
              placeholder="Value"
              value={f.value}
              onChange={(e) => updateCustomField(i, 'value', e.target.value)}
            />
          </div>
        ))}
        <button onClick={addCustomField}>+ Add Field</button>
      </div>

      <div className="field">
        <label>Image</label>
        <input type="file" accept="image/*" onChange={handleImageSelect} />
        {imagePreview && (
          <img src={imagePreview} alt="preview" className="image-preview" />
        )}
      </div>

      <button onClick={send} disabled={sending || !keys}>
        {sending ? 'Sending...' : 'Send'}
      </button>

      {sendStatus && <p className="status">{sendStatus}</p>}
    </div>
  );
}

// ============================================================================
// Inbox
// ============================================================================

function Inbox({ keys, address }) {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedMsg, setSelectedMsg] = useState(null);
  const [decrypted, setDecrypted] = useState(null);
  const [decrypting, setDecrypting] = useState(false);

  const refresh = async () => {
    if (!keys) return;
    setLoading(true);
    try {
      // Get all messages from indexer
      const allMessages = await indexerApi.getMessages();
      // Try to decrypt each one to see if it's for us
      const myMessages = [];
      for (const msg of allMessages) {
        // Store raw message data for later decryption attempt
        myMessages.push({
          ...msg,
          calldata: msg.calldata, // The encrypted payload
        });
      }
      setMessages(myMessages);
    } catch (err) {
      console.error('Failed to fetch messages:', err);
    }
    setLoading(false);
  };

  const decryptMessage = async (msg) => {
    if (!keys) return;
    setSelectedMsg(msg);
    setDecrypting(true);
    setDecrypted(null);

    try {
      // Extract the wrap payload from calldata
      console.log('Decrypting msg:', msg);
      if (!msg.calldata) {
        setDecrypted({ error: 'No calldata in message' });
        setDecrypting(false);
        return;
      }

      const calldataStr = hexToString(msg.calldata);
      console.log('Decoded calldata:', calldataStr?.slice(0, 50));
      if (!calldataStr || !calldataStr.startsWith('data:wrap,')) {
        setDecrypted({ error: 'Not a wrap message' });
        setDecrypting(false);
        return;
      }

      // Try to decrypt - unwrapAsync(recipientId, recipientKeys, calldata)
      console.log('Calling unwrapAsync...');
      const result = await unwrapAsync(address, keys, calldataStr);
      console.log('Decrypt result:', result);
      if (result) {
        // Result is Uint8Array, decode as JSON
        const decoded = JSON.parse(new TextDecoder().decode(result));
        // It's a chunked message with {id, part, total, data}
        const payload = JSON.parse(atob(decoded.data));
        setDecrypted(payload);
      } else {
        setDecrypted({ error: 'Message not for you or decryption failed' });
      }
    } catch (err) {
      setDecrypted({ error: 'Could not decrypt: ' + err.message });
    }
    setDecrypting(false);
  };

  useEffect(() => {
    if (keys) refresh();
  }, [keys]);

  return (
    <div className="inbox">
      <h3>Inbox</h3>
      <button onClick={refresh} disabled={loading}>
        {loading ? 'Loading...' : 'Refresh'}
      </button>

      {messages.length === 0 ? (
        <p className="empty">No messages yet</p>
      ) : (
        <ul className="message-list">
          {messages.map((msg, i) => (
            <li key={msg.txHash} onClick={() => decryptMessage(msg)} className={selectedMsg?.txHash === msg.txHash ? 'selected' : ''}>
              <span className="msg-from">{msg.from.slice(0, 10)}...</span>
              <span className="msg-time">{new Date(msg.timestamp).toLocaleString()}</span>
            </li>
          ))}
        </ul>
      )}

      {selectedMsg && (
        <div className="message-detail">
          <h4>Message</h4>
          <p><strong>From:</strong> {selectedMsg.from}</p>
          <p><strong>Time:</strong> {new Date(selectedMsg.timestamp).toLocaleString()}</p>
          <p><strong>Tx:</strong> <a href={`https://basescan.org/tx/${selectedMsg.txHash}`} target="_blank" rel="noreferrer">{selectedMsg.txHash.slice(0, 16)}...</a></p>

          {decrypting ? (
            <p className="status">Decrypting...</p>
          ) : decrypted ? (
            decrypted.error ? (
              <p className="error">{decrypted.error}</p>
            ) : (
              <div className="decrypted-content">
                {decrypted.name && <p><strong>Name:</strong> {decrypted.name}</p>}
                {decrypted.subject && <p><strong>Subject:</strong> {decrypted.subject}</p>}
                {decrypted.details && <p><strong>Details:</strong> {decrypted.details}</p>}
                {decrypted.image && <img src={decrypted.image} alt="attachment" className="msg-image" />}
              </div>
            )
          ) : null}
        </div>
      )}
    </div>
  );
}

// Helper to convert hex calldata to string
function hexToString(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  let str = '';
  for (let i = 0; i < hex.length; i += 2) {
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return str;
}

// ============================================================================
// Outbox
// ============================================================================

function Outbox({ address }) {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);

  const refresh = async () => {
    if (!address) return;
    setLoading(true);
    try {
      const sent = await indexerApi.getOutbox(address);
      setMessages(sent);
    } catch (err) {
      console.error('Failed to fetch outbox:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    if (address) refresh();
  }, [address]);

  return (
    <div className="inbox">
      <h3>Outbox</h3>
      <button onClick={refresh} disabled={loading}>
        {loading ? 'Loading...' : 'Refresh'}
      </button>

      {messages.length === 0 ? (
        <p className="empty">No sent messages yet</p>
      ) : (
        <ul className="message-list">
          {messages.map((msg) => (
            <li key={msg.txHash}>
              <span className="msg-time">{new Date(msg.timestamp).toLocaleString()}</span>
              <a
                href={`https://basescan.org/tx/${msg.txHash}`}
                target="_blank"
                rel="noreferrer"
                className="tx-link"
              >
                {msg.txHash.slice(0, 10)}...{msg.txHash.slice(-6)}
              </a>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ============================================================================
// Main App
// ============================================================================

export default function WrapApp() {
  const { address, isConnected } = useAccount();
  const { data: walletClient } = useWalletClient();
  const publicClient = usePublicClient();
  const [keys, setKeys] = useState(null);
  const [keysPublished, setKeysPublished] = useState(false);
  const [tab, setTab] = useState('keys');

  // Block access to Send/Inbox until keys are published
  const canUseApp = keys && keysPublished;

  return (
    <div className="wrap-app">
      <header>
        <h1>Wrap</h1>
        <ConnectButton />
      </header>

      {isConnected ? (
        <main>
          {canUseApp && (
            <nav>
              <button className={tab === 'keys' ? 'active' : ''} onClick={() => setTab('keys')}>Keys</button>
              <button className={tab === 'send' ? 'active' : ''} onClick={() => setTab('send')}>Send</button>
              <button className={tab === 'inbox' ? 'active' : ''} onClick={() => setTab('inbox')}>Inbox</button>
              <button className={tab === 'outbox' ? 'active' : ''} onClick={() => setTab('outbox')}>Outbox</button>
            </nav>
          )}

          {(!canUseApp || tab === 'keys') && (
            <KeyManager
              keys={keys}
              setKeys={setKeys}
              walletClient={walletClient}
              publicClient={publicClient}
              address={address}
              keysPublished={keysPublished}
              setKeysPublished={setKeysPublished}
            />
          )}

          {canUseApp && tab === 'send' && (
            <SendForm
              keys={keys}
              walletClient={walletClient}
              address={address}
            />
          )}

          {canUseApp && tab === 'inbox' && (
            <Inbox keys={keys} address={address} />
          )}

          {canUseApp && tab === 'outbox' && (
            <Outbox address={address} />
          )}
        </main>
      ) : (
        <main>
          <p>Connect wallet to start</p>
        </main>
      )}
    </div>
  );
}
