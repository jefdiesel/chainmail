import { ethers } from 'ethers';
import crypto from 'crypto';

// SENDER: Encrypt a message for a recipient
async function encryptMessageForRecipient(recipientAddress, message) {
  // 1. Get recipient's public key from chain
  const provider = new ethers.JsonRpcProvider('https://eth.llamarpc.com');
  const recipientPubKey = await getPublicKeyFromAddress(provider, recipientAddress);
  
  if (!recipientPubKey) {
    throw new Error('Could not retrieve public key for recipient. Have they made a transaction?');
  }

  // 2. Generate ephemeral keypair
  const ephemeralPrivKey = crypto.randomBytes(32);
  const ephemeralPubKey = getPublicKeyFromPrivateKey(ephemeralPrivKey);

  // 3. Derive shared secret using ECDH
  const sharedSecret = deriveSharedSecret(ephemeralPrivKey, recipientPubKey);

  // 4. Encrypt message
  const encrypted = encryptAES(message, sharedSecret);

  // 5. Combine ephemeral pubkey + encrypted message for calldata
  const calldata = '0x' + ephemeralPubKey.toString('hex') + encrypted.toString('hex');

  return {
    calldata,
    ephemeralPubKey: ephemeralPubKey.toString('hex'),
    encrypted: encrypted.toString('hex')
  };
}

// RECIPIENT: Decrypt a message from calldata
async function decryptMessage(privateKeyHex, calldata) {
  // Remove '0x' prefix
  const data = calldata.startsWith('0x') ? calldata.slice(2) : calldata;

  // 1. Extract ephemeral public key (first 65 bytes = 130 hex chars for uncompressed point)
  const ephemeralPubKeyHex = data.slice(0, 130);
  const ephemeralPubKey = Buffer.from(ephemeralPubKeyHex, 'hex');

  // 2. Extract encrypted message
  const encryptedHex = data.slice(130);
  const encrypted = Buffer.from(encryptedHex, 'hex');

  // 3. Derive shared secret using your private key
  const privateKey = Buffer.from(privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex, 'hex');
  const sharedSecret = deriveSharedSecret(privateKey, ephemeralPubKey);

  // 4. Decrypt message
  const decrypted = decryptAES(encrypted, sharedSecret);

  return decrypted;
}

// Get public key from an Ethereum address by fetching transaction history
async function getPublicKeyFromAddress(provider, address) {
  try {
    // Get transaction count to find first transaction
    const txCount = await provider.getTransactionCount(address);
    if (txCount === 0) {
      return null;
    }

    // Get first transaction sent by this address
    const blockNumber = await provider.getBlockNumber();
    
    for (let i = blockNumber; i >= Math.max(0, blockNumber - 10000); i--) {
      const block = await provider.getBlock(i);
      if (!block || !block.transactions) continue;

      for (const txHash of block.transactions) {
        const tx = await provider.getTransaction(txHash);
        if (tx && tx.from.toLowerCase() === address.toLowerCase()) {
          // Recover public key from transaction signature
          const msgHash = ethers.keccak256(ethers.toBeHex(tx.value, 32));
          const sig = { v: tx.v, r: tx.r, s: tx.s };
          const recoveredAddress = ethers.recoverAddress(msgHash, ethers.Signature.from(sig));
          
          // Use ethers to recover the public key from signature
          const publicKey = ethers.recoverPublicKey(
            ethers.hashMessage(ethers.toUtf8Bytes('dummy')),
            sig
          );
          
          return Buffer.from(publicKey.slice(2), 'hex');
        }
      }
    }
  } catch (error) {
    console.error('Error fetching public key:', error);
    return null;
  }
}

// Derive shared secret using ECDH
function deriveSharedSecret(privateKey, publicKey) {
  // privateKey and publicKey are Buffers
  // publicKey should be uncompressed (65 bytes starting with 0x04)
  
  // Ensure publicKey is uncompressed format
  let pubKeyBuffer = publicKey;
  if (pubKeyBuffer[0] !== 0x04) {
    // If compressed, would need decompression - for now assume uncompressed from on-chain
    if (pubKeyBuffer.length === 33) {
      throw new Error('Compressed public keys not yet supported in this implementation');
    }
  }

  // Use secp256k1 ECDH
  const secp256k1 = require('secp256k1');
  const sharedPointBuffer = secp256k1.publicKeyTweakMul(pubKeyBuffer, privateKey);
  
  // Hash the shared point to derive symmetric key
  const sharedSecret = crypto.createHash('sha256').update(sharedPointBuffer).digest();
  return sharedSecret;
}

// Get public key from private key
function getPublicKeyFromPrivateKey(privateKey) {
  const secp256k1 = require('secp256k1');
  const publicKey = secp256k1.publicKeyCreate(privateKey, false); // false = uncompressed
  return publicKey;
}

// Encrypt message using AES-256-GCM
function encryptAES(message, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  // Format: iv (16 bytes) + authTag (16 bytes) + encrypted data
  return Buffer.concat([iv, authTag, Buffer.from(encrypted, 'hex')]);
}

// Decrypt message using AES-256-GCM
function decryptAES(encryptedData, key) {
  const iv = encryptedData.slice(0, 16);
  const authTag = encryptedData.slice(16, 32);
  const encrypted = encryptedData.slice(32);
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// Example usage
async function example() {
  const recipientAddress = '0x...'; // Their Ethereum address
  const message = 'Secret message only they can read';
  
  // SENDER encrypts
  const { calldata } = await encryptMessageForRecipient(recipientAddress, message);
  console.log('Encrypted calldata:', calldata);
  // Post this to chain via ethscription/calldata
  
  // RECIPIENT decrypts
  const recipientPrivateKey = '0x...'; // Their private key
  const decrypted = decryptMessage(recipientPrivateKey, calldata);
  console.log('Decrypted message:', decrypted);
}

export { encryptMessageForRecipient, decryptMessage };