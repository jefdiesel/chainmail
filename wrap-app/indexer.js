import { createPublicClient, http } from 'viem';
import { base } from 'viem/chains';
import fs from 'fs';

const WRAP_KEYS_PREFIX = 'data:wrap-keys,';
const DB_FILE = './wrap-keys-db.json';
const POLL_INTERVAL = 10000; // 10 seconds

// Load existing database
let db = { keys: {}, lastBlock: 0 };
if (fs.existsSync(DB_FILE)) {
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    console.log(`Loaded DB: ${Object.keys(db.keys).length} addresses, last block ${db.lastBlock}`);
  } catch (e) {
    console.log('Starting fresh DB');
  }
}

const ALCHEMY_KEY = 'zQCBzfLN5hsgfwPQ1Gagu';

const client = createPublicClient({
  chain: base,
  transport: http(`https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}`),
});

function hexToString(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  let str = '';
  for (let i = 0; i < hex.length; i += 2) {
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return str;
}

function parseWrapKeys(calldata) {
  const str = hexToString(calldata);
  if (!str.startsWith(WRAP_KEYS_PREFIX)) return null;
  try {
    return JSON.parse(atob(str.slice(WRAP_KEYS_PREFIX.length)));
  } catch {
    return null;
  }
}

async function indexBlock(blockNumber) {
  const block = await client.getBlock({ blockNumber, includeTransactions: true });
  let found = 0;

  for (const tx of block.transactions) {
    // Self-sends with data
    if (tx.to?.toLowerCase() === tx.from?.toLowerCase() && tx.input && tx.input !== '0x') {
      const keys = parseWrapKeys(tx.input);
      if (keys) {
        const addr = tx.from.toLowerCase();
        db.keys[addr] = {
          ...keys,
          address: addr,
          txHash: tx.hash,
          blockNumber: Number(blockNumber),
        };
        found++;
        console.log(`Found keys for ${addr.slice(0, 10)}... in block ${blockNumber}`);
      }
    }
  }

  return found;
}

async function saveDb() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

async function run() {
  console.log('Wrap Keys Indexer starting...');

  // Get current block
  const currentBlock = await client.getBlockNumber();
  console.log(`Current block: ${currentBlock}`);

  // Start from last indexed block or recent blocks
  let startBlock = db.lastBlock || Number(currentBlock) - 1000;
  console.log(`Starting from block ${startBlock}`);

  // Catch up
  for (let block = startBlock; block <= currentBlock; block++) {
    if (block % 100 === 0) {
      console.log(`Indexing block ${block}...`);
    }
    try {
      await indexBlock(BigInt(block));
      db.lastBlock = block;
    } catch (e) {
      console.error(`Error at block ${block}:`, e.message);
    }

    // Save every 100 blocks
    if (block % 100 === 0) {
      await saveDb();
    }
  }

  await saveDb();
  console.log(`Caught up! ${Object.keys(db.keys).length} addresses indexed`);

  // Poll for new blocks
  console.log('Polling for new blocks...');
  setInterval(async () => {
    try {
      const latest = await client.getBlockNumber();
      if (Number(latest) > db.lastBlock) {
        for (let block = db.lastBlock + 1; block <= Number(latest); block++) {
          await indexBlock(BigInt(block));
          db.lastBlock = block;
        }
        await saveDb();
      }
    } catch (e) {
      console.error('Poll error:', e.message);
    }
  }, POLL_INTERVAL);
}

run().catch(console.error);
