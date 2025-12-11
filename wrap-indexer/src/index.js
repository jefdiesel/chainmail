const WRAP_KEYS_PREFIX = 'data:wrap-keys,';
const WRAP_MSG_PREFIX = 'data:wrap,';
const BASE_RPC = 'https://base-mainnet.g.alchemy.com/v2/';

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

function isWrapMessage(calldata) {
  const str = hexToString(calldata);
  return str.startsWith(WRAP_MSG_PREFIX);
}

async function rpc(env, method, params) {
  const res = await fetch(BASE_RPC + env.ALCHEMY_KEY, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const json = await res.json();
  return json.result;
}

async function indexBlock(env, blockNumber) {
  const block = await rpc(env, 'eth_getBlockByNumber', [
    '0x' + blockNumber.toString(16),
    true,
  ]);
  if (!block) return { keys: [], messages: [] };

  const keys = [];
  const messages = [];

  for (const tx of block.transactions || []) {
    // Self-sends with data
    if (tx.to?.toLowerCase() === tx.from?.toLowerCase() && tx.input && tx.input !== '0x') {
      const keyData = parseWrapKeys(tx.input);
      if (keyData) {
        const addr = tx.from.toLowerCase();
        keys.push({
          address: addr,
          ...keyData,
          txHash: tx.hash,
          blockNumber,
        });
      } else if (isWrapMessage(tx.input)) {
        // It's an encrypted message
        messages.push({
          from: tx.from.toLowerCase(),
          to: tx.to.toLowerCase(),
          txHash: tx.hash,
          blockNumber,
          timestamp: parseInt(block.timestamp, 16) * 1000,
          calldata: tx.input,
        });
      }
    }
  }
  return { keys, messages };
}

export default {
  // Cron trigger - index new blocks
  async scheduled(event, env, ctx) {
    const currentBlock = parseInt(await rpc(env, 'eth_blockNumber', []), 16);
    const lastBlockStr = await env.WRAP_KEYS.get('_lastBlock');
    const lastBlock = lastBlockStr ? parseInt(lastBlockStr, 10) : currentBlock - 5;

    // Limit to 20 blocks per cron to avoid CPU timeout
    const maxBlocks = 20;
    const endBlock = Math.min(lastBlock + maxBlocks, currentBlock);

    console.log(`Indexing from ${lastBlock + 1} to ${endBlock} (current: ${currentBlock})`);

    for (let block = lastBlock + 1; block <= endBlock; block++) {
      const { keys, messages } = await indexBlock(env, block);

      for (const entry of keys) {
        await env.WRAP_KEYS.put(entry.address, JSON.stringify(entry));
        console.log(`Found keys for ${entry.address}`);
      }

      for (const msg of messages) {
        // Store message by txHash, also add to sender's message list
        await env.WRAP_KEYS.put(`msg:${msg.txHash}`, JSON.stringify(msg));

        // Add to sender's outbox (avoid duplicates)
        const outboxKey = `outbox:${msg.from}`;
        const existingOutbox = JSON.parse(await env.WRAP_KEYS.get(outboxKey) || '[]');
        if (!existingOutbox.includes(msg.txHash)) {
          existingOutbox.push(msg.txHash);
          await env.WRAP_KEYS.put(outboxKey, JSON.stringify(existingOutbox));
        }

        console.log(`Found message from ${msg.from}`);
      }
    }

    await env.WRAP_KEYS.put('_lastBlock', endBlock.toString());
  },

  // HTTP handler - lookup keys
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // GET /keys/:address
    if (url.pathname.startsWith('/keys/')) {
      const address = url.pathname.slice(6).toLowerCase();
      const data = await env.WRAP_KEYS.get(address);

      if (data) {
        return new Response(data, {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ error: 'Not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // GET /keys - list all (for debugging)
    if (url.pathname === '/keys') {
      const list = await env.WRAP_KEYS.list();
      const keys = {};
      for (const key of list.keys) {
        if (!key.name.startsWith('_')) {
          keys[key.name] = JSON.parse(await env.WRAP_KEYS.get(key.name));
        }
      }
      return new Response(JSON.stringify(keys), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // GET /status
    if (url.pathname === '/status') {
      const lastBlock = await env.WRAP_KEYS.get('_lastBlock');
      const list = await env.WRAP_KEYS.list();
      return new Response(JSON.stringify({
        lastBlock: parseInt(lastBlock || '0', 10),
        addressCount: list.keys.filter(k => !k.name.startsWith('_')).length,
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // GET /backfill?from=X&to=Y - scan historical blocks
    if (url.pathname === '/backfill') {
      const from = parseInt(url.searchParams.get('from') || '0', 10);
      const to = parseInt(url.searchParams.get('to') || '0', 10);
      if (!from || !to || to < from) {
        return new Response(JSON.stringify({ error: 'Need ?from=X&to=Y' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      const foundKeys = [];
      const foundMessages = [];
      for (let block = from; block <= to; block++) {
        const { keys, messages } = await indexBlock(env, block);
        for (const entry of keys) {
          await env.WRAP_KEYS.put(entry.address, JSON.stringify(entry));
          foundKeys.push(entry.address);
        }
        for (const msg of messages) {
          await env.WRAP_KEYS.put(`msg:${msg.txHash}`, JSON.stringify(msg));
          const outboxKey = `outbox:${msg.from}`;
          const existingOutbox = JSON.parse(await env.WRAP_KEYS.get(outboxKey) || '[]');
          if (!existingOutbox.includes(msg.txHash)) {
            existingOutbox.push(msg.txHash);
            await env.WRAP_KEYS.put(outboxKey, JSON.stringify(existingOutbox));
          }
          foundMessages.push(msg.txHash);
        }
      }

      return new Response(JSON.stringify({
        scanned: to - from + 1,
        keys: foundKeys,
        messages: foundMessages
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // GET /messages - get all messages (encrypted calldata)
    if (url.pathname === '/messages') {
      const list = await env.WRAP_KEYS.list({ prefix: 'msg:' });
      const messages = [];
      for (const key of list.keys) {
        messages.push(JSON.parse(await env.WRAP_KEYS.get(key.name)));
      }
      // Sort by timestamp desc
      messages.sort((a, b) => b.timestamp - a.timestamp);
      return new Response(JSON.stringify(messages), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // GET /messages/:txHash - get specific message
    if (url.pathname.startsWith('/messages/')) {
      const txHash = url.pathname.slice(10).toLowerCase();
      const data = await env.WRAP_KEYS.get(`msg:${txHash}`);
      if (data) {
        return new Response(data, {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ error: 'Not found' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // GET /outbox/:address - get messages sent by address
    if (url.pathname.startsWith('/outbox/')) {
      const address = url.pathname.slice(8).toLowerCase();
      const txHashes = JSON.parse(await env.WRAP_KEYS.get(`outbox:${address}`) || '[]');
      const messages = [];
      for (const hash of txHashes) {
        const msg = await env.WRAP_KEYS.get(`msg:${hash}`);
        if (msg) messages.push(JSON.parse(msg));
      }
      messages.sort((a, b) => b.timestamp - a.timestamp);
      return new Response(JSON.stringify(messages), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    return new Response('Wrap Keys Indexer\n\nGET /keys/:address - Lookup keys\nGET /keys - List all\nGET /status - Indexer status', {
      headers: corsHeaders,
    });
  },
};
