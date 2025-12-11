// Wrap Indexer API Client
const INDEXER_URL = 'https://wrap-indexer.wrapit.workers.dev';

export async function getKeys(address) {
  const res = await fetch(`${INDEXER_URL}/keys/${address.toLowerCase()}`);
  if (!res.ok) return null;
  return res.json();
}

export async function getAllKeys() {
  const res = await fetch(`${INDEXER_URL}/keys`);
  if (!res.ok) return {};
  return res.json();
}

export async function getMessages() {
  const res = await fetch(`${INDEXER_URL}/messages`);
  if (!res.ok) return [];
  return res.json();
}

export async function getMessage(txHash) {
  const res = await fetch(`${INDEXER_URL}/messages/${txHash.toLowerCase()}`);
  if (!res.ok) return null;
  return res.json();
}

export async function getOutbox(address) {
  const res = await fetch(`${INDEXER_URL}/outbox/${address.toLowerCase()}`);
  if (!res.ok) return [];
  return res.json();
}

export async function getStatus() {
  const res = await fetch(`${INDEXER_URL}/status`);
  if (!res.ok) return null;
  return res.json();
}

export async function backfill(from, to) {
  const res = await fetch(`${INDEXER_URL}/backfill?from=${from}&to=${to}`);
  if (!res.ok) return null;
  return res.json();
}
