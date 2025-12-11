/**
 * Test ENS resolution
 * ENS → address, then fetch prekeys from chain by address
 */

import { resolve, resolveENS } from '../dist/registry.js';

async function main() {
  console.log('=== ENS → Address Resolution ===\n');

  const testNames = ['vitalik.eth', 'nick.eth', 'jesse.base.eth'];

  for (const name of testNames) {
    console.log(`${name}:`);
    try {
      const address = await resolveENS(name, { chainId: 1 }); // mainnet for .eth
      if (address) {
        console.log(`  → ${address}`);
        console.log(`  (next: fetch prekeys from chain for this address)`);
      } else {
        console.log(`  → not found`);
      }
    } catch (err) {
      console.log(`  → error: ${err.message}`);
    }
    console.log();
  }

  // Test unified resolve
  console.log('--- resolve() handles both ---');
  const addr = await resolve('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045');
  console.log(`0xd8dA... → ${addr}`);
}

main().catch(console.error);
