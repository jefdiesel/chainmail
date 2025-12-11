/**
 * Test ENS resolution for wrap keys
 */

import { resolve, resolveENS } from '../dist/registry.js';

async function main() {
  console.log('=== ENS Resolution Test ===\n');

  // Test with a known ENS name (vitalik.eth as example)
  const testNames = ['vitalik.eth', 'nick.eth', 'brantly.eth'];

  for (const name of testNames) {
    console.log(`Resolving ${name}...`);
    try {
      const result = await resolveENS(name, { chainId: 1 }); // mainnet for ENS
      if (result) {
        console.log(`  Address: ${result.address}`);
        console.log(`  Has wrap keys: ${result.bundle ? 'YES' : 'NO'}`);
      } else {
        console.log(`  No wrap keys set (or name not found)`);
      }
    } catch (err) {
      console.log(`  Error: ${err.message}`);
    }
    console.log();
  }

  // Test the unified resolve function
  console.log('--- Unified resolve() ---');
  console.log('alice.eth → tries ENS');
  console.log('0x123... → tries address registry');
}

main().catch(console.error);
