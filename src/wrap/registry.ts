/**
 * Wrap Protocol - Key Registry
 * ENS for public identities, raw addresses for private/anonymous use
 *
 * ENS text records:
 *   - wrap.identityKey: X25519 identity public key (hex)
 *   - wrap.signedPreKey: X25519 signed prekey (hex)
 */

import { createPublicClient, http } from 'viem';
import { mainnet, base, baseSepolia, sepolia } from 'viem/chains';
import { normalize } from 'viem/ens';
import { type KeyBundle, bundleFromHex, bundleToHex } from './wrap.js';

// ============================================================================
// Types
// ============================================================================

export interface ResolvedIdentity {
  address: string;
  ensName?: string;
  bundle: KeyBundle;
}

export interface RegistryConfig {
  chainId?: number;
  rpcUrl?: string;
}

// ============================================================================
// ENS Text Record Keys
// ============================================================================

export const ENS_KEYS = {
  IDENTITY_KEY: 'wrap.identityKey',
  SIGNED_PRE_KEY: 'wrap.signedPreKey',
} as const;

// ============================================================================
// Chain Configuration
// ============================================================================

const CHAINS = {
  1: mainnet,
  8453: base,
  84532: baseSepolia,
  11155111: sepolia,
} as const;

function getClient(config?: RegistryConfig) {
  const chainId = config?.chainId || 8453; // Default to Base
  const chain = CHAINS[chainId as keyof typeof CHAINS] || base;
  const transport = config?.rpcUrl ? http(config.rpcUrl) : http();

  return createPublicClient({
    chain,
    transport,
  });
}

// ============================================================================
// ENS Resolution (Public Identities)
// ============================================================================

/**
 * Resolve ENS name to key bundle
 * Works on mainnet and Base (via CCIP-Read)
 */
export async function resolveENS(
  ensName: string,
  config?: RegistryConfig
): Promise<ResolvedIdentity | null> {
  const client = getClient(config);

  try {
    const normalizedName = normalize(ensName);

    // Get address
    const address = await client.getEnsAddress({ name: normalizedName });
    if (!address) {
      return null;
    }

    // Get wrap keys from text records
    const [identityKey, signedPreKey] = await Promise.all([
      client.getEnsText({ name: normalizedName, key: ENS_KEYS.IDENTITY_KEY }),
      client.getEnsText({ name: normalizedName, key: ENS_KEYS.SIGNED_PRE_KEY }),
    ]);

    if (!identityKey || !signedPreKey) {
      return null; // No wrap keys registered
    }

    return {
      address,
      ensName: normalizedName,
      bundle: bundleFromHex({ identityKey, signedPreKey }),
    };
  } catch {
    return null;
  }
}

/**
 * Check if ENS name has wrap keys registered
 */
export async function hasWrapKeys(
  ensName: string,
  config?: RegistryConfig
): Promise<boolean> {
  const resolved = await resolveENS(ensName, config);
  return resolved !== null;
}

// ============================================================================
// Address-Based Registry (Private/Anonymous)
// ============================================================================

/**
 * In-memory key registry for address-based lookups
 * For production: persist to localStorage or IndexedDB
 */
const addressRegistry = new Map<string, KeyBundle>();

/**
 * Register a key bundle for an address (local only)
 */
export function registerAddress(address: string, bundle: KeyBundle): void {
  addressRegistry.set(address.toLowerCase(), bundle);
}

/**
 * Get key bundle for address (local registry)
 */
export function getAddressBundle(address: string): KeyBundle | null {
  return addressRegistry.get(address.toLowerCase()) || null;
}

/**
 * Remove address from registry
 */
export function unregisterAddress(address: string): boolean {
  return addressRegistry.delete(address.toLowerCase());
}

/**
 * Clear all registered addresses
 */
export function clearRegistry(): void {
  addressRegistry.clear();
}

/**
 * Export registry for backup
 */
export function exportRegistry(): Record<string, { identityKey: string; signedPreKey: string }> {
  const result: Record<string, { identityKey: string; signedPreKey: string }> = {};
  for (const [address, bundle] of addressRegistry) {
    result[address] = bundleToHex(bundle);
  }
  return result;
}

/**
 * Import registry from backup
 */
export function importRegistry(data: Record<string, { identityKey: string; signedPreKey: string }>): void {
  for (const [address, hexBundle] of Object.entries(data)) {
    addressRegistry.set(address.toLowerCase(), bundleFromHex(hexBundle));
  }
}

// ============================================================================
// Unified Resolution
// ============================================================================

/**
 * Resolve identifier to key bundle
 * Tries ENS first (if looks like ENS name), then address registry
 */
export async function resolve(
  identifier: string,
  config?: RegistryConfig
): Promise<ResolvedIdentity | null> {
  // Check if it looks like an ENS name
  if (identifier.includes('.')) {
    const ensResult = await resolveENS(identifier, config);
    if (ensResult) {
      return ensResult;
    }
  }

  // Try address registry
  const bundle = getAddressBundle(identifier);
  if (bundle) {
    return {
      address: identifier,
      bundle,
    };
  }

  return null;
}

/**
 * Resolve multiple identifiers
 */
export async function resolveMany(
  identifiers: string[],
  config?: RegistryConfig
): Promise<Map<string, ResolvedIdentity | null>> {
  const results = new Map<string, ResolvedIdentity | null>();

  // Resolve in parallel
  const resolutions = await Promise.all(
    identifiers.map(async (id) => ({
      id,
      result: await resolve(id, config),
    }))
  );

  for (const { id, result } of resolutions) {
    results.set(id, result);
  }

  return results;
}

// ============================================================================
// ENS Text Record Helpers (for setting keys)
// ============================================================================

/**
 * Generate ENS text record values for a key bundle
 * User needs to set these via ENS app or contract call
 */
export function getENSTextRecords(bundle: KeyBundle): Array<{ key: string; value: string }> {
  const hex = bundleToHex(bundle);
  return [
    { key: ENS_KEYS.IDENTITY_KEY, value: hex.identityKey },
    { key: ENS_KEYS.SIGNED_PRE_KEY, value: hex.signedPreKey },
  ];
}
