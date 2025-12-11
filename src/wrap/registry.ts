/**
 * Wrap Protocol - Key Registry
 * ENS resolves to address, then fetch prekeys from chain
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
  bundle?: KeyBundle; // From on-chain prekey announcement
}

export interface RegistryConfig {
  chainId?: number;
  rpcUrl?: string;
}

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
// ENS Resolution
// ============================================================================

/**
 * Resolve ENS name to address
 * Prekeys are fetched separately from chain by address
 */
export async function resolveENS(
  ensName: string,
  config?: RegistryConfig
): Promise<string | null> {
  const client = getClient(config);

  try {
    const normalizedName = normalize(ensName);
    const address = await client.getEnsAddress({ name: normalizedName });
    return address || null;
  } catch {
    return null;
  }
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
 * Resolve identifier to address
 * - ENS name (alice.eth) → resolves via ENS
 * - Address (0x...) → returns as-is
 *
 * Prekeys are fetched from chain separately (indexer looks up prekey announcements)
 */
export async function resolve(
  identifier: string,
  config?: RegistryConfig
): Promise<string | null> {
  // ENS name
  if (identifier.includes('.')) {
    return resolveENS(identifier, config);
  }

  // Already an address
  if (identifier.startsWith('0x') && identifier.length === 42) {
    return identifier;
  }

  return null;
}

/**
 * Resolve multiple identifiers to addresses
 */
export async function resolveMany(
  identifiers: string[],
  config?: RegistryConfig
): Promise<Map<string, string | null>> {
  const results = new Map<string, string | null>();

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
