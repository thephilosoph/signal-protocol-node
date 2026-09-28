import { CryptoProvider } from '../crypto/crypto-provider';
import { fromBase64 } from '../util/base64';
import { concatBytes, u32be, utf8ToBytes } from '../util/bytes';

/**
 * Safety numbers for out-of-band identity verification (the "compare 60 digits"
 * flow users know from Signal/WhatsApp).
 *
 * Format (stable, documented):
 * - The set of identity keys to verify (own key + every remote device key,
 *   which is what makes this work for multi-device contacts) is ordered
 *   lexicographically, so BOTH sides compute the same number regardless of
 *   who computes it or how their devices are enumerated.
 * - number = SHA-256("signal-protocol-node/safety-number/1" || len-prefixed
 *   sorted keys), first 30 bytes → 60 decimal digits (byte % 100, 2 digits).
 * - Works for any number of keys ≥ 2 (pairwise and multi-device alike).
 */

const SAFETY_NUMBER_INFO = 'signal-protocol-node/safety-number/1';
const FINGERPRINT_INFO = 'signal-protocol-node/fingerprint/1';
const FINGERPRINT_BYTES = 15;
const SAFETY_NUMBER_BYTES = 30;

/**
 * 60-digit safety number for a set of identity keys. Order-independent: the
 * keys are sorted internally, so both sides of a conversation arrive at the
 * same digits regardless of how they enumerate their devices.
 */
export async function computeSafetyNumber(keys: Uint8Array[], crypto: CryptoProvider): Promise<string> {
  if (keys.length < 2) {
    throw new Error('Safety number requires at least two identity keys');
  }
  const sorted = [...keys].sort(compareBytes);
  const digest = await crypto.sha256(concatBytes(utf8ToBytes(SAFETY_NUMBER_INFO), ...sorted.map(lengthPrefixed)));
  return bytesToDigits(digest.slice(0, SAFETY_NUMBER_BYTES));
}

/** 60-digit safety number for a pair of identity keys (order-independent). */
export async function computePairSafetyNumber(keyA: Uint8Array, keyB: Uint8Array, crypto: CryptoProvider): Promise<string> {
  return computeSafetyNumber([keyA, keyB], crypto);
}

/**
 * Convenience over identity keys given as base64 (e.g. straight out of
 * `IdentityKeyPairDTO` / `RemoteIdentityDTO`).
 */
export async function computeSafetyNumberFromBase64(keys: string[], crypto: CryptoProvider): Promise<string> {
  return computeSafetyNumber(keys.map(fromBase64), crypto);
}

/**
 * Per-key fingerprint (30 hex chars) — the stable identity material for QR
 * codes and safety-number UIs.
 */
export async function computeFingerprint(identityKey: Uint8Array, crypto: CryptoProvider): Promise<string> {
  const digest = await crypto.sha256(concatBytes(utf8ToBytes(FINGERPRINT_INFO), identityKey));
  return toHex(digest.slice(0, FINGERPRINT_BYTES));
}

/** Group the 60 digits into 12 blocks of 5 for readable UI display. */
export function formatSafetyNumber(digits: string): string {
  if (!/^\d{60}$/.test(digits)) {
    throw new Error('Safety number must be exactly 60 digits');
  }
  const blocks: string[] = [];
  for (let i = 0; i < 60; i += 5) {
    blocks.push(digits.slice(i, i + 5));
  }
  return blocks.join(' ');
}

function lengthPrefixed(key: Uint8Array): Uint8Array {
  return concatBytes(u32be(key.length), key);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function bytesToDigits(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) {
    out += String(byte % 100).padStart(2, '0');
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
