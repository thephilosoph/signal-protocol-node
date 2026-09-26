import { InvalidArgumentError } from '../errors';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8');

/** Concatenate byte arrays into one array. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Encode a UTF-8 string to bytes. */
export function utf8ToBytes(text: string): Uint8Array {
  return textEncoder.encode(text);
}

/** Decode bytes as a UTF-8 string. */
export function bytesToUtf8(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

/** Encode a number as a big-endian unsigned 32-bit integer. */
export function u32be(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, false);
  return out;
}

/** Length-independent comparison that does not short-circuit on the first differing byte. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** True when every byte is zero (X25519 all-zero shared secret = invalid input key). */
export function isAllZeros(bytes: Uint8Array): boolean {
  let acc = 0;
  for (const b of bytes) acc |= b;
  return acc === 0;
}

/**
 * Validate an identifier used as part of storage keys (self id or remote address).
 * Pipe characters and control characters would break the default key layout of
 * key-value-style store adapters, so they are rejected early with a clear error.
 */
export function assertValidIdentifier(value: string, kind: string): void {
  if (typeof value !== 'string' || value.length === 0) {
    throw new InvalidArgumentError(`${kind} must be a non-empty string`);
  }
  if (value.length > 255) {
    throw new InvalidArgumentError(`${kind} must be at most 255 characters`);
  }
  if (/[|\u0000-\u001f\u007f]/.test(value)) {
    throw new InvalidArgumentError(`${kind} must not contain '|' or control characters`);
  }
}
