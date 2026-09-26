import { InvalidEncodingError } from '../errors';

const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const LOOKUP: Record<string, number> = Object.create(null);
for (let i = 0; i < CHARS.length; i++) {
  LOOKUP[CHARS[i]] = i;
}

/** Encode bytes as standard base64 (with padding). No Buffer dependency, works everywhere. */
export function toBase64(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += CHARS[(n >>> 18) & 63] + CHARS[(n >>> 12) & 63] + CHARS[(n >>> 6) & 63] + CHARS[n & 63];
  }
  const remaining = bytes.length - i;
  if (remaining === 1) {
    const n = bytes[i] << 16;
    out += CHARS[(n >>> 18) & 63] + CHARS[(n >>> 12) & 63] + '==';
  } else if (remaining === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += CHARS[(n >>> 18) & 63] + CHARS[(n >>> 12) & 63] + CHARS[(n >>> 6) & 63] + '=';
  }
  return out;
}

/** Decode standard base64 into bytes. Throws {@link InvalidEncodingError} on malformed input. */
export function fromBase64(value: string): Uint8Array {
  const clean = value.replace(/\s/g, '');
  if (clean.length % 4 !== 0) {
    throw new InvalidEncodingError('Base64 string length must be a multiple of 4');
  }
  let padding = 0;
  if (clean.endsWith('==')) padding = 2;
  else if (clean.endsWith('=')) padding = 1;

  const out = new Uint8Array(Math.floor(clean.length / 4) * 3 - padding);
  let outIndex = 0;
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    if (ch === '=') break;
    const v = LOOKUP[ch];
    if (v === undefined) {
      throw new InvalidEncodingError(`Invalid base64 character: ${JSON.stringify(ch)}`);
    }
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outIndex++] = (buffer >>> bits) & 0xff;
    }
  }
  if (outIndex !== out.length) {
    throw new InvalidEncodingError('Base64 string has inconsistent padding');
  }
  return out;
}
