import { describe, expect, it } from 'vitest';
import { fromBase64, toBase64 } from '../src/util/base64';
import { InvalidEncodingError } from '../src/errors';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe('base64 codec', () => {
  it('matches RFC 4648 test vectors', () => {
    const cases: Array<[string, string]> = [
      ['', ''],
      ['f', 'Zg=='],
      ['fo', 'Zm8='],
      ['foo', 'Zm9v'],
      ['foob', 'Zm9vYg=='],
      ['fooba', 'Zm9vYmE='],
      ['foobar', 'Zm9vYmFy'],
    ];
    for (const [input, expected] of cases) {
      expect(toBase64(new TextEncoder().encode(input))).toBe(expected);
      expect(new TextDecoder().decode(fromBase64(expected))).toBe(input);
    }
  });

  it('round-trips random bytes of many lengths', () => {
    for (let len = 0; len < 100; len++) {
      const bytes = new Uint8Array(len).map(() => (Math.random() * 256) | 0);
      const decoded = fromBase64(toBase64(bytes));
      expect(Array.from(decoded)).toEqual(Array.from(bytes));
    }
  });

  it('rejects malformed input', () => {
    expect(() => fromBase64('Zm9vYm')).toThrow(InvalidEncodingError); // bad length
    expect(() => fromBase64('Zm9!Yg==')).toThrow(InvalidEncodingError); // bad char
    expect(() => fromBase64('Zg=A=')).toThrow(InvalidEncodingError); // inconsistent padding
  });
});
