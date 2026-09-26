import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../src/crypto/node-crypto-provider';
import { DecryptionFailedError, InvalidKeyError } from '../src/errors';
import { concatBytes } from '../src/util/bytes';
import type { CryptoProvider } from '../src/crypto/crypto-provider';

const providers: Array<[string, CryptoProvider]> = [
  ['node', new NodeCryptoProvider()],
];

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe.each(providers)('X25519 via %s provider', (name, crypto) => {
  it('derives the RFC 7748 §6.1 shared secret', async () => {
    const alicePrivate = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const alicePublic = hexToBytes('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    const bobPrivate = hexToBytes('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    const bobPublic = hexToBytes('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    const shared = hexToBytes('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');

    expect((await crypto.generateKeyPair()).publicKey.length).toBe(32);
    expect(Array.from(await crypto.agree(alicePrivate, bobPublic))).toEqual(Array.from(shared));
    expect(Array.from(await crypto.agree(bobPrivate, alicePublic))).toEqual(Array.from(shared));
  });

  it('rejects malformed keys and low-order points', async () => {
    await expect(crypto.agree(new Uint8Array(31), new Uint8Array(32))).rejects.toThrow(InvalidKeyError);
    const lowOrder = new Uint8Array(32);
    const pair = await crypto.generateKeyPair();
    await expect(crypto.agree(pair.privateKey, lowOrder)).rejects.toThrow(InvalidKeyError);
    void name;
  });
});

describe.each(providers)('Ed25519 via %s provider', (name, crypto) => {
  it('verifies the RFC 8032 §7.1 TEST 1 signature', async () => {
    const privateKey = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    const publicKey = hexToBytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    const message = new Uint8Array(0);
    const signature = hexToBytes(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    );

    expect(await crypto.verify(publicKey, message, signature)).toBe(true);
    expect((await crypto.sign(privateKey, message)).length).toBe(64);

    const tampered = signature.slice();
    tampered[0] ^= 0x01;
    expect(await crypto.verify(publicKey, message, tampered)).toBe(false);
    void name;
  });
});

describe.each(providers)('HKDF/HMAC/AES-GCM via %s provider', (name, crypto) => {
  it('matches RFC 5869 Test Case 1', async () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const salt = hexToBytes('000102030405060708090a0b0c');
    const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
    const okm = hexToBytes(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );

    const result = await crypto.hkdf(ikm, salt, info, 42);
    expect(Array.from(result)).toEqual(Array.from(okm));
  });

  it('treats an empty salt as zeros of hash length', async () => {
    const ikm = new Uint8Array(22).fill(0x0b);
    const withZeros = await crypto.hkdf(ikm, new Uint8Array(32), new Uint8Array(0), 32);
    const withEmpty = await crypto.hkdf(ikm, new Uint8Array(0), new Uint8Array(0), 32);
    expect(Array.from(withZeros)).toEqual(Array.from(withEmpty));
  });

  it('matches RFC 4231 HMAC Test Case 1', async () => {
    const key = new Uint8Array(20).fill(0x0b);
    const data = new TextEncoder().encode('Hi There');
    const expected = hexToBytes('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
    expect(Array.from(await crypto.hmacSha256(key, data))).toEqual(Array.from(expected));
  });

  it('round-trips AES-256-GCM and binds AAD', async () => {
    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const plaintext = crypto.randomBytes(137);
    const aad = crypto.randomBytes(32);

    const ciphertext = await crypto.aes256GcmEncrypt(key, nonce, plaintext, aad);
    expect(Array.from(await crypto.aes256GcmDecrypt(key, nonce, ciphertext, aad))).toEqual(
      Array.from(plaintext),
    );
    await expect(crypto.aes256GcmDecrypt(key, nonce, ciphertext, crypto.randomBytes(32))).rejects.toThrow(
      DecryptionFailedError,
    );
  });

  it('rejects tampered AES-GCM ciphertext and bad key sizes', async () => {
    const key = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const ciphertext = await crypto.aes256GcmEncrypt(key, nonce, new TextEncoder().encode('attack at dawn'));
    ciphertext[3] ^= 0xff;
    await expect(crypto.aes256GcmDecrypt(key, nonce, ciphertext)).rejects.toThrow(DecryptionFailedError);
    await expect(crypto.aes256GcmEncrypt(new Uint8Array(16), nonce, new Uint8Array(1))).rejects.toThrow(InvalidKeyError);
    await expect(crypto.aes256GcmEncrypt(key, crypto.randomBytes(8), new Uint8Array(1))).rejects.toThrow(InvalidKeyError);
    void name;
  });
});


describe('random bytes and helpers', () => {
  it('returns the requested length and does not repeat', async () => {
    const crypto = new NodeCryptoProvider();
    const a = crypto.randomBytes(32);
    const b = crypto.randomBytes(32);
    expect(a.length).toBe(32);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it('concatenates bytes', () => {
    const out = concatBytes(new Uint8Array([1, 2]), new Uint8Array([]), new Uint8Array([3]));
    expect(Array.from(out)).toEqual([1, 2, 3]);
  });
});
