import {
  CryptoProvider,
  KEY_LENGTH,
  NONCE_LENGTH,
  TAG_LENGTH,
  KeyPair,
} from './crypto-provider';
import { DecryptionFailedError, InvalidKeyError } from '../errors';
import { concatBytes, isAllZeros } from '../util/bytes';

/**
 * {@link CryptoProvider} implemented on WebCrypto (`crypto.subtle`) — enables
 * browsers, edge runtimes and any host with a modern WebCrypto implementation
 * including X25519/Ed25519 (RFC 9380 OKP curves).
 *
 * Works in Node.js ≥ 18.4 (`globalThis.crypto`) as a drop-in alternative to
 * {@link NodeCryptoProvider}, and in browsers that expose the OKP algorithms.
 * All methods are async, matching the provider contract.
 *
 * The WebCrypto interface below is a minimal *structural* type so this file
 * compiles without DOM lib types; at runtime it accepts the real
 * `crypto.subtle` object.
 */

interface SubtleLike {
  generateKey(algorithm: { name: string }, extractable: boolean, usages: string[]): Promise<unknown>;
  exportKey(format: 'raw' | 'pkcs8', key: unknown): Promise<ArrayBuffer>;
  importKey(
    format: 'raw' | 'jwk' | 'pkcs8',
    keyData: unknown,
    algorithm: unknown,
    extractable: boolean,
    usages: string[],
  ): Promise<unknown>;
  deriveBits(algorithm: unknown, key: unknown, length: number): Promise<ArrayBuffer>;
  sign(algorithm: unknown, key: unknown, data: Uint8Array): Promise<ArrayBuffer>;
  verify(algorithm: unknown, key: unknown, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
  digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
  encrypt(algorithm: unknown, key: unknown, data: Uint8Array): Promise<ArrayBuffer>;
  decrypt(algorithm: unknown, key: unknown, data: Uint8Array): Promise<ArrayBuffer>;
}

interface CryptoKeyPairLike {
  publicKey: unknown;
  privateKey: unknown;
}

interface JsonWebKeyLike {
  kty: string;
  crv?: string;
  d?: string;
  x?: string;
}

interface RandomSource {
  getRandomValues(array: Uint8Array): Uint8Array;
}

interface CryptoNamespaceLike {
  subtle?: SubtleLike;
  getRandomValues?: RandomSource['getRandomValues'];
}

function getGlobalSubtle(): SubtleLike {
  const host = globalThis as { crypto?: { subtle?: SubtleLike; getRandomValues?: RandomSource['getRandomValues'] } };
  if (!host.crypto?.subtle) {
    throw new Error('WebCryptoProvider requires crypto.subtle (Node ≥ 18.4 or a secure browser context)');
  }
  return host.crypto.subtle;
}

function getGlobalRandom(): RandomSource {
  const host = globalThis as { crypto?: CryptoNamespaceLike };
  if (!host.crypto?.getRandomValues) {
    throw new Error('WebCryptoProvider requires crypto.getRandomValues');
  }
  // Node's webcrypto enforces `this === crypto` on getRandomValues — bind it.
  return { getRandomValues: host.crypto.getRandomValues.bind(host.crypto) };
}

export class WebCryptoProvider implements CryptoProvider {
  private readonly subtle: SubtleLike;
  private readonly random: RandomSource;

  constructor(subtle?: SubtleLike) {
    this.subtle = subtle ?? getGlobalSubtle();
    this.random = getGlobalRandom();
  }

  randomBytes(length: number): Uint8Array {
    return this.random.getRandomValues(new Uint8Array(length));
  }

  async generateKeyPair(): Promise<KeyPair> {
    const pair = (await this.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPairLike;
    return {
      publicKey: new Uint8Array(await this.subtle.exportKey('raw', pair.publicKey)),
      privateKey: await exportOkpPrivateKey(this.subtle, pair.privateKey),
    };
  }

  async generateSigningKeyPair(): Promise<KeyPair> {
    const pair = (await this.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPairLike;
    return {
      publicKey: new Uint8Array(await this.subtle.exportKey('raw', pair.publicKey)),
      privateKey: await exportOkpPrivateKey(this.subtle, pair.privateKey),
    };
  }

  async agree(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
    if (privateKey.length !== KEY_LENGTH || publicKey.length !== KEY_LENGTH) {
      throw new InvalidKeyError('X25519 keys must be 32 bytes');
    }
    const priv = await this.subtle.importKey(
      'pkcs8',
      okpPkcs8('X25519', privateKey),
      { name: 'X25519' },
      false,
      ['deriveBits'],
    );
    const pub = await this.subtle.importKey('raw', publicKey, { name: 'X25519' }, false, []);
    let shared: Uint8Array;
    try {
      // Browsers per spec read `publicKey`; Node's X25519 reads `public`.
      // Pass both — runtimes ignore the member they don't know.
      shared = new Uint8Array(
        await this.subtle.deriveBits({ name: 'X25519', publicKey: pub, public: pub }, priv, 256),
      );
    } catch (error) {
      throw new InvalidKeyError('X25519 agreement failed', { cause: error });
    }
    if (isAllZeros(shared)) {
      throw new InvalidKeyError('X25519 produced an all-zero shared secret (malformed public key)');
    }
    return shared;
  }

  async sign(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    const key = await this.subtle.importKey(
      'pkcs8',
      okpPkcs8('Ed25519', privateKey),
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
    return new Uint8Array(await this.subtle.sign({ name: 'Ed25519' }, key, message));
  }

  async verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    try {
      const key = await this.subtle.importKey(
        'raw',
        publicKey,
        { name: 'Ed25519' },
        false,
        ['verify'],
      );
      return await this.subtle.verify({ name: 'Ed25519' }, key, signature, message);
    } catch {
      return false;
    }
  }

  async hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const hmacKey = await this.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    return new Uint8Array(await this.subtle.sign('HMAC', hmacKey, data));
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await this.subtle.digest('SHA-256', data));
  }

  async hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
    // HKDF with an empty salt uses a hash-length run of zeros (RFC 5869, 2.2);
    // some WebCrypto implementations reject zero-length salts outright.
    const effectiveSalt = salt.length > 0 ? salt : new Uint8Array(32);
    const keyMaterial = await this.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(
      await this.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: effectiveSalt, info },
        keyMaterial,
        length * 8,
      ),
    );
  }

  async aes256GcmEncrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    this.assertAesInput(key, nonce);
    const aesKey = await this.aesKey(key);
    return new Uint8Array(
      await this.subtle.encrypt(this.gcmParams(nonce, aad), aesKey, plaintext),
    );
  }

  async aes256GcmDecrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertextWithTag: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    this.assertAesInput(key, nonce);
    if (ciphertextWithTag.length < TAG_LENGTH) {
      throw new DecryptionFailedError('Ciphertext is shorter than the authentication tag');
    }
    const aesKey = await this.aesKey(key);
    try {
      return new Uint8Array(
        await this.subtle.decrypt(this.gcmParams(nonce, aad), aesKey, ciphertextWithTag),
      );
    } catch {
      throw new DecryptionFailedError('AES-256-GCM authentication failed (wrong key or tampered data)');
    }
  }

  private async aesKey(key: Uint8Array): Promise<unknown> {
    return this.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  private gcmParams(nonce: Uint8Array, aad?: Uint8Array): Record<string, unknown> {
    return {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad && aad.length > 0 ? aad : undefined,
      tagLength: 128,
    };
  }

  private assertAesInput(key: Uint8Array, nonce: Uint8Array): void {
    if (key.length !== KEY_LENGTH) throw new InvalidKeyError('AES-256-GCM key must be 32 bytes');
    if (nonce.length !== NONCE_LENGTH) throw new InvalidKeyError('AES-256-GCM nonce must be 12 bytes');
  }
}

/** Ed25519/X25519 private keys export as PKCS#8; the raw 32-byte seed is the tail. */
async function exportOkpPrivateKey(subtle: SubtleLike, privateKey: unknown): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', privateKey));
  return pkcs8.slice(pkcs8.length - KEY_LENGTH);
}

/**
 * Rebuild a PKCS#8 private key from the raw 32-byte seed using the fixed DER
 * prefix for the curve. This avoids JWK import quirks across runtimes.
 * Prefix = SEQUENCE { version 0, AlgorithmIdentifier 1.3.101.<110|112>, OCTET STRING(32) }.
 */
const PKCS8_PREFIX: Record<'X25519' | 'Ed25519', Uint8Array> = {
  // 1.3.101.110 (X25519) → 2b 65 6e
  X25519: Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]),
  // 1.3.101.112 (Ed25519) → 2b 65 70
  Ed25519: Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]),
};

function okpPkcs8(crv: 'X25519' | 'Ed25519', privateKey: Uint8Array): Uint8Array {
  const prefix = PKCS8_PREFIX[crv];
  return concatBytes(prefix, privateKey);
}
