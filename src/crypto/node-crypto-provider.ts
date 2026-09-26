import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { DecryptionFailedError, InvalidKeyError } from '../errors';
import { concatBytes, isAllZeros } from '../util/bytes';
import { CryptoProvider, KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH, KeyPair } from './crypto-provider';

const HASH_LENGTH = 32;

function toUint8Array(value: Uint8Array): Uint8Array {
  return value instanceof Uint8Array && value.constructor === Uint8Array ? value : new Uint8Array(value);
}

/**
 * Default {@link CryptoProvider} for Node.js.
 *
 * - X25519 / Ed25519: @noble/curves (audited, pure JS, raw 32-byte keys).
 * - HKDF / HMAC-SHA256: implemented on node:crypto HMAC (RFC 5869 vectors tested).
 * - AES-256-GCM: node:crypto (hardware accelerated).
 *
 * Methods are async to satisfy the (async) {@link CryptoProvider} contract; the
 * underlying node:crypto calls are synchronous, so this wrapper adds no
 * meaningful overhead.
 */
export class NodeCryptoProvider implements CryptoProvider {
  randomBytes(length: number): Uint8Array {
    return new Uint8Array(randomBytes(length));
  }

  async generateKeyPair(): Promise<KeyPair> {
    const privateKey = x25519.utils.randomPrivateKey();
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey: toUint8Array(privateKey), publicKey: toUint8Array(publicKey) };
  }

  async generateSigningKeyPair(): Promise<KeyPair> {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    return { privateKey: toUint8Array(privateKey), publicKey: toUint8Array(publicKey) };
  }

  async agree(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
    if (privateKey.length !== KEY_LENGTH || publicKey.length !== KEY_LENGTH) {
      throw new InvalidKeyError('X25519 keys must be 32 bytes');
    }
    let shared: Uint8Array;
    try {
      shared = toUint8Array(x25519.getSharedSecret(privateKey, publicKey));
    } catch (error) {
      throw new InvalidKeyError('X25519 agreement failed', { cause: error });
    }
    if (isAllZeros(shared)) {
      throw new InvalidKeyError('X25519 produced an all-zero shared secret (malformed public key)');
    }
    return shared;
  }

  async sign(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    return toUint8Array(ed25519.sign(message, privateKey));
  }

  async verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    try {
      return ed25519.verify(signature, message, publicKey);
    } catch {
      return false;
    }
  }

  async hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(createHmac('sha256', key).update(data).digest());
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(createHash('sha256').update(data).digest());
  }

  async hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
    // HKDF with an empty salt uses a hash-length run of zeros (RFC 5869, 2.2).
    const effectiveSalt = salt.length > 0 ? salt : new Uint8Array(HASH_LENGTH);
    const prk = await this.hmacSha256(effectiveSalt, ikm);
    const blocks = Math.ceil(length / HASH_LENGTH);
    const okm = new Uint8Array(blocks * HASH_LENGTH);
    let previous: Uint8Array = new Uint8Array(0);
    for (let block = 1; block <= blocks; block++) {
      previous = await this.hmacSha256(prk, concatBytes(previous, info, new Uint8Array([block])));
      okm.set(previous, (block - 1) * HASH_LENGTH);
    }
    return okm.slice(0, length);
  }

  async aes256GcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    if (key.length !== KEY_LENGTH) throw new InvalidKeyError('AES-256-GCM key must be 32 bytes');
    if (nonce.length !== NONCE_LENGTH) throw new InvalidKeyError('AES-256-GCM nonce must be 12 bytes');
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    if (aad && aad.length > 0) cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return concatBytes(new Uint8Array(ciphertext), new Uint8Array(tag));
  }

  async aes256GcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertextWithTag: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    if (key.length !== KEY_LENGTH) throw new InvalidKeyError('AES-256-GCM key must be 32 bytes');
    if (nonce.length !== NONCE_LENGTH) throw new InvalidKeyError('AES-256-GCM nonce must be 12 bytes');
    if (ciphertextWithTag.length < TAG_LENGTH) {
      throw new DecryptionFailedError('Ciphertext is shorter than the authentication tag');
    }
    const ciphertext = ciphertextWithTag.slice(0, ciphertextWithTag.length - TAG_LENGTH);
    const tag = ciphertextWithTag.slice(ciphertextWithTag.length - TAG_LENGTH);
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, nonce);
      if (aad && aad.length > 0) decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
    } catch {
      throw new DecryptionFailedError('AES-256-GCM authentication failed (wrong key or tampered data)');
    }
  }
}
