import { CryptoProvider, KEY_LENGTH, NONCE_LENGTH } from '../crypto/crypto-provider';
import { toBase64, fromBase64 } from '../util/base64';
import { concatBytes } from '../util/bytes';

/**
 * Encrypted attachment helpers for the "big payload out-of-band, key in-band"
 * pattern: encrypt a file once, upload the ciphertext anywhere (S3, CDN, your
 * storage), and send the small key through the Double Ratchet-protected
 * message channel.
 *
 * One-shot AES-256-GCM: suitable for payloads up to tens of megabytes.
 * For very large media, chunk and encrypt per chunk with the same pattern.
 */

export interface EncryptedAttachment {
  /**
   * The 32-byte content key, base64. Send this ONLY through the encrypted
   * message channel (e.g. `client.encrypt(address, fromBase64(att.key))`).
   */
  key: string;
  /**
   * Nonce (12 bytes) prefixed to the ciphertext — one byte blob to store.
   * Layout: nonce(12) || ciphertext || tag(16).
   */
  ciphertext: Uint8Array;
}

/** Encrypt bytes with a fresh random key; returns key + ciphertext (nonce-prefixed). */
export async function encryptAttachment(
  plaintext: Uint8Array,
  crypto: CryptoProvider,
  aad?: Uint8Array,
): Promise<EncryptedAttachment> {
  const key = crypto.randomBytes(KEY_LENGTH);
  const nonce = crypto.randomBytes(NONCE_LENGTH);
  const body = await crypto.aes256GcmEncrypt(key, nonce, plaintext, aad);
  return { key: toBase64(key), ciphertext: concatBytes(nonce, body) };
}

/** Decrypt an attachment produced by {@link encryptAttachment}. */
export async function decryptAttachment(
  key: string,
  ciphertext: Uint8Array,
  crypto: CryptoProvider,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if (ciphertext.length < NONCE_LENGTH) {
    throw new Error('Attachment ciphertext is too short');
  }
  const nonce = ciphertext.slice(0, NONCE_LENGTH);
  const body = ciphertext.slice(NONCE_LENGTH);
  return crypto.aes256GcmDecrypt(fromBase64(key), nonce, body, aad);
}
