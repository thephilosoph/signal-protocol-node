/**
 * The crypto abstraction (Strategy pattern). The whole protocol is written
 * against this interface; the default {@link NodeCryptoProvider} uses
 * @noble/curves for X25519/Ed25519 and node:crypto for AES-256-GCM, and a
 * `WebCryptoProvider` (same interface) enables browsers / edge runtimes.
 *
 * All operations are asynchronous so that any async backend (WebCrypto,
 * remote signing services, HSMs) can implement the interface. The public
 * protocol API was always async, so this costs callers nothing.
 *
 * Swap implementations by passing `crypto` to `SignalClient.create()` /
 * the NestJS module options.
 */

/** A Diffie-Hellman (X25519) or signing (Ed25519) key pair, 32-byte raw keys. */
export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Length of an X25519 private/public key, an Ed25519 key, and all chain keys. */
export const KEY_LENGTH = 32;
/** AES-GCM nonce length. */
export const NONCE_LENGTH = 12;
/** AES-GCM authentication tag length. */
export const TAG_LENGTH = 16;

export interface CryptoProvider {
  /** Cryptographically secure random bytes. */
  randomBytes(length: number): Uint8Array;

  /** Generate an X25519 key pair. */
  generateKeyPair(): Promise<KeyPair>;

  /** Generate an Ed25519 key pair. */
  generateSigningKeyPair(): Promise<KeyPair>;

  /**
   * X25519 Diffie-Hellman. Throws {@link InvalidKeyError} on invalid input or
   * an all-zero shared secret (small-subgroup / malformed public key).
   */
  agree(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array>;

  /** Ed25519 signature (64 bytes). */
  sign(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array>;

  /** Ed25519 verification. Returns false instead of throwing on bad input. */
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>;

  /** HMAC-SHA256. */
  hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>;

  /** Plain SHA-256 digest (used for fingerprints / safety numbers). */
  sha256(data: Uint8Array): Promise<Uint8Array>;

  /** HKDF-SHA256 (RFC 5869): extract + expand. */
  hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;

  /**
   * AES-256-GCM encrypt. Returns ciphertext with the 16-byte tag appended.
   */
  aes256GcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>;

  /**
   * AES-256-GCM decrypt (ciphertext with tag appended).
   * Throws {@link DecryptionFailedError} when authentication fails.
   */
  aes256GcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertextWithTag: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>;
}
