import { KeyPair } from '../crypto/crypto-provider';
import { toBase64 } from '../util/base64';

/** JSON-serializable key pair (base64 fields) — used in persisted store records. */
export interface KeyPairDTO {
  publicKey: string;
  privateKey: string;
}

/**
 * Identity key pair of this client.
 *
 * Deviation from the original Signal spec (documented in docs/SIGNAL_PROTOCOL.md):
 * we use two identity keys instead of XEdDSA —
 * - `dhKeyPair`: X25519, used for Diffie-Hellman (X3DH, ratchets, associated data)
 * - `signingKeyPair`: Ed25519, used to sign the signed prekey
 */
export interface IdentityKeyPairDTO {
  dhKeyPair: KeyPairDTO;
  signingKeyPair: KeyPairDTO;
  /** Random 14-bit identifier, informational only (multi-device bookkeeping). */
  registrationId?: number;
}

/** Persisted signed prekey record (private key stays server/device-side). */
export interface SignedPreKeyRecordDTO {
  id: number;
  keyPair: KeyPairDTO;
  /** Ed25519 signature of the public key, made by the identity signing key. */
  signature: string;
  createdAt: number;
}

/** Persisted one-time prekey record. */
export interface OneTimePreKeyRecordDTO {
  id: number;
  keyPair: KeyPairDTO;
  /**
   * Set when the key was handed out inside a prekey bundle (`consumeOneTime`).
   * Reserved keys are not offered again, but stay in the store until the
   * prekey message that used them is decrypted (they are single use).
   */
  reservedAt?: number;
}

/** Remote party's identity keys (Trust-On-First-Use record). */
export interface RemoteIdentityDTO {
  /** X25519 identity key (used in DH + associated data). */
  dhKey: string;
  /** Ed25519 identity key (signed prekey signatures). */
  signingKey: string;
  firstSeenAt: number;
}

export function keyPairToDTO(pair: KeyPair): KeyPairDTO {
  return { publicKey: toBase64(pair.publicKey), privateKey: toBase64(pair.privateKey) };
}
