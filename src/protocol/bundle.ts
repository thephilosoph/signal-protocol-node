import { CryptoProvider, KEY_LENGTH } from '../crypto/crypto-provider';
import { InvalidPreKeyBundleError, SignatureVerificationError } from '../errors';
import { fromBase64 } from '../util/base64';

/**
 * A prekey bundle is what a peer publishes (via your app's server) so that
 * strangers can start a session with them. It is pure JSON and travels over
 * any channel; its signed prekey is authenticated by the Ed25519 identity key.
 */
export interface PreKeyBundleJSON {
  version: 1;
  /** Device id this bundle belongs to (multi-device support); informational. */
  deviceId?: number;
  identity: {
    /** X25519 identity key used for DH (base64). */
    dhKey: string;
    /** Ed25519 identity key that signed the signed prekey (base64). */
    signingKey: string;
  };
  signedPreKey: {
    id: number;
    publicKey: string;
    signature: string;
  };
  /** Optional single-use prekey; adds forward secrecy for the very first message. */
  oneTimePreKey?: {
    id: number;
    publicKey: string;
  };
}

/** A bundle parsed into raw bytes, with the signature already verified. */
export interface ParsedPreKeyBundle {
  identityDhKey: Uint8Array;
  identitySigningKey: Uint8Array;
  signedPreKeyId: number;
  signedPreKey: Uint8Array;
  oneTimePreKeyId?: number;
  oneTimePreKey?: Uint8Array;
}

function expectKey(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new InvalidPreKeyBundleError(`${label} must be a base64 string`);
  }
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(value);
  } catch (error) {
    throw new InvalidPreKeyBundleError(`${label} is not valid base64`, { cause: error });
  }
  if (bytes.length !== KEY_LENGTH) {
    throw new InvalidPreKeyBundleError(`${label} must decode to ${KEY_LENGTH} bytes`);
  }
  return bytes;
}

function expectInt(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new InvalidPreKeyBundleError(`${label} must be a non-negative integer`);
  }
  return value;
}

/**
 * Validate and authenticate a bundle received from the network:
 * checks the shape and verifies the signed-prekey signature against the
 * bundle's Ed25519 identity key. Throws
 * {@link SignatureVerificationError} / {@link InvalidPreKeyBundleError}.
 */
export async function parsePreKeyBundle(raw: unknown, crypto: CryptoProvider): Promise<ParsedPreKeyBundle> {
  if (typeof raw !== 'object' || raw === null) {
    throw new InvalidPreKeyBundleError('Bundle must be an object');
  }
  const bundle = raw as Record<string, any>;
  if (bundle.version !== 1) {
    throw new InvalidPreKeyBundleError(`Unsupported bundle version: ${String(bundle.version)}`);
  }
  if (typeof bundle.identity !== 'object' || bundle.identity === null) {
    throw new InvalidPreKeyBundleError('Bundle is missing identity');
  }
  if (typeof bundle.signedPreKey !== 'object' || bundle.signedPreKey === null) {
    throw new InvalidPreKeyBundleError('Bundle is missing signedPreKey');
  }

  const identityDhKey = expectKey(bundle.identity.dhKey, 'identity.dhKey');
  const identitySigningKey = expectKey(bundle.identity.signingKey, 'identity.signingKey');
  const signedPreKey = expectKey(bundle.signedPreKey.publicKey, 'signedPreKey.publicKey');
  const signatureRaw = bundle.signedPreKey.signature;
  if (typeof signatureRaw !== 'string') {
    throw new InvalidPreKeyBundleError('signedPreKey.signature must be a base64 string');
  }
  let signature: Uint8Array;
  try {
    signature = fromBase64(signatureRaw);
  } catch (error) {
    throw new InvalidPreKeyBundleError('signedPreKey.signature is not valid base64', { cause: error });
  }

  const signatureValid = await crypto.verify(identitySigningKey, signedPreKey, signature);
  if (!signatureValid) {
    throw new SignatureVerificationError('Signed prekey signature verification failed');
  }

  const parsed: ParsedPreKeyBundle = {
    identityDhKey,
    identitySigningKey,
    signedPreKeyId: expectInt(bundle.signedPreKey.id, 'signedPreKey.id'),
    signedPreKey,
  };

  if (bundle.oneTimePreKey !== undefined && bundle.oneTimePreKey !== null) {
    parsed.oneTimePreKeyId = expectInt(bundle.oneTimePreKey.id, 'oneTimePreKey.id');
    parsed.oneTimePreKey = expectKey(bundle.oneTimePreKey.publicKey, 'oneTimePreKey.publicKey');
  }
  return parsed;
}
