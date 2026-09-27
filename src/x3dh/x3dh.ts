import { CryptoProvider, KeyPair } from '../crypto/crypto-provider';
import { InvalidKeyError, SignatureVerificationError } from '../errors';
import { constantTimeEqual, isAllZeros, concatBytes, utf8ToBytes } from '../util/bytes';
import { KEY_LENGTH } from '../crypto/crypto-provider';

/**
 * X3DH (Extended Triple Diffie-Hellman) — the initial key agreement that
 * establishes a shared secret between two parties who have never communicated.
 *
 * See docs/SIGNAL_PROTOCOL.md for the full walkthrough and docs/ARCHITECTURE.md
 * for where this fits in the layer stack.
 */

/** HKDF `info` used for the X3DH shared secret. */
export const DEFAULT_X3DH_INFO = 'signal-protocol-node/x3dh/1';

function assertKeyBytes(value: Uint8Array, label: string): void {
  if (value.length !== KEY_LENGTH) {
    throw new InvalidKeyError(`${label} must be ${KEY_LENGTH} bytes`);
  }
}

function assertDhOutput(value: Uint8Array, label: string): Uint8Array {
  if (isAllZeros(value)) {
    throw new InvalidKeyError(`X3DH ${label} produced an all-zero output (malformed peer key)`);
  }
  return value;
}

/** The prekey material a responder publishes for initiators. */
export interface X3dhBundleMaterial {
  identityDhKey: Uint8Array;
  identitySigningKey: Uint8Array;
  signedPreKey: Uint8Array;
  signedPreKeySignature: Uint8Array;
  oneTimePreKey?: Uint8Array | null;
}

export interface X3dhInitiationResult {
  /** 32-byte shared secret (the Double Ratchet root key). */
  sharedSecret: Uint8Array;
  /** The ephemeral key pair; its public key travels as the "base key". */
  ephemeralKeyPair: KeyPair;
  /** Associated data bound into every message AEAD: initiator ‖ responder identity DH keys. */
  associatedData: Uint8Array;
}

export interface X3dhReceiptResult {
  sharedSecret: Uint8Array;
  associatedData: Uint8Array;
}

/**
 * Initiator side (Alice): verify the bundle, run DH1..DH4 and derive the shared
 * secret. Throws {@link SignatureVerificationError} if the signed prekey was not
 * signed by the bundle's identity signing key.
 */
export async function initiateX3dh(params: {
  ourIdentityDhKeyPair: KeyPair;
  theirBundle: X3dhBundleMaterial;
  crypto: CryptoProvider;
  info?: string;
}): Promise<X3dhInitiationResult> {
  const { ourIdentityDhKeyPair, theirBundle, crypto } = params;
  const info = params.info ?? DEFAULT_X3DH_INFO;

  assertKeyBytes(theirBundle.identityDhKey, 'identity DH key');
  assertKeyBytes(theirBundle.identitySigningKey, 'identity signing key');
  assertKeyBytes(theirBundle.signedPreKey, 'signed prekey');
  assertKeyBytes(ourIdentityDhKeyPair.privateKey, 'our identity private key');

  const signatureValid = await crypto.verify(
    theirBundle.identitySigningKey,
    theirBundle.signedPreKey,
    theirBundle.signedPreKeySignature,
  );
  if (!signatureValid) {
    throw new SignatureVerificationError('Signed prekey signature verification failed');
  }

  const ephemeralKeyPair = await crypto.generateKeyPair();
  const dh1 = assertDhOutput(
    await crypto.agree(ourIdentityDhKeyPair.privateKey, theirBundle.signedPreKey),
    'DH1',
  );
  const dh2 = assertDhOutput(
    await crypto.agree(ephemeralKeyPair.privateKey, theirBundle.identityDhKey),
    'DH2',
  );
  const dh3 = assertDhOutput(
    await crypto.agree(ephemeralKeyPair.privateKey, theirBundle.signedPreKey),
    'DH3',
  );
  const dhParts = [dh1, dh2, dh3];
  if (theirBundle.oneTimePreKey) {
    assertKeyBytes(theirBundle.oneTimePreKey, 'one-time prekey');
    dhParts.push(assertDhOutput(await crypto.agree(ephemeralKeyPair.privateKey, theirBundle.oneTimePreKey), 'DH4'));
  }

  // SK = HKDF(DH1 || DH2 || DH3 [|| DH4], salt = zeros(hashLen), info)
  const sharedSecret = await crypto.hkdf(
    concatBytes(...dhParts),
    new Uint8Array(KEY_LENGTH),
    utf8ToBytes(info),
    KEY_LENGTH,
  );

  return {
    sharedSecret,
    ephemeralKeyPair,
    associatedData: concatBytes(ourIdentityDhKeyPair.publicKey, theirBundle.identityDhKey),
  };
}

/**
 * Responder side (Bob): recompute the same shared secret from the fields of the
 * received prekey message. `ourOneTimePreKeyPair` must be provided exactly when
 * the initiator used one (i.e. the message carried a one-time prekey id).
 */
export async function receiveX3dh(params: {
  ourIdentityDhKeyPair: KeyPair;
  ourSignedPreKeyPair: KeyPair;
  ourOneTimePreKeyPair?: KeyPair | null;
  theirIdentityDhKey: Uint8Array;
  theirEphemeralKey: Uint8Array;
  crypto: CryptoProvider;
  info?: string;
}): Promise<X3dhReceiptResult> {
  const { ourIdentityDhKeyPair, ourSignedPreKeyPair, theirIdentityDhKey, theirEphemeralKey, crypto } = params;
  const info = params.info ?? DEFAULT_X3DH_INFO;

  assertKeyBytes(theirIdentityDhKey, 'their identity DH key');
  assertKeyBytes(theirEphemeralKey, 'their ephemeral key');

  // Same order as the initiator: DH1 uses identities+signed prekey,
  // DH2..DH4 use the initiator's ephemeral key.
  const dh1 = assertDhOutput(
    await crypto.agree(ourSignedPreKeyPair.privateKey, theirIdentityDhKey),
    'DH1',
  );
  const dh2 = assertDhOutput(
    await crypto.agree(ourIdentityDhKeyPair.privateKey, theirEphemeralKey),
    'DH2',
  );
  const dh3 = assertDhOutput(
    await crypto.agree(ourSignedPreKeyPair.privateKey, theirEphemeralKey),
    'DH3',
  );
  const dhParts = [dh1, dh2, dh3];
  if (params.ourOneTimePreKeyPair) {
    dhParts.push(assertDhOutput(await crypto.agree(params.ourOneTimePreKeyPair.privateKey, theirEphemeralKey), 'DH4'));
  }

  const sharedSecret = await crypto.hkdf(
    concatBytes(...dhParts),
    new Uint8Array(KEY_LENGTH),
    utf8ToBytes(info),
    KEY_LENGTH,
  );

  return {
    sharedSecret,
    // Same byte order on both sides: initiator identity first.
    associatedData: concatBytes(theirIdentityDhKey, ourIdentityDhKeyPair.publicKey),
  };
}

/** Compare two identity keys for equality (constant time). */
export function identityKeysEqual(a: Uint8Array, b: Uint8Array): boolean {
  return constantTimeEqual(a, b);
}
