import { InvalidMessageError } from '../errors';
import { fromBase64 } from '../util/base64';
import { KEY_LENGTH } from '../crypto/crypto-provider';

/** Wire protocol version. Bumped on breaking envelope changes. */
export const PROTOCOL_VERSION = 1;

/** Library identity used in HKDF info strings and docs. */
export const PROTOCOL_NAME = 'signal-protocol-node';

/** Regular Double Ratchet message. */
export interface SignalMessageJSON {
  version: 1;
  type: 'signal';
  /** Sender's current ratchet public key (base64). */
  ratchetKey: string;
  /** Length of the sender's previous sending chain. */
  previousCounter: number;
  /** Position of this message in the sender's current chain. */
  counter: number;
  /** AES-256-GCM ciphertext with the tag appended (base64). */
  ciphertext: string;
}

/**
 * First message of a session: X3DH material wrapped around a regular message,
 * so the responder can build the session and decrypt in one step.
 */
export interface PreKeySignalMessageJSON {
  version: 1;
  type: 'prekey';
  /** Initiator's X25519 identity key (base64). */
  identityKey: string;
  /** Initiator's Ed25519 identity signing key (base64). */
  identitySigningKey: string;
  /** Initiator's ephemeral ("base") key used in X3DH (base64). */
  baseKey: string;
  signedPreKeyId: number;
  oneTimePreKeyId?: number;
  /** The inner, already-encrypted Signal message. */
  message: SignalMessageJSON;
}

/** Anything a transport needs to carry between two clients. */
export type SignalEnvelopeJSON = SignalMessageJSON | PreKeySignalMessageJSON;

function assertInt(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new InvalidMessageError(`${label} must be a non-negative 32-bit integer`);
  }
  return value;
}

function assertBase64Key(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new InvalidMessageError(`${label} must be a base64 string`);
  }
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(value);
  } catch (error) {
    throw new InvalidMessageError(`${label} is not valid base64`, { cause: error });
  }
  if (bytes.length !== KEY_LENGTH) {
    throw new InvalidMessageError(`${label} must decode to ${KEY_LENGTH} bytes`);
  }
  return value;
}

function parseSignalMessage(raw: unknown): SignalMessageJSON {
  if (typeof raw !== 'object' || raw === null) {
    throw new InvalidMessageError('Message must be an object');
  }
  const msg = raw as Record<string, unknown>;
  if (msg.version !== PROTOCOL_VERSION || msg.type !== 'signal') {
    throw new InvalidMessageError('Not a v1 signal message');
  }
  if (typeof msg.ciphertext !== 'string') {
    throw new InvalidMessageError('ciphertext must be a base64 string');
  }
  try {
    fromBase64(msg.ciphertext);
  } catch (error) {
    throw new InvalidMessageError('ciphertext is not valid base64', { cause: error });
  }
  return {
    version: 1,
    type: 'signal',
    ratchetKey: assertBase64Key(msg.ratchetKey, 'ratchetKey'),
    previousCounter: assertInt(msg.previousCounter, 'previousCounter'),
    counter: assertInt(msg.counter, 'counter'),
    ciphertext: msg.ciphertext,
  };
}

/**
 * Runtime validation of an untrusted envelope received over a transport.
 * Returns a fully typed envelope or throws {@link InvalidMessageError}.
 */
export function parseEnvelope(raw: unknown): SignalEnvelopeJSON {
  if (typeof raw !== 'object' || raw === null) {
    throw new InvalidMessageError('Envelope must be an object');
  }
  const env = raw as Record<string, unknown>;
  if (env.version !== PROTOCOL_VERSION) {
    throw new InvalidMessageError(`Unsupported envelope version: ${String(env.version)}`);
  }
  if (env.type === 'signal') {
    return parseSignalMessage(env);
  }
  if (env.type === 'prekey') {
    const message = parseSignalMessage(env.message);
    const envelope: PreKeySignalMessageJSON = {
      version: 1,
      type: 'prekey',
      identityKey: assertBase64Key(env.identityKey, 'identityKey'),
      identitySigningKey: assertBase64Key(env.identitySigningKey, 'identitySigningKey'),
      baseKey: assertBase64Key(env.baseKey, 'baseKey'),
      signedPreKeyId: assertInt(env.signedPreKeyId, 'signedPreKeyId'),
      message,
    };
    if (env.oneTimePreKeyId !== undefined) {
      envelope.oneTimePreKeyId = assertInt(env.oneTimePreKeyId, 'oneTimePreKeyId');
    }
    return envelope;
  }
  throw new InvalidMessageError(`Unknown envelope type: ${String(env.type)}`);
}
