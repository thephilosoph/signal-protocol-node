import { KeyPairDTO } from '../keys/types';
import { concatBytes, u32be, utf8ToBytes } from '../util/bytes';
import { InvalidMessageError } from '../errors';
import { fromBase64 } from '../util/base64';
import { KEY_LENGTH } from '../crypto/crypto-provider';

/**
 * Persistence contract for Sender Keys group state (Ports & Adapters).
 *
 * Two kinds of records live here, both shaped as {@link SenderKeyStateDTO}:
 * - **own** sending chains (`signingKeyPair` set, `signingPublicKey` absent) —
 *   what this client uses to encrypt group messages,
 * - **received** chains (`signingPublicKey` set) — what this client uses to
 *   decrypt other members' group messages.
 *
 * Records are JSON-serializable so adapters can persist them opaquely, same
 * contract as `SignalStore`. Ref format: `"<senderAddress>|<distributionId>"`.
 */
export interface SenderKeyStateDTO {
  version: 1;
  groupId: string;
  /** Address of the member whose sending chain this is (own address for own chains). */
  senderAddress: string;
  distributionId: string;
  /** Current chain key (base64); ratchets forward on every message. */
  chainKey: string;
  /** Next message iteration this chain will produce / accept. */
  iteration: number;
  /** OWN chains only: this client's Ed25519 group-signing key pair. */
  signingKeyPair?: KeyPairDTO;
  /** RECEIVED chains only: the sender's Ed25519 group-signing public key. */
  signingPublicKey?: string;
  /** Out-of-order cache: message keys for iterations that arrived early. */
  skipped: { iteration: number; messageKey: string }[];
  createdAt: number;
}

export interface GroupStore {
  saveSenderKey(scope: string, groupId: string, ref: string, state: SenderKeyStateDTO): Promise<void>;
  getSenderKey(scope: string, groupId: string, ref: string): Promise<SenderKeyStateDTO | null>;
  deleteSenderKey(scope: string, groupId: string, ref: string): Promise<void>;
  listSenderKeys(scope: string, groupId: string): Promise<SenderKeyStateDTO[]>;
}

/** Storage ref of one sender-key chain: "<senderAddress>|<distributionId>". */
export function senderKeyRef(senderAddress: string, distributionId: string): string {
  return `${senderAddress}|${distributionId}`;
}

/** Sender Keys AEAD info: binds group, distribution, iteration and signing key. */
export function senderKeyAad(
  groupId: string,
  distributionId: string,
  iteration: number,
  signingPublicKey: Uint8Array,
): Uint8Array {
  return concatBytes(
    utf8ToBytes('signal-protocol-node/sender-key/1'),
    utf8ToBytes(groupId),
    utf8ToBytes(distributionId),
    u32be(iteration),
    signingPublicKey,
  );
}

/** Signature input: header (AAD) + ciphertext, so tampering either fails loudly. */
export function senderKeySignatureInput(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return concatBytes(aad, ciphertext);
}

/** Validate a group id / distribution id pair used inside stored refs. */
export function assertGroupIds(groupId: string, distributionId?: string): void {
  if (typeof groupId !== 'string' || groupId.length === 0 || groupId.length > 255) {
    throw new InvalidMessageError('groupId must be a non-empty string of at most 255 characters');
  }
  if (distributionId !== undefined && (typeof distributionId !== 'string' || distributionId.length === 0 || distributionId.length > 255)) {
    throw new InvalidMessageError('distributionId must be a non-empty string of at most 255 characters');
  }
}

export interface ParsedSenderKeyDistribution {
  groupId: string;
  distributionId: string;
  chainKey: Uint8Array;
  iteration: number;
  signingKey: Uint8Array;
}

function expectB64Key(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new InvalidMessageError(`${label} must be a base64 string`);
  }
  const bytes = fromBase64(value);
  if (bytes.length !== KEY_LENGTH) {
    throw new InvalidMessageError(`${label} must decode to ${KEY_LENGTH} bytes`);
  }
  return bytes;
}

function expectInt(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new InvalidMessageError(`${label} must be a non-negative 32-bit integer`);
  }
  return value;
}

/** Cheap routing check (no throw) — is this decrypted pairwise payload a distribution? */
export function isSenderKeyDistribution(payload: unknown): boolean {
  return (
    typeof payload === 'object' &&
    payload !== null &&
    (payload as Record<string, unknown>).type === 'sender-key-distribution'
  );
}

/** Full validation of a distribution payload received over a pairwise session. */
export function parseSenderKeyDistribution(payload: unknown): ParsedSenderKeyDistribution {
  if (typeof payload !== 'object' || payload === null) {
    throw new InvalidMessageError('Sender key distribution must be an object');
  }
  const raw = payload as Record<string, unknown>;
  if (raw.version !== 1 || raw.type !== 'sender-key-distribution') {
    throw new InvalidMessageError('Not a v1 sender-key distribution');
  }
  const groupId = raw.groupId;
  if (typeof groupId !== 'string' || groupId.length === 0) {
    throw new InvalidMessageError('groupId must be a non-empty string');
  }
  const distributionId = raw.distributionId;
  if (typeof distributionId !== 'string' || distributionId.length === 0) {
    throw new InvalidMessageError('distributionId must be a non-empty string');
  }
  return {
    groupId,
    distributionId,
    chainKey: expectB64Key(raw.chainKey, 'chainKey'),
    iteration: expectInt(raw.iteration, 'iteration'),
    signingKey: expectB64Key(raw.signingKey, 'signingKey'),
  };
}

export interface ParsedSenderKeyGroupMessage {
  groupId: string;
  distributionId: string;
  iteration: number;
  signature: Uint8Array;
  /** nonce(12) || ciphertext || tag(16) */
  ciphertext: Uint8Array;
}

/** Full validation of a sender-key group message received from a transport. */
export function parseSenderKeyGroupMessage(payload: unknown): ParsedSenderKeyGroupMessage {
  if (typeof payload !== 'object' || payload === null) {
    throw new InvalidMessageError('Sender-key group message must be an object');
  }
  const raw = payload as Record<string, unknown>;
  if (raw.version !== 1 || raw.type !== 'group-sk') {
    throw new InvalidMessageError('Not a v1 sender-key group message');
  }
  const groupId = raw.groupId;
  if (typeof groupId !== 'string' || groupId.length === 0) {
    throw new InvalidMessageError('groupId must be a non-empty string');
  }
  const distributionId = raw.distributionId;
  if (typeof distributionId !== 'string' || distributionId.length === 0) {
    throw new InvalidMessageError('distributionId must be a non-empty string');
  }
  if (typeof raw.signature !== 'string' || typeof raw.ciphertext !== 'string') {
    throw new InvalidMessageError('signature and ciphertext must be base64 strings');
  }
  const ciphertext = fromBase64(raw.ciphertext);
  if (ciphertext.length < 12 + 16) {
    throw new InvalidMessageError('Sender-key ciphertext too short');
  }
  return {
    groupId,
    distributionId,
    iteration: expectInt(raw.iteration, 'iteration'),
    signature: fromBase64(raw.signature),
    ciphertext,
  };
}

/** Wire shape of the sender-key distribution (transmitted INSIDE a pairwise envelope). */
export interface SenderKeyDistributionJSON {
  version: 1;
  type: 'sender-key-distribution';
  groupId: string;
  distributionId: string;
  chainKey: string;
  iteration: number;
  signingKey: string;
}

/** Wire shape of an O(1) sender-key group message (transport carries one per message). */
export interface SenderKeyGroupMessageJSON {
  version: 1;
  type: 'group-sk';
  groupId: string;
  distributionId: string;
  iteration: number;
  signature: string;
  ciphertext: string;
}
