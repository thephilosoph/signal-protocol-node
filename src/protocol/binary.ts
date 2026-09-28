import { InvalidMessageError } from '../errors';
import { toBase64, fromBase64 } from '../util/base64';
import { concatBytes, u32be } from '../util/bytes';
import { KEY_LENGTH } from '../crypto/crypto-provider';
import { PreKeySignalMessageJSON, SignalEnvelopeJSON, SignalMessageJSON } from './messages';

/**
 * Compact binary encoding for pairwise envelopes (Phase 16).
 *
 * JSON envelopes remain the default — they are debuggable and easy to route —
 * but when bandwidth matters, encode the envelope your transport carries:
 *
 * ```ts
 * socket.send(encodeSignalEnvelope(await alice.encrypt('bob.1', text)));
 * // receiver side (both of these work):
 * const pt = await bob.decrypt('alice.1', decodeSignalEnvelope(bytes));
 * const pt2 = await bob.decrypt('alice.1', bytes); // Uint8Array auto-detected
 * ```
 *
 * Format v1 (all integers big-endian):
 * ```
 * byte 0 : format version (1)
 * byte 1 : type (0x01 = signal, 0x02 = prekey)
 * signal : ratchetKey(32) previousCounter(4) counter(4) ctLen(2) ciphertext
 * prekey : identityKey(32) identitySigningKey(32) baseKey(32) signedPreKeyId(4)
 *          hasOneTime(1) [oneTimePreKeyId(4)] <signal body>
 * ```
 * Only pairwise messages are covered; group envelopes stay JSON for now
 * (see PROGRESS.md Phase 16 follow-ups).
 */

export const BINARY_ENVELOPE_VERSION = 1;

const TYPE_SIGNAL = 0x01;
const TYPE_PREKEY = 0x02;

export function encodeSignalEnvelope(envelope: SignalEnvelopeJSON): Uint8Array {
  if (envelope.type === 'signal') {
    return encodeSignalBody(envelope);
  }
  const parts: Uint8Array[] = [
    new Uint8Array([BINARY_ENVELOPE_VERSION, TYPE_PREKEY]),
    fromBase64(envelope.identityKey),
    fromBase64(envelope.identitySigningKey),
    fromBase64(envelope.baseKey),
    u32be(envelope.signedPreKeyId),
  ];
  if (envelope.oneTimePreKeyId === undefined) {
    parts.push(new Uint8Array([0]));
  } else {
    parts.push(new Uint8Array([1]), u32be(envelope.oneTimePreKeyId));
  }
  return concatBytes(...parts, encodeSignalBody(envelope.message));
}

export function decodeSignalEnvelope(bytes: Uint8Array): SignalEnvelopeJSON {
  let offset = 0;
  const read = (n: number): Uint8Array => {
    if (offset + n > bytes.length) {
      throw new InvalidMessageError('Binary envelope truncated');
    }
    const out = bytes.slice(offset, offset + n);
    offset += n;
    return out;
  };

  const version = read(1)[0];
  const type = read(1)[0];
  if (version !== BINARY_ENVELOPE_VERSION) {
    throw new InvalidMessageError(`Unsupported binary envelope version: ${version}`);
  }
  if (type === TYPE_SIGNAL) {
    return decodeSignalBody(read);
  }
  if (type === TYPE_PREKEY) {
    const identityKey = read(KEY_LENGTH);
    const identitySigningKey = read(KEY_LENGTH);
    const baseKey = read(KEY_LENGTH);
    const signedPreKeyId = u32From(read(4));
    const hasOneTime = read(1)[0];
    let oneTimePreKeyId: number | undefined;
    if (hasOneTime === 1) {
      oneTimePreKeyId = u32From(read(4));
    } else if (hasOneTime !== 0) {
      throw new InvalidMessageError('Malformed one-time prekey flag');
    }
    // The nested signal body was encoded with its own version+type bytes.
    read(2);
    const message = decodeSignalBody(read);
    return {
      version: 1,
      type: 'prekey',
      identityKey: toBase64(identityKey),
      identitySigningKey: toBase64(identitySigningKey),
      baseKey: toBase64(baseKey),
      signedPreKeyId,
      ...(oneTimePreKeyId !== undefined ? { oneTimePreKeyId } : {}),
      message,
    };
  }
  throw new InvalidMessageError(`Unknown binary envelope type: ${type}`);
}

function decodeSignalBody(read: (n: number) => Uint8Array): SignalMessageJSON {
  const ratchetKey = read(KEY_LENGTH);
  const previousCounter = u32From(read(4));
  const counter = u32From(read(4));
  const lenBytes = read(2);
  const ctLen = new DataView(lenBytes.buffer, lenBytes.byteOffset).getUint16(0, false);
  const ciphertext = read(ctLen);
  return {
    version: 1,
    type: 'signal',
    ratchetKey: toBase64(ratchetKey),
    previousCounter,
    counter,
    ciphertext: toBase64(ciphertext),
  };
}

function encodeSignalBody(message: SignalMessageJSON): Uint8Array {
  const ciphertext = fromBase64(message.ciphertext);
  if (ciphertext.length > 0xffff) {
    throw new InvalidMessageError('Ciphertext too large for binary encoding (max 65535 bytes)');
  }
  const len = new Uint8Array(2);
  new DataView(len.buffer).setUint16(0, ciphertext.length, false);
  return concatBytes(
    new Uint8Array([BINARY_ENVELOPE_VERSION, TYPE_SIGNAL]),
    fromBase64(message.ratchetKey),
    u32be(message.previousCounter),
    u32be(message.counter),
    len,
    ciphertext,
  );
}

function u32From(bytes: Uint8Array): number {
  return new DataView(bytes.buffer, bytes.byteOffset).getUint32(0, false);
}
