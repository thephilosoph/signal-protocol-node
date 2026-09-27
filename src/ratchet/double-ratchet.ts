import { CryptoProvider, KEY_LENGTH } from '../crypto/crypto-provider';
import { InvalidKeyError, SessionNotReadyError, TooManySkippedMessagesError } from '../errors';
import { toBase64, fromBase64 } from '../util/base64';
import { concatBytes, u32be, utf8ToBytes } from '../util/bytes';
import { KeyPair } from '../crypto/crypto-provider';

/**
 * Double Ratchet (per the Signal specification).
 *
 * Each ratchet state holds:
 * - a root key that is re-keyed with every DH ratchet step,
 * - a sending chain and a receiving chain of HMAC-derived message keys,
 * - the current DH ratchet key pair and the peer's current ratchet public key,
 * - skipped message keys for out-of-order delivery.
 *
 * States are stored as JSON-serializable DTOs (base64 fields) so that the
 * storage layer can persist them anywhere without protocol knowledge.
 */

/** HKDF info for the root-key KDF (KDF_RK in the Signal spec). */
export const ROOT_KDF_INFO = 'signal-protocol-node/ratchet-root/1';
/** HKDF info for deriving AES key+nonce from a message key. */
export const MESSAGE_KEY_INFO = 'signal-protocol-node/message-key/1';

/** Default upper bound on message keys skipped within one chain. */
export const MAX_SKIP_DEFAULT = 1000;

export interface SkippedMessageKeyDTO {
  /** Ratchet public key (base64) of the chain this message key belongs to. */
  ratchetKey: string;
  counter: number;
  /** Message key (base64). */
  messageKey: string;
}

export interface RatchetStateDTO {
  rootKey: string;
  dhSelfPublicKey: string;
  dhSelfPrivateKey: string;
  /** Peer's current ratchet public key; null until the first message is received. */
  dhRemotePublicKey: string | null;
  chainKeySending: string | null;
  chainKeyReceiving: string | null;
  sendCount: number;
  recvCount: number;
  prevSendCount: number;
  skippedKeys: SkippedMessageKeyDTO[];
}

/** Message header, sent in the clear with every message. */
export interface RatchetHeader {
  /** Sender's current ratchet public key (base64). */
  ratchetKey: string;
  /** Length of the sender's previous sending chain. */
  previousCounter: number;
  /** Position of this message in the current sending chain. */
  counter: number;
}

export interface RatchetEncryptResult {
  header: RatchetHeader;
  /** Ciphertext with the 16-byte AES-GCM tag appended. */
  ciphertext: Uint8Array;
}

async function kdfRootKey(rootKey: Uint8Array, dhOutput: Uint8Array, crypto: CryptoProvider): Promise<[Uint8Array, Uint8Array]> {
  const okm = await crypto.hkdf(dhOutput, rootKey, utf8ToBytes(ROOT_KDF_INFO), 64);
  return [okm.slice(0, KEY_LENGTH), okm.slice(KEY_LENGTH, 64)];
}

/**
 * Symmetric chain ratchet (KDF_CK in the Signal spec): the message key for the
 * current position and the next chain key. Also used by the Sender Keys group
 * mode, which is a pure symmetric chain.
 */
export async function kdfChainKey(
  chainKey: Uint8Array,
  crypto: CryptoProvider,
): Promise<{ messageKey: Uint8Array; nextChainKey: Uint8Array }> {
  return {
    messageKey: await crypto.hmacSha256(chainKey, new Uint8Array([0x01])),
    nextChainKey: await crypto.hmacSha256(chainKey, new Uint8Array([0x02])),
  };
}

/**
 * Derive the AES-256-GCM key (32 bytes) and nonce (12 bytes) from a message key
 * so that identical message keys never reuse a key/nonce pair across contexts.
 */
export async function messageKeyToKeyNonce(
  messageKey: Uint8Array,
  crypto: CryptoProvider,
): Promise<{ key: Uint8Array; nonce: Uint8Array }> {
  const okm = await crypto.hkdf(messageKey, new Uint8Array(KEY_LENGTH), utf8ToBytes(MESSAGE_KEY_INFO), 44);
  return { key: okm.slice(0, 32), nonce: okm.slice(32, 44) };
}

/**
 * Associated data for the message AEAD. Binds the X3DH identity keys (AD) plus
 * the full header (version byte, ratchet key, counters) to the ciphertext, so
 * headers cannot be tampered with undetected.
 */
function aadFor(associatedData: Uint8Array, header: RatchetHeader): Uint8Array {
  return concatBytes(
    associatedData,
    new Uint8Array([1]), // protocol version byte
    fromBase64(header.ratchetKey),
    u32be(header.previousCounter),
    u32be(header.counter),
  );
}

/**
 * Initialize the ratchet for the X3DH *initiator*. The initiator immediately
 * ratchets once against the responder's signed prekey to open a sending chain.
 */
export async function initRatchetAsInitiator(
  sharedSecret: Uint8Array,
  remoteSignedPreKey: Uint8Array,
  crypto: CryptoProvider,
): Promise<RatchetStateDTO> {
  if (remoteSignedPreKey.length !== KEY_LENGTH) {
    throw new InvalidKeyError('Signed prekey must be 32 bytes');
  }
  const dhSelf = await crypto.generateKeyPair();
  const state: RatchetStateDTO = {
    rootKey: toBase64(sharedSecret),
    dhSelfPublicKey: toBase64(dhSelf.publicKey),
    dhSelfPrivateKey: toBase64(dhSelf.privateKey),
    dhRemotePublicKey: toBase64(remoteSignedPreKey),
    chainKeySending: null,
    chainKeyReceiving: null,
    sendCount: 0,
    recvCount: 0,
    prevSendCount: 0,
    skippedKeys: [],
  };
  const [rootKey, chainKey] = await kdfRootKey(sharedSecret, await crypto.agree(dhSelf.privateKey, remoteSignedPreKey), crypto);
  state.rootKey = toBase64(rootKey);
  state.chainKeySending = toBase64(chainKey);
  return state;
}

/**
 * Initialize the ratchet for the X3DH *responder*. The signed prekey pair
 * becomes the first DH ratchet key; the sending chain opens when the first
 * message arrives and triggers a DH ratchet step.
 */
export function initRatchetAsResponder(
  sharedSecret: Uint8Array,
  signedPreKeyPair: KeyPair,
  crypto: CryptoProvider,
): RatchetStateDTO {
  void crypto;
  return {
    rootKey: toBase64(sharedSecret),
    dhSelfPublicKey: toBase64(signedPreKeyPair.publicKey),
    dhSelfPrivateKey: toBase64(signedPreKeyPair.privateKey),
    dhRemotePublicKey: null,
    chainKeySending: null,
    chainKeyReceiving: null,
    sendCount: 0,
    recvCount: 0,
    prevSendCount: 0,
    skippedKeys: [],
  };
}

/** Encrypt one message with the current sending chain, advancing the chain. */
export async function ratchetEncrypt(
  state: RatchetStateDTO,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
  crypto: CryptoProvider,
): Promise<RatchetEncryptResult> {
  if (!state.chainKeySending) {
    throw new SessionNotReadyError(
      'No sending chain yet: the session owner must receive a message before it can send',
    );
  }
  const { messageKey, nextChainKey } = await kdfChainKey(fromBase64(state.chainKeySending), crypto);
  state.chainKeySending = toBase64(nextChainKey);

  const header: RatchetHeader = {
    ratchetKey: state.dhSelfPublicKey,
    previousCounter: state.prevSendCount,
    counter: state.sendCount,
  };
  state.sendCount += 1;

  const { key, nonce } = await messageKeyToKeyNonce(messageKey, crypto);
  const ciphertext = await crypto.aes256GcmEncrypt(key, nonce, plaintext, aadFor(associatedData, header));
  return { header, ciphertext };
}

/**
 * Decrypt one message, performing DH ratchet steps and skipped-key handling as
 * needed. Operates on the passed state in place — callers must pass a *clone*
 * and commit it only on success, so a failed/tampered message never corrupts
 * the stored session.
 */
export async function ratchetDecrypt(
  state: RatchetStateDTO,
  header: RatchetHeader,
  ciphertext: Uint8Array,
  associatedData: Uint8Array,
  crypto: CryptoProvider,
  maxSkip: number = MAX_SKIP_DEFAULT,
): Promise<Uint8Array> {
  // 1. Message from an old chain we already advanced past?
  const skippedIndex = state.skippedKeys.findIndex(
    (s) => s.ratchetKey === header.ratchetKey && s.counter === header.counter,
  );
  if (skippedIndex >= 0) {
    const messageKey = fromBase64(state.skippedKeys[skippedIndex].messageKey);
    state.skippedKeys.splice(skippedIndex, 1);
    const { key, nonce } = await messageKeyToKeyNonce(messageKey, crypto);
    return crypto.aes256GcmDecrypt(key, nonce, ciphertext, aadFor(associatedData, header));
  }

  // 2. New ratchet key from the peer? Advance the DH ratchet first.
  if (header.ratchetKey !== state.dhRemotePublicKey) {
    await skipMessageKeys(state, header.previousCounter, maxSkip, crypto);
    await dhRatchetStep(state, header.ratchetKey, crypto);
  }

  // 3. Skip ahead within the current receiving chain, storing message keys.
  await skipMessageKeys(state, header.counter, maxSkip, crypto);

  if (!state.chainKeyReceiving) {
    throw new SessionNotReadyError('No receiving chain in this state');
  }
  const { messageKey, nextChainKey } = await kdfChainKey(fromBase64(state.chainKeyReceiving), crypto);
  state.chainKeyReceiving = toBase64(nextChainKey);
  state.recvCount += 1;

  const { key, nonce } = await messageKeyToKeyNonce(messageKey, crypto);
  return crypto.aes256GcmDecrypt(key, nonce, ciphertext, aadFor(associatedData, header));
}

async function skipMessageKeys(
  state: RatchetStateDTO,
  until: number,
  maxSkip: number,
  crypto: CryptoProvider,
): Promise<void> {
  if (!state.chainKeyReceiving) return;
  if (state.recvCount + maxSkip < until) {
    throw new TooManySkippedMessagesError(
      `Message counter ${until} exceeds the allowed skip window of ${maxSkip}`,
    );
  }
  while (state.recvCount < until) {
    const { messageKey, nextChainKey } = await kdfChainKey(fromBase64(state.chainKeyReceiving), crypto);
    state.chainKeyReceiving = toBase64(nextChainKey);
    // Bound memory: drop the oldest skipped key when over capacity.
    if (state.skippedKeys.length >= maxSkip) {
      state.skippedKeys.shift();
    }
    state.skippedKeys.push({
      ratchetKey: state.dhRemotePublicKey as string,
      counter: state.recvCount,
      messageKey: toBase64(messageKey),
    });
    state.recvCount += 1;
  }
}

async function dhRatchetStep(state: RatchetStateDTO, remotePublicKey: string, crypto: CryptoProvider): Promise<void> {
  state.prevSendCount = state.sendCount;
  state.sendCount = 0;
  state.recvCount = 0;
  state.dhRemotePublicKey = remotePublicKey;

  const [rootKey, receivingChain] = await kdfRootKey(
    fromBase64(state.rootKey),
    await crypto.agree(fromBase64(state.dhSelfPrivateKey), fromBase64(remotePublicKey)),
    crypto,
  );
  state.rootKey = toBase64(rootKey);
  state.chainKeyReceiving = toBase64(receivingChain);

  const fresh = await crypto.generateKeyPair();
  state.dhSelfPublicKey = toBase64(fresh.publicKey);
  state.dhSelfPrivateKey = toBase64(fresh.privateKey);

  const [nextRootKey, sendingChain] = await kdfRootKey(rootKey, await crypto.agree(fresh.privateKey, fromBase64(remotePublicKey)), crypto);
  state.rootKey = toBase64(nextRootKey);
  state.chainKeySending = toBase64(sendingChain);
}

/** Deep-clone a ratchet state (pure JSON data) for clone-then-commit decryption. */
export function cloneRatchetState(state: RatchetStateDTO): RatchetStateDTO {
  return {
    ...state,
    skippedKeys: state.skippedKeys.map((k) => ({ ...k })),
  };
}
