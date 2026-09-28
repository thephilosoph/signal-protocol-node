/**
 * signal-protocol-node — Signal Protocol (X3DH + Double Ratchet) for Node.js.
 *
 * Start with `SignalClient` for the high-level API. The NestJS integration
 * lives in the separate entry point `signal-protocol-node/nest`.
 */

// High-level API (Facade)
export { SignalClient } from './protocol/signal-client';
export type { SignalClientOptions, SignalClientConfig } from './protocol/signal-client';

// Group messaging (fan-out + Sender Keys)
export { SignalGroup } from './group/signal-group';
export type { GroupEnvelopeJSON, GroupMode, SignalGroupOptions } from './group/signal-group';
export { InMemoryGroupStore } from './group/in-memory-group-store';
export { senderKeyRef, isSenderKeyDistribution } from './group/sender-keys';
export type {
  GroupStore,
  SenderKeyStateDTO,
  SenderKeyDistributionJSON,
  SenderKeyGroupMessageJSON,
} from './group/sender-keys';

// Identity verification (safety numbers)
export {
  computeSafetyNumber,
  computePairSafetyNumber,
  computeSafetyNumberFromBase64,
  computeFingerprint,
  formatSafetyNumber,
} from './protocol/safety-number';

// Multi-device helpers
export { addressOf, parseAddress, partitionAddressesByUser } from './protocol/multi-device';

// Binary envelope serialization (alternative to JSON on the wire)
export { encodeSignalEnvelope, decodeSignalEnvelope, BINARY_ENVELOPE_VERSION } from './protocol/binary';

// Encrypted attachments (key in-band, ciphertext out-of-band)
export { encryptAttachment, decryptAttachment } from './protocol/attachments';
export type { EncryptedAttachment } from './protocol/attachments';

// Prekey bundles
export { parsePreKeyBundle } from './protocol/bundle';
export type { PreKeyBundleJSON, ParsedPreKeyBundle } from './protocol/bundle';

// Message envelopes (what your transport carries)
export { parseEnvelope, PROTOCOL_VERSION, PROTOCOL_NAME } from './protocol/messages';
export type {
  SignalEnvelopeJSON,
  SignalMessageJSON,
  PreKeySignalMessageJSON,
} from './protocol/messages';

// Storage contract + default implementation (Ports & Adapters)
export { InMemorySignalStore } from './stores/in-memory-store';
export type {
  SignalStore,
  IdentityStorePort,
  PreKeyStorePort,
  SessionStorePort,
} from './stores/signal-store';

// Crypto abstraction (Strategy)
export { NodeCryptoProvider } from './crypto/node-crypto-provider';
export { WebCryptoProvider } from './crypto/web-crypto-provider';
export type { CryptoProvider, KeyPair } from './crypto/crypto-provider';
export { KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH } from './crypto/crypto-provider';

// Key / prekey records
export type {
  KeyPairDTO,
  IdentityKeyPairDTO,
  SignedPreKeyRecordDTO,
  OneTimePreKeyRecordDTO,
  RemoteIdentityDTO,
} from './keys/types';
export { generateSignedPreKeyRecord, generateOneTimePreKeyRecord } from './keys/prekeys';

// Session records (what the session store persists)
export type { SessionRecordDTO, PendingPreKeyDTO } from './session/session-record';
export { SessionCipher } from './session/session-cipher';

// Low-level protocol primitives (exported for advanced use / testing)
export {
  initiateX3dh,
  receiveX3dh,
  DEFAULT_X3DH_INFO,
} from './x3dh/x3dh';
export type { X3dhBundleMaterial, X3dhInitiationResult, X3dhReceiptResult } from './x3dh/x3dh';
export {
  initRatchetAsInitiator,
  initRatchetAsResponder,
  ratchetEncrypt,
  ratchetDecrypt,
  cloneRatchetState,
  MAX_SKIP_DEFAULT,
  ROOT_KDF_INFO,
  MESSAGE_KEY_INFO,
} from './ratchet/double-ratchet';
export type {
  RatchetStateDTO,
  RatchetHeader,
  RatchetEncryptResult,
  SkippedMessageKeyDTO,
} from './ratchet/double-ratchet';

// Errors
export {
  SignalError,
  InvalidMessageError,
  InvalidPreKeyBundleError,
  SignatureVerificationError,
  IdentityKeyChangedError,
  SessionNotFoundError,
  SessionNotReadyError,
  PreKeyNotFoundError,
  RemoteIdentityNotFoundError,
  GroupEncryptionError,
  SenderKeyNotFoundError,
  MessageDecryptError,
  TooManySkippedMessagesError,
  InvalidKeyError,
  DecryptionFailedError,
  InvalidEncodingError,
  InvalidArgumentError,
} from './errors';

// Byte utilities
export { toBase64, fromBase64 } from './util/base64';
export {
  concatBytes,
  utf8ToBytes,
  bytesToUtf8,
  u32be,
  constantTimeEqual,
} from './util/bytes';
