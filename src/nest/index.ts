/**
 * NestJS entry point: `import { SignalModule, SignalService } from 'signal-protocol-node/nest'`.
 *
 * Re-exports the pieces implementers of custom stores need so that Nest
 * applications can depend on a single import path.
 */
export { SignalModule } from './signal.module';
export type { SignalModuleOptions, SignalModuleAsyncOptions } from './signal.module';
export { SignalService } from './signal.service';
export { SIGNAL_MODULE_OPTIONS } from './tokens';

// Re-exports for store/crypto implementers
export type { SignalStore, IdentityStorePort, PreKeyStorePort, SessionStorePort } from '../stores/signal-store';
export { InMemorySignalStore } from '../stores/in-memory-store';
export type { CryptoProvider, KeyPair } from '../crypto/crypto-provider';
export { NodeCryptoProvider } from '../crypto/node-crypto-provider';
export type { SignalEnvelopeJSON, SignalMessageJSON, PreKeySignalMessageJSON } from '../protocol/messages';
export type { PreKeyBundleJSON } from '../protocol/bundle';
export type { SignalClientConfig } from '../protocol/signal-client';
export { SignalClient } from '../protocol/signal-client';
export type { SignalClientOptions } from '../protocol/signal-client';
export { SignalGroup } from '../group/signal-group';
export type { GroupEnvelopeJSON, GroupMode, SignalGroupOptions } from '../group/signal-group';
export { InMemoryGroupStore } from '../group/in-memory-group-store';
export { senderKeyRef, isSenderKeyDistribution } from '../group/sender-keys';
export type {
  GroupStore,
  SenderKeyStateDTO,
  SenderKeyDistributionJSON,
  SenderKeyGroupMessageJSON,
} from '../group/sender-keys';
export {
  computeSafetyNumber,
  computePairSafetyNumber,
  computeSafetyNumberFromBase64,
  computeFingerprint,
  formatSafetyNumber,
} from '../protocol/safety-number';
export { encryptAttachment, decryptAttachment } from '../protocol/attachments';
export type { EncryptedAttachment } from '../protocol/attachments';
export { addressOf, parseAddress, partitionAddressesByUser } from '../protocol/multi-device';
export { encodeSignalEnvelope, decodeSignalEnvelope, BINARY_ENVELOPE_VERSION } from '../protocol/binary';
export { WebCryptoProvider } from '../crypto/web-crypto-provider';
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
} from '../errors';
