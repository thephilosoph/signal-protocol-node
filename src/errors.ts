/**
 * Error hierarchy for the Signal Protocol library.
 *
 * All errors thrown by this library extend {@link SignalError}, so callers can
 * catch a single base class and then branch on the specific subclasses.
 */
export class SignalError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** Thrown when an incoming envelope or message fails structural validation. */
export class InvalidMessageError extends SignalError {}

/** Thrown when a prekey bundle is malformed. */
export class InvalidPreKeyBundleError extends SignalError {}

/** Thrown when a signed prekey signature does not verify. */
export class SignatureVerificationError extends SignalError {}

/** Thrown when a remote party's identity key changed (possible MITM). */
export class IdentityKeyChangedError extends SignalError {}

/** Thrown when encrypting/decrypting without an established session. */
export class SessionNotFoundError extends SignalError {}

/** Thrown when a session exists but cannot produce a message yet. */
export class SessionNotReadyError extends SignalError {}

/** Thrown when a referenced (signed/one-time) prekey is not in storage. */
export class PreKeyNotFoundError extends SignalError {}

/** Thrown when identity verification is requested for an unknown remote party. */
export class RemoteIdentityNotFoundError extends SignalError {}

/** Thrown when encrypting a group message fails for a specific member. */
export class GroupEncryptionError extends SignalError {}

/** Thrown when a sender-key chain (own or received) is missing for a group message. */
export class SenderKeyNotFoundError extends SignalError {}

/** Thrown when a message cannot be decrypted with any known session state. */
export class MessageDecryptError extends SignalError {}

/** Thrown when a message's counter exceeds the configured skip window. */
export class TooManySkippedMessagesError extends SignalError {}

/** Thrown on invalid key material (wrong size, all-zero shared secret, ...). */
export class InvalidKeyError extends SignalError {}

/** Thrown when AES-256-GCM authentication fails (wrong key or tampered data). */
export class DecryptionFailedError extends SignalError {}

/** Thrown when base64/UTF-8 decoding fails. */
export class InvalidEncodingError extends SignalError {}

/** Thrown when an identifier (self id, address) is not usable as a storage key. */
export class InvalidArgumentError extends SignalError {}
