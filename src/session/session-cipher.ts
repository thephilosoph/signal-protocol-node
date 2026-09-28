import { CryptoProvider } from '../crypto/crypto-provider';
import { MessageDecryptError, SessionNotReadyError, TooManySkippedMessagesError } from '../errors';
import {
  RatchetHeader,
  RatchetStateDTO,
  cloneRatchetState,
  ratchetDecrypt,
  ratchetEncrypt,
} from '../ratchet/double-ratchet';
import { fromBase64, toBase64 } from '../util/base64';
import { SignalMessageJSON } from '../protocol/messages';
import { SessionRecordDTO } from './session-record';

/**
 * Per-session encrypt/decrypt operations on a {@link SessionRecordDTO}.
 *
 * The record is mutated in place and the caller (SignalClient) persists it.
 * Decryption is *clone-then-commit*: every archived/current state is tried on a
 * clone, so a tampered or replayed message can never advance the real chains.
 */
export class SessionCipher {
  constructor(
    private readonly record: SessionRecordDTO,
    private readonly crypto: CryptoProvider,
    private readonly maxSkip: number,
  ) {}

  /** Encrypt with the current (first) state; advances its sending chain. */
  async encryptMessage(plaintext: Uint8Array): Promise<SignalMessageJSON> {
    if (this.record.states.length === 0) {
      throw new SessionNotReadyError('Session record has no ratchet states');
    }
    const state = this.record.states[0];
    const associatedData = fromBase64(this.record.associatedData);
    const { header, ciphertext } = await ratchetEncrypt(state, plaintext, associatedData, this.crypto);
    return {
      version: 1,
      type: 'signal',
      ratchetKey: header.ratchetKey,
      previousCounter: header.previousCounter,
      counter: header.counter,
      ciphertext: toBase64(ciphertext),
    };
  }

  /**
   * Try the current state, then the archived states. On success the matching
   * state is committed (and promoted to current if it was archived).
   */
  async decryptSignalMessage(message: SignalMessageJSON): Promise<Uint8Array> {
    const header: RatchetHeader = {
      ratchetKey: message.ratchetKey,
      previousCounter: message.previousCounter,
      counter: message.counter,
    };
    const ciphertext = fromBase64(message.ciphertext);
    const associatedData = fromBase64(this.record.associatedData);

    let lastError: unknown;
    for (let i = 0; i < this.record.states.length; i++) {
      const attempt: RatchetStateDTO = cloneRatchetState(this.record.states[i]);
      try {
        const plaintext = await ratchetDecrypt(attempt, header, ciphertext, associatedData, this.crypto, this.maxSkip);
        this.record.states.splice(i, 1, attempt);
        if (i > 0) {
          // A message that still belongs to an archived state means the peer
          // has not switched to the new session yet — make it current again.
          this.record.states.shift();
          this.record.states.unshift(attempt);
        }
        return plaintext;
      } catch (error) {
        if (error instanceof TooManySkippedMessagesError) {
          throw error;
        }
        lastError = error;
      }
    }
    throw new MessageDecryptError(
      `Message could not be decrypted with any of ${this.record.states.length} known session state(s)`,
      { cause: lastError },
    );
  }
}
