import { RatchetStateDTO } from '../ratchet/double-ratchet';

/**
 * Persisted session state for one remote address. `states[0]` is the current
 * ratchet state used for encryption; the remaining entries are archived states
 * kept briefly so that in-flight messages from before a session restart or
 * session collision can still be decrypted.
 */
export interface PendingPreKeyDTO {
  signedPreKeyId: number;
  oneTimePreKeyId?: number;
  /** Our ephemeral ("base") public key from X3DH (base64). */
  baseKey: string;
}

export interface SessionRecordDTO {
  version: 1;
  remoteAddress: string;
  /** X3DH associated data (base64): initiator ‖ responder identity DH keys. */
  associatedData: string;
  remoteIdentityDhKey: string;
  remoteIdentitySigningKey: string;
  /** Our ephemeral base key; identifies the session we initiated (dedupe on resend). */
  initiatorBaseKey?: string;
  /**
   * Set while we are the initiator and have not yet received a reply: every
   * message is wrapped in a prekey envelope so the responder can (re)build the
   * session. Cleared on the first successful decrypt.
   */
  pendingPreKey?: PendingPreKeyDTO | null;
  states: RatchetStateDTO[];
}

export function cloneSessionRecord(record: SessionRecordDTO): SessionRecordDTO {
  return JSON.parse(JSON.stringify(record)) as SessionRecordDTO;
}
