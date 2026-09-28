import { SignalClient } from '../protocol/signal-client';
import { PreKeyBundleJSON } from '../protocol/bundle';
import { SignalEnvelopeJSON } from '../protocol/messages';
import {
  CryptoProvider,
} from '../crypto/crypto-provider';
import {
  GroupEncryptionError,
  InvalidArgumentError,
  MessageDecryptError,
  SenderKeyNotFoundError,
  SignatureVerificationError,
  TooManySkippedMessagesError,
} from '../errors';
import { assertValidIdentifier, bytesToUtf8, concatBytes, utf8ToBytes } from '../util/bytes';
import { toBase64, fromBase64 } from '../util/base64';
import { kdfChainKey, messageKeyToKeyNonce, MAX_SKIP_DEFAULT } from '../ratchet/double-ratchet';
import {
  SenderKeyStateDTO,
  GroupStore,
  senderKeyRef,
  senderKeyAad,
  senderKeySignatureInput,
  parseSenderKeyDistribution,
  parseSenderKeyGroupMessage,
  isSenderKeyDistribution,
  SenderKeyDistributionJSON,
  SenderKeyGroupMessageJSON,
} from './sender-keys';
import { InMemoryGroupStore } from './in-memory-group-store';

/**
 * Group messaging over a `SignalClient`, in one of two modes:
 *
 * - **`'fanout'`** (default): encrypt once *per member* through each member's
 *   pairwise Double Ratchet session. Full pairwise-grade security for every
 *   message; cost O(members). Receivers need no group logic at all.
 *
 * - **`'sender-keys'`**: the sender distributes a symmetric chain key to all
 *   members (encrypted pairwise, once per distribution), then encrypts every
 *   group message **once** (O(1)), signed with a per-distribution Ed25519 key
 *   for authenticity. Weaker forward secrecy than fan-out (any member holds
 *   the chain key until the next rotation) — the standard Sender Keys
 *   trade-off for large groups. See docs/SIGNAL_PROTOCOL.md §10.
 *
 * Membership is enforced by the sender plus your server's group authorization.
 * The member list lives in memory; persist group membership in your app and
 * re-add members after restarts (idempotent; no bundle needed while the
 * pairwise session persists).
 */
export type GroupMode = 'fanout' | 'sender-keys';

export interface SignalGroupOptions {
  mode?: GroupMode;
  /** Persistence for sender-key chains (sender-keys mode). Default: in-memory. */
  groupStore?: GroupStore;
  /** Max iterations to skip ahead for out-of-order group messages. Default 1000. */
  maxSkip?: number;
}

/** Fan-out envelope: one pairwise envelope per recipient, keyed by address. */
export interface GroupEnvelopeJSON {
  version: 1;
  type: 'group';
  /** Application-chosen group identifier (opaque to the protocol). */
  groupId: string;
  /** Sender's selfId (informational, for routing/UI on the receiving side). */
  from: string;
  /** One pairwise envelope per recipient, keyed by the recipient's address. */
  messages: Record<string, SignalEnvelopeJSON>;
}

const sharedDefaultGroupStore = new InMemoryGroupStore();

export class SignalGroup {
  private readonly members = new Set<string>();
  private readonly groupMode: GroupMode;
  private readonly groupStore: GroupStore;
  private readonly maxSkip: number;
  private currentDistributionId: string | null = null;

  private constructor(
    private readonly client: SignalClient,
    readonly groupId: string,
    options: SignalGroupOptions,
  ) {
    this.groupMode = options.mode ?? 'fanout';
    this.groupStore = options.groupStore ?? sharedDefaultGroupStore;
    this.maxSkip = options.maxSkip ?? MAX_SKIP_DEFAULT;
  }

  /** Create a group handle for this client. */
  static create(client: SignalClient, groupId: string, options: SignalGroupOptions = {}): SignalGroup {
    if (typeof groupId !== 'string' || groupId.length === 0 || groupId.length > 255) {
      throw new InvalidArgumentError('groupId must be a non-empty string of at most 255 characters');
    }
    return new SignalGroup(client, groupId, options);
  }

  get mode(): GroupMode {
    return this.groupMode;
  }

  /**
   * Add a member. If a pairwise session with them already exists (direct chat,
   * earlier group membership, or a previous process run), no bundle is needed;
   * otherwise the bundle is required to establish the session (X3DH).
   * Idempotent: adding an existing member is a no-op.
   *
   * In sender-keys mode, call {@link createDistribution} (or
   * {@link rotateDistribution}) after membership changes so new members — and
   * only current members — hold the next chain key.
   */
  async addMember(address: string, bundle?: PreKeyBundleJSON): Promise<void> {
    assertValidIdentifier(address, 'member address');
    if (!(await this.client.hasSession(address))) {
      if (!bundle) {
        throw new InvalidArgumentError(
          `No session with "${address}" and no bundle provided — fetch their prekey bundle first`,
        );
      }
      await this.client.createSessionFromBundle(address, bundle);
    }
    this.members.add(address);
  }

  /**
   * Add every listed device of a user at once (multi-device fan-out). Keys of
   * the record are device ids, values are each device's prekey bundle.
   */
  async addUserDevices(user: string, bundlesByDevice: Record<string, PreKeyBundleJSON>): Promise<void> {
    if (typeof user !== 'string' || user.length === 0) {
      throw new InvalidArgumentError('user must be a non-empty string');
    }
    for (const [deviceId, bundle] of Object.entries(bundlesByDevice)) {
      await this.addMember(`${user}.${deviceId}`, bundle);
    }
  }

  /**
   * Remove a member: they stop receiving future group messages (and, in
   * sender-keys mode, stop holding future chain keys after the next
   * {@link rotateDistribution}). Their pairwise session is intentionally kept.
   */
  removeMember(address: string): void {
    this.members.delete(address);
  }

  listMembers(): string[] {
    return [...this.members];
  }

  memberCount(): number {
    return this.members.size;
  }

  // ── Fan-out mode ─────────────────────────────────────────────────────────

  /**
   * Encrypt one plaintext for every member (fan-out). Returns a
   * {@link GroupEnvelopeJSON}: transmit it, and each recipient decrypts
   * `envelope.messages[theirAddress]` with `client.decrypt(senderAddress, ...)`.
   */
  async encrypt(plaintext: Uint8Array): Promise<GroupEnvelopeJSON> {
    this.assertMode('fanout');
    if (this.members.size === 0) {
      throw new GroupEncryptionError(`Group "${this.groupId}" has no members`);
    }
    const messages: Record<string, SignalEnvelopeJSON> = {};
    for (const address of this.members) {
      try {
        messages[address] = await this.client.encrypt(address, plaintext);
      } catch (error) {
        throw new GroupEncryptionError(`Failed to encrypt group message for "${address}"`, { cause: error });
      }
    }
    return {
      version: 1,
      type: 'group',
      groupId: this.groupId,
      from: this.client.selfId,
      messages,
    };
  }

  /** Text convenience for {@link encrypt}. */
  async encryptText(text: string): Promise<GroupEnvelopeJSON> {
    return this.encrypt(utf8ToBytes(text));
  }

  // ── Sender Keys mode ─────────────────────────────────────────────────────

  /**
   * Create a fresh sender-key chain and distribute it pairwise to every
   * current member. Returns one pairwise envelope per member — transmit each
   * to its address. Call after every membership change (rotation = revocation
   * for removed members), or to start the group.
   */
  async createDistribution(): Promise<Record<string, SignalEnvelopeJSON>> {
    this.assertMode('sender-keys');
    if (this.members.size === 0) {
      throw new GroupEncryptionError(`Group "${this.groupId}" has no members to distribute to`);
    }
    const crypto = this.client.getCrypto();
    const distributionId = toBase64(crypto.randomBytes(12));
    const chainKey = crypto.randomBytes(32);
    const signing = await crypto.generateSigningKeyPair();
    const signingKeyPair = {
      publicKey: toBase64(signing.publicKey),
      privateKey: toBase64(signing.privateKey),
    };

    const state: SenderKeyStateDTO = {
      version: 1,
      groupId: this.groupId,
      senderAddress: this.client.ownAddress,
      distributionId,
      chainKey: toBase64(chainKey),
      iteration: 0,
      signingKeyPair,
      skipped: [],
      createdAt: Date.now(),
    };
    await this.groupStore.saveSenderKey(
      this.client.scope,
      this.groupId,
      senderKeyRef(this.client.ownAddress, distributionId),
      state,
    );
    this.currentDistributionId = distributionId;

    const payload: SenderKeyDistributionJSON = {
      version: 1,
      type: 'sender-key-distribution',
      groupId: this.groupId,
      distributionId,
      chainKey: state.chainKey,
      iteration: 0,
      signingKey: signingKeyPair.publicKey,
    };
    const envelopes: Record<string, SignalEnvelopeJSON> = {};
    for (const address of this.members) {
      try {
        envelopes[address] = await this.client.encrypt(address, utf8ToBytes(JSON.stringify(payload)));
      } catch (error) {
        throw new GroupEncryptionError(`Failed to send sender-key distribution to "${address}"`, { cause: error });
      }
    }
    return envelopes;
  }

  /** Rotate = create a new distribution (fresh chain + signing key). */
  async rotateDistribution(): Promise<Record<string, SignalEnvelopeJSON>> {
    return this.createDistribution();
  }

  /**
   * Encrypt one group message for the whole group with ONE encryption (O(1)).
   * The returned {@link SenderKeyGroupMessageJSON} goes to your group channel;
   * every member decrypts it via {@link decryptOnce}.
   */
  async encryptOnce(plaintext: Uint8Array): Promise<SenderKeyGroupMessageJSON> {
    this.assertMode('sender-keys');
    const crypto = this.client.getCrypto();
    const distributionId = await this.resolveCurrentDistributionId();
    if (!distributionId) {
      throw new GroupEncryptionError(
        'No sender-key distribution yet — call createDistribution() first (and re-rotate after membership changes)',
      );
    }
    const ref = senderKeyRef(this.client.ownAddress, distributionId);
    const state = await this.groupStore.getSenderKey(this.client.scope, this.groupId, ref);
    if (!state?.signingKeyPair) {
      throw new SenderKeyNotFoundError(`Own sender key for group "${this.groupId}" vanished from storage`);
    }
    const signingKeyPair = state.signingKeyPair;

    const iteration = state.iteration;
    const { messageKey, nextChainKey } = await kdfChainKey(fromBase64(state.chainKey), crypto);
    state.chainKey = toBase64(nextChainKey);
    state.iteration = iteration + 1;

    const signingPublicKey = fromBase64(signingKeyPair.publicKey);
    const aad = senderKeyAad(this.groupId, distributionId, iteration, signingPublicKey);
    const nonce = crypto.randomBytes(12);
    const body = await crypto.aes256GcmEncrypt(messageKey, nonce, plaintext, aad);
    const ciphertext = concatBytes(nonce, body);
    const signature = await crypto.sign(
      fromBase64(signingKeyPair.privateKey),
      senderKeySignatureInput(aad, ciphertext),
    );

    await this.groupStore.saveSenderKey(this.client.scope, this.groupId, ref, state);
    return {
      version: 1,
      type: 'group-sk',
      groupId: this.groupId,
      distributionId,
      iteration,
      signature: toBase64(signature),
      ciphertext: toBase64(ciphertext),
    };
  }

  /** Text convenience for {@link encryptOnce}. */
  async encryptOnceText(text: string): Promise<SenderKeyGroupMessageJSON> {
    return this.encryptOnce(utf8ToBytes(text));
  }

  /**
   * Receiver side: store a sender-key distribution that arrived (decrypted)
   * over the pairwise channel. Use {@link onPairwiseMessage} to route
   * automatically, or call this directly with the parsed payload.
   */
  async acceptDistribution(senderAddress: string, payload: unknown): Promise<void> {
    this.assertMode('sender-keys');
    assertValidIdentifier(senderAddress, 'sender address');
    const dist = parseSenderKeyDistribution(payload);
    if (dist.groupId !== this.groupId) {
      throw new InvalidArgumentError(`Distribution is for group "${dist.groupId}", not "${this.groupId}"`);
    }
    const state: SenderKeyStateDTO = {
      version: 1,
      groupId: this.groupId,
      senderAddress,
      distributionId: dist.distributionId,
      chainKey: toBase64(dist.chainKey),
      iteration: dist.iteration,
      signingPublicKey: toBase64(dist.signingKey),
      skipped: [],
      createdAt: Date.now(),
    };
    await this.groupStore.saveSenderKey(
      this.client.scope,
      this.groupId,
      senderKeyRef(senderAddress, dist.distributionId),
      state,
    );
  }

  /**
   * Decrypt a sender-key group message from `senderAddress`. Requires their
   * distribution to have been accepted already. Signature is verified before
   * decryption; message keys are consumed exactly once (replays fail).
   */
  async decryptOnce(senderAddress: string, message: unknown): Promise<Uint8Array> {
    this.assertMode('sender-keys');
    assertValidIdentifier(senderAddress, 'sender address');
    const msg = parseSenderKeyGroupMessage(message);
    if (msg.groupId !== this.groupId) {
      throw new MessageDecryptError(`Group message is for "${msg.groupId}", not "${this.groupId}"`);
    }
    const crypto = this.client.getCrypto();
    const ref = senderKeyRef(senderAddress, msg.distributionId);
    const state = await this.groupStore.getSenderKey(this.client.scope, this.groupId, ref);
    if (!state?.signingPublicKey) {
      throw new SenderKeyNotFoundError(
        `No sender key from "${senderAddress}" (distribution ${msg.distributionId}) — ` +
          'accept their distribution over the pairwise channel first',
      );
    }

    // 1. Authenticate: only the holder of the distribution's signing key could
    //    have produced this header + ciphertext combination.
    const signingPublicKey = fromBase64(state.signingPublicKey);
    const aad = senderKeyAad(this.groupId, msg.distributionId, msg.iteration, signingPublicKey);
    const signatureValid = await crypto.verify(
      signingPublicKey,
      senderKeySignatureInput(aad, msg.ciphertext),
      msg.signature,
    );
    if (!signatureValid) {
      throw new SignatureVerificationError('Sender-key group message signature verification failed');
    }

    // 2. Derive the message key for this iteration (clone-then-commit).
    const attempt: SenderKeyStateDTO = { ...state, skipped: state.skipped.map((k) => ({ ...k })) };
    const messageKey = await this.advanceTo(attempt, msg.iteration, crypto);

    // 3. Decrypt.
    const nonce = msg.ciphertext.slice(0, 12);
    const body = msg.ciphertext.slice(12);
    let plaintext: Uint8Array;
    try {
      plaintext = await crypto.aes256GcmDecrypt(fromBase64(messageKey), nonce, body, aad);
    } catch (error) {
      throw new MessageDecryptError('Sender-key group message failed to decrypt', { cause: error });
    }
    await this.groupStore.saveSenderKey(this.client.scope, this.groupId, ref, attempt);
    return plaintext;
  }

  /** Text convenience for {@link decryptOnce}. */
  async decryptOnceText(senderAddress: string, message: unknown): Promise<string> {
    return bytesToUtf8(await this.decryptOnce(senderAddress, message));
  }

  /**
   * Convenience receiver pipeline: decrypt a pairwise envelope from a group
   * member; if it is a sender-key distribution for this group, accept it and
   * return null; otherwise return the plaintext bytes (your normal message).
   */
  async onPairwiseMessage(senderAddress: string, envelope: unknown): Promise<Uint8Array | null> {
    const bytes = await this.client.decrypt(senderAddress, envelope);
    try {
      const parsed: unknown = JSON.parse(bytesToUtf8(bytes));
      if (isSenderKeyDistribution(parsed)) {
        if ((parsed as { groupId?: unknown }).groupId === this.groupId) {
          await this.acceptDistribution(senderAddress, parsed);
          return null;
        }
      }
    } catch (error) {
      if (error instanceof InvalidArgumentError || error instanceof MessageDecryptError) {
        throw error;
      }
      // Not JSON — a plain app-level message.
    }
    return bytes;
  }

  /**
   * Prune stored sender-key chains (own + received), keeping the newest `keep`
   * per group. Old received chains die naturally once everyone rotates.
   */
  async pruneSenderKeys(keep = 3): Promise<number> {
    const all = await this.groupStore.listSenderKeys(this.client.scope, this.groupId);
    const sorted = [...all].sort((a, b) => b.createdAt - a.createdAt);
    const removed = sorted.slice(keep);
    for (const state of removed) {
      await this.groupStore.deleteSenderKey(
        this.client.scope,
        this.groupId,
        senderKeyRef(state.senderAddress, state.distributionId),
      );
    }
    return removed.length;
  }

  /**
   * The distribution id currently used for sending (sender-keys mode).
   * Recovered lazily from the store after a restart.
   */
  getCurrentDistributionId(): string | null {
    return this.currentDistributionId;
  }

  /** Find (and memoize) our newest own distribution — survives process restarts. */
  private async resolveCurrentDistributionId(): Promise<string | null> {
    if (this.currentDistributionId) return this.currentDistributionId;
    const all = await this.groupStore.listSenderKeys(this.client.scope, this.groupId);
    const own = all
      .filter((s) => s.senderAddress === this.client.ownAddress && s.signingKeyPair)
      .sort((a, b) => b.createdAt - a.createdAt);
    if (own.length === 0) return null;
    this.currentDistributionId = own[0].distributionId;
    return this.currentDistributionId;
  }

  // ── internals ────────────────────────────────────────────────────────────

  private assertMode(mode: GroupMode): void {
    if (this.groupMode !== mode) {
      throw new InvalidArgumentError(
        `Group "${this.groupId}" is in "${this.mode}" mode; this method requires "${mode}" — ` +
          'create it with SignalGroup.create(client, id, { mode })',
      );
    }
  }

  /** Advance a cloned receiving chain to the requested iteration, caching skipped keys. */
  private async advanceTo(
    state: SenderKeyStateDTO,
    until: number,
    crypto: CryptoProvider,
  ): Promise<string> {
    if (until < state.iteration) {
      const index = state.skipped.findIndex((s) => s.iteration === until);
      if (index >= 0) {
        const messageKey = state.skipped[index].messageKey;
        state.skipped.splice(index, 1);
        return messageKey;
      }
      throw new MessageDecryptError(
        'Sender-key message was already consumed (replay) or predates the known chain',
      );
    }
    if (until - state.iteration > this.maxSkip) {
      throw new TooManySkippedMessagesError(
        `Sender-key iteration ${until} exceeds the allowed skip window of ${this.maxSkip}`,
      );
    }
    let chainKey = fromBase64(state.chainKey);
    while (state.iteration < until) {
      const { messageKey, nextChainKey } = await kdfChainKey(chainKey, crypto);
      if (state.skipped.length >= this.maxSkip) {
        state.skipped.shift();
      }
      state.skipped.push({ iteration: state.iteration, messageKey: toBase64(messageKey) });
      chainKey = nextChainKey;
      state.iteration += 1;
    }
    const { messageKey, nextChainKey } = await kdfChainKey(chainKey, crypto);
    state.chainKey = toBase64(nextChainKey);
    state.iteration += 1;
    return toBase64(messageKey);
  }
}
