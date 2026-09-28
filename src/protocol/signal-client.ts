import { CryptoProvider } from '../crypto/crypto-provider';
import { NodeCryptoProvider } from '../crypto/node-crypto-provider';
import {
  IdentityKeyChangedError,
  InvalidArgumentError,
  PreKeyNotFoundError,
  RemoteIdentityNotFoundError,
  SessionNotFoundError,
} from '../errors';
import {
  IdentityKeyPairDTO,
  OneTimePreKeyRecordDTO,
  SignedPreKeyRecordDTO,
} from '../keys/types';
import { generateOneTimePreKeyRecord, generateSignedPreKeyRecord } from '../keys/prekeys';
import { initRatchetAsInitiator, initRatchetAsResponder, MAX_SKIP_DEFAULT } from '../ratchet/double-ratchet';
import { PreKeyBundleJSON, ParsedPreKeyBundle, parsePreKeyBundle } from './bundle';
import { PreKeySignalMessageJSON, SignalEnvelopeJSON, SignalMessageJSON, parseEnvelope } from './messages';
import { SessionCipher } from '../session/session-cipher';
import { SessionRecordDTO } from '../session/session-record';
import { InMemorySignalStore } from '../stores/in-memory-store';
import { SignalStore } from '../stores/signal-store';
import { assertValidIdentifier, constantTimeEqual, bytesToUtf8, utf8ToBytes } from '../util/bytes';
import { fromBase64, toBase64 } from '../util/base64';
import { initiateX3dh, receiveX3dh } from '../x3dh/x3dh';
import { computeSafetyNumber, formatSafetyNumber } from './safety-number';
import { decodeSignalEnvelope } from './binary';

/** Tunable behaviour of a client. */
export interface SignalClientConfig {
  /** Max message keys derived ahead when messages arrive out of order. Default 1000. */
  maxSkip?: number;
  /** How many superseded ratchet states to keep for late messages. Default 5. */
  archivedStatesLimit?: number;
  /** Generate identity + prekeys automatically on first create(). Default true. */
  autoGeneratePreKeys?: boolean;
  /** How many one-time prekeys to generate on first create(). Default 50. */
  oneTimePreKeyCount?: number;
  /** HKDF info string for X3DH (namespace your deployment if you like). */
  x3dhInfo?: string;
}

export interface SignalClientOptions {
  /** Local account name (storage scope). Defaults to "default". */
  selfId?: string;
  /**
   * This device's id within the account. Addresses become "<selfId>.<deviceId>";
   * one account can run several clients (devices) side by side. Default 1.
   */
  deviceId?: number;
  /** Import an existing identity instead of generating one. */
  identityKeyPair?: IdentityKeyPairDTO;
  /** Persistence adapter. Defaults to {@link InMemorySignalStore}. */
  stores?: SignalStore;
  /** Crypto implementation. Defaults to {@link NodeCryptoProvider}. */
  crypto?: CryptoProvider;
  config?: SignalClientConfig;
}

interface ResolvedConfig {
  maxSkip: number;
  archivedStatesLimit: number;
  autoGeneratePreKeys: boolean;
  oneTimePreKeyCount: number;
  x3dhInfo?: string;
}

const DEFAULT_ONE_TIME_PRE_KEY_COUNT = 50;

/**
 * High-level facade over X3DH + Double Ratchet + storage. One client instance
 * represents ONE local identity ("user" or "device") and can hold sessions
 * with any number of remote addresses (`"<name>.<deviceId>"`).
 *
 * The library is transport-agnostic: `encrypt` returns a JSON envelope the app
 * sends over its own channel (WebSocket, MQTT, HTTP...), and `decrypt`
 * consumes whatever envelope arrived from that address.
 *
 * @example
 * ```ts
 * const alice = await SignalClient.create({ selfId: 'alice' });
 * const bob = await SignalClient.create({ selfId: 'bob' });
 *
 * const bundle = await bob.getPreKeyBundle();
 * await alice.createSessionFromBundle('bob.1', bundle);
 *
 * const envelope = await alice.encryptText('bob.1', 'hello');
 * const plaintext = await bob.decryptText('alice.1', envelope);
 * ```
 */
export class SignalClient {
  readonly selfId: string;
  readonly deviceId: number;
  /**
   * Storage scope for this client = "<selfId>.<deviceId>". Every DEVICE owns
   * its own identity keys and prekeys (per the Signal model), so multi-device
   * accounts simply run one client per device scope in the shared store.
   */
  readonly scope: string;
  private readonly store: SignalStore;
  private readonly crypto: CryptoProvider;
  private readonly config: ResolvedConfig;
  private identity!: IdentityKeyPairDTO;

  private constructor(
    selfId: string,
    deviceId: number,
    store: SignalStore,
    crypto: CryptoProvider,
    config: ResolvedConfig,
  ) {
    this.selfId = selfId;
    this.deviceId = deviceId;
    this.scope = `${selfId}.${deviceId}`;
    this.store = store;
    this.crypto = crypto;
    this.config = config;
  }

  /** This client's full address as remote parties should know it: "<selfId>.<deviceId>". */
  get ownAddress(): string {
    return `${this.selfId}.${this.deviceId}`;
  }

  /** The crypto provider in use (e.g. to reuse it for group/attachment helpers). */
  getCrypto(): CryptoProvider {
    return this.crypto;
  }

  /** Create (or rehydrate) a client. Safe to call again with the same store+selfId. */
  static async create(options: SignalClientOptions = {}): Promise<SignalClient> {
    const selfId = options.selfId ?? 'default';
    assertValidIdentifier(selfId, 'selfId');
    const deviceId = options.deviceId ?? 1;
    if (!Number.isInteger(deviceId) || deviceId < 1 || deviceId > 65535) {
      throw new InvalidArgumentError('deviceId must be an integer between 1 and 65535');
    }

    const store = options.stores ?? new InMemorySignalStore();
    const crypto = options.crypto ?? new NodeCryptoProvider();
    const config: ResolvedConfig = {
      maxSkip: options.config?.maxSkip ?? MAX_SKIP_DEFAULT,
      archivedStatesLimit: options.config?.archivedStatesLimit ?? 5,
      autoGeneratePreKeys: options.config?.autoGeneratePreKeys ?? true,
      oneTimePreKeyCount: options.config?.oneTimePreKeyCount ?? DEFAULT_ONE_TIME_PRE_KEY_COUNT,
      x3dhInfo: options.config?.x3dhInfo,
    };

    const client = new SignalClient(selfId, deviceId, store, crypto, config);
    await client.loadOrCreateIdentity(options.identityKeyPair);
    if (client.config.autoGeneratePreKeys) {
      await client.ensurePreKeys();
    }
    return client;
  }

  private async loadOrCreateIdentity(imported?: IdentityKeyPairDTO): Promise<void> {
    let identity = await this.store.getIdentityKeyPair(this.scope);
    if (!identity) {
      identity = imported ?? {
        dhKeyPair: keyPairToDTO(await this.crypto.generateKeyPair()),
        signingKeyPair: keyPairToDTO(await this.crypto.generateSigningKeyPair()),
        registrationId: this.randomRegistrationId(),
      };
      await this.store.saveIdentityKeyPair(this.scope, identity);
    }
    this.identity = identity;
  }

  private randomRegistrationId(): number {
    const bytes = this.crypto.randomBytes(2);
    return ((bytes[0] << 8) | bytes[1]) & 0x3fff;
  }

  private async ensurePreKeys(): Promise<void> {
    const signedIds = await this.store.listSignedPreKeyIds(this.scope);
    if (signedIds.length === 0) {
      await this.generateSignedPreKey();
    }
    const oneTimeIds = await this.store.listOneTimePreKeyIds(this.scope);
    if (oneTimeIds.length === 0 && this.config.oneTimePreKeyCount > 0) {
      await this.generatePreKeys(1, this.config.oneTimePreKeyCount);
    }
  }

  /** The local identity keys (dh = X25519 for DH, signing = Ed25519). */
  getIdentityKeyPair(): IdentityKeyPairDTO {
    return this.identity;
  }

  /** Generate `count` one-time prekeys with sequential ids starting at `startId`. */
  async generatePreKeys(startId: number, count: number): Promise<OneTimePreKeyRecordDTO[]> {
    if (!Number.isInteger(startId) || startId < 1 || !Number.isInteger(count) || count < 0) {
      throw new InvalidArgumentError('startId must be a positive integer and count a non-negative integer');
    }
    const records: OneTimePreKeyRecordDTO[] = [];
    for (let id = startId; id < startId + count; id++) {
      const record = await generateOneTimePreKeyRecord(id, this.crypto);
      await this.store.saveOneTimePreKey(this.scope, id, record);
      records.push(record);
    }
    return records;
  }

  /** Generate a signed prekey (id defaults to current max + 1). */
  async generateSignedPreKey(id?: number): Promise<SignedPreKeyRecordDTO> {
    let keyId = id;
    if (keyId === undefined) {
      const ids = await this.store.listSignedPreKeyIds(this.scope);
      keyId = ids.length > 0 ? Math.max(...ids) + 1 : 1;
    }
    const record = await generateSignedPreKeyRecord(
      keyId,
      fromBase64(this.identity.signingKeyPair.privateKey),
      this.crypto,
    );
    await this.store.saveSignedPreKey(this.scope, keyId, record);
    return record;
  }

  /**
   * Rotate the signed prekey: generate a fresh one that new sessions will use.
   * The previous key is intentionally kept in storage for a grace period —
   * peers may still hold bundles referencing it. Trim old keys afterwards
   * with {@link pruneSignedPreKeys} (e.g. on a weekly rotation schedule).
   */
  async rotateSignedPreKey(): Promise<SignedPreKeyRecordDTO> {
    return this.generateSignedPreKey();
  }

  /**
   * Delete the oldest signed prekeys, keeping the newest `keep` (min 1).
   * Only prune keys older than the longest possible bundle-cache delay in
   * your deployment; deleting a key a peer still references makes their first
   * message undecryptable (`PreKeyNotFoundError`).
   */
  async pruneSignedPreKeys(keep = 2): Promise<number[]> {
    if (keep < 1) {
      throw new InvalidArgumentError('keep must be at least 1');
    }
    const ids = (await this.store.listSignedPreKeyIds(this.scope)).sort((a, b) => a - b);
    const removed: number[] = [];
    while (ids.length > keep) {
      const id = ids.shift() as number;
      await this.store.removeSignedPreKey(this.scope, id);
      removed.push(id);
    }
    return removed;
  }

  /**
   * Build a bundle peers can use to start sessions with this client.
   *
   * With `consumeOneTime: true` the chosen one-time prekey is *reserved*:
   * it is never offered in another bundle, but stays in the store because
   * this client still needs its private key to decrypt the peer's first
   * message. It is deleted after that first decrypt (single use).
   */
  async getPreKeyBundle(options: { consumeOneTime?: boolean } = {}): Promise<PreKeyBundleJSON> {
    const signedIds = await this.store.listSignedPreKeyIds(this.scope);
    if (signedIds.length === 0) {
      throw new PreKeyNotFoundError('No signed prekey exists yet; call generateSignedPreKey() first');
    }
    const latestSignedId = Math.max(...signedIds);
    const signedPreKey = await this.store.getSignedPreKey(this.scope, latestSignedId);
    if (!signedPreKey) {
      throw new PreKeyNotFoundError(`Signed prekey ${latestSignedId} vanished from storage`);
    }

    let oneTimePreKeyId: number | undefined;
    let oneTimePreKeyPublic: string | undefined;
    const available = await this.listAvailableOneTimePreKeyIds();
    if (available.length > 0) {
      const id = available[0];
      const record = (await this.store.getOneTimePreKey(this.scope, id)) as OneTimePreKeyRecordDTO;
      oneTimePreKeyId = id;
      oneTimePreKeyPublic = record.keyPair.publicKey;
      if (options.consumeOneTime) {
        await this.store.saveOneTimePreKey(this.scope, id, { ...record, reservedAt: Date.now() });
      }
    }

    return {
      version: 1,
      deviceId: this.deviceId,
      identity: {
        dhKey: this.identity.dhKeyPair.publicKey,
        signingKey: this.identity.signingKeyPair.publicKey,
      },
      signedPreKey: {
        id: signedPreKey.id,
        publicKey: signedPreKey.keyPair.publicKey,
        signature: signedPreKey.signature,
      },
      ...(oneTimePreKeyId !== undefined
        ? { oneTimePreKey: { id: oneTimePreKeyId, publicKey: oneTimePreKeyPublic as string } }
        : {}),
    };
  }

  /** One-time prekey ids that have not been reserved for a bundle yet. */
  async listAvailableOneTimePreKeyIds(): Promise<number[]> {
    const ids = await this.store.listOneTimePreKeyIds(this.scope);
    const available: number[] = [];
    for (const id of ids) {
      const record = await this.store.getOneTimePreKey(this.scope, id);
      if (record && record.reservedAt === undefined) {
        available.push(id);
      }
    }
    return available;
  }

  /**
   * Establish a session as the X3DH *initiator* using a peer's bundle.
   * The first `encrypt()` afterwards produces a prekey envelope; as soon as a
   * reply (or any message) from the peer is decrypted successfully, the session
   * is confirmed and regular envelopes are used.
   *
   * If a session already exists (both sides initiated), the old ratchet states
   * are archived so in-flight messages still decrypt.
   */
  async createSessionFromBundle(remoteAddress: string, bundle: PreKeyBundleJSON): Promise<void> {
    assertValidIdentifier(remoteAddress, 'remoteAddress');
    const parsed = await parsePreKeyBundle(bundle, this.crypto);
    await this.assertRemoteIdentityUnchanged(remoteAddress, parsed.identityDhKey);

    const x3dh = await initiateX3dh({
      ourIdentityDhKeyPair: {
        privateKey: fromBase64(this.identity.dhKeyPair.privateKey),
        publicKey: fromBase64(this.identity.dhKeyPair.publicKey),
      },
      theirBundle: {
        identityDhKey: parsed.identityDhKey,
        identitySigningKey: parsed.identitySigningKey,
        signedPreKey: parsed.signedPreKey,
        signedPreKeySignature: fromBase64(bundle.signedPreKey.signature),
        oneTimePreKey: parsed.oneTimePreKey ?? null,
      },
      crypto: this.crypto,
      info: this.config.x3dhInfo,
    });

    const state = await initRatchetAsInitiator(x3dh.sharedSecret, parsed.signedPreKey, this.crypto);
    const previous = await this.store.loadSession(this.scope, remoteAddress);
    const baseKey = toBase64(x3dh.ephemeralKeyPair.publicKey);

    const record: SessionRecordDTO = {
      version: 1,
      remoteAddress,
      associatedData: toBase64(x3dh.associatedData),
      remoteIdentityDhKey: toBase64(parsed.identityDhKey),
      remoteIdentitySigningKey: toBase64(parsed.identitySigningKey),
      initiatorBaseKey: baseKey,
      pendingPreKey: {
        signedPreKeyId: parsed.signedPreKeyId,
        baseKey,
        ...(parsed.oneTimePreKeyId !== undefined ? { oneTimePreKeyId: parsed.oneTimePreKeyId } : {}),
      },
      states: [state, ...(previous?.states ?? []).slice(0, this.config.archivedStatesLimit - 1)],
    };

    await this.saveRemoteIdentity(remoteAddress, parsed);
    await this.store.storeSession(this.scope, remoteAddress, record);
  }

  /** Encrypt bytes for a remote address. Requires an established session. */
  async encrypt(remoteAddress: string, plaintext: Uint8Array): Promise<SignalEnvelopeJSON> {
    assertValidIdentifier(remoteAddress, 'remoteAddress');
    const record = await this.getRequiredSession(remoteAddress);

    const cipher = new SessionCipher(record, this.crypto, this.config.maxSkip);
    const message = await cipher.encryptMessage(plaintext);

    let envelope: SignalEnvelopeJSON;
    if (record.pendingPreKey) {
      const pending = record.pendingPreKey;
      const prekey: PreKeySignalMessageJSON = {
        version: 1,
        type: 'prekey',
        identityKey: this.identity.dhKeyPair.publicKey,
        identitySigningKey: this.identity.signingKeyPair.publicKey,
        baseKey: pending.baseKey,
        signedPreKeyId: pending.signedPreKeyId,
        message,
      };
      if (pending.oneTimePreKeyId !== undefined) {
        prekey.oneTimePreKeyId = pending.oneTimePreKeyId;
      }
      envelope = prekey;
    } else {
      envelope = message;
    }

    await this.store.storeSession(this.scope, remoteAddress, record);
    return envelope;
  }

  /** Encrypt a UTF-8 string. */
  async encryptText(remoteAddress: string, text: string): Promise<SignalEnvelopeJSON> {
    return this.encrypt(remoteAddress, utf8ToBytes(text));
  }

  /**
   * Decrypt an envelope received from `remoteAddress`. Accepts any parsed JSON
   * the transport delivered — or the raw binary form produced by
   * {@link encodeSignalEnvelope} — and dispatches prekey vs regular messages.
   */
  async decrypt(remoteAddress: string, envelope: unknown): Promise<Uint8Array> {
    assertValidIdentifier(remoteAddress, 'remoteAddress');
    const parsed = envelope instanceof Uint8Array ? decodeSignalEnvelope(envelope) : parseEnvelope(envelope);

    if (parsed.type === 'prekey') {
      return this.decryptPreKeyMessage(remoteAddress, parsed);
    }
    return this.decryptRegularMessage(remoteAddress, parsed);
  }

  /** Decrypt an envelope and interpret the plaintext as UTF-8. */
  async decryptText(remoteAddress: string, envelope: unknown): Promise<string> {
    return bytesToUtf8(await this.decrypt(remoteAddress, envelope));
  }

  private async decryptPreKeyMessage(
    remoteAddress: string,
    envelope: PreKeySignalMessageJSON,
  ): Promise<Uint8Array> {
    const remoteDhKey = fromBase64(envelope.identityKey);
    await this.assertRemoteIdentityUnchanged(remoteAddress, remoteDhKey);

    const current = await this.store.loadSession(this.scope, remoteAddress);

    let record: SessionRecordDTO;
    if (current && current.initiatorBaseKey === envelope.baseKey) {
      // Redelivery of a prekey message we already processed — reuse that session.
      record = current;
    } else {
      const signedPreKey = await this.store.getSignedPreKey(this.scope, envelope.signedPreKeyId);
      if (!signedPreKey) {
        throw new PreKeyNotFoundError(`Signed prekey ${envelope.signedPreKeyId} not found`);
      }

      let oneTimePreKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array } | null = null;
      if (envelope.oneTimePreKeyId !== undefined) {
        const oneTimePreKey = await this.store.getOneTimePreKey(this.scope, envelope.oneTimePreKeyId);
        if (!oneTimePreKey) {
          throw new PreKeyNotFoundError(`One-time prekey ${envelope.oneTimePreKeyId} not found (already consumed?)`);
        }
        oneTimePreKeyPair = {
          privateKey: fromBase64(oneTimePreKey.keyPair.privateKey),
          publicKey: fromBase64(oneTimePreKey.keyPair.publicKey),
        };
        // One-time prekeys are single use; remove immediately after reading.
        await this.store.removeOneTimePreKey(this.scope, envelope.oneTimePreKeyId);
      }

      const x3dh = await receiveX3dh({
        ourIdentityDhKeyPair: {
          privateKey: fromBase64(this.identity.dhKeyPair.privateKey),
          publicKey: fromBase64(this.identity.dhKeyPair.publicKey),
        },
        ourSignedPreKeyPair: {
          privateKey: fromBase64(signedPreKey.keyPair.privateKey),
          publicKey: fromBase64(signedPreKey.keyPair.publicKey),
        },
        ourOneTimePreKeyPair: oneTimePreKeyPair,
        theirIdentityDhKey: remoteDhKey,
        theirEphemeralKey: fromBase64(envelope.baseKey),
        crypto: this.crypto,
        info: this.config.x3dhInfo,
      });

      const state = initRatchetAsResponder(x3dh.sharedSecret, {
        privateKey: fromBase64(signedPreKey.keyPair.privateKey),
        publicKey: fromBase64(signedPreKey.keyPair.publicKey),
      }, this.crypto);

      record = {
        version: 1,
        remoteAddress,
        associatedData: toBase64(x3dh.associatedData),
        remoteIdentityDhKey: envelope.identityKey,
        remoteIdentitySigningKey: envelope.identitySigningKey,
        initiatorBaseKey: envelope.baseKey,
        pendingPreKey: null,
        states: [state, ...(current?.states ?? []).slice(0, this.config.archivedStatesLimit - 1)],
      };

      await this.store.saveRemoteIdentity(this.scope, remoteAddress, {
        dhKey: envelope.identityKey,
        signingKey: envelope.identitySigningKey,
        firstSeenAt: Date.now(),
      });
      await this.store.storeSession(this.scope, remoteAddress, record);
    }

    const cipher = new SessionCipher(record, this.crypto, this.config.maxSkip);
    const plaintext = await cipher.decryptSignalMessage(envelope.message);

    if (record.pendingPreKey) {
      record.pendingPreKey = null;
    }
    await this.store.storeSession(this.scope, remoteAddress, record);
    return plaintext;
  }

  private async decryptRegularMessage(
    remoteAddress: string,
    envelope: SignalMessageJSON,
  ): Promise<Uint8Array> {
    const record = await this.getRequiredSession(remoteAddress);
    const cipher = new SessionCipher(record, this.crypto, this.config.maxSkip);
    const plaintext = await cipher.decryptSignalMessage(envelope);

    // A successful decrypt confirms the peer has our session — stop resending X3DH material.
    if (record.pendingPreKey) {
      record.pendingPreKey = null;
    }
    await this.store.storeSession(this.scope, remoteAddress, record);
    return plaintext;
  }

  private async getRequiredSession(remoteAddress: string): Promise<SessionRecordDTO> {
    const record = await this.store.loadSession(this.scope, remoteAddress);
    if (!record) {
      throw new SessionNotFoundError(
        `No session with "${remoteAddress}". Call createSessionFromBundle() with the peer's prekey bundle first.`,
      );
    }
    return record;
  }

  /**
   * Trust-On-First-Use guard: if we already know this peer's identity DH key,
   * a different key means either re-registration or an interception attempt.
   */
  private async assertRemoteIdentityUnchanged(
    remoteAddress: string,
    identityDhKey: Uint8Array,
  ): Promise<void> {
    const known = await this.store.getRemoteIdentity(this.scope, remoteAddress);
    if (known && !constantTimeEqual(fromBase64(known.dhKey), identityDhKey)) {
      throw new IdentityKeyChangedError(
        `Identity key of "${remoteAddress}" changed since the first session. ` +
          'Verify out of band, then deleteSession() and accept the new identity explicitly.',
      );
    }
  }

  private async saveRemoteIdentity(
    remoteAddress: string,
    parsed: ParsedPreKeyBundle,
  ): Promise<void> {
    // Identity equality was already asserted before reaching this point.
    const known = await this.store.getRemoteIdentity(this.scope, remoteAddress);
    await this.store.saveRemoteIdentity(this.scope, remoteAddress, {
      dhKey: toBase64(parsed.identityDhKey),
      signingKey: toBase64(parsed.identitySigningKey),
      firstSeenAt: known?.firstSeenAt ?? Date.now(),
    });
  }

  /** Whether an established session exists for the address. */
  async hasSession(remoteAddress: string): Promise<boolean> {
    return (await this.store.loadSession(this.scope, remoteAddress)) !== null;
  }

  /** Remove the session (e.g. after an identity-key-change decision). */
  async deleteSession(remoteAddress: string): Promise<void> {
    await this.store.deleteSession(this.scope, remoteAddress);
  }

  /** All remote addresses this client has (or had) sessions with. */
  async listSessionAddresses(): Promise<string[]> {
    return this.store.listSessionAddresses(this.scope);
  }

  /** The stored TOFU identity record of a remote address, if any. */
  async getRemoteIdentity(remoteAddress: string) {
    return this.store.getRemoteIdentity(this.scope, remoteAddress);
  }

  /**
   * Seed a remote identity from an out-of-band source (e.g. your server's
   * device directory, or a bundle fetched but not yet used). Used to make
   * multi-device safety numbers possible before every device has chatted with
   * every other. Refuses to overwrite a *different* known identity.
   */
  async recordRemoteIdentity(remoteAddress: string, dhKey: string, signingKey: string): Promise<void> {
    assertValidIdentifier(remoteAddress, 'remoteAddress');
    const known = await this.store.getRemoteIdentity(this.scope, remoteAddress);
    if (known) {
      if (!constantTimeEqual(fromBase64(known.dhKey), fromBase64(dhKey))) {
        throw new IdentityKeyChangedError(
          `Refusing to record a different identity for "${remoteAddress}"`,
        );
      }
      return;
    }
    await this.store.saveRemoteIdentity(this.scope, remoteAddress, {
      dhKey,
      signingKey,
      firstSeenAt: Date.now(),
    });
  }

  /**
   * 60-digit safety number with one or more remote addresses (a user's
   * devices). Order-independent, so both sides see the same value as long as
   * they verify the same set of devices. Requires stored remote identities,
   * i.e. a session was created or a message was received at least once.
   * Compare it out-of-band (voice call, QR scan) to detect man-in-the-middle.
   */
  async getSafetyNumber(remoteAddresses: string | string[]): Promise<string> {
    const addresses = Array.isArray(remoteAddresses) ? remoteAddresses : [remoteAddresses];
    if (addresses.length === 0) {
      throw new InvalidArgumentError('At least one remote address is required');
    }
    const keys: Uint8Array[] = [fromBase64(this.identity.dhKeyPair.publicKey)];
    for (const address of addresses) {
      const remote = await this.store.getRemoteIdentity(this.scope, address);
      if (!remote) {
        throw new RemoteIdentityNotFoundError(
          `No known identity for "${address}" yet — create a session or receive a message first`,
        );
      }
      keys.push(fromBase64(remote.dhKey));
    }
    return computeSafetyNumber(keys, this.crypto);
  }

  /** Grouped display form for {@link getSafetyNumber} output ("12345 67890 ..."). */
  formatSafetyNumber(digits: string): string {
    return formatSafetyNumber(digits);
  }

  /** Forget the stored identity of a remote address (after explicit verification). */
  async removeRemoteIdentity(remoteAddress: string): Promise<void> {
    await this.store.removeRemoteIdentity(this.scope, remoteAddress);
  }

  /** Access the underlying store (for maintenance tools). */
  getStores(): SignalStore {
    return this.store;
  }
}

function keyPairToDTO(pair: { publicKey: Uint8Array; privateKey: Uint8Array }) {
  return { publicKey: toBase64(pair.publicKey), privateKey: toBase64(pair.privateKey) };
}
