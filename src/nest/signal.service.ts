import { Inject, Injectable } from '@nestjs/common';
import { SignalClient, SignalClientConfig } from '../protocol/signal-client';
import { PreKeyBundleJSON } from '../protocol/bundle';
import { SignalEnvelopeJSON } from '../protocol/messages';
import { CryptoProvider } from '../crypto/crypto-provider';
import { InMemorySignalStore } from '../stores/in-memory-store';
import { SignalStore } from '../stores/signal-store';
import { SIGNAL_MODULE_OPTIONS } from './tokens';
import { SignalModuleOptions } from './signal.module';
import { SignalGroup, GroupEnvelopeJSON, GroupMode } from '../group/signal-group';
import { InMemoryGroupStore } from '../group/in-memory-group-store';
import { GroupStore, SenderKeyDistributionJSON, SenderKeyGroupMessageJSON } from '../group/sender-keys';
import { addressOf } from '../protocol/multi-device';

/**
 * Multi-user manager over {@link SignalClient} (Facade over the facade):
 * one protocol client per user device, all sharing the configured store/crypto.
 *
 * Typical usage in a chat backend:
 * - `registerUser(userId)` when a user signs up
 * - `getPreKeyBundle(userId, { consumeOneTime: true })` when a peer asks for it
 * - `initiateSession` + `encrypt`/`decrypt` on the message path
 * - `getGroup`/`encryptGroup` for group chats, `getSafetyNumber` for verification
 */
@Injectable()
export class SignalService {
  @Inject(SIGNAL_MODULE_OPTIONS)
  private readonly moduleOptions!: SignalModuleOptions;

  private readonly clients = new Map<string, Promise<SignalClient>>();
  private readonly groups = new Map<string, SignalGroup>();
  private defaultStore: SignalStore | null = null;
  private defaultGroupStore: GroupStore | null = null;

  /**
   * Get (or lazily create) the protocol client for a user device. Each device
   * owns its own identity keys and prekeys (scope "<userId>.<deviceId>").
   */
  async getClient(selfId: string, deviceId = 1): Promise<SignalClient> {
    const cacheKey = `${selfId}#${deviceId}`;
    const cached = this.clients.get(cacheKey);
    if (cached) return cached;

    const creation = this.createClient(selfId, deviceId);
    this.clients.set(cacheKey, creation);
    try {
      return await creation;
    } catch (error) {
      this.clients.delete(cacheKey);
      throw error;
    }
  }

  private async createClient(selfId: string, deviceId: number): Promise<SignalClient> {
    const options = this.moduleOptions;
    const store = options.storeFactory
      ? await options.storeFactory(`${selfId}.${deviceId}`)
      : options.store ?? (this.defaultStore ??= new InMemorySignalStore());

    return SignalClient.create({
      selfId,
      deviceId,
      stores: store,
      crypto: options.crypto,
      config: {
        oneTimePreKeyCount: options.defaultOneTimePreKeyCount,
        ...options.config,
      },
    });
  }

  /**
   * Ensure the user has an identity and prekeys. Returns the user's bundle so
   * the app can publish it (e.g. store it in the user profile).
   */
  async registerUser(
    selfId: string,
    options: { oneTimePreKeyCount?: number } = {},
  ): Promise<PreKeyBundleJSON> {
    const client = await this.getClient(selfId);
    if (options.oneTimePreKeyCount !== undefined) {
      await this.topUpOneTimePreKeys(selfId, options.oneTimePreKeyCount);
    }
    return client.getPreKeyBundle();
  }

  /**
   * Fetch the bundle to serve to a peer. By default this consumes a one-time
   * prekey, because in a server-mediated deployment each bundle should be
   * handed out at most once.
   */
  async getPreKeyBundle(
    selfId: string,
    options: { consumeOneTime?: boolean } = {},
  ): Promise<PreKeyBundleJSON> {
    const client = await this.getClient(selfId);
    return client.getPreKeyBundle({ consumeOneTime: options.consumeOneTime ?? true });
  }

  /** Keep at least `targetCount` *unreserved* one-time prekeys available for a user. */
  async topUpOneTimePreKeys(selfId: string, targetCount = 50): Promise<void> {
    const client = await this.getClient(selfId);
    const available = await client.listAvailableOneTimePreKeyIds();
    const missing = targetCount - available.length;
    if (missing <= 0) return;
    const allIds = await client.getStores().listOneTimePreKeyIds(client.scope);
    const nextId = allIds.length > 0 ? Math.max(...allIds) + 1 : 1;
    await client.generatePreKeys(nextId, missing);
  }

  /** Establish a session from a user to a remote address, using the peer's bundle. */
  async initiateSession(selfId: string, remoteAddress: string, bundle: PreKeyBundleJSON): Promise<void> {
    const client = await this.getClient(selfId);
    await client.createSessionFromBundle(remoteAddress, bundle);
  }

  /** Whether the user has an established session with the remote address. */
  async hasSession(selfId: string, remoteAddress: string): Promise<boolean> {
    const client = await this.getClient(selfId);
    return client.hasSession(remoteAddress);
  }

  /** Encrypt text for a remote address; returns the envelope to transmit. */
  async encrypt(selfId: string, remoteAddress: string, plaintext: string | Uint8Array): Promise<SignalEnvelopeJSON> {
    const client = await this.getClient(selfId);
    if (typeof plaintext === 'string') {
      return client.encryptText(remoteAddress, plaintext);
    }
    return client.encrypt(remoteAddress, plaintext);
  }

  /** Decrypt an envelope received from a remote address (raw bytes). */
  async decrypt(selfId: string, remoteAddress: string, envelope: unknown): Promise<Uint8Array> {
    const client = await this.getClient(selfId);
    return client.decrypt(remoteAddress, envelope);
  }

  /** Decrypt an envelope and interpret the plaintext as UTF-8 text. */
  async decryptText(selfId: string, remoteAddress: string, envelope: unknown): Promise<string> {
    const client = await this.getClient(selfId);
    return client.decryptText(remoteAddress, envelope);
  }

  /** Delete a session (e.g. after an identity-key-change decision). */
  async deleteSession(selfId: string, remoteAddress: string): Promise<void> {
    const client = await this.getClient(selfId);
    await client.deleteSession(remoteAddress);
  }

  /** Addresses the user has sessions with. */
  async listSessions(selfId: string): Promise<string[]> {
    const client = await this.getClient(selfId);
    return client.listSessionAddresses();
  }

  // ── Groups (fan-out or Sender Keys, chosen at first creation) ───────────

  /** Get (or lazily create) a group handle for a user device. */
  async getGroup(
    userId: string,
    groupId: string,
    options: { mode?: GroupMode } = {},
  ): Promise<SignalGroup> {
    const cacheKey = `${userId}|${groupId}`;
    const cached = this.groups.get(cacheKey);
    if (cached) return cached;

    const group = SignalGroup.create(await this.getClient(userId), groupId, {
      mode: options.mode,
      groupStore: this.moduleOptions.groupStore ?? (this.defaultGroupStore ??= new InMemoryGroupStore()),
    });
    this.groups.set(cacheKey, group);
    return group;
  }

  /** Add a member to a user's group (bundle optional if a session already exists). */
  async addToGroup(
    userId: string,
    groupId: string,
    memberAddress: string,
    bundle?: PreKeyBundleJSON,
  ): Promise<void> {
    const group = await this.getGroup(userId, groupId);
    await group.addMember(memberAddress, bundle);
  }

  /** Add every device of a user at once (multi-device fan-out). */
  async addUserToGroup(
    userId: string,
    groupId: string,
    memberUser: string,
    bundlesByDevice: Record<string, PreKeyBundleJSON>,
  ): Promise<void> {
    const group = await this.getGroup(userId, groupId);
    await group.addUserDevices(memberUser, bundlesByDevice);
  }

  /** Remove a member from a user's group (they stop receiving future messages). */
  async removeFromGroup(userId: string, groupId: string, memberAddress: string): Promise<void> {
    const group = await this.getGroup(userId, groupId);
    group.removeMember(memberAddress);
  }

  /** Members of a user's group handle. */
  async listGroupMembers(userId: string, groupId: string): Promise<string[]> {
    const group = await this.getGroup(userId, groupId);
    return group.listMembers();
  }

  /** Fan-out encrypt a group message for a user; route `messages` per recipient. */
  async encryptGroup(
    userId: string,
    groupId: string,
    plaintext: string | Uint8Array,
  ): Promise<GroupEnvelopeJSON> {
    const group = await this.getGroup(userId, groupId);
    if (typeof plaintext === 'string') {
      return group.encryptText(plaintext);
    }
    return group.encrypt(plaintext);
  }

  /**
   * Sender Keys: create/rotate the user's sender-key chain and return one
   * pairwise envelope per member (transmit each to its address).
   */
  async createGroupDistribution(
    userId: string,
    groupId: string,
  ): Promise<Record<string, SignalEnvelopeJSON>> {
    const group = await this.getGroup(userId, groupId, { mode: 'sender-keys' });
    return group.createDistribution();
  }

  /** Sender Keys: O(1) group encrypt. Requires a prior `createGroupDistribution`. */
  async encryptGroupOnce(
    userId: string,
    groupId: string,
    plaintext: string | Uint8Array,
  ): Promise<SenderKeyGroupMessageJSON> {
    const group = await this.getGroup(userId, groupId, { mode: 'sender-keys' });
    if (typeof plaintext === 'string') {
      return group.encryptOnceText(plaintext);
    }
    return group.encryptOnce(plaintext);
  }

  /**
   * Sender Keys receiver pipeline: decrypt a pairwise envelope; if it is a
   * sender-key distribution for this group, accept it and return null.
   */
  async onGroupPairwiseMessage(
    userId: string,
    groupId: string,
    senderAddress: string,
    envelope: unknown,
  ): Promise<Uint8Array | null> {
    const group = await this.getGroup(userId, groupId, { mode: 'sender-keys' });
    return group.onPairwiseMessage(senderAddress, envelope);
  }

  /** Sender Keys: decrypt a group message from a member (distribution accepted first). */
  async decryptGroupOnce(
    userId: string,
    groupId: string,
    senderAddress: string,
    message: SenderKeyGroupMessageJSON | unknown,
  ): Promise<Uint8Array> {
    const group = await this.getGroup(userId, groupId, { mode: 'sender-keys' });
    return group.decryptOnce(senderAddress, message);
  }

  /** Sender Keys: rotate the user's chain (revokes removed members once distributed). */
  async rotateGroupDistribution(userId: string, groupId: string): Promise<Record<string, SignalEnvelopeJSON>> {
    const group = await this.getGroup(userId, groupId, { mode: 'sender-keys' });
    return group.rotateDistribution();
  }

  /** This user device's own address ("<userId>.<deviceId>"). */
  async getOwnAddress(userId: string, deviceId = 1): Promise<string> {
    await this.getClient(userId, deviceId); // ensure the device exists
    return addressOf(userId, deviceId);
  }

  // ── Identity verification ────────────────────────────────────────────────

  /** 60-digit safety number between a user and a remote address. */
  async getSafetyNumber(userId: string, remoteAddress: string): Promise<string> {
    const client = await this.getClient(userId);
    return client.getSafetyNumber(remoteAddress);
  }

  // ── Signed prekey rotation ───────────────────────────────────────────────

  /** Rotate a user's signed prekey (old keys remain for a grace period). */
  async rotateSignedPreKey(userId: string): Promise<void> {
    const client = await this.getClient(userId);
    await client.rotateSignedPreKey();
  }

  /** Delete a user's oldest signed prekeys, keeping the newest `keep`. */
  async pruneSignedPreKeys(userId: string, keep = 2): Promise<number[]> {
    const client = await this.getClient(userId);
    return client.pruneSignedPreKeys(keep);
  }

  /** Drop cached clients of a user (all devices); next access rehydrates from the store. */
  evictClient(selfId: string): void {
    for (const key of this.clients.keys()) {
      if (key.startsWith(`${selfId}#`)) {
        this.clients.delete(key);
      }
    }
    for (const key of this.groups.keys()) {
      if (key.startsWith(`${selfId}|`)) {
        this.groups.delete(key);
      }
    }
  }

  /** Access the underlying crypto provider, if one was configured. */
  getCrypto(): CryptoProvider | undefined {
    return this.moduleOptions.crypto;
  }

  /** Access the resolved client config. */
  getConfig(): SignalClientConfig | undefined {
    return this.moduleOptions.config;
  }
}
