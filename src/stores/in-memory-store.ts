import {
  IdentityKeyPairDTO,
  OneTimePreKeyRecordDTO,
  RemoteIdentityDTO,
  SignedPreKeyRecordDTO,
} from '../keys/types';
import { SessionRecordDTO } from '../session/session-record';
import { SignalStore } from './signal-store';

/**
 * Default {@link SignalStore}: plain Maps, no persistence. Used when no store
 * is provided to `SignalClient.create()` and as the reference implementation
 * of the store contract.
 */
export class InMemorySignalStore implements SignalStore {
  private identity = new Map<string, IdentityKeyPairDTO>();
  private remoteIdentities = new Map<string, RemoteIdentityDTO>();
  private signedPreKeys = new Map<string, SignedPreKeyRecordDTO>();
  private oneTimePreKeys = new Map<string, OneTimePreKeyRecordDTO>();
  private sessions = new Map<string, SessionRecordDTO>();

  async getIdentityKeyPair(scope: string): Promise<IdentityKeyPairDTO | null> {
    return this.identity.get(scope) ?? null;
  }

  async saveIdentityKeyPair(scope: string, keyPair: IdentityKeyPairDTO): Promise<void> {
    this.identity.set(scope, structuredCloneJson(keyPair));
  }

  async getRemoteIdentity(scope: string, address: string): Promise<RemoteIdentityDTO | null> {
    return this.remoteIdentities.get(key(scope, address)) ?? null;
  }

  async saveRemoteIdentity(scope: string, address: string, identity: RemoteIdentityDTO): Promise<void> {
    this.remoteIdentities.set(key(scope, address), structuredCloneJson(identity));
  }

  async removeRemoteIdentity(scope: string, address: string): Promise<void> {
    this.remoteIdentities.delete(key(scope, address));
  }

  async saveSignedPreKey(scope: string, id: number, record: SignedPreKeyRecordDTO): Promise<void> {
    this.signedPreKeys.set(signedPreKeyKey(scope, id), structuredCloneJson(record));
  }

  async getSignedPreKey(scope: string, id: number): Promise<SignedPreKeyRecordDTO | null> {
    return this.signedPreKeys.get(signedPreKeyKey(scope, id)) ?? null;
  }

  async removeSignedPreKey(scope: string, id: number): Promise<void> {
    this.signedPreKeys.delete(signedPreKeyKey(scope, id));
  }

  async listSignedPreKeyIds(scope: string): Promise<number[]> {
    const ids: number[] = [];
    const prefix = `spk|${scope}|`;
    for (const k of this.signedPreKeys.keys()) {
      if (k.startsWith(prefix)) ids.push(Number(k.slice(prefix.length)));
    }
    return ids.sort((a, b) => a - b);
  }

  async saveOneTimePreKey(scope: string, id: number, record: OneTimePreKeyRecordDTO): Promise<void> {
    this.oneTimePreKeys.set(oneTimePreKeyKey(scope, id), structuredCloneJson(record));
  }

  async getOneTimePreKey(scope: string, id: number): Promise<OneTimePreKeyRecordDTO | null> {
    return this.oneTimePreKeys.get(oneTimePreKeyKey(scope, id)) ?? null;
  }

  async removeOneTimePreKey(scope: string, id: number): Promise<void> {
    this.oneTimePreKeys.delete(oneTimePreKeyKey(scope, id));
  }

  async listOneTimePreKeyIds(scope: string): Promise<number[]> {
    const ids: number[] = [];
    const prefix = `opk|${scope}|`;
    for (const k of this.oneTimePreKeys.keys()) {
      if (k.startsWith(prefix)) ids.push(Number(k.slice(prefix.length)));
    }
    return ids.sort((a, b) => a - b);
  }

  async loadSession(scope: string, address: string): Promise<SessionRecordDTO | null> {
    return this.sessions.get(sessionKey(scope, address)) ?? null;
  }

  async storeSession(scope: string, address: string, record: SessionRecordDTO): Promise<void> {
    this.sessions.set(sessionKey(scope, address), structuredCloneJson(record));
  }

  async deleteSession(scope: string, address: string): Promise<void> {
    this.sessions.delete(sessionKey(scope, address));
  }

  async listSessionAddresses(scope: string): Promise<string[]> {
    const addresses: string[] = [];
    const prefix = `sess|${scope}|`;
    for (const k of this.sessions.keys()) {
      if (k.startsWith(prefix)) addresses.push(k.slice(prefix.length));
    }
    return addresses;
  }
}

function key(scope: string, address: string): string {
  return `${scope}|${address}`;
}

function sessionKey(scope: string, address: string): string {
  return `sess|${scope}|${address}`;
}

function signedPreKeyKey(scope: string, id: number): string {
  return `spk|${scope}|${id}`;
}

function oneTimePreKeyKey(scope: string, id: number): string {
  return `opk|${scope}|${id}`;
}

function structuredCloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
