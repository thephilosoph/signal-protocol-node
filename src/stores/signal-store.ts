import {
  IdentityKeyPairDTO,
  OneTimePreKeyRecordDTO,
  RemoteIdentityDTO,
  SignedPreKeyRecordDTO,
} from '../keys/types';
import { SessionRecordDTO } from '../session/session-record';

/**
 * Persistence contract (Ports & Adapters). The protocol core depends only on
 * this interface; applications provide adapters backed by any store — in-memory
 * (default), Prisma, TypeORM, Redis, MongoDB, ...
 *
 * All DTOs are plain JSON-serializable objects, so a KV-style adapter can
 * persist them opaquely, and an SQL adapter maps them to columns/JSON columns.
 *
 * `scope` identifies the *local* account (e.g. a user id in a server-side
 * deployment, or a fixed name in a single-user client). Keeping it in the
 * interface (instead of inside each adapter) lets one store instance serve
 * many accounts — the NestJS `SignalService` relies on this.
 */
export interface IdentityStorePort {
  getIdentityKeyPair(scope: string): Promise<IdentityKeyPairDTO | null>;
  saveIdentityKeyPair(scope: string, keyPair: IdentityKeyPairDTO): Promise<void>;
  getRemoteIdentity(scope: string, address: string): Promise<RemoteIdentityDTO | null>;
  saveRemoteIdentity(scope: string, address: string, identity: RemoteIdentityDTO): Promise<void>;
  removeRemoteIdentity(scope: string, address: string): Promise<void>;
}

export interface PreKeyStorePort {
  saveSignedPreKey(scope: string, id: number, record: SignedPreKeyRecordDTO): Promise<void>;
  getSignedPreKey(scope: string, id: number): Promise<SignedPreKeyRecordDTO | null>;
  removeSignedPreKey(scope: string, id: number): Promise<void>;
  listSignedPreKeyIds(scope: string): Promise<number[]>;

  saveOneTimePreKey(scope: string, id: number, record: OneTimePreKeyRecordDTO): Promise<void>;
  getOneTimePreKey(scope: string, id: number): Promise<OneTimePreKeyRecordDTO | null>;
  removeOneTimePreKey(scope: string, id: number): Promise<void>;
  listOneTimePreKeyIds(scope: string): Promise<number[]>;
}

export interface SessionStorePort {
  loadSession(scope: string, address: string): Promise<SessionRecordDTO | null>;
  storeSession(scope: string, address: string, record: SessionRecordDTO): Promise<void>;
  deleteSession(scope: string, address: string): Promise<void>;
  listSessionAddresses(scope: string): Promise<string[]>;
}

/** The aggregate store a `SignalClient` needs. */
export interface SignalStore extends IdentityStorePort, PreKeyStorePort, SessionStorePort {}
