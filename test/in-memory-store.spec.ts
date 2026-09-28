import { describe, expect, it } from 'vitest';
import { InMemorySignalStore } from '../src/stores/in-memory-store';
import {
  IdentityKeyPairDTO,
  OneTimePreKeyRecordDTO,
  RemoteIdentityDTO,
  SignedPreKeyRecordDTO,
} from '../src/keys/types';
import { SessionRecordDTO } from '../src/session/session-record';

const identity: IdentityKeyPairDTO = {
  dhKeyPair: { publicKey: 'aGk=', privateKey: 'aGk=' },
  signingKeyPair: { publicKey: 'aGk=', privateKey: 'aGk=' },
  registrationId: 42,
};

const signedPreKey: SignedPreKeyRecordDTO = {
  id: 1,
  keyPair: { publicKey: 'aGk=', privateKey: 'aGk=' },
  signature: 'aGk=',
  createdAt: 1,
};

const oneTimePreKey: OneTimePreKeyRecordDTO = { id: 7, keyPair: { publicKey: 'aGk=', privateKey: 'aGk=' } };

const remoteIdentity: RemoteIdentityDTO = { dhKey: 'aGk=', signingKey: 'aGk=', firstSeenAt: 5 };

const session: SessionRecordDTO = {
  version: 1,
  remoteAddress: 'bob.1',
  associatedData: 'aGk=',
  remoteIdentityDhKey: 'aGk=',
  remoteIdentitySigningKey: 'aGk=',
  states: [],
};

describe('InMemorySignalStore', () => {
  it('stores and scopes identity key pairs', async () => {
    const store = new InMemorySignalStore();
    expect(await store.getIdentityKeyPair('alice')).toBeNull();
    await store.saveIdentityKeyPair('alice', identity);
    await store.saveIdentityKeyPair('bob', identity);
    expect(await store.getIdentityKeyPair('alice')).toEqual(identity);
    expect(await store.getIdentityKeyPair('carol')).toBeNull();
  });

  it('stores and removes remote identities', async () => {
    const store = new InMemorySignalStore();
    await store.saveRemoteIdentity('alice', 'bob.1', remoteIdentity);
    expect(await store.getRemoteIdentity('alice', 'bob.1')).toEqual(remoteIdentity);
    expect(await store.getRemoteIdentity('alice', 'eve.1')).toBeNull();
    await store.removeRemoteIdentity('alice', 'bob.1');
    expect(await store.getRemoteIdentity('alice', 'bob.1')).toBeNull();
  });

  it('handles signed and one-time prekey records with listing', async () => {
    const store = new InMemorySignalStore();
    await store.saveSignedPreKey('alice', 3, signedPreKey);
    await store.saveSignedPreKey('alice', 1, signedPreKey);
    await store.saveSignedPreKey('bob', 1, signedPreKey);
    expect(await store.listSignedPreKeyIds('alice')).toEqual([1, 3]);
    expect(await store.getSignedPreKey('alice', 3)).toEqual(signedPreKey);
    await store.removeSignedPreKey('alice', 3);
    expect(await store.getSignedPreKey('alice', 3)).toBeNull();

    await store.saveOneTimePreKey('alice', 7, oneTimePreKey);
    await store.saveOneTimePreKey('alice', 2, oneTimePreKey);
    expect(await store.listOneTimePreKeyIds('alice')).toEqual([2, 7]);
    expect(await store.getOneTimePreKey('alice', 7)).toEqual(oneTimePreKey);
    await store.removeOneTimePreKey('alice', 7);
    expect(await store.listOneTimePreKeyIds('alice')).toEqual([2]);
  });

  it('handles sessions and address listing', async () => {
    const store = new InMemorySignalStore();
    await store.storeSession('alice', 'bob.1', session);
    await store.storeSession('alice', 'carol.1', session);
    expect(await store.listSessionAddresses('alice').then((a) => a.sort())).toEqual(['bob.1', 'carol.1']);
    expect(await store.loadSession('alice', 'bob.1')).toEqual(session);
    await store.deleteSession('alice', 'bob.1');
    expect(await store.loadSession('alice', 'bob.1')).toBeNull();
    expect(await store.listSessionAddresses('bob')).toEqual([]);
  });
});
