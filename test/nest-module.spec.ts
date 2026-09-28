import 'reflect-metadata';
import { describe, expect, it, beforeEach } from 'vitest';
import { Test } from '@nestjs/testing';
import { InMemorySignalStore, SignalModule, SignalService } from '../src/nest';

describe('SignalModule (NestJS integration)', () => {
  let service: SignalService;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [SignalModule.forRoot({ store: new InMemorySignalStore() })],
    }).compile();
    service = moduleRef.get(SignalService);
  });

  it('registers users and serves bundles', async () => {
    const aliceBundle = await service.registerUser('alice');
    expect(aliceBundle.identity.dhKey).toBeDefined();
    expect(aliceBundle.signedPreKey.publicKey).toBeDefined();
    expect(aliceBundle.oneTimePreKey).toBeDefined();

    // Serving a bundle consumes a one-time prekey by default.
    const served = await service.getPreKeyBundle('alice');
    expect(served.oneTimePreKey).toBeDefined();
  });

  it('exchanges end-to-end encrypted messages between two users', async () => {
    await service.registerUser('alice');
    await service.registerUser('bob');

    const bobBundle = await service.getPreKeyBundle('bob');
    await service.initiateSession('alice', 'bob.1', bobBundle);

    const envelope = await service.encrypt('alice', 'bob.1', 'hello from alice');
    expect(await service.decryptText('bob', 'alice.1', envelope)).toBe('hello from alice');

    const reply = await service.encrypt('bob', 'alice.1', 'hello alice');
    expect(await service.decryptText('alice', 'bob.1', reply)).toBe('hello alice');

    expect(await service.hasSession('alice', 'bob.1')).toBe(true);
    expect(await service.listSessions('alice')).toEqual(['bob.1']);
  });

  it('supports byte payloads', async () => {
    await service.registerUser('alice');
    await service.registerUser('bob');
    await service.initiateSession('alice', 'bob.1', await service.getPreKeyBundle('bob'));

    const payload = new Uint8Array([1, 2, 3, 250, 251]);
    const envelope = await service.encrypt('alice', 'bob.1', payload);
    const decrypted = await service.decrypt('bob', 'alice.1', envelope);
    expect(Array.from(decrypted)).toEqual(Array.from(payload));
  });

  it('tops up one-time prekeys', async () => {
    await service.registerUser('alice');
    const client = await service.getClient('alice');
    const before = (await client.getStores().listOneTimePreKeyIds('alice.1')).length;

    await service.topUpOneTimePreKeys('alice', before + 10);
    const after = (await client.getStores().listOneTimePreKeyIds('alice.1')).length;
    expect(after).toBe(before + 10);
  });

  it('supports forRootAsync with a factory and a per-user store factory', async () => {
    const stores = new Map<string, InMemorySignalStore>();
    const moduleRef = await Test.createTestingModule({
      imports: [
        SignalModule.forRootAsync({
          inject: [],
          useFactory: () => ({
            storeFactory: (selfId: string) => {
              const existing = stores.get(selfId) ?? new InMemorySignalStore();
              stores.set(selfId, existing);
              return existing;
            },
            defaultOneTimePreKeyCount: 5,
          }),
        }),
      ],
    }).compile();

    const asyncService = moduleRef.get(SignalService);
    await asyncService.registerUser('alice');
    await asyncService.registerUser('bob');
    await asyncService.initiateSession('alice', 'bob.1', await asyncService.getPreKeyBundle('bob'));

    const envelope = await asyncService.encrypt('alice', 'bob.1', 'async config');
    expect(await asyncService.decryptText('bob', 'alice.1', envelope)).toBe('async config');

    // Each user got a dedicated store instance from the factory.
    expect(stores.size).toBe(2);
  });

  it('caches clients per user', async () => {
    const first = await service.getClient('alice');
    const second = await service.getClient('alice');
    expect(first).toBe(second);

    service.evictClient('alice');
    const third = await service.getClient('alice');
    expect(third).not.toBe(first);
  });

  it('supports group fan-out through the service', async () => {
    for (const user of ['alice', 'bob', 'carol']) {
      await service.registerUser(user);
    }
    await service.addToGroup('alice', 'team', 'bob.1', await service.getPreKeyBundle('bob'));
    await service.addToGroup('alice', 'team', 'carol.1', await service.getPreKeyBundle('carol'));

    const envelope = await service.encryptGroup('alice', 'team', 'team update');
    expect(Object.keys(envelope.messages).sort()).toEqual(['bob.1', 'carol.1']);

    expect(await service.decryptText('bob', 'alice.1', envelope.messages['bob.1'])).toBe('team update');
    expect(await service.decryptText('carol', 'alice.1', envelope.messages['carol.1'])).toBe('team update');

    await service.removeFromGroup('alice', 'team', 'bob.1');
    expect(await service.listGroupMembers('alice', 'team')).toEqual(['carol.1']);
  });

  it('exposes safety numbers and prekey rotation', async () => {
    await service.registerUser('alice');
    await service.registerUser('bob');
    await service.initiateSession('alice', 'bob.1', await service.getPreKeyBundle('bob'));
    await service.decryptText('bob', 'alice.1', await service.encrypt('alice', 'bob.1', 'ping'));

    const aliceSide = await service.getSafetyNumber('alice', 'bob.1');
    const bobSide = await service.getSafetyNumber('bob', 'alice.1');
    expect(aliceSide).toMatch(/^\d{60}$/);
    expect(aliceSide).toBe(bobSide);

    await service.rotateSignedPreKey('bob');
    const removed = await service.pruneSignedPreKeys('bob', 1);
    expect(removed).toEqual([1]);
  });
});
