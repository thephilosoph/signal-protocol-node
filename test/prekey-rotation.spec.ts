import { describe, expect, it } from 'vitest';
import { InMemorySignalStore } from '../src/stores/in-memory-store';
import { SignalClient } from '../src/protocol/signal-client';

describe('signed prekey rotation', () => {
  it('rotates to a new key id; old sessions keep working; new sessions use the new key', async () => {
    const store = new InMemorySignalStore();
    const alice = await SignalClient.create({ selfId: 'alice', stores: store });
    const bob = await SignalClient.create({ selfId: 'bob', stores: store });

    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());
    expect(await bob.decryptText('alice.1', await alice.encryptText('bob.1', 'before rotation'))).toBe(
      'before rotation',
    );

    const idsBefore = await bob.getStores().listSignedPreKeyIds('bob.1');
    const rotated = await bob.rotateSignedPreKey();
    expect(rotated.id).toBeGreaterThan(Math.max(...idsBefore));

    // Existing sessions are unaffected by rotation.
    expect(await bob.decryptText('alice.1', await alice.encryptText('bob.1', 'after rotation'))).toBe(
      'after rotation',
    );

    // New sessions pick up the rotated key.
    const alice2 = await SignalClient.create({ selfId: 'alice2', stores: store });
    const freshBundle = await bob.getPreKeyBundle();
    expect(freshBundle.signedPreKey.id).toBe(rotated.id);
    await alice2.createSessionFromBundle('bob.1', freshBundle);
    expect(await bob.decryptText('alice2.1', await alice2.encryptText('bob.1', 'new session'))).toBe(
      'new session',
    );
  });

  it('prunes old signed prekeys while keeping the newest', async () => {
    const store = new InMemorySignalStore();
    const bob = await SignalClient.create({ selfId: 'bob', stores: store });
    await bob.rotateSignedPreKey(); // id 2
    await bob.rotateSignedPreKey(); // id 3
    await bob.rotateSignedPreKey(); // id 4

    let ids = await bob.getStores().listSignedPreKeyIds('bob.1');
    expect(ids).toEqual([1, 2, 3, 4]);

    const removed = await bob.pruneSignedPreKeys(2);
    expect(removed).toEqual([1, 2]);
    ids = await bob.getStores().listSignedPreKeyIds('bob.1');
    expect(ids).toEqual([3, 4]);

    // Never prunes everything.
    expect(await bob.pruneSignedPreKeys(10)).toEqual([]);
    expect((await bob.getStores().listSignedPreKeyIds('bob.1')).length).toBe(2);
    await expect(bob.pruneSignedPreKeys(0)).rejects.toThrow();
  });

  it('fails loudly on the receiver when a pruned prekey is referenced', async () => {
    const store = new InMemorySignalStore();
    const alice = await SignalClient.create({ selfId: 'alice', stores: store });
    const bob = await SignalClient.create({ selfId: 'bob', stores: store });

    const staleBundle = await bob.getPreKeyBundle(); // references signed prekey id 1
    await bob.rotateSignedPreKey();
    await bob.pruneSignedPreKeys(1); // remove id 1 entirely

    // Session creation succeeds (the bundle only carries public keys) — the
    // failure surfaces on Bob's side when the prekey is needed to derive SK.
    await alice.createSessionFromBundle('bob.1', staleBundle);
    const envelope = await alice.encryptText('bob.1', 'doomed message');
    await expect(bob.decryptText('alice.1', envelope)).rejects.toThrow(/Signed prekey 1 not found/);
  });
});
