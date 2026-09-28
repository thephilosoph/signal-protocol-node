import { describe, expect, it } from 'vitest';
import { InMemorySignalStore } from '../src/stores/in-memory-store';
import { SignalClient } from '../src/protocol/signal-client';
import { SignalGroup } from '../src/group/signal-group';
import { InMemoryGroupStore } from '../src/group/in-memory-group-store';
import { WebCryptoProvider } from '../src/crypto/web-crypto-provider';

/**
 * End-to-end conversations running entirely on the WebCrypto provider —
 * the same validation path browsers/edge runtimes will take.
 */
describe('WebCrypto end-to-end', () => {
  it('runs a full pairwise conversation with only WebCrypto primitives', async () => {
    const store = new InMemorySignalStore();
    const alice = await SignalClient.create({ selfId: 'alice', stores: store, crypto: new WebCryptoProvider() });
    const bob = await SignalClient.create({ selfId: 'bob', stores: store, crypto: new WebCryptoProvider() });

    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());
    expect(await bob.decryptText('alice.1', await alice.encryptText('bob.1', 'webcrypto hello'))).toBe(
      'webcrypto hello',
    );
    const reply = await bob.encryptText('alice.1', 'webcrypto reply');
    expect(await alice.decryptText('bob.1', reply)).toBe('webcrypto reply');

    // Out-of-order still works (ratchet layer is provider-independent).
    const batch = [];
    for (let i = 0; i < 3; i++) batch.push(await alice.encryptText('bob.1', `msg-${i}`));
    expect(await bob.decryptText('alice.1', batch[2])).toBe('msg-2');
    expect(await bob.decryptText('alice.1', batch[0])).toBe('msg-0');
    expect(await bob.decryptText('alice.1', batch[1])).toBe('msg-1');
  });

  it('runs sender-key groups across mixed providers', async () => {
    const store = new InMemorySignalStore();
    const groupStore = new InMemoryGroupStore();
    const alice = await SignalClient.create({ selfId: 'alice', stores: store, crypto: new WebCryptoProvider() });
    const bob = await SignalClient.create({ selfId: 'bob', stores: store }); // Node provider

    const aliceGroup = SignalGroup.create(alice, 'mixed', { mode: 'sender-keys', groupStore });
    const bobGroup = SignalGroup.create(bob, 'mixed', { mode: 'sender-keys', groupStore });
    await aliceGroup.addMember('bob.1', await bob.getPreKeyBundle());
    await bobGroup.addMember('alice.1', await alice.getPreKeyBundle());

    for (const [, envelope] of Object.entries(await aliceGroup.createDistribution())) {
      expect(await bobGroup.onPairwiseMessage('alice.1', envelope)).toBeNull();
    }
    const message = await aliceGroup.encryptOnceText('mixed providers, one encryption');
    expect(await bobGroup.decryptOnceText('alice.1', message)).toBe('mixed providers, one encryption');
  });
});
