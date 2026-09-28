import { describe, expect, it } from 'vitest';
import { InMemorySignalStore } from '../src/stores/in-memory-store';
import { SignalClient } from '../src/protocol/signal-client';
import {
  IdentityKeyChangedError,
  MessageDecryptError,
  SessionNotFoundError,
  SignatureVerificationError,
} from '../src/errors';

async function makePair() {
  const store = new InMemorySignalStore();
  const alice = await SignalClient.create({ selfId: 'alice', stores: store });
  const bob = await SignalClient.create({ selfId: 'bob', stores: store });
  return { alice, bob };
}

describe('SignalClient end-to-end', () => {
  it('exchanges messages over the full X3DH + Double Ratchet flow', async () => {
    const { alice, bob } = await makePair();

    const bundle = await bob.getPreKeyBundle();
    await alice.createSessionFromBundle('bob.1', bundle);

    // First message is a prekey envelope carrying the X3DH material.
    const first = await alice.encryptText('bob.1', 'hello bob');
    expect(first.type).toBe('prekey');

    const reply1 = await bob.decryptText('alice.1', first);
    expect(reply1).toBe('hello bob');

    // Bob's reply uses the session he just built.
    const answer = await bob.encryptText('alice.1', 'hi alice');
    expect(await alice.decryptText('bob.1', answer)).toBe('hi alice');

    // After the first receipt, Alice's session is confirmed: plain envelopes.
    const third = await alice.encryptText('bob.1', 'regular now');
    expect(third.type).toBe('signal');
    expect(await bob.decryptText('alice.1', third)).toBe('regular now');
  });

  it('supports long conversations with repeated ratchet steps', async () => {
    const { alice, bob } = await makePair();
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());

    for (let i = 0; i < 20; i++) {
      const aToB = `a->b #${i}`;
      const envelope = await alice.encryptText('bob.1', aToB);
      expect(await bob.decryptText('alice.1', envelope)).toBe(aToB);

      const bToA = `b->a #${i}`;
      const reply = await bob.encryptText('alice.1', bToA);
      expect(await alice.decryptText('bob.1', reply)).toBe(bToA);
    }
  });

  it('delivers out-of-order messages', async () => {
    const { alice, bob } = await makePair();
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());

    const envelopes = [];
    for (let i = 0; i < 5; i++) {
      envelopes.push(await alice.encryptText('bob.1', `msg-${i}`));
    }
    const shuffled = [envelopes[3], envelopes[0], envelopes[4], envelopes[2], envelopes[1]];
    const received: string[] = [];
    for (const envelope of shuffled) {
      received.push(await bob.decryptText('alice.1', envelope));
    }
    expect(received.sort()).toEqual(['msg-0', 'msg-1', 'msg-2', 'msg-3', 'msg-4']);
  });

  it('rehydrates sessions from storage after a "restart"', async () => {
    const store = new InMemorySignalStore();
    const alice = await SignalClient.create({ selfId: 'alice', stores: store });
    const bob = await SignalClient.create({ selfId: 'bob', stores: store });
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());
    expect(await bob.decryptText('alice.1', await alice.encryptText('bob.1', 'before'))).toBe('before');

    // Recreate both clients over the same store: identities and sessions survive.
    const alice2 = await SignalClient.create({ selfId: 'alice', stores: store });
    const bob2 = await SignalClient.create({ selfId: 'bob', stores: store });

    const envelope = await alice2.encryptText('bob.1', 'after restart');
    expect(await bob2.decryptText('alice.1', envelope)).toBe('after restart');
    const reply = await bob2.encryptText('alice.1', 'reply');
    expect(await alice2.decryptText('bob.1', reply)).toBe('reply');
  });

  it('reuses the session when a prekey envelope is redelivered, and rejects replays', async () => {
    const { alice, bob } = await makePair();
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());

    const envelope = await alice.encryptText('bob.1', 'only-once');
    expect(await bob.decryptText('alice.1', envelope)).toBe('only-once');

    // Same envelope twice = replay, rejected by message-key consumption.
    await expect(bob.decryptText('alice.1', envelope)).rejects.toBeInstanceOf(MessageDecryptError);

    // A *new* prekey envelope (session not yet confirmed on Alice's side) still decrypts.
    const second = await alice.encryptText('bob.1', 'second try');
    expect(await bob.decryptText('alice.1', second)).toBe('second try');
  });

  it('keeps archived states so in-flight messages survive a session collision', async () => {
    // Both sides initiate simultaneously with each other's bundles.
    const { alice, bob } = await makePair();
    const aliceBundle = await alice.getPreKeyBundle();
    const bobBundle = await bob.getPreKeyBundle();
    await alice.createSessionFromBundle('bob.1', bobBundle);
    await bob.createSessionFromBundle('alice.1', aliceBundle);

    const fromAlice = await alice.encryptText('bob.1', 'via session A');
    const fromBob = await bob.encryptText('alice.1', 'via session B');

    // Bob's old session (B) is archived when Alice's prekey message arrives.
    expect(await bob.decryptText('alice.1', fromAlice)).toBe('via session A');
    // Alice's reply path still works; Bob's message under the archived initiator session...
    // Bob can still decrypt his own archived-session message when it comes back to Alice:
    expect(await alice.decryptText('bob.1', fromBob)).toBe('via session B');
  });

  it('rejects a changed remote identity (TOFU)', async () => {
    const { alice, bob } = await makePair();
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());

    // "Bob" re-registers with a brand-new identity.
    const newBob = await SignalClient.create({ selfId: 'bob', stores: new InMemorySignalStore() });
    await expect(
      alice.createSessionFromBundle('bob.1', await newBob.getPreKeyBundle()),
    ).rejects.toBeInstanceOf(IdentityKeyChangedError);
  });

  it('rejects tampered bundles and envelopes', async () => {
    const { alice, bob } = await makePair();
    const bundle = await bob.getPreKeyBundle();
    bundle.signedPreKey.signature = bundle.signedPreKey.signature.slice(0, -4) + 'AAAA';
    await expect(alice.createSessionFromBundle('bob.1', bundle)).rejects.toBeInstanceOf(
      SignatureVerificationError,
    );

    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());
    const envelope = await alice.encryptText('bob.1', 'integrity check');
    const tampered: any = JSON.parse(JSON.stringify(envelope));
    // Flip one character inside the ciphertext (keeps base64 valid).
    const c = tampered.message.ciphertext;
    const mid = Math.floor(c.length / 2);
    tampered.message.ciphertext = c.slice(0, mid) + (c[mid] === 'A' ? 'B' : 'A') + c.slice(mid + 1);
    await expect(bob.decryptText('alice.1', tampered)).rejects.toBeInstanceOf(MessageDecryptError);
  });

  it('throws helpful errors without a session', async () => {
    const { alice } = await makePair();
    await expect(alice.encryptText('stranger.1', 'hi')).rejects.toBeInstanceOf(SessionNotFoundError);
    await expect(
      alice.decryptText('stranger.1', { version: 1, type: 'signal' }),
    ).rejects.not.toBeNull();
  });

  it('works without one-time prekeys', async () => {
    const store = new InMemorySignalStore();
    const alice = await SignalClient.create({ selfId: 'alice', stores: store });
    const bob = await SignalClient.create({
      selfId: 'bob',
      stores: store,
      config: { oneTimePreKeyCount: 0 },
    });
    const bundle = await bob.getPreKeyBundle();
    expect(bundle.oneTimePreKey).toBeUndefined();

    await alice.createSessionFromBundle('bob.1', bundle);
    expect(await bob.decryptText('alice.1', await alice.encryptText('bob.1', 'no opk'))).toBe('no opk');
  });

  it('reserves one-time prekeys when serving bundles and deletes them after use', async () => {
    const { alice, bob } = await makePair();

    const before = await bob.listAvailableOneTimePreKeyIds();
    expect(before.length).toBeGreaterThan(0);

    const bundle = await bob.getPreKeyBundle({ consumeOneTime: true });
    expect(bundle.oneTimePreKey).toBeDefined();

    // Reserved: still stored (its private key is needed to decrypt), but not offered again.
    expect(await bob.getStores().getOneTimePreKey('bob.1', bundle.oneTimePreKey!.id)).not.toBeNull();
    expect(await bob.listAvailableOneTimePreKeyIds()).toEqual(before.filter((id) => id !== bundle.oneTimePreKey!.id));

    // A second bundle does not reuse the same one-time prekey.
    const second = await bob.getPreKeyBundle({ consumeOneTime: true });
    expect(second.oneTimePreKey!.id).not.toBe(bundle.oneTimePreKey!.id);

    // After the first decrypt, the consumed key is deleted from the store.
    await alice.createSessionFromBundle('bob.1', bundle);
    expect(await bob.decryptText('alice.1', await alice.encryptText('bob.1', 'hi'))).toBe('hi');
    expect(await bob.getStores().getOneTimePreKey('bob.1', bundle.oneTimePreKey!.id)).toBeNull();

    // Generate more prekeys on demand.
    await bob.generatePreKeys(1000, 3);
    expect((await bob.getStores().listOneTimePreKeyIds('bob.1')).length).toBeGreaterThan(0);
    void alice;
  });

  it('tracks session lifecycle helpers', async () => {
    const { alice, bob } = await makePair();
    expect(await alice.hasSession('bob.1')).toBe(false);
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());
    expect(await alice.hasSession('bob.1')).toBe(true);
    expect(await alice.listSessionAddresses()).toEqual(['bob.1']);
    expect((await alice.getRemoteIdentity('bob.1'))?.dhKey).toBe(
      bob.getIdentityKeyPair().dhKeyPair.publicKey,
    );

    await alice.deleteSession('bob.1');
    expect(await alice.hasSession('bob.1')).toBe(false);
  });
});
