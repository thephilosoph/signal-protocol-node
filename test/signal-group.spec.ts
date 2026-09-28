import { describe, expect, it } from 'vitest';
import { InMemorySignalStore } from '../src/stores/in-memory-store';
import { SignalClient } from '../src/protocol/signal-client';
import { SignalGroup } from '../src/group/signal-group';
import { GroupEncryptionError, InvalidArgumentError } from '../src/errors';

async function makeClients(...selfIds: string[]) {
  const store = new InMemorySignalStore();
  const clients = new Map<string, SignalClient>();
  for (const selfId of selfIds) {
    clients.set(selfId, await SignalClient.create({ selfId, stores: store }));
  }
  return { store, clients };
}

describe('SignalGroup (fan-out group chat)', () => {
  it('encrypts one message to every member; each member decrypts their envelope', async () => {
    const { clients } = await makeClients('alice', 'bob', 'carol', 'dave');
    const alice = clients.get('alice') as SignalClient;

    const group = SignalGroup.create(alice, 'friends');
    for (const name of ['bob', 'carol', 'dave']) {
      await group.addMember(`${name}.1`, await (clients.get(name) as SignalClient).getPreKeyBundle());
    }
    expect(group.memberCount()).toBe(3);

    const envelope = await group.encryptText('hello group!');

    expect(envelope.type).toBe('group');
    expect(envelope.groupId).toBe('friends');
    expect(envelope.from).toBe('alice');
    expect(Object.keys(envelope.messages).sort()).toEqual(['bob.1', 'carol.1', 'dave.1']);

    for (const name of ['bob', 'carol', 'dave']) {
      const member = clients.get(name) as SignalClient;
      const plaintext = await member.decryptText('alice.1', envelope.messages[`${name}.1`]);
      expect(plaintext).toBe('hello group!');
    }
  });

  it('supports long conversations with repeated ratchet steps per member', async () => {
    const { clients } = await makeClients('alice', 'bob');
    const alice = clients.get('alice') as SignalClient;
    const bob = clients.get('bob') as SignalClient;

    const group = SignalGroup.create(alice, 'pair');
    await group.addMember('bob.1', await bob.getPreKeyBundle());

    for (let i = 0; i < 10; i++) {
      const envelope = await group.encryptText(`round ${i}`);
      expect(await bob.decryptText('alice.1', envelope.messages['bob.1'])).toBe(`round ${i}`);
    }
  });

  it('keeps working out-of-order and after members reply', async () => {
    const { clients } = await makeClients('alice', 'bob', 'carol');
    const alice = clients.get('alice') as SignalClient;
    const bob = clients.get('bob') as SignalClient;
    const carol = clients.get('carol') as SignalClient;

    const group = SignalGroup.create(alice, 'chat');
    await group.addMember('bob.1', await bob.getPreKeyBundle());
    await group.addMember('carol.1', await carol.getPreKeyBundle());

    const first = await group.encryptText('one');
    const second = await group.encryptText('two');

    // Bob gets both; Carol only the second (delivered out of order first).
    expect(await carol.decryptText('alice.1', second.messages['carol.1'])).toBe('two');
    expect(await bob.decryptText('alice.1', second.messages['bob.1'])).toBe('two');
    expect(await bob.decryptText('alice.1', first.messages['bob.1'])).toBe('one');
    expect(await carol.decryptText('alice.1', first.messages['carol.1'])).toBe('one');

    // Members reply through their own pairwise sessions (group is symmetric per user).
    const bobGroup = SignalGroup.create(bob, 'chat');
    await bobGroup.addMember('alice.1'); // session exists from receiving — no bundle needed
    const reply = await bobGroup.encryptText('bob here');
    expect(await alice.decryptText('bob.1', reply.messages['alice.1'])).toBe('bob here');
  });

  it('removes members from future fan-outs without affecting other members', async () => {
    const { clients } = await makeClients('alice', 'bob', 'carol');
    const alice = clients.get('alice') as SignalClient;

    const group = SignalGroup.create(alice, 'chat');
    await group.addMember('bob.1', await (clients.get('bob') as SignalClient).getPreKeyBundle());
    await group.addMember('carol.1', await (clients.get('carol') as SignalClient).getPreKeyBundle());

    group.removeMember('bob.1');
    expect(group.listMembers()).toEqual(['carol.1']);

    const envelope = await group.encryptText('bob is gone');
    expect(envelope.messages['bob.1']).toBeUndefined();
    expect(
      await (clients.get('carol') as SignalClient).decryptText('alice.1', envelope.messages['carol.1']),
    ).toBe('bob is gone');
  });

  it('re-adds members idempotently after a restart without a bundle', async () => {
    const store = new InMemorySignalStore();
    const alice = await SignalClient.create({ selfId: 'alice', stores: store });
    const bob = await SignalClient.create({ selfId: 'bob', stores: store });
    const group = SignalGroup.create(alice, 'chat');
    await group.addMember('bob.1', await bob.getPreKeyBundle());

    // "Restart": fresh group + fresh client over the same store.
    const alice2 = await SignalClient.create({ selfId: 'alice', stores: store });
    const bob2 = await SignalClient.create({ selfId: 'bob', stores: store });
    const group2 = SignalGroup.create(alice2, 'chat');
    await group2.addMember('bob.1'); // session persisted — no bundle needed
    expect(await bob2.decryptText('alice.1', (await group2.encryptText('still here')).messages['bob.1'])).toBe(
      'still here',
    );
  });

  it('rejects members without a session and groups without members', async () => {
    const { clients } = await makeClients('alice', 'bob');
    const alice = clients.get('alice') as SignalClient;

    const group = SignalGroup.create(alice, 'chat');
    await expect(group.addMember('stranger.1')).rejects.toBeInstanceOf(InvalidArgumentError);
    await expect(group.encryptText('nobody home')).rejects.toBeInstanceOf(GroupEncryptionError);

    await expect(group.addMember('bob.1')).rejects.toBeInstanceOf(InvalidArgumentError); // no bundle, no session
    await group.addMember('bob.1', await (clients.get('bob') as SignalClient).getPreKeyBundle());
    expect(group.memberCount()).toBe(1);
    await group.addMember('bob.1'); // idempotent
    expect(group.memberCount()).toBe(1);
  });
});
