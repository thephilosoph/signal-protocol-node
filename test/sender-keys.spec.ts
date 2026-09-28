import { describe, expect, it } from 'vitest';
import { InMemorySignalStore } from '../src/stores/in-memory-store';
import { InMemoryGroupStore } from '../src/group/in-memory-group-store';
import { SignalClient } from '../src/protocol/signal-client';
import { SignalGroup } from '../src/group/signal-group';
import { isSenderKeyDistribution } from '../src/group/sender-keys';
import {
  GroupEncryptionError,
  InvalidArgumentError,
  MessageDecryptError,
  SenderKeyNotFoundError,
  SignatureVerificationError,
} from '../src/errors';

async function makeClients(...selfIds: string[]) {
  const store = new InMemorySignalStore();
  const groupStore = new InMemoryGroupStore();
  const clients = new Map<string, SignalClient>();
  for (const selfId of selfIds) {
    clients.set(selfId, await SignalClient.create({ selfId, stores: store }));
  }
  return { store, groupStore, clients };
}

interface Setup {
  alice: SignalGroup;
  bob: SignalGroup;
  carol: SignalGroup;
}

/** Build a 3-member sender-keys group with the distribution exchanged pairwise. */
async function setupSenderKeyGroup(): Promise<Setup> {
  const { clients, groupStore } = await makeClients('alice', 'bob', 'carol');
  const create = (selfId: string) =>
    SignalGroup.create(clients.get(selfId) as SignalClient, 'team', {
      mode: 'sender-keys',
      groupStore,
    });

  const alice = create('alice');
  const bob = create('bob');
  const carol = create('carol');

  const aliceClient = clients.get('alice') as SignalClient;
  const aliceBundle = await aliceClient.getPreKeyBundle();
  for (const name of ['bob', 'carol']) {
    await alice.addMember(`${name}.1`, await (clients.get(name) as SignalClient).getPreKeyBundle());
  }
  // Members need pairwise sessions TO alice for her distributions to arrive:
  await bob.addMember('alice.1', aliceBundle);
  await carol.addMember('alice.1', aliceBundle);

  // Sender distributes the chain key pairwise; receivers route via onPairwiseMessage.
  const distributions = await alice.createDistribution();
  for (const [address, envelope] of Object.entries(distributions)) {
    const receiver = address === 'bob.1' ? bob : carol;
    const consumed = await receiver.onPairwiseMessage('alice.1', envelope);
    expect(consumed).toBeNull(); // consumed as a distribution
  }
  return { alice, bob, carol };
}

describe('Sender Keys groups (O(1) mode)', () => {
  it('encrypts once and every member decrypts the same message', async () => {
    const { alice, bob, carol } = await setupSenderKeyGroup();

    const message = await alice.encryptOnceText('one encryption for everyone');

    // Exactly one ciphertext regardless of member count:
    expect(Object.keys(message)).toContain('ciphertext');

    expect(await bob.decryptOnceText('alice.1', message)).toBe('one encryption for everyone');
    expect(await carol.decryptOnceText('alice.1', message)).toBe('one encryption for everyone');
  });

  it('supports long chains and out-of-order delivery', async () => {
    const { alice, bob } = await setupSenderKeyGroup();

    const messages = [];
    for (let i = 0; i < 5; i++) {
      messages.push(await alice.encryptOnceText(`sk-${i}`));
    }
    const shuffled = [messages[3], messages[0], messages[4], messages[2], messages[1]];
    const received = [];
    for (const m of shuffled) {
      received.push(await bob.decryptOnceText('alice.1', m));
    }
    expect(received.sort()).toEqual(['sk-0', 'sk-1', 'sk-2', 'sk-3', 'sk-4']);
  });

  it('rejects tampered ciphertext and forged signatures', async () => {
    const { alice, bob } = await setupSenderKeyGroup();
    const message = await alice.encryptOnceText('authentic');

    // Any ciphertext change breaks the signature (checked before decryption)
    // — an attacker cannot swap content without alice's signing key.
    const tampered = JSON.parse(JSON.stringify(message));
    const c = tampered.ciphertext;
    const mid = Math.floor(c.length / 2);
    tampered.ciphertext = c.slice(0, mid) + (c[mid] === 'A' ? 'B' : 'A') + c.slice(mid + 1);
    await expect(bob.decryptOnceText('alice.1', tampered)).rejects.toBeInstanceOf(SignatureVerificationError);

    // The same tampering must also fail on carol's copy (attribution is universal).
    const { carol } = await setupSenderKeyGroup();
    void carol;
    const second = await alice.encryptOnceText('second');
    const tampered2 = JSON.parse(JSON.stringify(second));
    const c2 = tampered2.ciphertext;
    tampered2.ciphertext = c2.slice(0, -8) + c2.slice(-7);
    await expect(bob.decryptOnceText('alice.1', tampered2)).rejects.toThrow();
  });

  it('rejects replays of consumed messages', async () => {
    const { alice, bob } = await setupSenderKeyGroup();
    const message = await alice.encryptOnceText('only once');
    expect(await bob.decryptOnceText('alice.1', message)).toBe('only once');
    await expect(bob.decryptOnceText('alice.1', message)).rejects.toBeInstanceOf(MessageDecryptError);
  });

  it('rotation revokes removed members while current members continue', async () => {
    const { groupStore, clients } = await makeClients('alice', 'bob', 'carol');
    const create = (selfId: string) =>
      SignalGroup.create(clients.get(selfId) as SignalClient, 'team', {
        mode: 'sender-keys',
        groupStore,
      });
    const alice = create('alice');
    const bob = create('bob');
    const carol = create('carol');

    await alice.addMember('bob.1', await (clients.get('bob') as SignalClient).getPreKeyBundle());
    await alice.addMember('carol.1', await (clients.get('carol') as SignalClient).getPreKeyBundle());
    const aliceBundle = await (clients.get('alice') as SignalClient).getPreKeyBundle();
    await bob.addMember('alice.1', aliceBundle);
    await carol.addMember('alice.1', aliceBundle);
    for (const [address, envelope] of Object.entries(await alice.createDistribution())) {
      const receiver = address === 'bob.1' ? bob : carol;
      await receiver.onPairwiseMessage('alice.1', envelope);
    }

    // Carol is removed, then alice rotates: the new chain reaches only bob.
    alice.removeMember('carol.1');
    for (const [address, envelope] of Object.entries(await alice.rotateDistribution())) {
      // Bob receives the new distribution; carol is no longer a target.
      expect(address).toBe('bob.1');
      await bob.onPairwiseMessage('alice.1', envelope);
    }

    const afterRotation = await alice.encryptOnceText('carol excluded');
    expect(await bob.decryptOnceText('alice.1', afterRotation)).toBe('carol excluded');
    // Carol never got the new distribution and cannot decrypt the future.
    await expect(carol.decryptOnceText('alice.1', afterRotation)).rejects.toBeInstanceOf(SenderKeyNotFoundError);
  });

  it('requires the distribution before decrypting and a distribution before encrypting', async () => {
    const { clients, groupStore } = await makeClients('alice', 'bob');
    const alice = SignalGroup.create(clients.get('alice') as SignalClient, 'g', {
      mode: 'sender-keys',
      groupStore,
    });
    await expect(alice.encryptOnceText('premature')).rejects.toBeInstanceOf(GroupEncryptionError);

    const bob = SignalGroup.create(clients.get('bob') as SignalClient, 'g', {
      mode: 'sender-keys',
      groupStore,
    });
    await alice.addMember('bob.1', await (clients.get('bob') as SignalClient).getPreKeyBundle());
    await alice.createDistribution();
    const message = await alice.encryptOnceText('hello');
    await expect(bob.decryptOnceText('alice.1', message)).rejects.toBeInstanceOf(SenderKeyNotFoundError);
  });

  it('rejects cross-mode method use', async () => {
    const { clients } = await makeClients('alice');
    const fanout = SignalGroup.create(clients.get('alice') as SignalClient, 'g');
    await expect(fanout.encryptOnceText('x')).rejects.toBeInstanceOf(InvalidArgumentError);
  });

  it('persists chains across restarts through the GroupStore', async () => {
    const { store, groupStore, clients } = await makeClients('alice', 'bob');
    const alice = SignalGroup.create(clients.get('alice') as SignalClient, 'g', {
      mode: 'sender-keys',
      groupStore,
    });
    const bob = SignalGroup.create(clients.get('bob') as SignalClient, 'g', {
      mode: 'sender-keys',
      groupStore,
    });
    await alice.addMember('bob.1', await (clients.get('bob') as SignalClient).getPreKeyBundle());
    await bob.addMember('alice.1', await (clients.get('alice') as SignalClient).getPreKeyBundle());
    for (const [, envelope] of Object.entries(await alice.createDistribution())) {
      await bob.onPairwiseMessage('alice.1', envelope);
    }
    await alice.encryptOnceText('warming up');

    // "Restart": fresh group handles, same stores.
    const alice2 = SignalGroup.create((await SignalClient.create({ selfId: 'alice', stores: store })), 'g', {
      mode: 'sender-keys',
      groupStore,
    });
    const bob2 = SignalGroup.create((await SignalClient.create({ selfId: 'bob', stores: store })), 'g', {
      mode: 'sender-keys',
      groupStore,
    });
    await alice2.addMember('bob.1');
    await bob2.addMember('alice.1');
    const message = await alice2.encryptOnceText('after restart');
    expect(await bob2.decryptOnceText('alice.1', message)).toBe('after restart');
  });

  it('exposes a routing helper for distribution payloads', () => {
    expect(isSenderKeyDistribution({ version: 1, type: 'sender-key-distribution' })).toBe(true);
    expect(isSenderKeyDistribution({ version: 1, type: 'signal' })).toBe(false);
    expect(isSenderKeyDistribution('hello')).toBe(false);
  });
});
