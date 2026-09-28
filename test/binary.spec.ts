import { describe, expect, it } from 'vitest';
import { InMemorySignalStore } from '../src/stores/in-memory-store';
import { SignalClient } from '../src/protocol/signal-client';
import {
  encodeSignalEnvelope,
  decodeSignalEnvelope,
} from '../src/protocol/binary';
import { InvalidMessageError } from '../src/errors';

async function makePair() {
  const store = new InMemorySignalStore();
  const alice = await SignalClient.create({ selfId: 'alice', stores: store });
  const bob = await SignalClient.create({ selfId: 'bob', stores: store });
  return { alice, bob };
}

describe('binary envelope serialization', () => {
  it('round-trips a prekey envelope with all fields intact', async () => {
    const { alice, bob } = await makePair();
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());
    const envelope = await alice.encryptText('bob.1', 'binary round trip');

    const decoded = decodeSignalEnvelope(encodeSignalEnvelope(envelope));
    expect(decoded).toEqual(envelope);
    expect(decoded.type).toBe('prekey');
  });

  it('round-trips a regular signal envelope', async () => {
    const { alice, bob } = await makePair();
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());
    await bob.decryptText('alice.1', await alice.encryptText('bob.1', 'setup'));
    // Bob replies so alice's session is confirmed → next envelope is 'signal'.
    await alice.decryptText('bob.1', await bob.encryptText('alice.1', 'ack'));
    const envelope = await alice.encryptText('bob.1', 'second');

    const decoded = decodeSignalEnvelope(encodeSignalEnvelope(envelope));
    expect(decoded).toEqual(envelope);
    expect(decoded.type).toBe('signal');
  });

  it('is meaningfully smaller than JSON', async () => {
    const { alice, bob } = await makePair();
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());
    await bob.decryptText('alice.1', await alice.encryptText('bob.1', 'setup'));
    const envelope = await alice.encryptText('bob.1', 'x'.repeat(64));

    const binary = encodeSignalEnvelope(envelope).length;
    const json = JSON.stringify(envelope).length;
    expect(binary).toBeLessThan(json / 2);
  });

  it('decrypts binary envelopes end-to-end (auto-detect and explicit decode)', async () => {
    const { alice, bob } = await makePair();
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());

    // Raw bytes on the wire — decrypt() detects the binary form automatically.
    const first = encodeSignalEnvelope(await alice.encryptText('bob.1', 'over the wire'));
    expect(await bob.decryptText('alice.1', first)).toBe('over the wire');

    // Explicit decode before decrypt — same result.
    const second = await alice.encryptText('bob.1', 'explicit decode');
    expect(await bob.decryptText('alice.1', decodeSignalEnvelope(encodeSignalEnvelope(second)))).toBe(
      'explicit decode',
    );
  });

  it('rejects truncated, unknown-version and unknown-type payloads', async () => {
    const { alice, bob } = await makePair();
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());
    const bytes = encodeSignalEnvelope(await alice.encryptText('bob.1', 'x'));

    await expect(
      (async () => decodeSignalEnvelope(bytes.slice(0, bytes.length - 4)))(),
    ).rejects.toThrow(InvalidMessageError);

    const badVersion = bytes.slice();
    badVersion[0] = 9;
    expect(() => decodeSignalEnvelope(badVersion)).toThrow(InvalidMessageError);

    const badType = bytes.slice();
    badType[1] = 0x7f;
    expect(() => decodeSignalEnvelope(badType)).toThrow(InvalidMessageError);

    expect(() => decodeSignalEnvelope(new Uint8Array(3))).toThrow(InvalidMessageError);
  });
});
