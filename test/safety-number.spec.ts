import { describe, expect, it } from 'vitest';
import { InMemorySignalStore } from '../src/stores/in-memory-store';
import { SignalClient } from '../src/protocol/signal-client';
import { NodeCryptoProvider } from '../src/crypto/node-crypto-provider';
import { WebCryptoProvider } from '../src/crypto/web-crypto-provider';
import {
  computeSafetyNumber,
  computeSafetyNumberFromBase64,
  computeFingerprint,
  formatSafetyNumber,
} from '../src/protocol/safety-number';
import { RemoteIdentityNotFoundError } from '../src/errors';

const crypto = new NodeCryptoProvider();

describe('safety numbers', () => {
  it('is 60 digits, order-independent for any key set size', async () => {
    const keys = [
      await crypto.generateKeyPair(),
      await crypto.generateKeyPair(),
      await crypto.generateKeyPair(),
    ].map((k) => k.publicKey);

    const digits = await computeSafetyNumber(keys, crypto);
    expect(digits).toMatch(/^\d{60}$/);
    expect(digits).toBe(await computeSafetyNumber([...keys].reverse(), crypto));
    expect(digits).toBe(await computeSafetyNumber([keys[2], keys[0], keys[1]], crypto));
  });

  it('differs for different key sets and is deterministic', async () => {
    const a = (await crypto.generateKeyPair()).publicKey;
    const b = (await crypto.generateKeyPair()).publicKey;
    const c = (await crypto.generateKeyPair()).publicKey;

    expect(await computeSafetyNumber([a, b], crypto)).not.toBe(await computeSafetyNumber([a, c], crypto));
    expect(await computeSafetyNumber([a, b], crypto)).toBe(await computeSafetyNumber([a, b], crypto));
  });

  it('works from base64 keys and produces stable fingerprints', async () => {
    const key = (await crypto.generateKeyPair()).publicKey;
    const fp1 = await computeFingerprint(key, crypto);
    const fp2 = await computeFingerprint(key, crypto);
    expect(fp1).toBe(fp2);
    expect(fp1).toMatch(/^[0-9a-f]{30}$/);

    const web = new WebCryptoProvider();
    expect(await computeFingerprint(key, crypto)).toBe(await computeFingerprint(key, web));

    const other = (await crypto.generateKeyPair()).publicKey;
    const digits = await computeSafetyNumberFromBase64(
      [Buffer.from(key).toString('base64'), Buffer.from(other).toString('base64')],
      crypto,
    );
    expect(digits).toMatch(/^\d{60}$/);
  });

  it('formats into 12 blocks of 5', () => {
    const formatted = formatSafetyNumber('1'.repeat(60));
    expect(formatted.split(' ')).toHaveLength(12);
    expect(formatted.split(' ').every((b) => b === '11111')).toBe(true);
    expect(() => formatSafetyNumber('1'.repeat(59))).toThrow();
  });
});

describe('SignalClient.getSafetyNumber', () => {
  it('returns the same number on both sides of a conversation', async () => {
    const store = new InMemorySignalStore();
    const alice = await SignalClient.create({ selfId: 'alice', stores: store });
    const bob = await SignalClient.create({ selfId: 'bob', stores: store });

    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());

    const aliceSide = await alice.getSafetyNumber('bob.1');

    // Bob learns Alice's identity when her (prekey) message arrives.
    await bob.decryptText('alice.1', await alice.encryptText('bob.1', 'hi'));
    const bobSide = await bob.getSafetyNumber('alice.1');

    expect(aliceSide).toMatch(/^\d{60}$/);
    expect(aliceSide).toBe(bobSide);
  });

  it('covers multiple devices identically on both sides', async () => {
    const store = new InMemorySignalStore();
    const alice = await SignalClient.create({ selfId: 'alice', stores: store });
    const bobPhone = await SignalClient.create({ selfId: 'bob', deviceId: 1, stores: store });
    const bobTablet = await SignalClient.create({ selfId: 'bob', deviceId: 2, stores: store });

    await alice.createSessionFromBundle('bob.1', await bobPhone.getPreKeyBundle());
    await alice.createSessionFromBundle('bob.2', await bobTablet.getPreKeyBundle());
    await bobPhone.decryptText('alice.1', await alice.encryptText('bob.1', 'hi phone'));
    await bobTablet.decryptText('alice.1', await alice.encryptText('bob.2', 'hi tablet'));

    // Bob's devices learn each other's identities from the server's device
    // directory (seeded via recordRemoteIdentity) — a realistic app-level step.
    const phoneIdentity = bobPhone.getIdentityKeyPair();
    const tabletIdentity = bobTablet.getIdentityKeyPair();
    await bobPhone.recordRemoteIdentity(
      'bob.2',
      tabletIdentity.dhKeyPair.publicKey,
      tabletIdentity.signingKeyPair.publicKey,
    );
    await bobTablet.recordRemoteIdentity(
      'bob.1',
      phoneIdentity.dhKeyPair.publicKey,
      phoneIdentity.signingKeyPair.publicKey,
    );

    const aliceSide = await alice.getSafetyNumber(['bob.1', 'bob.2']);
    const bobPhoneSide = await bobPhone.getSafetyNumber(['alice.1', 'bob.2']);
    const bobTabletSide = await bobTablet.getSafetyNumber(['alice.1', 'bob.1']);

    expect(aliceSide).toBe(bobPhoneSide);
    expect(aliceSide).toBe(bobTabletSide);
  });

  it('throws when no identity is known yet', async () => {
    const alice = await SignalClient.create({ selfId: 'alice' });
    await expect(alice.getSafetyNumber('stranger.1')).rejects.toBeInstanceOf(RemoteIdentityNotFoundError);
  });
});
