import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../src/crypto/node-crypto-provider';
import {
  RatchetStateDTO,
  initRatchetAsInitiator,
  initRatchetAsResponder,
  ratchetDecrypt,
  ratchetEncrypt,
} from '../src/ratchet/double-ratchet';
import { TooManySkippedMessagesError } from '../src/errors';
import { utf8ToBytes, bytesToUtf8 } from '../src/util/bytes';
import { toBase64 } from '../src/util/base64';

const crypto = new NodeCryptoProvider();

interface Pair {
  alice: RatchetStateDTO;
  bob: RatchetStateDTO;
}

async function makePair(): Promise<Pair> {
  const sharedSecret = crypto.randomBytes(32);
  const signedPreKey = await crypto.generateKeyPair();
  return {
    alice: await initRatchetAsInitiator(sharedSecret, signedPreKey.publicKey, crypto),
    bob: initRatchetAsResponder(sharedSecret, signedPreKey, crypto),
  };
}

describe('Double Ratchet', () => {
  it('round-trips messages in both directions', async () => {
    const { alice, bob } = await makePair();

    const m1 = await ratchetEncrypt(alice, utf8ToBytes('hello bob'), new Uint8Array(8), crypto);
    const p1 = await ratchetDecrypt(bob, m1.header, m1.ciphertext, new Uint8Array(8), crypto);
    expect(bytesToUtf8(p1)).toBe('hello bob');

    const m2 = await ratchetEncrypt(bob, utf8ToBytes('hi alice'), new Uint8Array(8), crypto);
    const p2 = await ratchetDecrypt(alice, m2.header, m2.ciphertext, new Uint8Array(8), crypto);
    expect(bytesToUtf8(p2)).toBe('hi alice');

    const m3 = await ratchetEncrypt(alice, utf8ToBytes('ratcheted'), new Uint8Array(8), crypto);
    const p3 = await ratchetDecrypt(bob, m3.header, m3.ciphertext, new Uint8Array(8), crypto);
    expect(bytesToUtf8(p3)).toBe('ratcheted');

    // Counters are chain-local: Alice opened a fresh sending chain after
    // receiving Bob's reply, so m3 restarts at 0 and reports the old length.
    expect(m1.header.counter).toBe(0);
    expect(m3.header.counter).toBe(0);
    expect(m3.header.previousCounter).toBe(1);
    expect(alice.sendCount).toBe(1);
    expect(bob.recvCount).toBe(1);
  });

  it('delivers out-of-order messages via skipped message keys', async () => {
    const { alice, bob } = await makePair();

    const envelopes = [];
    for (let i = 0; i < 5; i++) {
      envelopes.push(await ratchetEncrypt(alice, utf8ToBytes(`msg-${i}`), new Uint8Array(8), crypto));
    }
    const shuffled = [envelopes[3], envelopes[0], envelopes[4], envelopes[2], envelopes[1]];

    const received = [];
    for (const e of shuffled) {
      received.push(bytesToUtf8(await ratchetDecrypt(bob, e.header, e.ciphertext, new Uint8Array(8), crypto)));
    }
    expect(received.sort()).toEqual(['msg-0', 'msg-1', 'msg-2', 'msg-3', 'msg-4']);
    expect(bob.skippedKeys).toHaveLength(0); // all consumed
  });

  it('advances the DH ratchet on each direction change', async () => {
    const { alice, bob } = await makePair();

    const m1 = await ratchetEncrypt(alice, utf8ToBytes('a'), new Uint8Array(8), crypto);
    const aliceFirstKey = m1.header.ratchetKey; // A1
    const bobFirstKey = bob.dhSelfPublicKey; // Bob's signed prekey
    expect(bobFirstKey).not.toBe(aliceFirstKey);

    await ratchetDecrypt(bob, m1.header, m1.ciphertext, new Uint8Array(8), crypto);

    // Bob ratcheted on receipt: his reply uses a fresh key, not his signed prekey.
    const m2 = await ratchetEncrypt(bob, utf8ToBytes('b'), new Uint8Array(8), crypto);
    expect(m2.header.ratchetKey).not.toBe(bobFirstKey);

    // Alice ratchets on receipt: she now targets Bob's new key...
    await ratchetDecrypt(alice, m2.header, m2.ciphertext, new Uint8Array(8), crypto);
    expect(alice.dhRemotePublicKey).toBe(m2.header.ratchetKey);

    // ...and generates her own fresh sending key.
    const m3 = await ratchetEncrypt(alice, utf8ToBytes('c'), new Uint8Array(8), crypto);
    expect(m3.header.ratchetKey).not.toBe(aliceFirstKey);
  });

  it('rejects messages beyond the skip window', async () => {
    const { bob } = await makePair();
    // Header claims counter 1500 from an unseen ratchet key: deriving 1500 keys
    // exceeds maxSkip (1000) and must fail closed before any key is used.
    const fakeHeader = {
      ratchetKey: toBase64((await crypto.generateKeyPair()).publicKey),
      previousCounter: 0,
      counter: 1500,
    };
    await expect(
      ratchetDecrypt(bob, fakeHeader, crypto.randomBytes(64), new Uint8Array(8), crypto),
    ).rejects.toThrow(TooManySkippedMessagesError);
  });

  it('fails decryption on tampered ciphertext (wrong key)', async () => {
    const { alice, bob } = await makePair();
    const m1 = await ratchetEncrypt(alice, utf8ToBytes('secret'), new Uint8Array(8), crypto);
    const fake = { ...m1.header, counter: m1.header.counter + 100 };
    await expect(
      ratchetDecrypt(bob, fake, m1.ciphertext, new Uint8Array(8), crypto),
    ).rejects.toThrow();
  });

  it('keeps archived chains decryptable for late messages after a ratchet step', async () => {
    const { alice, bob } = await makePair();
    const early = await ratchetEncrypt(alice, utf8ToBytes('early'), new Uint8Array(8), crypto);
    const later = await ratchetEncrypt(alice, utf8ToBytes('later'), new Uint8Array(8), crypto);

    // Bob receives only the second message first (triggers ratchet + skip store).
    expect(bytesToUtf8(await ratchetDecrypt(bob, later.header, later.ciphertext, new Uint8Array(8), crypto))).toBe('later');
    // The early message still decrypts afterwards from the skipped keys.
    expect(bytesToUtf8(await ratchetDecrypt(bob, early.header, early.ciphertext, new Uint8Array(8), crypto))).toBe('early');
  });
});
