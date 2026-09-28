import { describe, expect, it } from 'vitest';
import { InMemorySignalStore } from '../src/stores/in-memory-store';
import { SignalClient } from '../src/protocol/signal-client';
import { NodeCryptoProvider } from '../src/crypto/node-crypto-provider';
import { encryptAttachment, decryptAttachment } from '../src/protocol/attachments';
import { utf8ToBytes, bytesToUtf8 } from '../src/util/bytes';
import { fromBase64, toBase64 } from '../src/util/base64';
import { DecryptionFailedError, SessionNotFoundError } from '../src/errors';

const crypto = new NodeCryptoProvider();

describe('encrypted attachments', () => {
  it('round-trips bytes with a fresh key each time', async () => {
    const payload = crypto.randomBytes(1024 * 33 + 7); // non-block-aligned size
    const first = await encryptAttachment(payload, crypto);
    const second = await encryptAttachment(payload, crypto);

    expect(first.key).not.toBe(second.key); // fresh key per file
    expect(first.ciphertext.length).toBe(payload.length + 12 + 16); // nonce + tag
    expect(Array.from(await decryptAttachment(first.key, first.ciphertext, crypto))).toEqual(
      Array.from(payload),
    );
  });

  it('binds optional AAD (e.g. filename/mime) and rejects tampering', async () => {
    const payload = utf8ToBytes('quarterly-report.pdf contents');
    const aad = utf8ToBytes('quarterly-report.pdf');

    const att = await encryptAttachment(payload, crypto, aad);
    expect(bytesToUtf8(await decryptAttachment(att.key, att.ciphertext, crypto, aad))).toBe(
      'quarterly-report.pdf contents',
    );

    await expect(decryptAttachment(att.key, att.ciphertext, crypto, utf8ToBytes('other.pdf'))).rejects.toThrow(
      DecryptionFailedError,
    );

    att.ciphertext[20] ^= 0xff;
    await expect(decryptAttachment(att.key, att.ciphertext, crypto, aad)).rejects.toThrow(
      DecryptionFailedError,
    );
  });

  it('rejects truncated ciphertext', async () => {
    await expect(decryptAttachment('aGk=', new Uint8Array(5), crypto)).rejects.toThrow();
  });

  it('fits the intended flow: ciphertext out-of-band, key through the ratchet', async () => {
    const store = new InMemorySignalStore();
    const alice = await SignalClient.create({ selfId: 'alice', stores: store });
    const bob = await SignalClient.create({ selfId: 'bob', stores: store });
    await alice.createSessionFromBundle('bob.1', await bob.getPreKeyBundle());

    const secretFile = crypto.randomBytes(2048);
    const attachment = await encryptAttachment(secretFile, crypto);

    // 1. Upload attachment.ciphertext anywhere; tell bob where it is (plaintext ok).
    // 2. Send ONLY the key through the encrypted channel:
    const keyMessage = await alice.encrypt('bob.1', fromBase64(attachment.key));
    const key = await bob.decrypt('alice.1', keyMessage);

    // 3. Bob fetches the ciphertext and decrypts locally.
    const recovered = await decryptAttachment(toBase64(key), attachment.ciphertext, crypto);
    expect(Array.from(recovered)).toEqual(Array.from(secretFile));
    void SessionNotFoundError;
  });
});
