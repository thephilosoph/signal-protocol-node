import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../src/crypto/node-crypto-provider';
import { SignatureVerificationError } from '../src/errors';
import { initiateX3dh, receiveX3dh } from '../src/x3dh/x3dh';
import { KeyPair } from '../src/crypto/crypto-provider';

const crypto = new NodeCryptoProvider();

interface TestIdentity {
  dh: KeyPair;
  signing: KeyPair;
}

async function makeIdentity(): Promise<TestIdentity> {
  return { dh: await crypto.generateKeyPair(), signing: await crypto.generateSigningKeyPair() };
}

describe('X3DH', () => {
  it('derives the same shared secret on both sides (with one-time prekey)', async () => {
    const alice = await makeIdentity();
    const bob = await makeIdentity();
    const bobSignedPreKey = await crypto.generateKeyPair();
    const bobOneTimePreKey = await crypto.generateKeyPair();
    const signature = await crypto.sign(bob.signing.privateKey, bobSignedPreKey.publicKey);

    const init = await initiateX3dh({
      ourIdentityDhKeyPair: alice.dh,
      theirBundle: {
        identityDhKey: bob.dh.publicKey,
        identitySigningKey: bob.signing.publicKey,
        signedPreKey: bobSignedPreKey.publicKey,
        signedPreKeySignature: signature,
        oneTimePreKey: bobOneTimePreKey.publicKey,
      },
      crypto,
    });

    const receipt = await receiveX3dh({
      ourIdentityDhKeyPair: bob.dh,
      ourSignedPreKeyPair: bobSignedPreKey,
      ourOneTimePreKeyPair: bobOneTimePreKey,
      theirIdentityDhKey: alice.dh.publicKey,
      theirEphemeralKey: init.ephemeralKeyPair.publicKey,
      crypto,
    });

    expect(Array.from(init.sharedSecret)).toEqual(Array.from(receipt.sharedSecret));
    expect(Array.from(init.associatedData)).toEqual(Array.from(receipt.associatedData));
    expect(Array.from(init.associatedData)).toEqual(
      Array.from(new Uint8Array([...alice.dh.publicKey, ...bob.dh.publicKey])),
    );
  });

  it('derives the same shared secret without a one-time prekey', async () => {
    const alice = await makeIdentity();
    const bob = await makeIdentity();
    const bobSignedPreKey = await crypto.generateKeyPair();
    const signature = await crypto.sign(bob.signing.privateKey, bobSignedPreKey.publicKey);

    const init = await initiateX3dh({
      ourIdentityDhKeyPair: alice.dh,
      theirBundle: {
        identityDhKey: bob.dh.publicKey,
        identitySigningKey: bob.signing.publicKey,
        signedPreKey: bobSignedPreKey.publicKey,
        signedPreKeySignature: signature,
        oneTimePreKey: null,
      },
      crypto,
    });

    const receipt = await receiveX3dh({
      ourIdentityDhKeyPair: bob.dh,
      ourSignedPreKeyPair: bobSignedPreKey,
      theirIdentityDhKey: alice.dh.publicKey,
      theirEphemeralKey: init.ephemeralKeyPair.publicKey,
      crypto,
    });

    expect(Array.from(init.sharedSecret)).toEqual(Array.from(receipt.sharedSecret));
  });

  it('rejects bundles whose signed prekey signature does not verify', async () => {
    const alice = await makeIdentity();
    const bob = await makeIdentity();
    const attacker = await makeIdentity();
    const bobSignedPreKey = await crypto.generateKeyPair();
    const attackerSignature = await crypto.sign(attacker.signing.privateKey, bobSignedPreKey.publicKey);

    await expect(
      initiateX3dh({
        ourIdentityDhKeyPair: alice.dh,
        theirBundle: {
          identityDhKey: bob.dh.publicKey,
          identitySigningKey: bob.signing.publicKey,
          signedPreKey: bobSignedPreKey.publicKey,
          signedPreKeySignature: attackerSignature,
          oneTimePreKey: null,
        },
        crypto,
      }),
    ).rejects.toThrow(SignatureVerificationError);
  });

  it('produces different shared secrets for different ephemerals (freshness)', async () => {
    const alice = await makeIdentity();
    const bob = await makeIdentity();
    const bobSignedPreKey = await crypto.generateKeyPair();
    const signature = await crypto.sign(bob.signing.privateKey, bobSignedPreKey.publicKey);
    const bundle = {
      identityDhKey: bob.dh.publicKey,
      identitySigningKey: bob.signing.publicKey,
      signedPreKey: bobSignedPreKey.publicKey,
      signedPreKeySignature: signature,
      oneTimePreKey: null,
    };

    const first = await initiateX3dh({ ourIdentityDhKeyPair: alice.dh, theirBundle: bundle, crypto });
    const second = await initiateX3dh({ ourIdentityDhKeyPair: alice.dh, theirBundle: bundle, crypto });
    expect(Array.from(first.sharedSecret)).not.toEqual(Array.from(second.sharedSecret));
  });
});
