import { CryptoProvider } from '../crypto/crypto-provider';
import { OneTimePreKeyRecordDTO, SignedPreKeyRecordDTO, keyPairToDTO } from './types';
import { toBase64 } from '../util/base64';

/**
 * Generate a signed prekey record. The public key is signed with the Ed25519
 * identity signing key so that bundles can be authenticated by strangers.
 */
export async function generateSignedPreKeyRecord(
  id: number,
  identitySigningPrivateKey: Uint8Array,
  crypto: CryptoProvider,
): Promise<SignedPreKeyRecordDTO> {
  const pair = await crypto.generateKeyPair();
  const signature = await crypto.sign(identitySigningPrivateKey, pair.publicKey);
  return {
    id,
    keyPair: keyPairToDTO(pair),
    signature: toBase64(signature),
    createdAt: Date.now(),
  };
}

/** Generate a one-time prekey record. */
export async function generateOneTimePreKeyRecord(id: number, crypto: CryptoProvider): Promise<OneTimePreKeyRecordDTO> {
  return { id, keyPair: keyPairToDTO(await crypto.generateKeyPair()) };
}
