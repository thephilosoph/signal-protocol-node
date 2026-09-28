# signal-protocol-node

A TypeScript implementation of the **Signal Protocol** (X3DH key agreement + Double Ratchet) for **Node.js and NestJS**. Build end-to-end encrypted messaging into any application with a small, transport-agnostic API and pluggable storage.

```
npm install signal-protocol-node
```

- 🔐 **X3DH** — asynchronous key agreement between strangers (identity + signed prekeys + optional one-time prekeys)
- 🔁 **Double Ratchet** — per-message forward secrecy, post-compromise security, out-of-order delivery
- 👥 **Group chats, two modes** — pairwise fan-out for small groups, **Sender Keys** (O(1), signed) for large ones
- 📱 **Multi-device** — per-device identities and sessions, device fan-out, multi-device safety numbers
- ✔️ **Safety numbers** — 60-digit out-of-band identity verification, identical on all sides
- 🔑 **Prekey rotation** — rotate and prune signed prekeys on a schedule
- 📎 **Encrypted attachments** — big payload out-of-band, key through the ratchet
- 🧩 **Pluggable storage** — implement one interface, back it with Prisma, TypeORM, Redis, MongoDB... (in-memory adapters included)
- 🪶 **Transport-agnostic** — JSON envelopes by default, **compact binary encoding** when bandwidth matters
- 🟩 **NestJS integration** — `SignalModule.forRoot()` / `forRootAsync()` and a multi-user `SignalService`
- 🌐 **Two crypto backends** — Node (`node:crypto` + noble) or **WebCrypto** (browsers/edge/Node ≥ 18.4)
- ✅ **Tested** — 92 tests: RFC 7748/8032/5869 vectors, Google Wycheproof, full end-to-end conversations, groups, multi-device, NestJS

> **Status:** v0.1.0 — protocol core, groups (both modes), verification, attachments, binary envelopes, WebCrypto and multi-device groundwork complete. An independent security review is recommended before production use.

---

## Table of contents

- [How it works in 30 seconds](#how-it-works-in-30-seconds)
- [Quick start (plain Node.js)](#quick-start-plain-nodejs)
- [Group chats](#group-chats)
- [Identity verification (safety numbers)](#identity-verification-safety-numbers)
- [Signed prekey rotation](#signed-prekey-rotation)
- [Encrypted attachments](#encrypted-attachments)
- [Using it in NestJS](#using-it-in-nestjs)
- [Wiring up a real transport](#wiring-up-a-real-transport)
- [Persistent storage adapters](#persistent-storage-adapters)
- [API reference](#api-reference)
- [Security notes](#security-notes)
- [Development](#development)
- [Documentation](#documentation)

---

## How it works in 30 seconds

Every participant (user or device) has a `SignalClient` — one local identity with:

1. **Identity keys** — a long-term X25519 key (for Diffie-Hellman) and an Ed25519 key (for signing).
2. **A signed prekey** — a medium-lived X25519 key, signed by the identity key.
3. **One-time prekeys** — short-lived keys that make the first message forward-secret.

To message a stranger you fetch their **prekey bundle** (published via your app's server), run **X3DH** to establish a shared secret, and from then on every message is protected by the **Double Ratchet**: each message uses a key derived from a hash chain, and the chain re-keys with a fresh Diffie-Hellman every time the direction of the conversation flips. The result: stealing current keys does not reveal past messages (forward secrecy), and a stolen session heals itself as new messages flow (post-compromise security).

You never touch any of that directly — the API is four calls: `createSessionFromBundle`, `encrypt`, `send it yourself`, `decrypt`.

---

## Quick start (plain Node.js)

```ts
import { SignalClient, InMemorySignalStore } from 'signal-protocol-node';

// One client per local identity. `stores` is where keys/sessions persist —
// swap InMemorySignalStore for a database-backed adapter in production.
const store = new InMemorySignalStore();
const alice = await SignalClient.create({ selfId: 'alice', stores: store });
const bob = await SignalClient.create({ selfId: 'bob', stores: store });

// 1. Bob publishes his bundle (in a real app your server hands this out).
const bobBundle = await bob.getPreKeyBundle({ consumeOneTime: true });

// 2. Alice establishes a session from it. Address format: "<name>.<deviceId>".
await alice.createSessionFromBundle('bob.1', bobBundle);

// 3. Encrypt. Returns a JSON envelope — send it however you like.
const envelope = await alice.encryptText('bob.1', 'hello bob');
// envelope.type === 'prekey' on the first message: it carries the X3DH material.

// 4. Decrypt on the other side. Nothing else to configure.
const plaintext = await bob.decryptText('alice.1', envelope);
console.log(plaintext); // "hello bob"

// Replies work immediately; every message after this is a regular envelope.
const reply = await bob.encryptText('alice.1', 'hi alice');
await alice.decryptText('bob.1', reply);
```

That's the whole protocol flow. Out-of-order delivery, ratcheting, prekey consumption, session persistence and identity-change detection are all handled for you.

Binary payloads work too — `encrypt()`/`decrypt()` accept and return `Uint8Array`:

```ts
const env = await alice.encrypt('bob.1', new Uint8Array([1, 2, 3]));
const bytes = await bob.decrypt('alice.1', env);
```

A runnable version of this lives in [`examples/basic-usage.ts`](examples/basic-usage.ts).

---

## Group chats — two modes

`SignalGroup` supports both group strategies; choose per group at creation.

### Mode 1: pairwise fan-out (default — small/medium groups)

Encrypt once *per member* through each member's own Double Ratchet session. Every member
gets full pairwise security; receivers need **no group logic** — they decrypt with the
ordinary `decrypt()` they already use.

```ts
const group = SignalGroup.create(alice, 'team-alpha');           // mode: 'fanout'
await group.addMember('bob.1', bobBundle);
await group.addMember('carol.1', carolBundle);

const groupEnvelope = await group.encryptText('standup in 5');
// → { version: 1, type: 'group', groupId, from: 'alice',
//     messages: { 'bob.1': {...}, 'carol.1': {...} } }

// Each recipient decrypts their own envelope:
const plaintext = await bob.decryptText('alice.1', groupEnvelope.messages['bob.1']);
```

### Mode 2: Sender Keys (large groups — one encryption per message)

The sender distributes a symmetric chain key to every member **over the pairwise
sessions**, then encrypts each group message **once** (O(1)), signed with a
per-distribution Ed25519 key so every member can attribute the message. This is
Signal's large-group design; the trade-off is weaker forward secrecy — every member
holds the chain key until the next rotation (see [SIGNAL_PROTOCOL.md §10](docs/SIGNAL_PROTOCOL.md)).

```ts
const group = SignalGroup.create(alice, 'town-hall', { mode: 'sender-keys' });
await group.addMember('bob.1', bobBundle);
await group.addMember('carol.1', carolBundle);
// members also need sessions TO alice so her distribution can reach them:
await bobGroupHandle.addMember('alice.1', aliceBundle);   // on bob's side

// 1. Distribute the chain key pairwise (after creating the group and after
//    EVERY membership change — rotation is how removed members lose access):
const distributions = await group.createDistribution();
for (const [address, envelope] of Object.entries(distributions)) {
  sendPairwise(address, envelope);                        // your transport
}

// 2. Then every message costs exactly one encryption:
const skMessage = await group.encryptOnceText('one ciphertext for 500 people');
sendToGroupChannel(skMessage);
```

**On the receiving side**, each member runs their own sender-keys group handle and
routes incoming pairwise envelopes through it — distributions are consumed
automatically, normal messages pass through:

```ts
const bobGroup = SignalGroup.create(bob, 'town-hall', { mode: 'sender-keys' });
await bobGroup.addMember('alice.1', aliceBundle);

socket.on('pairwise', async ({ from, envelope }) => {
  const plaintext = await bobGroup.onPairwiseMessage(from, envelope);
  if (plaintext === null) return;                  // was a sender-key distribution
  handleMessage(from, plaintext);                  // your normal pairwise message
});

socket.on('group', async ({ from, message }) => {
  const text = await bobGroup.decryptOnceText(from, message);  // verifies signature
});
```

Membership: adding a member = `addMember` + re-`createDistribution` (so they get the
current chain key). Removing = `removeMember` + re-`createDistribution` (revocation).
Prune stale chains with `pruneSenderKeys(keep)`. Sender-key state persists through the
pluggable `GroupStore` (in-memory by default, pass your own adapter for databases).

---

## Identity verification (safety numbers)

The protocol pins remote identities on first contact (TOFU). To actually detect a
man-in-the-middle, compare a **safety number** out of band (voice call, QR code) —
both parties compute the *same* 60 digits:

```ts
const digits = await alice.getSafetyNumber('bob.1'); // "17 22 ..." → 60 digits
alice.formatSafetyNumber(digits);                    // "12345 67890 ..." (12 × 5)
```

```ts
// NestJS
const digits = await signal.getSafetyNumber(userId, remoteAddress);
```

If Bob's identity key ever changes, `decrypt`/`createSessionFromBundle` throw
`IdentityKeyChangedError` before anything is trusted — verify the new safety number
out of band, then explicitly reset (`deleteSession` + `removeRemoteIdentity`).

**Multi-device verification:** safety numbers are computed over a *set* of identity
keys, so all devices of both parties can produce the same digits. Devices that haven't
talked yet learn each other's identity from your server's directory:

```ts
// seed from your device directory, then verify the whole device set
await client.recordRemoteIdentity('bob.2', bobTabletDhKey, bobTabletSigningKey);
const digits = await alice.getSafetyNumber(['bob.1', 'bob.2']);
```

---

## Multi-device

Every device is a first-class protocol endpoint with **its own identity keys and
prekeys** (the Signal model). The storage scope of a client is `"<selfId>.<deviceId>"`,
so one shared store safely hosts every device of every user.

```ts
// Bob runs two devices — two clients, two identities, one store:
const bobPhone  = await SignalClient.create({ selfId: 'bob', deviceId: 1, stores: store });
const bobTablet = await SignalClient.create({ selfId: 'bob', deviceId: 2, stores: store });

bobPhone.ownAddress;                       // "bob.1"
(await bobTablet.getPreKeyBundle()).deviceId; // 2

// Alice reaches each device by address, or fans out to all devices at once:
const group = SignalGroup.create(alice, 'chat');
await group.addUserDevices('bob', {
  1: await bobPhone.getPreKeyBundle(),
  2: await bobTablet.getPreKeyBundle(),
});

// Group sessions by user for UI purposes:
import { partitionAddressesByUser } from 'signal-protocol-node';
partitionAddressesByUser(await alice.listSessionAddresses());
// → { bob: ['bob.1', 'bob.2'] }
```

---

## Choosing a crypto backend

The whole protocol runs on the `CryptoProvider` interface (all async). Two shipped
implementations:

```ts
import { NodeCryptoProvider, WebCryptoProvider } from 'signal-protocol-node';

const node = await SignalClient.create({ selfId: 'a', crypto: new NodeCryptoProvider() });
const web  = await SignalClient.create({ selfId: 'b', crypto: new WebCryptoProvider() });
```

| | `NodeCryptoProvider` | `WebCryptoProvider` |
| --- | --- | --- |
| Runtime | Node.js (any) | Node ≥ 18.4, browsers with X25519/Ed25519, edge |
| Curves | @noble/curves (pure JS) | `crypto.subtle` (native) |
| AES-GCM | `node:crypto` (native) | `crypto.subtle` (native) |
| Use when | Server-side only | Browser clients, edge functions, mixed fleets |

Providers are **interoperable**: a Node client and a WebCrypto client converse
end-to-end (tested). Custom providers (HSM, remote signing) implement the same 11
methods.

---

## Compact binary envelopes

JSON is the default wire format. When bandwidth matters, encode pairwise envelopes
to a compact binary form (~50% smaller) — `decrypt` accepts both:

```ts
import { encodeSignalEnvelope } from 'signal-protocol-node';

socket.send(encodeSignalEnvelope(await alice.encrypt('bob.1', text)));
// receiver — both forms work:
const pt = await bob.decrypt('alice.1', rawBytes);          // auto-detected
const pt2 = await bob.decrypt('alice.1', decodeSignalEnvelope(rawBytes));
```


---

## Signed prekey rotation

Signed prekeys should be rotated periodically (weekly is a common cadence). Old keys
are kept for a grace period because peers may still hold cached bundles, then pruned:

```ts
await bob.rotateSignedPreKey();     // new sessions use the fresh key; existing sessions unaffected
await bob.pruneSignedPreKeys(2);    // keep the 2 newest, drop older ones

// NestJS
await signal.rotateSignedPreKey(userId);
const removed = await signal.pruneSignedPreKeys(userId, 2);
```

Only prune keys older than the longest bundle-cache delay in your deployment — a peer
holding a pruned bundle gets a loud `PreKeyNotFoundError` on first message (tested).

---

## Encrypted attachments

The standard pattern for files: encrypt once with a random key, upload the ciphertext
anywhere (S3, CDN...), and send **only the key** through the Double Ratchet channel.

```ts
import { encryptAttachment, decryptAttachment } from 'signal-protocol-node';

// 1. Encrypt the payload (optional AAD binds e.g. filename/mime type).
const attachment = encryptAttachment(fileBytes, crypto, utf8ToBytes('report.pdf'));
// attachment.ciphertext = nonce(12) || ciphertext || tag(16)  → upload this blob

// 2. Send the key through the encrypted message channel:
await alice.encrypt('bob.1', fromBase64(attachment.key));

// 3. Bob downloads the ciphertext and decrypts locally:
const file = decryptAttachment(keyFromMessage, downloadedCiphertext, crypto, utf8ToBytes('report.pdf'));
```

One-shot AES-256-GCM per file — right for payloads up to tens of MB; chunk very large
media (streaming helpers are on the roadmap).

---

## Using it in NestJS

The package ships a second entry point, `signal-protocol-node/nest`, with a dynamic module and a multi-user service. Install the package into your Nest app (`@nestjs/common` is an optional peer dependency you already have):

```ts
// app.module.ts
import { Module } from '@nestjs/common';
import { SignalModule } from 'signal-protocol-node/nest';

@Module({
  imports: [
    SignalModule.forRoot({
      // one store instance for all users; each client scopes its keys by user id
      // store: new PrismaSignalStore(prisma),   // ← your adapter (see below)
    }),
  ],
})
export class AppModule {}
```

Then inject `SignalService` anywhere. It manages one protocol client **per user id** — the typical shape of a chat backend where the server holds the users' protocol state:

```ts
import { Injectable } from '@nestjs/common';
import { SignalService } from 'signal-protocol-node/nest';

@Injectable()
export class ChatService {
  constructor(private readonly signal: SignalService) {}

  // When a user signs up: create identity + prekeys, publish their bundle.
  async onUserRegistered(userId: string) {
    const bundle = await this.signal.registerUser(userId);
    await this.bundleRepository.save({ userId, bundle }); // serve this to their peers
  }

  // When someone asks "give me alice's bundle so I can message her":
  async serveBundle(userId: string) {
    return this.signal.getPreKeyBundle(userId, { consumeOneTime: true });
  }

  // On the message path (e.g. inside a WebSocket gateway):
  async handleIncoming(from: string, to: string, envelope: unknown) {
    // Envelope arrives addressed to `to`; the server just relays it.
    const plaintext = await this.signal.decryptText(to, from, envelope);
    await this.storeMessage(from, to, plaintext);

    const reply = await this.signal.encrypt(to, from, 'got it');
    return reply; // send this JSON envelope back over the socket
  }

  // Starting a session from a peer's bundle:
  async startSession(userId: string, remoteAddress: string, bundle: unknown) {
    await this.signal.initiateSession(userId, remoteAddress, bundle);
  }
}
```

### Async configuration

Use `forRootAsync` when the store needs other providers (config, ORM clients):

```ts
SignalModule.forRootAsync({
  imports: [PrismaModule],
  inject: [PrismaService],
  useFactory: (prisma: PrismaService) => ({
    storeFactory: (userId: string) => new PrismaSignalStore(prisma, userId),
    defaultOneTimePreKeyCount: 100,
  }),
})
```

### `SignalService` API

| Method | Purpose |
| --- | --- |
| `getClient(userId)` | Raw `SignalClient` for the user (lazily created, cached) |
| `registerUser(userId, opts?)` | Create identity + prekeys; returns the user's bundle |
| `getPreKeyBundle(userId, { consumeOneTime? })` | Bundle to serve to peers (reserves a one-time prekey by default) |
| `topUpOneTimePreKeys(userId, target?)` | Keep enough unreserved one-time prekeys in stock |
| `initiateSession(userId, remoteAddress, bundle)` | X3DH session setup as initiator |
| `hasSession / deleteSession / listSessions` | Session lifecycle |
| `encrypt(userId, remote, textOrBytes)` | Returns the envelope to transmit |
| `decrypt / decryptText(userId, remote, envelope)` | Plaintext from a received envelope |
| `getGroup(userId, groupId, { mode? })` | Group handle (`'fanout'` default or `'sender-keys'`), cached |
| `addToGroup / addUserToGroup / removeFromGroup / listGroupMembers` | Group membership (multi-device aware) |
| `encryptGroup(userId, groupId, textOrBytes)` | Fan-out encrypt → `GroupEnvelopeJSON` |
| `createGroupDistribution(userId, groupId)` | Sender Keys: distribute/rotate chain key pairwise |
| `encryptGroupOnce / decryptGroupOnce` | Sender Keys O(1) group encrypt/decrypt |
| `onGroupPairwiseMessage(userId, groupId, from, envelope)` | Receiver routing (accepts distributions, returns normal plaintext) |
| `rotateGroupDistribution(userId, groupId)` | Re-key the group after membership changes |
| `getSafetyNumber(userId, remote \| remotes[])` | 60-digit identity verification number |
| `getOwnAddress(userId, deviceId?)` | The user device's address |
| `rotateSignedPreKey(userId)` / `pruneSignedPreKeys(userId, keep?)` | Prekey rotation |
| `evictClient(userId)` | Drop cached clients of all devices (next access rehydrates) |

---

## Wiring up a real transport

The library is deliberately transport-free. Envelopes are plain JSON, so any channel works. A minimal WebSocket gateway sketch:

```ts
// Client side
socket.on('signal-message', async ({ from, envelope }) => {
  const plaintext = await client.decryptText(from, envelope); // from = "alice.1"
  const reply = await client.encryptText(from, 'thanks!');
  socket.emit('signal-message', { from: myAddress, envelope: reply });
});
```

Rules of thumb:

- **Never modify an envelope.** Hand `decrypt` exactly what you received (parsed JSON is fine).
- Envelopes are **address-independent** — routing (who sends what to whom) is your server's job; the protocol only cares about the sender's address string you pass to `decrypt`.
- The **first** message of a session is a `prekey` envelope; if it gets lost, the next message is also a prekey envelope (the session isn't confirmed until the initiator successfully decrypts something).

---

## Persistent storage adapters

All protocol state goes through one interface:

```ts
interface SignalStore {
  // identity (scoped by selfId)
  getIdentityKeyPair(scope): Promise<IdentityKeyPairDTO | null>;
  saveIdentityKeyPair(scope, keyPair): Promise<void>;
  getRemoteIdentity(scope, address): Promise<RemoteIdentityDTO | null>;
  saveRemoteIdentity(scope, address, identity): Promise<void>;
  removeRemoteIdentity(scope, address): Promise<void>;
  // prekeys
  saveSignedPreKey / getSignedPreKey / removeSignedPreKey / listSignedPreKeyIds
  saveOneTimePreKey / getOneTimePreKey / removeOneTimePreKey / listOneTimePreKeyIds
  // sessions
  loadSession(scope, address): Promise<SessionRecordDTO | null>;
  storeSession(scope, address, record): Promise<void>;
  deleteSession(scope, address): Promise<void>;
  listSessionAddresses(scope): Promise<string[]>;
}
```

Every record is a **plain JSON-serializable object**, so the simplest adapter is a generic KV store (all of Prisma/TypeORM/Redis/Mongo can serve as one). For example with Prisma:

```ts
// schema.prisma
model SignalKV {
  key   String @id
  value Json
}

// signal-store.ts
import { SignalStore } from 'signal-protocol-node';

export class PrismaSignalStore implements SignalStore {
  constructor(private prisma: PrismaService, private scopePrefix = '') {}

  private k(...parts: (string | number)[]) {
    return [this.scopePrefix, ...parts].join('|');
  }
  private async get<T>(key: string): Promise<T | null> {
    const row = await this.prisma.signalKV.findUnique({ where: { key } });
    return (row?.value as T) ?? null;
  }
  private async put(key: string, value: unknown) {
    await this.prisma.signalKV.upsert({
      where: { key },
      update: { value: value as any },
      create: { key, value: value as any },
    });
  }

  async getIdentityKeyPair(scope: string) { return this.get(this.k('id', scope)); }
  async saveIdentityKeyPair(scope: string, kp: IdentityKeyPairDTO) { await this.put(this.k('id', scope), kp); }
  async getRemoteIdentity(scope: string, address: string) { return this.get(this.k('rid', scope, address)); }
  async saveRemoteIdentity(scope: string, address: string, rec: RemoteIdentityDTO) { await this.put(this.k('rid', scope, address), rec); }
  async removeRemoteIdentity(scope: string, address: string) { await this.prisma.signalKV.deleteMany({ where: { key: this.k('rid', scope, address) } }); }

  async saveSignedPreKey(scope: string, id: number, rec: SignedPreKeyRecordDTO) { await this.put(this.k('spk', scope, id), rec); }
  async getSignedPreKey(scope: string, id: number) { return this.get(this.k('spk', scope, id)); }
  async removeSignedPreKey(scope: string, id: number) { await this.prisma.signalKV.deleteMany({ where: { key: this.k('spk', scope, id) } }); }
  async listSignedPreKeyIds(scope: string) { /* SELECT keys LIKE 'spk|scope|%', parse trailing number */ }

  // ...one-time prekeys and sessions follow the same pattern
}
```

(The full file is a mechanical exercise — see [`src/stores/in-memory-store.ts`](src/stores/in-memory-store.ts) for the exact contract, including the id-listing methods.)

Because `scope` is part of the interface (not the adapter), **one store instance serves every user** — that's what `SignalService` does under the hood. Prefer dedicated instances per user? Pass a `storeFactory` to the Nest module instead.

---

## API reference

### `SignalClient`

| Member | Description |
| --- | --- |
| `SignalClient.create(options?)` | Create or rehydrate a client. Options: `selfId`, `stores`, `crypto`, `config`, `identityKeyPair` (import existing identity). |
| `getPreKeyBundle({ consumeOneTime? })` | Bundle for peers. `consumeOneTime` reserves a one-time prekey (use when *serving* bundles). |
| `generatePreKeys(startId, count)` / `generateSignedPreKey(id?)` | Prekey management (auto-done on first `create`). |
| `createSessionFromBundle(address, bundle)` | X3DH initiator. Verifies the bundle signature; archives any existing session. |
| `encrypt(address, bytes)` / `encryptText(address, text)` | Returns the envelope to transmit. |
| `decrypt(address, envelope)` / `decryptText(address, envelope)` | Plaintext. Handles prekey and regular envelopes transparently. |
| `hasSession / deleteSession / listSessionAddresses` | Session lifecycle. |
| `getRemoteIdentity(address)` / `removeRemoteIdentity(address)` | TOFU identity records. |
| `getSafetyNumber(address)` | 60-digit verification number (order-independent; both sides see the same digits). |
| `rotateSignedPreKey()` / `pruneSignedPreKeys(keep)` | Signed prekey rotation with grace period. |
| `getIdentityKeyPair()` | The local identity (persist after first creation if you import/export it). |

Group API lives on `SignalGroup` (`SignalGroup.create(client, groupId, { mode })`):
fan-out `encrypt`/`encryptText` → `GroupEnvelopeJSON`, sender-keys
`createDistribution`/`encryptOnce`/`decryptOnce`/`rotateDistribution`, plus
`addMember`/`addUserDevices`/`removeMember`. Attachments:
`encryptAttachment` / `decryptAttachment` standalone helpers.

### Configuration (`config`)

| Option | Default | Meaning |
| --- | --- | --- |
| `maxSkip` | 1000 | Max message keys derived ahead for out-of-order delivery per chain |
| `archivedStatesLimit` | 5 | Superseded ratchet states kept for late messages |
| `autoGeneratePreKeys` | true | Generate identity + prekeys on first `create()` |
| `oneTimePreKeyCount` | 50 | One-time prekeys generated on first `create()` |
| `x3dhInfo` | library default | HKDF info string for X3DH (namespace per deployment) |

### Error handling

Everything throws a subclass of `SignalError`:

| Error | Meaning | Suggested handling |
| --- | --- | --- |
| `SessionNotFoundError` | No session with that address | Fetch their bundle and `createSessionFromBundle` |
| `IdentityKeyChangedError` | Peer's identity key changed (re-registration or MITM) | Verify out of band (safety number), then `deleteSession` + `removeRemoteIdentity` if accepted |
| `SignatureVerificationError` / `InvalidPreKeyBundleError` | Bundle invalid or forged | Don't trust the source |
| `MessageDecryptError` | Tampered/replayed message, or no matching state | Log and drop (replays are expected to fail) |
| `TooManySkippedMessagesError` | Counter gap beyond `maxSkip` | Treat as a desynced session; re-establish |
| `PreKeyNotFoundError` | Referenced prekey gone (used/replayed/pruned bundle) | Usually safe to drop; sender will re-initiate |
| `RemoteIdentityNotFoundError` | Safety number requested before any contact | Create a session or receive a message first |
| `SenderKeyNotFoundError` | Group message without an accepted distribution | Deliver the sender's distribution over the pairwise channel |
| `GroupEncryptionError` | Fan-out/distribution failed (cause carries the address), or mode misuse | Surface to the sender; check member sessions and mode |
| `InvalidMessageError` | Envelope failed structural validation | Bug or garbage on the wire |

---

## Security notes

- **Storage holds private keys.** Whatever backs `SignalStore` must be protected at rest (disk encryption, DB access control). Encrypting the DTOs before persisting is straightforward and recommended for high-risk deployments.
- **Identity verification.** The protocol authenticates identities via TOFU (Trust On First Use). For real-world safety, surface remote identity keys (via `getRemoteIdentity`) as a safety number / QR code and verify out of band.
- **Replays and tampering are rejected** by the Double Ratchet + AES-GCM; treat `MessageDecryptError` as routine noise on the wire.
- **Both sides initiating at once** is supported (archived states), but the cleanest pattern is a deterministic initiator (e.g. lexicographically smaller id initiates).
- **Deviation from the original spec:** identity keys are split into an X25519 DH key + an Ed25519 signing key instead of XEdDSA on a single curve — a design used by other Double Ratchet implementations (e.g. Olm) and documented in [docs/SIGNAL_PROTOCOL.md](docs/SIGNAL_PROTOCOL.md). This library does **not** interoperate with libsignal wire formats.


---

## Development

```bash
npm install
npm test        # 92 tests: units, RFC/Wycheproof vectors, e2e, groups, multi-device, NestJS
npm run typecheck
npm run build   # dual CJS/ESM + .d.ts via tsup (dist/index and dist/nest)
npx tsx examples/basic-usage.ts
```

Project layout:

```
src/
  crypto/      CryptoProvider (Strategy): Node + WebCrypto implementations
  x3dh/        X3DH key agreement
  ratchet/     Double Ratchet (root/chain KDFs, DH ratchet, skipped keys)
  session/     SessionRecord + SessionCipher (clone-then-commit decrypt)
  stores/      SignalStore interface (Ports & Adapters) + in-memory adapter
  protocol/    SignalClient facade, envelopes, binary encoding, bundles,
               safety numbers, attachments, multi-device helpers
  group/       SignalGroup (fan-out + Sender Keys), GroupStore + adapters
  nest/        SignalModule + SignalService (NestJS integration)
test/          vitest suites
docs/          protocol, architecture, design patterns, rebuild guide
.github/       CI + npm publish workflows
```

---

## Documentation

- [docs/SIGNAL_PROTOCOL.md](docs/SIGNAL_PROTOCOL.md) — protocol explanation incl. group messaging (§10)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — layers, data flows, storage contracts, extension points
- [docs/DESIGN_PATTERNS.md](docs/DESIGN_PATTERNS.md) — the design patterns used and why
- Original protocol papers: [X3DH](https://signal.org/docs/specifications/x3dh/) · [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)

## License

MIT — see [LICENSE](LICENSE).
