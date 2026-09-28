# Architecture

This document describes how the library is structured, how data flows through it, and where you can extend it. Companion documents: [SIGNAL_PROTOCOL.md](SIGNAL_PROTOCOL.md) explains the cryptography, [DESIGN_PATTERNS.md](DESIGN_PATTERNS.md) catalogs the patterns.

## 1. The layer stack

The library is a strictly layered core with the framework integration bolted on as a peer entry point. Dependencies point downward only.

```
┌───────────────────────────────────────────────────────────────────┐
│  Your application (Node.js service, NestJS app, CLI, ...)         │
│      transports envelopes over your own channel                   │
└───────────────┬───────────────────────────────┬───────────────────┘
                │                               │
┌───────────────▼───────────────┐   ┌───────────▼───────────────────┐
│  NestJS integration  (src/nest)│   │  Protocol facade (src/protocol)│
│  SignalModule (dynamic module) │──►│  SignalClient  ← the public API │
│  SignalService (multi-user)    │   └───────┬───────────────────────┘
└───────────────┬───────────────┘           │
                │                   ┌───────▼────────────────────────┐
                │                   │  Session layer (src/session)   │
                │                   │  SessionRecord + SessionCipher │
                │                   └───────┬────────────────────────┘
                │             ┌─────────────┼─────────────┐
                │   ┌─────────▼──────┐ ┌────▼─────────┐ ┌─▼──────────────┐
                │   │ X3DH (src/x3dh)│ │Double Ratchet│ │Bundle/Envelope │
                │   │ key agreement  │ │(src/ratchet) │ │(src/protocol)  │
                │   └─────────┬──────┘ └────┬─────────┘ └─┬──────────────┘
                │             └─────────────┼─────────────┘
                │                   ┌───────▼────────────────────────┐
                │                   │  Crypto (src/crypto)           │
                │                   │  CryptoProvider (interface)    │
                │                   │  NodeCryptoProvider (default)  │
                │                   └───────┬────────────────────────┘
                │                   ┌───────▼────────────────────────┐
                └──────────────────►│  Storage (src/stores)          │
                    your adapters   │  SignalStore (interface)       │
                                    │  InMemorySignalStore (default) │
                                    └────────────────────────────────┘
```

Key rule: **the protocol core knows nothing about transports or persistence.** It hands you JSON envelopes and accepts JSON envelopes; it asks a `SignalStore` interface for state. Everything else is your choice.

## 2. Module responsibilities

| Module | Responsibility | Key exports |
| --- | --- | --- |
| `src/crypto` | Abstract primitive set (async) + Node & WebCrypto implementations | `CryptoProvider`, `NodeCryptoProvider`, `WebCryptoProvider` |
| `src/util` | base64, byte helpers, identifier validation | `toBase64`, `concatBytes`, ... |
| `src/errors` | Single error hierarchy rooted at `SignalError` | 18 error classes |
| `src/keys` | Key/persistent-record DTOs, prekey generation | `generateSignedPreKeyRecord`, ... |
| `src/x3dh` | X3DH handshake, both roles | `initiateX3dh`, `receiveX3dh` |
| `src/ratchet` | Double Ratchet state machine + shared chain KDFs | `initRatchetAs*`, `ratchetEncrypt/Decrypt`, `kdfChainKey` |
| `src/session` | Per-remote session state + cipher | `SessionRecordDTO`, `SessionCipher` |
| `src/stores` | Persistence contract + default adapter | `SignalStore`, `InMemorySignalStore` |
| `src/protocol` | Facade, envelope/bundle validation, binary encoding, safety numbers, attachments, multi-device helpers | `SignalClient`, `parseEnvelope`, `encodeSignalEnvelope`, `computeSafetyNumber` |
| `src/group` | Group chat: fan-out mode + Sender Keys mode, `GroupStore` port | `SignalGroup`, `GroupStore`, `InMemoryGroupStore` |
| `src/nest` | Framework integration (separate entry point) | `SignalModule`, `SignalService` |

## 3. The two entry points

```
import { SignalClient }            from 'signal-protocol-node';      // core, zero framework deps
import { SignalModule, SignalService } from 'signal-protocol-node/nest'; // adds @nestjs/common (optional peer dep)
```

The Nest entry point is compiled separately (`dist/nest.js|mjs`); applications that never import it never load Nest types. `@nestjs/common` is declared as an **optional peer dependency**, so the core works in any Node project with zero Nest footprint.

## 4. Data flow: the first message (X3DH + ratchet start)

```
Alice                                            Bob (offline)
─────                                            ─────────────
                                  prekeys generated at create():
                                  identity, signed prekey, 50 one-time prekeys
        getPreKeyBundle()  ◄──────────────  (served by your app's server;
                                            consumeOneTime reserves an OPK)

bundle ──► createSessionFromBundle()
             parsePreKeyBundle()        verify Ed25519 signature
             initiateX3dh()             DH1..DH4 → SK, AD
             initRatchetAsInitiator()   root = SK, first sending chain
             TOFU check                 remote identity recorded
             store.storeSession()       pendingPreKey = { baseKey, spkId, opkId? }

encryptText("hello")
  SessionCipher.encryptMessage()  → signal message, counter 0
  wrapped in PreKeySignalMessage (because pendingPreKey is set)
  ─────────── your transport ─────────────────────────────────►  decrypt()
                                                                   parseEnvelope()
                 TOFU check (identity key must match / be new)
                 dedupe: existing session with same initiatorBaseKey? reuse.
                 else: receiveX3dh() → same SK, AD
                       initRatchetAsResponder()
                       OPK deleted (single use)
                 SessionCipher.decryptSignalMessage()
                     header.ratchetKey ≠ mine → DH ratchet step
                     skipped keys cached as needed
                 pendingPreKey not cleared (Bob never had one)
             ◄─────────── your transport ─────────────────────  encryptText("hi")

decrypt()
  ... succeeds → alice's pendingPreKey cleared: session confirmed,
  from now on regular SignalMessage envelopes flow both ways
```

## 5. Data flow: steady-state message exchange

```
encrypt(address, plaintext)
  load session record        (store.loadSession)
  states[0] is current       → chainKeySending → MK → CK'
  AES-256-GCM(key, nonce, plaintext, AD || header)
  save session record        (chains advanced)

decrypt(address, envelope)
  parseEnvelope()            structural validation of untrusted input
  load session record
  for each state (current first, then archived):
      clone state → ratchetDecrypt on the clone
      success?  commit clone, promote to current if archived
      failure?  discard clone, try next
  clear pendingPreKey (session confirmed by receipt)
  save session record
```

**Clone-then-commit** is the crucial safety property at this layer: a tampered or replayed message must never consume chain keys or skipped keys of the stored session — otherwise one bad message would corrupt the session and break the *next* good message.

## 5b. Data flow: group fan-out

```
SignalGroup (sender side)                    members
┌────────────────────────────┐
│ members: {bob.1, carol.1}  │
│ encryptText("hi")          │
│   for each member:         │
│     client.encrypt(m, "hi")│──┬──► bob.1 envelope   → bob.decrypt('alice.1', ...)
│                            │  ├──► carol.1 envelope → carol.decrypt('alice.1', ...)
└────────────────────────────┘
```

- `SignalGroup` is **sender-side composition only** — it owns no protocol state of its
  own (members in memory; membership persistence is app-level, re-adding is idempotent).
- Receivers run no group logic: `client.decrypt(senderAddress, envelope.messages[myAddress])`.
- First group message to each member is that pair's prekey envelope, exactly as in the
  pairwise flow — X3DH happens per member on first contact.
- Membership enforcement is sender-side + server authorization (see
  SIGNAL_PROTOCOL.md §10 for the security analysis; Sender Keys = Phase 15).

## 5c. Data flow: Sender Keys (O(1) groups)

```
alice (sender)                                bob (member)
─────                                         ───
createDistribution()
  fresh chainKey + Ed25519 signing pair
  saved to GroupStore (own chain)
  pairwise envelope per member ─────────────► onPairwiseMessage('alice.1', env)
                                                client.decrypt → distribution payload
                                                acceptDistribution → GroupStore
encryptOnce("hi")  — ONE encryption
  MK = HMAC(CK,0x01), CK'=HMAC(0x02)
  ciphertext = AES-GCM(MK-material, aad=group|dist|iter|signingKey)
  signature  = Ed25519(aad ‖ ciphertext)
  single message ──────────────────────────► decryptOnce('alice.1', msg)
                                                verify signature FIRST (stateless)
                                                advance chain clone to iteration
                                                (skipped-key cache for out-of-order)
                                                AES-GCM decrypt → commit
rotateDistribution() after membership change:
  new chain + signing key, distributed to current members only
  → removed members hold no future keys (revocation)
```

Key properties: the chain key is secret (distributed pairwise), authenticity is
universal (signature verifies for every member, not just the pairwise peer), and
message keys are consumed exactly once (clone-then-commit on the receiver). The
known trade-off: members hold the chain key until the next rotation, so per-message
forward secrecy is weaker than pairwise fan-out — the standard Sender Keys bargain.

## 6. The storage contract (Ports & Adapters)

`SignalStore` (src/stores/signal-store.ts) is the single persistence seam. Design decisions:

1. **All records are JSON-serializable DTOs.** No classes, no `Uint8Array` (base64 strings instead). Any KV/SQL/document store can hold them opaquely; nothing needs custom (de)serialization.
2. **`scope` is explicit in every method.** The scope is the client's `selfId`. This lets one store instance safely serve many accounts — the NestJS `SignalService` hosts all users on one store. Adapters that prefer per-user instances can use the `storeFactory` option instead.
3. **Addresses are strings** (`"<name>.<deviceId>"`). Multi-device support later = more devices per name, no schema change.
4. **Session records are versioned** (`version: 1`) so future format migrations can be handled in `loadSession` adapters or a future upgrade path.

One-time prekeys carry the only stateful subtlety: `reservedAt` distinguishes *available* keys from keys already handed out in a bundle. Serving a bundle **reserves** (never deletes — the private key is still needed to decrypt the peer's first message); the first successful decrypt **deletes**.

## 7. Extension points

| You want to... | Do this |
| --- | --- |
| Persist to your DB | Implement `SignalStore` (see README's Prisma sketch) |
| Persist Sender Keys chains | Implement `GroupStore` (4 methods, same DTO style) |
| Run in browsers / edge | `WebCryptoProvider` (or implement `CryptoProvider` — 11 async primitives) |
| Namespace a deployment's protocol | `config.x3dhInfo` |
| Tune delivery/memory behavior | `config.maxSkip`, `config.archivedStatesLimit`, group `maxSkip` |
| Import an existing identity | `SignalClient.create({ identityKeyPair })` |
| Rotate prekeys on a schedule | `rotateSignedPreKey()` + `pruneSignedPreKeys(keep)` (cron in your app) |
| Encrypt large files | `encryptAttachment`/`decryptAttachment` (key travels via the ratchet) |
| Save bandwidth on the wire | `encodeSignalEnvelope` (binary, ~50% smaller; `decrypt` accepts bytes) |
| Multi-device | One client per `"<user>.<deviceId>"` scope; `addUserDevices` fan-out |
| Integrate a framework other than Nest | Wrap `SignalClient` directly — that's all `SignalService` does |
| Binary group envelopes | Phase 20 — pairwise binary encoding is done |

## 8. Concurrency and lifecycle model

- `SignalClient` methods are `async` but the client itself holds no locks: a single Node event loop serializes access per process. For multi-process deployments (clustered servers), route messages of one session through one worker (e.g. consistent hashing by address), or wrap your store in optimistic concurrency — the protocol state per session is a single JSON document that is read-modify-written.
- Clients are cheap to **rehydrate**: `SignalClient.create()` with an existing store restores identity + sessions from storage, so instances can be ephemeral (per request, per socket) if your store is fast. `SignalService` caches clients per user for the common case.
- `decrypt` persists the session only on success; failed attempts leave stored state untouched.

## 9. Threat-model notes for implementers

- The **server** (bundle distribution + relay) can deny service and observe metadata, but cannot read or alter messages. It *could* serve a stale-but-valid bundle (e.g. withhold the one-time prekey) — the session still establishes, just without DH4's forward secrecy; detect via `envelope.oneTimePreKeyId` being absent.
- **TOFU**: identity keys are pinned per remote address on first contact. A changed key throws `IdentityKeyChangedError` — the application must decide (verify out of band, then explicitly reset). Don't catch-and-ignore this error.
- **Storage compromise** is the scope of forward secrecy claims: protect the store at rest; the protocol limits what a stolen store can reveal (see SIGNAL_PROTOCOL.md §7).
- Skipped-key and archive caps bound memory regardless of attacker input; exceeding them fails closed (`TooManySkippedMessagesError`).
