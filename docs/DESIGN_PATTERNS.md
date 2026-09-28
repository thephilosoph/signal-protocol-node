# Design patterns in this library

Each pattern below is used deliberately and can be located in the code. Companion documents: [ARCHITECTURE.md](ARCHITECTURE.md) (structure and flows), [SIGNAL_PROTOCOL.md](SIGNAL_PROTOCOL.md) (the cryptography).

## Overview

| Pattern | Where | One-line reason |
| --- | --- | --- |
| Facade | `SignalClient`, `SignalService` | The protocol is complex; users need 5 methods |
| Composite facade | `SignalGroup` | Groups compose the pairwise facade; Sender Keys reuses the chain KDFs |
| Strategy | `CryptoProvider` (Node + WebCrypto) | Swap primitives without touching protocol code |
| Ports & Adapters (Repository) | `SignalStore`, `GroupStore` + in-memory adapters | Persistence is the app's decision, not the library's |
| Dependency Injection | constructor options; Nest providers | State flows in; nothing is globally reachable |
| Factory Method | `SignalClient.create()` | Async construction with auto-provisioning |
| Dynamic Module | `SignalModule.forRoot/forRootAsync` | Nest-idiomatic configurability |
| DTO / Envelope | `*DTO`, `SignalEnvelopeJSON` | JSON-serializable boundary between protocol and world |
| Decorator (validation) | `parseEnvelope`, `parsePreKeyBundle`, group parsers | Trust nothing at the network boundary |
| Pure-function module | `safety-number.ts`, `attachments.ts` | Deterministic, auditable features without state |
| Version-tagged codec | JSON + `binary.ts` encodings | Two wire formats behind one validated shape |
| Template-ish flow | `decrypt` dispatch | prekey vs regular messages share one entry point |
| Guard clauses via typed errors | `src/errors.ts` | Callers branch on semantics, not string matching |

## 1. Facade — `SignalClient` and `SignalService`

**Where:** `src/protocol/signal-client.ts`, `src/nest/signal.service.ts`

The protocol stack underneath is genuinely complex: X3DH roles, ratchet states, skipped keys, pending prekeys, TOFU checks, dedupe. A user of the library should never need to know those words. `SignalClient` compresses all of it into a handful of calls (`createSessionFromBundle`, `encrypt`, `decrypt`, `getPreKeyBundle`) and owns the sequencing between layers.

`SignalService` is a facade over a *fleet* of facades: one `SignalClient` per user, cached, sharing the configured store — the shape a chat backend actually needs.

**Trade-off:** the low-level pieces (`initiateX3dh`, `ratchetDecrypt`, ...) are still exported for advanced use and testing, so the facade is a convenience layer, not a cage.

## 2. Strategy — `CryptoProvider`

**Where:** `src/crypto/crypto-provider.ts` (interface), `src/crypto/node-crypto-provider.ts` (default)

The protocol code only knows a small primitive vocabulary:

```ts
interface CryptoProvider {
  randomBytes; generateKeyPair;       // X25519
  generateSigningKeyPair;             // Ed25519
  agree;                              // X25519 DH
  sign; verify;                       // Ed25519
  hmacSha256; hkdf;                   // key derivation
  aes256GcmEncrypt; aes256GcmDecrypt; // AEAD
}
```

Every crypto call site in the protocol layer goes through this interface. Consequences:

- Node-specific imports exist in exactly **one file**.
- A WebCrypto provider for browsers/edge runtimes is a drop-in class.
- Tests can inject deterministic crypto if ever needed.

The default provider also centralizes **input validation** (key lengths, all-zero DH rejection — a known X25519 pitfall).

## 3. Ports & Adapters — `SignalStore`

**Where:** `src/stores/signal-store.ts` (port), `src/stores/in-memory-store.ts` (adapter), README (SQL example)

All persisted state (identity, remote identities, prekeys, sessions) is read/written through one interface. The protocol core has **zero** storage implementation inside it; the in-memory adapter is just the most trivial adapter, and it's what makes the library work out of the box.

The port is shaped for adapters, not for the library's convenience:

- records are plain JSON DTOs (an adapter can store them opaquely);
- `scope` (the local account) is an explicit parameter (one adapter serves many accounts);
- id-listing methods exist because prekey pools need maintenance (top-up, consume).

## 4. Dependency Injection — options objects and Nest providers

**Where:** `SignalClientOptions`, `SignalModuleOptions`, `@Inject` in `SignalService`

Nothing in the library reaches for singletons or ambient config. A `SignalClient` receives its store, crypto and config through construction; the Nest module wires the same objects through providers (`SIGNAL_MODULE_OPTIONS` token, `useFactory`, `storeFactory`). This keeps the core framework-free while remaining idiomatic inside Nest.

## 5. Factory Method — `SignalClient.create()`

**Where:** `src/protocol/signal-client.ts`

Construction is asynchronous (identity may need generating and persisting; prekeys may need creating) so a plain `new` cannot do it. `create()` is the async factory that:

1. loads **or** creates the identity (idempotent — safe to call on every boot),
2. auto-provisions a signed prekey + one-time prekey pool on first run,
3. returns a fully ready client.

## 6. Dynamic Module — `SignalModule`

**Where:** `src/nest/signal.module.ts`

Nest's idiomatic way of shipping a configurable feature module. `forRoot()` accepts a store instance (shared, scope-first) or a per-user `storeFactory`; `forRootAsync()` supports factory + injection for config-driven setups. Both export `SignalService` for injection anywhere in the app.

Property injection (`@Inject(SIGNAL_MODULE_OPTIONS)`) is used instead of constructor parameter decorators so the compiled output does not depend on `emitDecoratorMetadata` (which esbuild/tsup cannot emit) — the library compiles with plain esbuild semantics and still wires correctly in Nest.

## 7. DTO / Envelope — the serialization boundary

**Where:** `src/keys/types.ts` (`*DTO`), `src/protocol/messages.ts` (`SignalEnvelopeJSON`), `src/session/session-record.ts`

Two distinct representations exist on purpose:

- **In-memory wire objects** (`SignalEnvelopeJSON`) — what your transport carries. Plain JSON, human-debuggable, stable shape, versioned (`version: 1`).
- **Persisted records** (`*DTO`) — base64 fields, JSON-serializable, so a `SignalStore` adapter never needs custom serialization.

Everything crossing a boundary (transport, storage) is one of these plain objects; everything internal to a running session stays typed (`Uint8Array`, `KeyPair`).

## 8. Decorator-as-validator (parse, don't validate) — `parseEnvelope` / `parsePreKeyBundle`

**Where:** `src/protocol/messages.ts`, `src/protocol/bundle.ts`

Anything arriving from the network is `unknown` and passes through a parser that checks structure, types, base64 fields, key lengths, counter ranges — and in the bundle's case, the Ed25519 signature — before the protocol core ever sees it. Downstream code then works with fully-typed, fully-trusted-shape values. This is the "parse, don't validate" discipline: one choke point per boundary, no scattered `if (typeof x === 'string')` checks.

## 9. Dispatch on type — the decrypt path

**Where:** `SignalClient.decrypt`

One entry point branches on envelope type (`prekey` vs `signal`), and each branch composes the same building blocks (TOFU check → session lookup/creation → `SessionCipher`). New envelope types (e.g. a future receipt or group message type) slot into the same `version`/`type` dispatch without changing existing paths.

## 10. Errors as semantics — `src/errors.ts`

**Where:** all of `src`

Fourteen error classes rooted at `SignalError` encode *what the caller should do*, not where the code broke: `SessionNotFoundError` (go fetch a bundle), `IdentityKeyChangedError` (verify out of band), `TooManySkippedMessagesError` (session desync, re-establish), `MessageDecryptError` (routine noise, drop the message). Each carries `name = class name` and `cause` chains for debugging.

## 11. Composite facade — `SignalGroup`

**Where:** `src/group/signal-group.ts`

Groups add no new pairwise protocol machinery: the fan-out mode is a **composite over the existing facade** — it holds member addresses and fans each `encrypt()` out through `SignalClient.encrypt()` per member. Because it composes rather than extends, every security property of the pairwise layer (forward secrecy, clone-then-commit, replay rejection) applies to groups with zero new crypto code on the pairwise path. The Sender Keys mode reuses the ratchet layer's exported chain KDFs (`kdfChainKey`, `messageKeyToKeyNonce`) rather than reimplementing them, and persists through its own `GroupStore` port — the same Ports & Adapters move as `SignalStore`.

## 12. Pure-function modules — safety numbers & attachments

**Where:** `src/protocol/safety-number.ts`, `src/protocol/attachments.ts`

Not every feature needs a class. Both modules are pure functions over `(bytes, crypto)`:

- `computeSafetyNumber(keys)` is deterministic and order-independent by construction — trivial to test (property tests: same digits both sides and across device sets, different digits for different keys).
- `encryptAttachment`/`decryptAttachment` have no session or storage dependencies, so they compose with any transport: the "ciphertext out-of-band, key through the ratchet" flow is just two library calls your code arranges.

Pure modules like these are the cheapest to audit — no hidden state, no I/O — which matters disproportionately for verification-flavored features.

## 13. Version-tagged codecs — `parseEnvelope`, `decodeSignalEnvelope`

**Where:** `src/protocol/messages.ts`, `src/protocol/binary.ts`

Two encodings (JSON default, compact binary) behind one shape, both carrying an
explicit `version` byte/field and validated at the boundary before the protocol core
sees anything. Adding a future encoding (protobuf, group binary) is a sibling module,
not a rewrite: `SignalClient.decrypt` dispatches on input type (`Uint8Array` → binary
decoder, object → JSON parser).

## Anti-patterns deliberately avoided

- **No global state / singletons** — two clients in one process (Alice and Bob in tests/examples) never interfere.
- **No hidden I/O** — the library never opens sockets or files; the only I/O seam is the store you provide.
- **No callback soup** — async flows are plain `async/await` chains readable top to bottom.
- **No stringly-typed errors** or error codes: catch `SignalError`, branch by class.
- **No premature binary formats** — JSON now; a protobuf envelope type can be added behind `parseEnvelope` without touching crypto.
