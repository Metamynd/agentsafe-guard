# magp-hcs2 — decentralized discovery (MAGP Phase D)

Resolve a `did:hedera` document — and its MAGP **service endpoint** — from the DID's **own HCS
registry topic** via a public Hedera **mirror node**, so a peer can discover and verify a
counterparty **with MetaMynd offline**.

## Why this works

A `did:hedera` is `did:hedera:<network>:<publicKeyMultibase>_<topicId>` — it **embeds** the HCS
topic its DID document was anchored to at issuance (op `did-create`, spec §4.3.2). So a peer needs
no issuer: it parses the topic id from the DID, reads the topic from a mirror node's public REST
API, and replays the registry to the current document.

## Trustless

- The **verification key** is parsed from the DID itself (spec §4.1.2) — never trusted from the
  document or the mirror.
- `resolveDidViaMirror` additionally **rejects** any mirror-served document whose key does not match
  the key embedded in the DID. A mirror node relays data but cannot forge which key a DID commits
  to, so a lying or compromised mirror cannot substitute keys.

## API

```js
import { resolveDidViaMirror, parseHederaDid, replayDidRegistry } from './magp-hcs2.mjs';

const r = await resolveDidViaMirror('did:hedera:testnet:z6Mk..._0.0.9459675');
// → { did, document, service: { serviceEndpoint, channels, protoVersions }, source:'hcs-mirror', verifiedKeyMatch:true }
//   or null (malformed DID / unreachable mirror / no did-create / key mismatch → caller can fall back)
```

- `parseHederaDid(did)` → `{ network, publicKeyMultibase, topicId }`.
- `parseRegistryMessages(apiMessages)` → decode a mirror `/topics/{id}/messages` payload (base64) into ordered ops.
- `replayDidRegistry(ops, did)` → the current document (latest write wins; `did-deactivate` tombstones).
- `resolveDidViaMirror(did, { fetchImpl?, network?, limit? })` → the trustless result above.

## Run

```bash
node integrations/magp-hcs2/magp-hcs2.test.mjs   # 17 assertions (mocked fetch — logic only)
```

## Live proof

The suite above proves the parsing/replay/key-binding logic; it never proves this actually
round-trips against a real Hedera mirror node. `magp-hcs2.live-demo.mjs` does — it anchors a
REAL `did:hedera` on testnet, then resolves it back via `resolveDidViaMirror` against the
real public mirror node, with no mocked fetch anywhere. Verified 2026-08-30 against
`did:hedera:testnet:z4riH55TDEqinyZsBduNbkHgsX55j662G6Q7XnU7vT6H1_0.0.10291873` — resolved on
the first attempt, `verifiedKeyMatch: true`. Not run by `npm test`/CI (a live network call
shouldn't gate a test run) — run it by hand:

```bash
HEDERA_OPERATOR_ID=... HEDERA_OPERATOR_KEY=... node magp-hcs2.live-demo.mjs
# or point at an existing testnet-configured .env:
MAGP_HCS2_DOTENV_PATH=/path/to/.env node magp-hcs2.live-demo.mjs
```

Uses testnet HBAR, which has no real-world value.

## Status / caveats

- **Zero dependencies** (fetch + base64 + JSON). Wired into the demo agent's MCP discovery
  (mirror-first, MetaMynd fallback).
- **Single-message documents.** HCS messages > ~1 KB are chunked; DID documents are small (single
  message). Multi-part (chunked) registry entries are a follow-on.
- **Follow-on:** HCS-2 rule-pack / policy-bundle registry discovery (spec §5.3.1) and key-status
  (revocation) lists on the same replay model; live mirror-node reads are network-dependent (the
  demo falls back to MetaMynd if the mirror is unreachable).
