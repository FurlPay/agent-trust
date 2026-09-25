# @furlpay/agent-trust

A **Trusted-Agent-Protocol-aligned trust layer for agentic payments**: Ed25519 agent identity, user-signed spend mandates, replay-safe booking tokens, and RFC 9421 HTTP message signatures. Zero dependencies.

Visa's [Trusted Agent Protocol](https://github.com/visa/trusted-agent-protocol) reached live production transactions in July 2026. Its premise: an agent-initiated payment must carry cryptographic proof of **who** the agent is, **that** the user consented, and **what** the agent is allowed to do. This package implements that trust chain so any FurlPay rail — the [travel MCP server](https://www.npmjs.com/package/@furlpay/travel-mcp), an HTTP API, an x402 facilitator — can gate spend behind it.

## Status

**Published on npm: `0.1.0`.**

`0.2.0` is prepared but **not released**. It adds the `/approval` and `/spend`
entry points, and fixes a packaging bug in which the approval API shipped inside
the tarball but could not be imported by any published path. Until `0.2.0` is on
npm, `@furlpay/agent-trust/approval` resolves from the repository, not from an
installed `0.1.0`.

No third-party security audit has been performed. What exists is the test suite:
**73 tests, 73 passing, 0 failing**, covering the approval binding, domain
separation, and each distinct verification failure.

## Install

```sh
npm install @furlpay/agent-trust
```

**Mind the scope.** An unrelated package is published under the unscoped name
`agent-trust`; it is not this project and is not maintained by us. Always install
the `@furlpay/` scoped name.

ESM only (`"type": "module"`) — `require()` will fail with
`ERR_PACKAGE_PATH_NOT_EXPORTED`. Node 18+. TypeScript consumers should have
`@types/node` installed (`Buffer` is in the public type surface); it is declared
as an optional peer.

### Entry points

| Import | Contains |
|---|---|
| `@furlpay/agent-trust` | identity, mandates, booking tokens, RFC 9421 signing |
| `@furlpay/agent-trust/approval` | `issueApproval`, `verifyApproval`, `APPROVAL_SIGNING_DOMAIN` |
| `@furlpay/agent-trust/spend` | spend-tracking helpers |

## The trust chain

```
user key (uk_…)                agent key (ak_…)              verifier
     │                               │                           │
     │  issueMandate()               │                           │
     │  cap · MCC · expiry ─────────►│                           │
     │                               │  createBookingToken()     │
     │                               │  signs ONE exact intent ─►│
     │                               │                           │  verifyBookingToken()
     │                               │                           │  ① agent key registered + signed this intent
     │                               │                           │  ② user key registered + signed this mandate
     │                               │                           │  ③ mandate names THIS agent
     │                               │                           │  ④ claims == signed intent (amount/mcc/source)
     │                               │                           │  ⑤ cap, per-booking cap, MCC, source, expiry
     │                               │                           │  ⑥ nonce never seen (replay-safe)
```

The agent can never widen its own permissions — only the user's key can sign a mandate. A verifier can never be tricked into charging more than the token says — the claims it is about to execute must equal the signed intent byte-for-byte.

## Quickstart

```js
import { AgentTrust, generateKeypair, issueMandate, createBookingToken } from "@furlpay/agent-trust";

// Identities
const user  = generateKeypair("user");   // uk_…
const agent = generateKeypair("agent");  // ak_…

// Verifier (held by the payment rail)
const trust = new AgentTrust();
trust.registerUser(user.publicKeyPem);
trust.registerAgent(agent.publicKeyPem);

// 1. User grants a mandate: $500 trip budget, lodging + airlines only, 7 days
const mandate = issueMandate({
  userPrivateKeyPem: user.privateKeyPem,
  userPublicKeyPem: user.publicKeyPem,
  agentKeyId: agent.keyId,
  constraints: {
    maxTotalUsd: 500,
    maxPerBookingUsd: 400,
    mccAllowlist: ["7011", "4511"],
    expiresAt: new Date(Date.now() + 7 * 864e5).toISOString(),
  },
});

// 2. Agent signs one exact booking intent
const token = createBookingToken({
  mandate,
  agentPrivateKeyPem: agent.privateKeyPem,
  agentPublicKeyPem: agent.publicKeyPem,
  intent: { amountUsd: 320, source: "legacy", mcc: "7011", merchant: "Hotel CDMX" },
});

// 3. Rail verifies the full chain before issuing a credential
const decision = await trust.verifyBookingToken(token, { amountUsd: 320, mcc: "7011", source: "legacy" });
// → { ok: true, agentKeyId: "ak_…", mandateId: "mnd_…", remainingUsd: 180 }
```

### Gating the FurlPay travel MCP server

`AgentTrust` structurally implements `@furlpay/travel-mcp`'s `MandateVerifier` — plug it straight in and `travel_authorize_booking` refuses any call without a valid token:

```js
import { TravelClient } from "@furlpay/travel-mcp";
const client = new TravelClient({ trust }); // every booking now requires mandateToken
```

### RFC 9421 HTTP signatures

The same identity keys authenticate raw HTTP calls (TAP's transport binding — `@method`, `@target-uri`, `content-digest` covered components, `tag="agent-payment"`):

```js
import { signRequest, verifyRequest } from "@furlpay/agent-trust";

const headers = signRequest({ method: "POST", url, body, keyId: agent.keyId, privateKeyPem: agent.privateKeyPem });
// → { "content-digest", "signature-input", "signature" }

const { keyId } = verifyRequest({ method: "POST", url, body, headers, resolvePublicKey });
```

## Step-up approval evidence

A mandate can say "above $5, a human must approve". A facilitator cannot act on that by asking anyone — by settlement time the approval either happened or it did not, and its only moves are settle and refuse. So the threshold is enforceable only if the payment **arrives carrying proof**.

AP2 expresses this structurally (a closed mandate signed on a Trusted Surface vs. an open one closed by the agent), but that presumes AP2 envelopes on both ends. Most x402 traffic has none. The minimum that works without them is two base64url strings in the `extra` field x402 already carries:

```ts
import { issueApproval, verifyApproval } from "@furlpay/agent-trust/approval";

// the human approves ONE payment
const approval = issueApproval({ userPrivateKeyPem, userPublicKeyPem, mandateId, paymentHash });
// → { payload, signature }   rides as extra.approval on the X-PAYMENT header

const v = verifyApproval(approval, { userPublicKeyPem, paymentHash, mandateId, maxAgeSeconds: 300 });
// → { ok: true, approvedAtSeconds, userKeyId } | { ok: false, reason }
```

The signature covers `paymentHash`, `mandateId`, `keyId` and `approvedAt`, under the domain `x402-approval/v1`. Each earns its place by what breaks without it:

| Field | Without it |
|---|---|
| `paymentHash` | proves only that the user approved *something*, once — a replay proves that equally well, forever |
| `mandateId` | evidence minted under a $50 mandate works under a $5000 one |
| `keyId` | a valid signature from an unrelated user's key passes |
| `approvedAt` | one approval authorizes above-threshold payments indefinitely |
| domain | a signature over the same bytes can be reinterpreted as another signed object type |

Amount, resource, seller and asset are deliberately **absent** — they are already committed by `paymentHash`, and a second copy is one that can disagree.

Signed by the **user** key, never the agent's: an agent that can mint its own step-up evidence is approving its own above-threshold spending. `maxAgeSeconds` is required with no default, because a default is a security parameter chosen by whoever forgot to set it. Future-dated evidence is refused rather than treated as unusually fresh (60s skew allowed).

Failure reasons stay distinguishable rather than collapsing into one authorization failure: `missing`, `malformed`, `unsupported_version`, `signature_invalid`, `key_mismatch`, `payment_mismatch`, `mandate_mismatch`, `expired`, `future_dated`. `missing` and `malformed` are separate on purpose — one means fetch an approval, the other means fix the one you have.

**This is cryptographic evidence carried in the payment, not a transaction.**
Nothing here touches a chain: `issueApproval` produces a detached Ed25519
signature, `verifyApproval` checks it, and the result is an input to whatever
decides whether a payment may settle. The enforcement half lives in
[`@furlpay/x402-guard`](https://github.com/FurlPay/x402-guard).

The enforcement half — window budgets, atomic reservation, the policy evaluator — lives in [`@furlpay/x402-guard`](https://github.com/FurlPay/x402-guard).

## API

| Export | Purpose |
|---|---|
| `generateKeypair(role)` | Ed25519 keypair; keyId is a role-prefixed SPKI fingerprint |
| `issueMandate(params)` | User signs constraints binding one agent key |
| `verifyMandate(sm, userPem)` | Decode + verify a signed mandate |
| `createBookingToken(params)` | Agent wraps the mandate around one signed intent (fresh nonce) |
| `mintCapability(params)` | Agent mints a single-use, audience-bound capability for one tool-server call |
| `AgentTrust` | Stateful verifier: key registry, budget decrement, single-use consumption, replay set. `verifyBookingToken` (spend) + `verifyCapability` (tool-server access) |
| `signRequest` / `verifyRequest` | RFC 9421 HTTP message signatures |

## Capability tokens (tool-server tier)

The mandate says *what* an agent may spend; a **capability** says *which* tool-server it may call, for *how long*, and exactly *once*. `mintCapability` produces a short-lived, `audience`-restricted token the agent presents per call; `AgentTrust.verifyCapability(token, { audience, action, presenterKeyId })` accepts it only when:

- the `audience` equals **this** server's id (a token leaked from one tool-server can't be replayed at another),
- the `presenterKeyId` — the agent key that authenticated the request (e.g. the `keyid` returned by `verifyRequest`) — is the **same key that minted the token** (proof-of-possession; a stolen token is useless to another holder),
- it hasn't expired, its `action` matches, its `maxUsd` is within the server ceiling, and its `jti` hasn't been burned (single-use via the same `NonceStore`).

Together with `signRequest`/`verifyRequest`, this is the multi-tier chain: **mandate** (user consent + budget) → **request signature** (who is calling now) → **capability** (this call, this server, once).
| `NonceStore` | Pluggable replay store (in-memory default; back with Redis `SETNX` across instances) |

## Security model

- **Verification is stateful.** Budgets decrement on success, nonces burn, single-use mandates are consumed. A mandate is a spend allowance, not a reusable password.
- **Fail closed.** Malformed tokens, unknown keys, tampered payloads, expired mandates, and mismatched claims all return `ok: false` with a specific reason — nothing throws into a rail's happy path.
- **In-memory stores are single-process.** For multi-instance verifiers, implement `NonceStore` on Redis (`add` → `SETNX`) and persist budgets.

MIT © FurlPay
