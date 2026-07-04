# @furlpay/agent-trust

A **Trusted-Agent-Protocol-aligned trust layer for agentic payments**: Ed25519 agent identity, user-signed spend mandates, replay-safe booking tokens, and RFC 9421 HTTP message signatures. Zero dependencies.

Visa's [Trusted Agent Protocol](https://github.com/visa/trusted-agent-protocol) reached live production transactions in July 2026. Its premise: an agent-initiated payment must carry cryptographic proof of **who** the agent is, **that** the user consented, and **what** the agent is allowed to do. This package implements that trust chain so any FurlPay rail — the [travel MCP server](https://www.npmjs.com/package/@furlpay/travel-mcp), an HTTP API, an x402 facilitator — can gate spend behind it.

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

## API

| Export | Purpose |
|---|---|
| `generateKeypair(role)` | Ed25519 keypair; keyId is a role-prefixed SPKI fingerprint |
| `issueMandate(params)` | User signs constraints binding one agent key |
| `verifyMandate(sm, userPem)` | Decode + verify a signed mandate |
| `createBookingToken(params)` | Agent wraps the mandate around one signed intent (fresh nonce) |
| `AgentTrust` | Stateful verifier: key registry, budget decrement, single-use consumption, replay set |
| `signRequest` / `verifyRequest` | RFC 9421 HTTP message signatures |
| `NonceStore` | Pluggable replay store (in-memory default; back with Redis `SETNX` across instances) |

## Security model

- **Verification is stateful.** Budgets decrement on success, nonces burn, single-use mandates are consumed. A mandate is a spend allowance, not a reusable password.
- **Fail closed.** Malformed tokens, unknown keys, tampered payloads, expired mandates, and mismatched claims all return `ok: false` with a specific reason — nothing throws into a rail's happy path.
- **In-memory stores are single-process.** For multi-instance verifiers, implement `NonceStore` on Redis (`add` → `SETNX`) and persist budgets.

MIT © FurlPay
