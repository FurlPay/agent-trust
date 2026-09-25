// ---------------------------------------------------------------------------
// @furlpay/agent-trust — a Trusted-Agent-Protocol-aligned trust layer for
// agentic payments.
//
// Visa introduced the Trusted Agent Protocol (TAP,
// github.com/visa/trusted-agent-protocol) in October 2025 with Cloudflare and
// other partners. This comment previously said TAP "moved to live production
// transactions in July 2026" — a claim the linked repository does not support
// (it describes itself as a sample implementation) and which was wrong about
// the date by roughly nine months. Its core idea: every
// agent-initiated request carries a cryptographic proof of (1) WHO the agent
// is, (2) THAT the user consented, and (3) WHAT the agent is allowed to do —
// transmitted as RFC 9421 HTTP Message Signatures so merchants can separate
// credentialed agents from anonymous bots without new infrastructure.
//
// This package implements that trust chain for FurlPay rails:
//
//   1. Identity      Ed25519 keypairs for users (uk_…) and agents (ak_…).
//                    Key ids are SPKI fingerprints, so a key id commits to the
//                    public key it names.
//
//   2. Mandate       A user-signed grant binding ONE agent key to explicit
//                    spend constraints: total USD cap, MCC allowlist, allowed
//                    booking sources, expiry, single-use. The agent cannot
//                    widen its own permissions — only the user's key can.
//
//   3. Intent        Each booking presents an agent-signed intent (amount,
//                    mcc, source, merchant, nonce) wrapped with its mandate
//                    into a compact booking token. The verifier checks the
//                    full chain: user signed the mandate → mandate names this
//                    agent key → agent signed this exact intent → intent fits
//                    the constraints → nonce never seen before.
//
//   4. HTTP layer    signRequest()/verifyRequest() produce and check
//                    RFC 9421 Signature-Input / Signature / Content-Digest
//                    headers (@method, @target-uri, content-digest covered
//                    components, tag="agent-payment") so the same identity
//                    keys authenticate raw HTTP calls to FurlPay APIs.
//
// Replay is closed with a stateful nonce set (same pattern as x402-guard's
// nonce linearization): a token clears verification exactly once. Budgets are
// decremented on successful verification, so a mandate is a spend allowance,
// not a reusable password.
//
// No runtime dependencies — Ed25519 via node:crypto. (`@types/node` is an
// optional peer, for TypeScript consumers only.) The nonce/budget stores are
// in-memory and correct within one process; back them with Redis for
// multi-instance verifiers.
// ---------------------------------------------------------------------------

import crypto from "crypto";

// ── identity ────────────────────────────────────────────────────────────────

export type KeyRole = "user" | "agent";

export interface Keypair {
  /** Fingerprint id: uk_/ak_ + base64url(sha256(SPKI DER)) prefix. */
  keyId: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function spkiFingerprint(publicKeyPem: string, role: KeyRole): string {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return (role === "user" ? "uk_" : "ak_") + b64url(crypto.createHash("sha256").update(der).digest()).slice(0, 24);
}

/** Generate an Ed25519 identity keypair for a user or an agent. */
export function generateKeypair(role: KeyRole): Keypair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  return { keyId: spkiFingerprint(publicKeyPem, role), publicKeyPem, privateKeyPem };
}

/** Derive the canonical key id for a public key (verifies a claimed keyId). */
export function keyIdOf(publicKeyPem: string, role: KeyRole): string {
  return spkiFingerprint(publicKeyPem, role);
}

function signBytes(data: Buffer, privateKeyPem: string): Buffer {
  return crypto.sign(null, data, privateKeyPem);
}

function verifyBytes(data: Buffer, signature: Buffer, publicKeyPem: string): boolean {
  try {
    return crypto.verify(null, data, crypto.createPublicKey(publicKeyPem), signature);
  } catch {
    return false;
  }
}

// ── mandates: user-signed consent ───────────────────────────────────────────

export interface MandateConstraints {
  /** Total spend allowance across all bookings under this mandate, in USD. */
  maxTotalUsd: number;
  /** Per-booking ceiling. Default: maxTotalUsd. */
  maxPerBookingUsd?: number;
  /** Merchant Category Codes the agent may transact under (e.g. 7011 lodging). Empty/omitted = any. */
  mccAllowlist?: string[];
  /** Booking sources the agent may use (e.g. "travala", "legacy"). Empty/omitted = any. */
  sourceAllowlist?: string[];
  /** ISO 8601 expiry. Bookings after this instant are rejected. */
  expiresAt: string;
  /** If true the mandate is consumed by its first successful booking. */
  singleUse?: boolean;
}

export interface Mandate {
  v: 1;
  mandateId: string;
  /** Key id of the user who granted consent. */
  userKeyId: string;
  /** Key id of the ONE agent this mandate empowers. */
  agentKeyId: string;
  constraints: MandateConstraints;
  issuedAt: string;
}

/** A mandate as transmitted: base64url(JSON payload) + user signature over it. */
export interface SignedMandate {
  payload: string;
  signature: string;
}

export interface IssueMandateParams {
  userPrivateKeyPem: string;
  userPublicKeyPem: string;
  agentKeyId: string;
  constraints: MandateConstraints;
}

/** User grants an agent a spend mandate by signing the constraint payload. */
export function issueMandate(p: IssueMandateParams): SignedMandate {
  if (p.constraints.maxTotalUsd <= 0) throw new Error("maxTotalUsd must be > 0");
  if (Number.isNaN(Date.parse(p.constraints.expiresAt))) throw new Error("expiresAt must be ISO 8601");
  const mandate: Mandate = {
    v: 1,
    mandateId: "mnd_" + b64url(crypto.randomBytes(12)),
    userKeyId: spkiFingerprint(p.userPublicKeyPem, "user"),
    agentKeyId: p.agentKeyId,
    constraints: p.constraints,
    issuedAt: new Date().toISOString(),
  };
  const payload = b64url(Buffer.from(JSON.stringify(mandate)));
  const signature = b64url(signBytes(Buffer.from(payload), p.userPrivateKeyPem));
  return { payload, signature };
}

/** Decode + verify a signed mandate against the granting user's public key. */
export function verifyMandate(sm: SignedMandate, userPublicKeyPem: string): Mandate {
  if (!verifyBytes(Buffer.from(sm.payload), Buffer.from(sm.signature, "base64url"), userPublicKeyPem)) {
    throw new Error("mandate signature invalid");
  }
  const mandate = JSON.parse(Buffer.from(sm.payload, "base64url").toString()) as Mandate;
  if (mandate.v !== 1) throw new Error(`unsupported mandate version ${mandate.v}`);
  if (mandate.userKeyId !== spkiFingerprint(userPublicKeyPem, "user")) {
    throw new Error("mandate userKeyId does not match the verifying key");
  }
  return mandate;
}

// ── booking tokens: agent-signed intents under a mandate ───────────────────

export interface BookingIntent {
  amountUsd: number;
  currency?: string;
  /** Merchant Category Code for card-routed bookings (e.g. 7011). */
  mcc?: string;
  source: string;
  merchant?: string;
  reference?: string;
}

interface IntentEnvelope extends BookingIntent {
  mandateId: string;
  agentKeyId: string;
  nonce: string;
  createdAt: string;
}

/**
 * A compact presentation the agent hands to a payment rail: the user-signed
 * mandate plus this specific intent, signed by the agent's key.
 */
export interface BookingToken {
  mandate: SignedMandate;
  intent: string; // base64url(JSON IntentEnvelope)
  intentSignature: string; // agent signature over `intent`
}

export interface CreateBookingTokenParams {
  mandate: SignedMandate;
  agentPrivateKeyPem: string;
  agentPublicKeyPem: string;
  intent: BookingIntent;
}

/** Agent wraps a mandate around one concrete booking intent. */
export function createBookingToken(p: CreateBookingTokenParams): string {
  const envelope: IntentEnvelope = {
    ...p.intent,
    mandateId: decodeMandatePayload(p.mandate).mandateId,
    agentKeyId: spkiFingerprint(p.agentPublicKeyPem, "agent"),
    nonce: b64url(crypto.randomBytes(16)),
    createdAt: new Date().toISOString(),
  };
  const intent = b64url(Buffer.from(JSON.stringify(envelope)));
  const token: BookingToken = {
    mandate: p.mandate,
    intent,
    intentSignature: b64url(signBytes(Buffer.from(intent), p.agentPrivateKeyPem)),
  };
  return b64url(Buffer.from(JSON.stringify(token)));
}

function decodeMandatePayload(sm: SignedMandate): Mandate {
  return JSON.parse(Buffer.from(sm.payload, "base64url").toString()) as Mandate;
}

// ── capability tokens: single-use, audience-bound tool-server grants ─────────
//
// The mandate says WHAT an agent may spend; a capability says WHICH tool-server
// it may call, for HOW LONG, and exactly ONCE. This is the third tier of the
// multi-tier session model: a short-lived, audience-restricted token the agent
// mints per tool-server call. It is proof-of-possession bound — valid only when
// presented by the same agent key that minted it (the caller must independently
// authenticate that key, e.g. via signRequest/verifyRequest) — so an
// intercepted token cannot be replayed by a different holder or against a
// different audience. Single-use via the same nonce store that guards bookings.

export interface CapabilityGrant {
  v: 1;
  jti: string;
  /** Agent key that minted AND must present this token (PoP binding). */
  agentKeyId: string;
  /** The ONE tool-server / resource this token authorizes (e.g. a URL or id). */
  audience: string;
  /** Scope of what may be done at the audience (e.g. "wallet.read", "pay:travala"). */
  action: string;
  /** Optional link to the spend mandate this capability acts under. */
  mandateId?: string;
  /** Optional per-call USD ceiling for value-moving actions. */
  maxUsd?: number;
  iat: string;
  /** Short expiry — capabilities are minted per call, not held. */
  exp: string;
}

export interface SignedCapability {
  payload: string; // base64url(JSON CapabilityGrant)
  signature: string; // agent signature over payload
}

export interface MintCapabilityParams {
  agentPrivateKeyPem: string;
  agentPublicKeyPem: string;
  audience: string;
  action: string;
  mandateId?: string;
  maxUsd?: number;
  /** Token lifetime in seconds. Default 120. */
  ttlSeconds?: number;
}

/** Agent mints a single-use, audience-bound capability for one tool-server call. */
export function mintCapability(p: MintCapabilityParams): string {
  if (!p.audience) throw new Error("audience is required");
  if (!p.action) throw new Error("action is required");
  const now = Date.now();
  const grant: CapabilityGrant = {
    v: 1,
    jti: "cap_" + b64url(crypto.randomBytes(16)),
    agentKeyId: spkiFingerprint(p.agentPublicKeyPem, "agent"),
    audience: p.audience,
    action: p.action,
    mandateId: p.mandateId,
    maxUsd: p.maxUsd,
    iat: new Date(now).toISOString(),
    exp: new Date(now + (p.ttlSeconds ?? 120) * 1000).toISOString(),
  };
  const payload = b64url(Buffer.from(JSON.stringify(grant)));
  const token: SignedCapability = {
    payload,
    signature: b64url(signBytes(Buffer.from(payload), p.agentPrivateKeyPem)),
  };
  return b64url(Buffer.from(JSON.stringify(token)));
}

export interface CapabilityDecision {
  ok: boolean;
  reason?: string;
  agentKeyId?: string;
  jti?: string;
  audience?: string;
  action?: string;
  mandateId?: string;
  maxUsd?: number;
}

// ── verifier ────────────────────────────────────────────────────────────────

export interface TrustDecision {
  ok: boolean;
  reason?: string;
  agentKeyId?: string;
  mandateId?: string;
  /** USD allowance left on the mandate after this booking. */
  remainingUsd?: number;
}

/** Pluggable stores; in-memory defaults are correct within one process. */
export interface NonceStore {
  /** Atomically record a nonce; return false if it was already present. */
  add(nonce: string): boolean | Promise<boolean>;
  /**
   * Optional read-only membership check. When present, replays are reported
   * as such before other constraint errors; the atomic add() at commit time
   * remains the actual guard, so races between has() and add() are safe.
   */
  has?(nonce: string): boolean | Promise<boolean>;
}

class MemoryNonceStore implements NonceStore {
  private readonly seen = new Set<string>();
  add(nonce: string): boolean {
    if (this.seen.has(nonce)) return false;
    this.seen.add(nonce);
    return true;
  }
  has(nonce: string): boolean {
    return this.seen.has(nonce);
  }
}

export interface AgentTrustOptions {
  nonceStore?: NonceStore;
  /** Tolerated clock skew for intent createdAt, seconds. Default 300. */
  maxSkewSeconds?: number;
}

/**
 * The verifier a payment rail (MCP server, HTTP API, x402 facilitator) holds.
 * Register user and agent public keys, then gate every booking through
 * verifyBookingToken(). Verification is stateful: budgets decrement, nonces
 * burn, single-use mandates are consumed.
 */
export class AgentTrust {
  private readonly users = new Map<string, string>(); // userKeyId → pem
  private readonly agents = new Map<string, string>(); // agentKeyId → pem
  private readonly spent = new Map<string, number>(); // mandateId → USD spent
  private readonly consumed = new Set<string>(); // exhausted single-use mandates
  private readonly nonces: NonceStore;
  private readonly maxSkewMs: number;

  constructor(opts: AgentTrustOptions = {}) {
    this.nonces = opts.nonceStore ?? new MemoryNonceStore();
    this.maxSkewMs = (opts.maxSkewSeconds ?? 300) * 1000;
  }

  registerUser(publicKeyPem: string): string {
    const id = spkiFingerprint(publicKeyPem, "user");
    this.users.set(id, publicKeyPem);
    return id;
  }

  registerAgent(publicKeyPem: string): string {
    const id = spkiFingerprint(publicKeyPem, "agent");
    this.agents.set(id, publicKeyPem);
    return id;
  }

  /**
   * Verify the full trust chain for one booking. `claims` are the parameters
   * the rail is about to execute with — they must match what the agent signed,
   * so a rail can never be tricked into charging more than the token says.
   */
  async verifyBookingToken(
    tokenB64: string,
    claims: { amountUsd: number; mcc?: string; source: string },
  ): Promise<TrustDecision> {
    let token: BookingToken;
    let envelope: IntentEnvelope;
    try {
      token = JSON.parse(Buffer.from(tokenB64, "base64url").toString()) as BookingToken;
      envelope = JSON.parse(Buffer.from(token.intent, "base64url").toString()) as IntentEnvelope;
    } catch {
      return { ok: false, reason: "malformed booking token" };
    }

    // 1. Agent identity: registered key, and it really signed this intent.
    const agentPem = this.agents.get(envelope.agentKeyId);
    if (!agentPem) return { ok: false, reason: `unknown agent key ${envelope.agentKeyId}` };
    if (!verifyBytes(Buffer.from(token.intent), Buffer.from(token.intentSignature, "base64url"), agentPem)) {
      return { ok: false, reason: "intent signature invalid" };
    }

    // 2. User consent: mandate signed by a registered user key, naming this agent.
    let mandate: Mandate;
    try {
      const draft = decodeMandatePayload(token.mandate);
      const userPem = this.users.get(draft.userKeyId);
      if (!userPem) return { ok: false, reason: `unknown user key ${draft.userKeyId}` };
      mandate = verifyMandate(token.mandate, userPem);
    } catch (e) {
      return { ok: false, reason: (e as Error).message };
    }
    if (mandate.agentKeyId !== envelope.agentKeyId) {
      return { ok: false, reason: "mandate was granted to a different agent" };
    }
    if (mandate.mandateId !== envelope.mandateId) {
      return { ok: false, reason: "intent references a different mandate" };
    }

    // 3. The signed intent must match what the rail is about to execute.
    if (envelope.amountUsd !== claims.amountUsd) return { ok: false, reason: "amount does not match signed intent" };
    if (envelope.source !== claims.source) return { ok: false, reason: "source does not match signed intent" };
    if ((envelope.mcc ?? undefined) !== (claims.mcc ?? undefined)) {
      return { ok: false, reason: "mcc does not match signed intent" };
    }

    // 4. Replay (report early so the reason names the attack, not a side
    //    effect like an exhausted budget; the atomic add in step 6 is the guard).
    if (this.nonces.has && (await this.nonces.has(envelope.nonce))) {
      return { ok: false, reason: "replayed booking token" };
    }

    // 5. Constraints.
    const c = mandate.constraints;
    const now = Date.now();
    if (now > Date.parse(c.expiresAt)) return { ok: false, reason: "mandate expired" };
    const created = Date.parse(envelope.createdAt);
    if (Number.isNaN(created) || created - now > this.maxSkewMs) {
      return { ok: false, reason: "intent createdAt out of range" };
    }
    if (this.consumed.has(mandate.mandateId)) return { ok: false, reason: "single-use mandate already consumed" };
    if (claims.amountUsd <= 0) return { ok: false, reason: "amount must be > 0" };
    const perBooking = c.maxPerBookingUsd ?? c.maxTotalUsd;
    if (claims.amountUsd > perBooking) {
      return { ok: false, reason: `amount $${claims.amountUsd} exceeds per-booking cap $${perBooking}` };
    }
    const spent = this.spent.get(mandate.mandateId) ?? 0;
    if (spent + claims.amountUsd > c.maxTotalUsd) {
      return { ok: false, reason: `amount $${claims.amountUsd} exceeds remaining allowance $${(c.maxTotalUsd - spent).toFixed(2)}` };
    }
    if (c.mccAllowlist?.length && claims.mcc && !c.mccAllowlist.includes(claims.mcc)) {
      return { ok: false, reason: `mcc ${claims.mcc} not in mandate allowlist` };
    }
    if (c.mccAllowlist?.length && !claims.mcc && claims.source !== "travala") {
      return { ok: false, reason: "mandate requires an MCC for card-routed bookings" };
    }
    if (c.sourceAllowlist?.length && !c.sourceAllowlist.includes(claims.source)) {
      return { ok: false, reason: `source ${claims.source} not in mandate allowlist` };
    }

    // 6. Replay: this exact token clears verification once.
    if (!(await this.nonces.add(envelope.nonce))) return { ok: false, reason: "replayed booking token" };

    // Commit.
    this.spent.set(mandate.mandateId, spent + claims.amountUsd);
    if (c.singleUse) this.consumed.add(mandate.mandateId);
    return {
      ok: true,
      agentKeyId: envelope.agentKeyId,
      mandateId: mandate.mandateId,
      remainingUsd: Math.round((c.maxTotalUsd - spent - claims.amountUsd) * 100) / 100,
    };
  }

  /**
   * Verify a single-use capability token at a tool-server.
   *
   * `expect.audience` MUST be this server's own id — a token minted for another
   * audience is rejected, so a capability leaked from one tool-server can't be
   * replayed at another. `expect.presenterKeyId` is the agent key that
   * authenticated THIS request (e.g. the keyid from verifyRequest); it must
   * equal the key that minted the token — the proof-of-possession check that
   * stops a stolen token from being used by a different holder. The jti burns
   * on first success, so the token clears exactly once.
   */
  async verifyCapability(
    tokenB64: string,
    expect: {
      audience: string;
      action?: string;
      presenterKeyId?: string;
      /** Reject value-moving calls above this ceiling even if the token allows more. */
      maxUsd?: number;
      maxSkewSeconds?: number;
    },
  ): Promise<CapabilityDecision> {
    let token: SignedCapability;
    let grant: CapabilityGrant;
    try {
      token = JSON.parse(Buffer.from(tokenB64, "base64url").toString()) as SignedCapability;
      grant = JSON.parse(Buffer.from(token.payload, "base64url").toString()) as CapabilityGrant;
    } catch {
      return { ok: false, reason: "malformed capability token" };
    }
    if (grant.v !== 1) return { ok: false, reason: `unsupported capability version ${grant.v}` };

    // 1. Minter identity: registered agent key that really signed this grant.
    const agentPem = this.agents.get(grant.agentKeyId);
    if (!agentPem) return { ok: false, reason: `unknown agent key ${grant.agentKeyId}` };
    if (!verifyBytes(Buffer.from(token.payload), Buffer.from(token.signature, "base64url"), agentPem)) {
      return { ok: false, reason: "capability signature invalid" };
    }

    // 2. Proof-of-possession: presenter must be the key the token was minted for.
    if (expect.presenterKeyId && expect.presenterKeyId !== grant.agentKeyId) {
      return { ok: false, reason: "capability presented by a different key than it was minted for" };
    }

    // 3. Audience + action binding.
    if (grant.audience !== expect.audience) {
      return { ok: false, reason: `capability audience ${grant.audience} does not match this server` };
    }
    if (expect.action && grant.action !== expect.action) {
      return { ok: false, reason: `capability action ${grant.action} does not grant ${expect.action}` };
    }

    // 4. Freshness.
    const now = Date.now();
    const exp = Date.parse(grant.exp);
    if (Number.isNaN(exp) || now > exp) return { ok: false, reason: "capability expired" };
    const iat = Date.parse(grant.iat);
    const skewMs = (expect.maxSkewSeconds ?? 300) * 1000;
    if (Number.isNaN(iat) || iat - now > skewMs) return { ok: false, reason: "capability iat out of range" };

    // 5. Value ceiling.
    if (expect.maxUsd != null && grant.maxUsd != null && grant.maxUsd > expect.maxUsd) {
      return { ok: false, reason: `capability maxUsd $${grant.maxUsd} exceeds server ceiling $${expect.maxUsd}` };
    }

    // 6. Replay check (report before the burn so the reason names the attack).
    if (this.nonces.has && (await this.nonces.has(grant.jti))) {
      return { ok: false, reason: "replayed capability token" };
    }
    // 7. Single-use burn — clears exactly once.
    if (!(await this.nonces.add(grant.jti))) return { ok: false, reason: "replayed capability token" };

    return {
      ok: true,
      agentKeyId: grant.agentKeyId,
      jti: grant.jti,
      audience: grant.audience,
      action: grant.action,
      mandateId: grant.mandateId,
      maxUsd: grant.maxUsd,
    };
  }
}

// ── RFC 9421 HTTP Message Signatures (TAP transport binding) ────────────────
//
// Covered components: "@method" "@target-uri" "content-digest"; parameters
// keyid, created, expires, nonce, tag. This is the subset TAP profiles for
// agent-initiated requests — enough for a merchant/API to authenticate WHO
// sent a request and THAT the body wasn't swapped, without TLS client certs.

export interface SignRequestParams {
  method: string;
  url: string;
  body?: string | Buffer;
  keyId: string;
  privateKeyPem: string;
  /** RFC 9421 tag parameter. Default "agent-payment". */
  tag?: string;
  /** Signature lifetime in seconds. Default 120. */
  ttlSeconds?: number;
}

export interface SignedRequestHeaders {
  "content-digest": string;
  "signature-input": string;
  signature: string;
}

const SIG_LABEL = "furlpay";

function contentDigest(body: string | Buffer): string {
  return `sha-256=:${crypto.createHash("sha256").update(body).digest("base64")}:`;
}

function signatureBase(method: string, url: string, digest: string, params: string): string {
  return [
    `"@method": ${method.toUpperCase()}`,
    `"@target-uri": ${new URL(url).href}`,
    `"content-digest": ${digest}`,
    `"@signature-params": ${params}`,
  ].join("\n");
}

/** Produce RFC 9421 headers for an agent-initiated HTTP request. */
export function signRequest(p: SignRequestParams): SignedRequestHeaders {
  const created = Math.floor(Date.now() / 1000);
  const expires = created + (p.ttlSeconds ?? 120);
  const nonce = b64url(crypto.randomBytes(16));
  const digest = contentDigest(p.body ?? "");
  const params =
    `("@method" "@target-uri" "content-digest")` +
    `;created=${created};expires=${expires};keyid="${p.keyId}";nonce="${nonce}";tag="${p.tag ?? "agent-payment"}"`;
  const sig = signBytes(Buffer.from(signatureBase(p.method, p.url, digest, params)), p.privateKeyPem);
  return {
    "content-digest": digest,
    "signature-input": `${SIG_LABEL}=${params}`,
    signature: `${SIG_LABEL}=:${sig.toString("base64")}:`,
  };
}

export interface VerifyRequestParams {
  method: string;
  url: string;
  body?: string | Buffer;
  headers: Record<string, string | undefined>;
  /** Resolve a keyid to its public key PEM; return undefined for unknown keys. */
  resolvePublicKey: (keyId: string) => string | undefined;
}

export interface VerifiedRequest {
  keyId: string;
  tag?: string;
  nonce?: string;
  created: number;
  expires: number;
}

/** Verify RFC 9421 headers on an inbound request. Throws on any failure. */
export function verifyRequest(p: VerifyRequestParams): VerifiedRequest {
  const header = (n: string) => p.headers[n] ?? p.headers[n.toLowerCase()];
  const sigInput = header("signature-input");
  const sigHeader = header("signature");
  const digestHeader = header("content-digest");
  if (!sigInput || !sigHeader || !digestHeader) throw new Error("missing signature headers");

  const inputMatch = sigInput.match(new RegExp(`${SIG_LABEL}=(\\(.*?\\);.*)$`));
  if (!inputMatch) throw new Error(`no "${SIG_LABEL}" entry in signature-input`);
  const params = inputMatch[1];

  const param = (name: string) => params.match(new RegExp(`;${name}="?([^;"]+)"?`))?.[1];
  const keyId = param("keyid");
  const created = Number(param("created"));
  const expires = Number(param("expires"));
  if (!keyId || !created || !expires) throw new Error("missing signature parameters");
  const now = Math.floor(Date.now() / 1000);
  if (now > expires) throw new Error("signature expired");

  const expectedDigest = contentDigest(p.body ?? "");
  if (digestHeader !== expectedDigest) throw new Error("content-digest mismatch");

  const pem = p.resolvePublicKey(keyId);
  if (!pem) throw new Error(`unknown keyid ${keyId}`);

  const sigMatch = sigHeader.match(new RegExp(`${SIG_LABEL}=:([A-Za-z0-9+/=]+):`));
  if (!sigMatch) throw new Error(`no "${SIG_LABEL}" entry in signature header`);

  const base = signatureBase(p.method, p.url, expectedDigest, params);
  if (!verifyBytes(Buffer.from(base), Buffer.from(sigMatch[1], "base64"), pem)) {
    throw new Error("request signature invalid");
  }
  return { keyId, tag: param("tag"), nonce: param("nonce"), created, expires };
}

// ── Per-request spend policy ───────────────────────────────────────────────
//
// Separate from the mandate system above, and deliberately so. A mandate
// governs BOOKINGS — a signed allowance spent on discrete purchases. An agent
// paying an API per request is the opposite shape: thousands of sub-cent calls
// with no per-call human intent, where the operator's question is rate, not
// authorisation. See ./spend.ts.
export {
  MICROS_PER_UNIT,
  SpendLimiter,
  authorize,
  formatMicros,
  priceFor,
  toMicros,
  type DenialReason,
  type EndpointPrices,
  type Micros,
  type Reservation,
  type SpendDecision,
  type SpendLimiterOptions,
  type SpendPolicy,
} from "./spend.js";
