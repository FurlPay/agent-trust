import test from "node:test";
import assert from "node:assert/strict";
import {
  AgentTrust,
  createBookingToken,
  generateKeypair,
  issueMandate,
  keyIdOf,
  mintCapability,
  signRequest,
  verifyMandate,
  verifyRequest,
} from "../dist/src/index.js";

const HOUR = 3600 * 1000;
const inOneHour = () => new Date(Date.now() + HOUR).toISOString();

function setup(constraints = {}) {
  const user = generateKeypair("user");
  const agent = generateKeypair("agent");
  const trust = new AgentTrust();
  trust.registerUser(user.publicKeyPem);
  trust.registerAgent(agent.publicKeyPem);
  const mandate = issueMandate({
    userPrivateKeyPem: user.privateKeyPem,
    userPublicKeyPem: user.publicKeyPem,
    agentKeyId: agent.keyId,
    constraints: { maxTotalUsd: 1000, expiresAt: inOneHour(), ...constraints },
  });
  const token = (intent) =>
    createBookingToken({
      mandate,
      agentPrivateKeyPem: agent.privateKeyPem,
      agentPublicKeyPem: agent.publicKeyPem,
      intent,
    });
  return { user, agent, trust, mandate, token };
}

// ── identity ────────────────────────────────────────────────────────────────

test("keypair ids are role-prefixed SPKI fingerprints", () => {
  const user = generateKeypair("user");
  const agent = generateKeypair("agent");
  assert.match(user.keyId, /^uk_/);
  assert.match(agent.keyId, /^ak_/);
  assert.equal(keyIdOf(user.publicKeyPem, "user"), user.keyId);
});

// ── mandates ────────────────────────────────────────────────────────────────

test("mandate round-trips and verifies against the user key", () => {
  const { user, agent, mandate } = setup();
  const decoded = verifyMandate(mandate, user.publicKeyPem);
  assert.equal(decoded.agentKeyId, agent.keyId);
  assert.equal(decoded.constraints.maxTotalUsd, 1000);
});

test("mandate signed by a different key is rejected", () => {
  const { mandate } = setup();
  const stranger = generateKeypair("user");
  assert.throws(() => verifyMandate(mandate, stranger.publicKeyPem), /invalid|match/);
});

test("tampered mandate payload is rejected", () => {
  const { user, mandate } = setup();
  const decoded = JSON.parse(Buffer.from(mandate.payload, "base64url").toString());
  decoded.constraints.maxTotalUsd = 1_000_000;
  const forged = { ...mandate, payload: Buffer.from(JSON.stringify(decoded)).toString("base64url") };
  assert.throws(() => verifyMandate(forged, user.publicKeyPem), /invalid/);
});

// ── booking token verification ──────────────────────────────────────────────

test("valid booking token clears the full chain and decrements budget", async () => {
  const { trust, token } = setup();
  const t = token({ amountUsd: 250, source: "travala" });
  const d = await trust.verifyBookingToken(t, { amountUsd: 250, source: "travala" });
  assert.equal(d.ok, true);
  assert.equal(d.remainingUsd, 750);
});

test("replayed token is rejected", async () => {
  const { trust, token } = setup();
  const t = token({ amountUsd: 10, source: "travala" });
  assert.equal((await trust.verifyBookingToken(t, { amountUsd: 10, source: "travala" })).ok, true);
  const replay = await trust.verifyBookingToken(t, { amountUsd: 10, source: "travala" });
  assert.equal(replay.ok, false);
  assert.match(replay.reason, /replayed/);
});

test("claims that differ from the signed intent are rejected", async () => {
  const { trust, token } = setup();
  const t = token({ amountUsd: 100, source: "travala" });
  const d = await trust.verifyBookingToken(t, { amountUsd: 900, source: "travala" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /amount does not match/);
});

test("budget exhaustion across bookings is enforced", async () => {
  const { trust, token } = setup();
  const first = token({ amountUsd: 800, source: "travala" });
  assert.equal((await trust.verifyBookingToken(first, { amountUsd: 800, source: "travala" })).ok, true);
  const second = token({ amountUsd: 300, source: "travala" });
  const d = await trust.verifyBookingToken(second, { amountUsd: 300, source: "travala" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /remaining allowance/);
});

test("per-booking cap is enforced independently of the total", async () => {
  const { trust, token } = setup({ maxPerBookingUsd: 100 });
  const t = token({ amountUsd: 500, source: "travala" });
  const d = await trust.verifyBookingToken(t, { amountUsd: 500, source: "travala" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /per-booking cap/);
});

test("MCC allowlist blocks off-category card bookings", async () => {
  const { trust, token } = setup({ mccAllowlist: ["7011"] });
  const flights = token({ amountUsd: 50, source: "legacy", mcc: "4511" });
  const d = await trust.verifyBookingToken(flights, { amountUsd: 50, source: "legacy", mcc: "4511" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /not in mandate allowlist/);

  const lodging = token({ amountUsd: 50, source: "legacy", mcc: "7011" });
  assert.equal((await trust.verifyBookingToken(lodging, { amountUsd: 50, source: "legacy", mcc: "7011" })).ok, true);
});

test("card-routed booking without an MCC is rejected when the mandate scopes MCCs", async () => {
  const { trust, token } = setup({ mccAllowlist: ["7011"] });
  const t = token({ amountUsd: 50, source: "legacy" });
  const d = await trust.verifyBookingToken(t, { amountUsd: 50, source: "legacy" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /requires an MCC/);
});

test("source allowlist is enforced", async () => {
  const { trust, token } = setup({ sourceAllowlist: ["travala"] });
  const t = token({ amountUsd: 50, source: "legacy", mcc: "7011" });
  const d = await trust.verifyBookingToken(t, { amountUsd: 50, source: "legacy", mcc: "7011" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /source legacy not in/);
});

test("expired mandate is rejected", async () => {
  const { trust, token } = setup({ expiresAt: new Date(Date.now() - 1000).toISOString() });
  const t = token({ amountUsd: 10, source: "travala" });
  const d = await trust.verifyBookingToken(t, { amountUsd: 10, source: "travala" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /expired/);
});

test("single-use mandate is consumed by its first booking", async () => {
  const { trust, token } = setup({ singleUse: true });
  const first = token({ amountUsd: 10, source: "travala" });
  assert.equal((await trust.verifyBookingToken(first, { amountUsd: 10, source: "travala" })).ok, true);
  const second = token({ amountUsd: 10, source: "travala" });
  const d = await trust.verifyBookingToken(second, { amountUsd: 10, source: "travala" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /already consumed/);
});

test("mandate granted to a different agent cannot be presented by another", async () => {
  const { user, trust, mandate } = setup();
  const rogue = generateKeypair("agent");
  trust.registerAgent(rogue.publicKeyPem);
  const t = createBookingToken({
    mandate,
    agentPrivateKeyPem: rogue.privateKeyPem,
    agentPublicKeyPem: rogue.publicKeyPem,
    intent: { amountUsd: 10, source: "travala" },
  });
  const d = await trust.verifyBookingToken(t, { amountUsd: 10, source: "travala" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /different agent/);
  void user;
});

test("unregistered agent key is rejected", async () => {
  const { token } = setup();
  const emptyTrust = new AgentTrust();
  const t = token({ amountUsd: 10, source: "travala" });
  const d = await emptyTrust.verifyBookingToken(t, { amountUsd: 10, source: "travala" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /unknown agent key/);
});

test("garbage token is rejected, not thrown", async () => {
  const { trust } = setup();
  const d = await trust.verifyBookingToken("not-a-token", { amountUsd: 1, source: "travala" });
  assert.equal(d.ok, false);
  assert.match(d.reason, /malformed/);
});

// ── RFC 9421 request signatures ─────────────────────────────────────────────

test("signed HTTP request verifies end-to-end", () => {
  const agent = generateKeypair("agent");
  const body = JSON.stringify({ amountUsd: 42 });
  const url = "https://api.furlpay.com/v1/escrow";
  const headers = signRequest({ method: "POST", url, body, keyId: agent.keyId, privateKeyPem: agent.privateKeyPem });
  const verified = verifyRequest({
    method: "POST",
    url,
    body,
    headers,
    resolvePublicKey: (id) => (id === agent.keyId ? agent.publicKeyPem : undefined),
  });
  assert.equal(verified.keyId, agent.keyId);
  assert.equal(verified.tag, "agent-payment");
});

test("body tamper breaks content-digest", () => {
  const agent = generateKeypair("agent");
  const url = "https://api.furlpay.com/v1/escrow";
  const headers = signRequest({ method: "POST", url, body: '{"amountUsd":42}', keyId: agent.keyId, privateKeyPem: agent.privateKeyPem });
  assert.throws(
    () =>
      verifyRequest({
        method: "POST",
        url,
        body: '{"amountUsd":9000}',
        headers,
        resolvePublicKey: () => agent.publicKeyPem,
      }),
    /content-digest mismatch/,
  );
});

test("signature from a different key is rejected", () => {
  const agent = generateKeypair("agent");
  const other = generateKeypair("agent");
  const url = "https://api.furlpay.com/v1/escrow";
  const body = "{}";
  const headers = signRequest({ method: "POST", url, body, keyId: agent.keyId, privateKeyPem: agent.privateKeyPem });
  assert.throws(
    () => verifyRequest({ method: "POST", url, body, headers, resolvePublicKey: () => other.publicKeyPem }),
    /signature invalid/,
  );
});

test("unknown keyid is rejected", () => {
  const agent = generateKeypair("agent");
  const url = "https://api.furlpay.com/v1/escrow";
  const headers = signRequest({ method: "POST", url, body: "", keyId: agent.keyId, privateKeyPem: agent.privateKeyPem });
  assert.throws(
    () => verifyRequest({ method: "POST", url, body: "", headers, resolvePublicKey: () => undefined }),
    /unknown keyid/,
  );
});

// ── capability tokens (single-use, audience-bound, PoP) ─────────────────────

function capSetup() {
  const agent = generateKeypair("agent");
  const trust = new AgentTrust();
  trust.registerAgent(agent.publicKeyPem);
  const mint = (over = {}) =>
    mintCapability({
      agentPrivateKeyPem: agent.privateKeyPem,
      agentPublicKeyPem: agent.publicKeyPem,
      audience: "https://travel-mcp.furlpay.com",
      action: "pay:travala",
      ...over,
    });
  return { agent, trust, mint };
}

test("capability: valid token at the right audience clears once", async () => {
  const { agent, trust, mint } = capSetup();
  const tok = mint();
  const d = await trust.verifyCapability(tok, {
    audience: "https://travel-mcp.furlpay.com",
    action: "pay:travala",
    presenterKeyId: agent.keyId,
  });
  assert.equal(d.ok, true);
  assert.equal(d.agentKeyId, agent.keyId);
  assert.equal(d.audience, "https://travel-mcp.furlpay.com");
});

test("capability: single-use — a replay is rejected", async () => {
  const { agent, trust, mint } = capSetup();
  const tok = mint();
  const opts = { audience: "https://travel-mcp.furlpay.com", presenterKeyId: agent.keyId };
  assert.equal((await trust.verifyCapability(tok, opts)).ok, true);
  const replay = await trust.verifyCapability(tok, opts);
  assert.equal(replay.ok, false);
  assert.match(replay.reason, /replay/);
});

test("capability: wrong audience is rejected (no cross-server replay)", async () => {
  const { agent, trust, mint } = capSetup();
  const tok = mint();
  const d = await trust.verifyCapability(tok, {
    audience: "https://payments.furlpay.com",
    presenterKeyId: agent.keyId,
  });
  assert.equal(d.ok, false);
  assert.match(d.reason, /audience/);
});

test("capability: proof-of-possession — a different presenter key is rejected", async () => {
  const { agent, trust, mint } = capSetup();
  const other = generateKeypair("agent");
  const tok = mint();
  const d = await trust.verifyCapability(tok, {
    audience: "https://travel-mcp.furlpay.com",
    presenterKeyId: other.keyId,
  });
  assert.equal(d.ok, false);
  assert.match(d.reason, /different key/);
});

test("capability: action mismatch is rejected", async () => {
  const { agent, trust, mint } = capSetup();
  const tok = mint({ action: "wallet.read" });
  const d = await trust.verifyCapability(tok, {
    audience: "https://travel-mcp.furlpay.com",
    action: "pay:travala",
    presenterKeyId: agent.keyId,
  });
  assert.equal(d.ok, false);
  assert.match(d.reason, /action/);
});

test("capability: expired token is rejected", async () => {
  const { agent, trust, mint } = capSetup();
  const tok = mint({ ttlSeconds: -1 });
  const d = await trust.verifyCapability(tok, {
    audience: "https://travel-mcp.furlpay.com",
    presenterKeyId: agent.keyId,
  });
  assert.equal(d.ok, false);
  assert.match(d.reason, /expired/);
});

test("capability: unregistered agent key is rejected", async () => {
  const { mint } = capSetup();
  const strangerTrust = new AgentTrust();
  const tok = mint();
  const d = await strangerTrust.verifyCapability(tok, {
    audience: "https://travel-mcp.furlpay.com",
  });
  assert.equal(d.ok, false);
  assert.match(d.reason, /unknown agent key/);
});

test("capability: server value ceiling overrides a larger token maxUsd", async () => {
  const { agent, trust, mint } = capSetup();
  const tok = mint({ maxUsd: 5000 });
  const d = await trust.verifyCapability(tok, {
    audience: "https://travel-mcp.furlpay.com",
    presenterKeyId: agent.keyId,
    maxUsd: 1000,
  });
  assert.equal(d.ok, false);
  assert.match(d.reason, /ceiling/);
});

test("capability: tampered payload fails the signature check", async () => {
  const { agent, trust } = capSetup();
  const tok = mintCapability({
    agentPrivateKeyPem: agent.privateKeyPem,
    agentPublicKeyPem: agent.publicKeyPem,
    audience: "https://travel-mcp.furlpay.com",
    action: "pay:travala",
    maxUsd: 100,
  });
  // Flip a byte in the inner payload, re-encode the outer token.
  const outer = JSON.parse(Buffer.from(tok, "base64url").toString());
  const grant = JSON.parse(Buffer.from(outer.payload, "base64url").toString());
  grant.maxUsd = 999999;
  outer.payload = Buffer.from(JSON.stringify(grant)).toString("base64url");
  const tampered = Buffer.from(JSON.stringify(outer)).toString("base64url");
  const d = await trust.verifyCapability(tampered, {
    audience: "https://travel-mcp.furlpay.com",
    presenterKeyId: agent.keyId,
  });
  assert.equal(d.ok, false);
  assert.match(d.reason, /signature invalid/);
});
