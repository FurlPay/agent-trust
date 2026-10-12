import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  AgentTrust,
  createBookingToken,
  generateKeypair,
  issueMandate,
  mintCapability,
  verifyMandate,
} from "../dist/src/index.js";

// ---------------------------------------------------------------------------
// Spend caps are enforced on exact amounts, and hold under concurrency.
//
// Two defects, one path. Spend was summed as IEEE-754 doubles, so a $0.30
// mandate refused $0.20 after $0.10 (0.1 + 0.2 > 0.3). And the cap was read
// before an `await` and written after it, so concurrent bookings each saw the
// same `spent`: three $60 bookings cleared a $100 cap, and a single-use
// mandate was spent twice. Expected values below are written out by hand,
// not computed with the library's own helpers.
// ---------------------------------------------------------------------------

const inOneHour = () => new Date(Date.now() + 3600_000).toISOString();
const b64url = (s) => Buffer.from(s).toString("base64url");
const sign = (data, pem) => crypto.sign(null, Buffer.from(data), pem).toString("base64url");

function setup(constraints = {}, opts = {}) {
  const user = generateKeypair("user");
  const agent = generateKeypair("agent");
  const trust = new AgentTrust(opts);
  trust.registerUser(user.publicKeyPem);
  trust.registerAgent(agent.publicKeyPem);
  const mandate = issueMandate({
    userPrivateKeyPem: user.privateKeyPem,
    userPublicKeyPem: user.publicKeyPem,
    agentKeyId: agent.keyId,
    constraints: { maxTotalUsd: 0.3, expiresAt: inOneHour(), ...constraints },
  });
  const token = (amountUsd, m = mandate) =>
    createBookingToken({ mandate: m, agentPrivateKeyPem: agent.privateKeyPem, agentPublicKeyPem: agent.publicKeyPem, intent: { amountUsd, source: "travala" } });
  const book = (amountUsd, t = token(amountUsd)) => trust.verifyBookingToken(t, { amountUsd, source: "travala" });
  return { user, agent, trust, mandate, token, book };
}

/** A booking token signed by hand, for intents createBookingToken now refuses to build. */
function forgedToken({ agent, mandate }, amountUsd) {
  const envelope = {
    amountUsd,
    source: "travala",
    mandateId: JSON.parse(Buffer.from(mandate.payload, "base64url")).mandateId,
    agentKeyId: agent.keyId,
    nonce: crypto.randomBytes(16).toString("base64url"),
    createdAt: new Date().toISOString(),
  };
  const intent = b64url(JSON.stringify(envelope));
  return b64url(JSON.stringify({ mandate, intent, intentSignature: sign(intent, agent.privateKeyPem) }));
}

/** A mandate signed by hand, as an older or foreign issuer might have produced it. */
function legacyMandate({ user, agent }, constraints) {
  const userKeyId = JSON.parse(
    Buffer.from(
      issueMandate({ userPrivateKeyPem: user.privateKeyPem, userPublicKeyPem: user.publicKeyPem, agentKeyId: agent.keyId, constraints: { maxTotalUsd: 1, expiresAt: inOneHour() } }).payload,
      "base64url"
    )
  ).userKeyId;
  const payload = b64url(
    JSON.stringify({ v: 1, mandateId: "mnd_legacy_" + crypto.randomBytes(4).toString("hex"), userKeyId, agentKeyId: agent.keyId, constraints: { expiresAt: inOneHour(), ...constraints }, issuedAt: new Date().toISOString() })
  );
  return { payload, signature: sign(payload, user.privateKeyPem) };
}

// ── the reported case ──────────────────────────────────────────────────────

test("a $0.30 cap accepts $0.10 then $0.20, then refuses any further spend", async () => {
  const { book } = setup({ maxTotalUsd: 0.3 });
  const first = await book(0.1);
  assert.equal(first.ok, true);
  assert.equal(first.remainingUsdExact, "0.20");
  const second = await book(0.2);
  assert.equal(second.ok, true, second.reason);
  assert.equal(second.remainingUsdExact, "0.00");
  assert.equal(second.remainingUsd, 0);
  const third = await book(0.01);
  assert.equal(third.ok, false);
  assert.equal(third.reason, "amount $0.01 exceeds remaining allowance $0.00");
});

test("a booking equal to the whole cap is accepted", async () => {
  const { book } = setup({ maxTotalUsd: 123.45 });
  assert.equal((await book(123.45)).ok, true);
});

test("one micro-dollar over the remaining allowance is refused; exactly the allowance is not", async () => {
  const { book } = setup({ maxTotalUsd: 0.3 });
  await book(0.1);
  const over = await book(0.200001);
  assert.equal(over.ok, false);
  assert.equal(over.reason, "amount $0.200001 exceeds remaining allowance $0.20");
  assert.equal((await book(0.2)).ok, true);
});

test("the per-booking cap is enforced independently of the total", async () => {
  const { book } = setup({ maxTotalUsd: 1, maxPerBookingUsd: 0.05 });
  const big = await book(0.050001);
  assert.equal(big.ok, false);
  assert.equal(big.reason, "amount $0.050001 exceeds per-booking cap $0.05");
  assert.equal((await book(0.05)).ok, true);
});

test("many small bookings accumulate without drift", async () => {
  const cents = setup({ maxTotalUsd: 1 });
  for (let i = 0; i < 100; i++) assert.equal((await cents.book(0.01)).ok, true, `booking ${i + 1}`);
  assert.equal((await cents.book(0.01)).ok, false);

  const dimes = setup({ maxTotalUsd: 1 });
  for (let i = 0; i < 10; i++) assert.equal((await dimes.book(0.1)).ok, true, `dime ${i + 1}`);
  assert.equal((await dimes.book(0.000001)).ok, false);
});

test("boundary values: the largest cap is exact, and $1e9 is refused", async () => {
  const { book } = setup({ maxTotalUsd: 999999999.999999 });
  assert.equal((await book(999999999.999998)).ok, true);
  const over = await book(0.000002);
  assert.equal(over.ok, false);
  assert.equal(over.reason, "amount $0.000002 exceeds remaining allowance $0.000001");
  assert.throws(() => setup({ maxTotalUsd: 1e9 }), /maxTotalUsd/);
});

// ── inputs the library refuses ─────────────────────────────────────────────

const UNREADABLE = [NaN, Infinity, -Infinity, -0.01, 0.1234567, 1e-7, 1e21, 0.1 + 0.2, "0.10", null];

test("issuers refuse amounts they could not later read back exactly", () => {
  const { user, agent, mandate } = setup();
  for (const bad of UNREADABLE) {
    assert.throws(
      () => issueMandate({ userPrivateKeyPem: user.privateKeyPem, userPublicKeyPem: user.publicKeyPem, agentKeyId: agent.keyId, constraints: { maxTotalUsd: bad, expiresAt: inOneHour() } }),
      /maxTotalUsd/,
      `cap ${String(bad)}`
    );
    assert.throws(
      () => createBookingToken({ mandate, agentPrivateKeyPem: agent.privateKeyPem, agentPublicKeyPem: agent.publicKeyPem, intent: { amountUsd: bad, source: "travala" } }),
      /amountUsd/,
      `amount ${String(bad)}`
    );
  }
  for (const bad of [0, -1]) {
    assert.throws(() => issueMandate({ userPrivateKeyPem: user.privateKeyPem, userPublicKeyPem: user.publicKeyPem, agentKeyId: agent.keyId, constraints: { maxTotalUsd: 1, maxPerBookingUsd: bad, expiresAt: inOneHour() } }), /maxPerBookingUsd/);
  }
});

test("a signed intent with a zero, negative or unreadable amount is refused and spends nothing", async () => {
  const s = setup({ maxTotalUsd: 0.3 });
  for (const bad of [0, -0.1, 0.1234567, 1e-7, 0.1 + 0.2]) {
    const r = await s.trust.verifyBookingToken(forgedToken(s, bad), { amountUsd: bad, source: "travala" });
    assert.equal(r.ok, false, `amount ${bad} was approved`);
  }
  assert.equal((await s.book(0.3)).ok, true, "the whole cap is still available");
});

test("a legacy mandate whose cap cannot be read exactly is refused, never approximated", async () => {
  const s = setup();
  for (const constraints of [{ maxTotalUsd: 0.1234567 }, { maxTotalUsd: 1, maxPerBookingUsd: 1e-9 }, { maxTotalUsd: -5 }]) {
    const m = legacyMandate(s, constraints);
    const r = await s.trust.verifyBookingToken(s.token(0.01, m), { amountUsd: 0.01, source: "travala" });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "mandate spend limits are not exact USD amounts");
  }
});

test("a legacy mandate with exact amounts still works unchanged", async () => {
  const s = setup();
  const m = legacyMandate(s, { maxTotalUsd: 0.3 });
  assert.equal((await s.trust.verifyBookingToken(s.token(0.1, m), { amountUsd: 0.1, source: "travala" })).ok, true);
  assert.equal((await s.trust.verifyBookingToken(s.token(0.2, m), { amountUsd: 0.2, source: "travala" })).ok, true);
});

// ── serialization and signatures ───────────────────────────────────────────

test("the signed payload carries the amount as written, and verifies to the same value", () => {
  const s = setup({ maxTotalUsd: 0.3, maxPerBookingUsd: 0.25 });
  const text = Buffer.from(s.mandate.payload, "base64url").toString();
  assert.match(text, /"maxTotalUsd":0\.3[,}]/);
  assert.match(text, /"maxPerBookingUsd":0\.25[,}]/);
  const decoded = verifyMandate(s.mandate, s.user.publicKeyPem);
  assert.equal(decoded.constraints.maxTotalUsd, 0.3);
  assert.equal(decoded.v, 1, "the wire format is unchanged");
});

test("raising the signed cap breaks the user's signature", async () => {
  const s = setup({ maxTotalUsd: 0.3 });
  const body = JSON.parse(Buffer.from(s.mandate.payload, "base64url"));
  body.constraints.maxTotalUsd = 0.31;
  const forged = { payload: b64url(JSON.stringify(body)), signature: s.mandate.signature };
  const r = await s.trust.verifyBookingToken(s.token(0.31, forged), { amountUsd: 0.31, source: "travala" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "mandate signature invalid");
});

test("the rail's claimed amount must equal the signed amount exactly", async () => {
  const s = setup({ maxTotalUsd: 1 });
  const t = s.token(0.3);
  const r = await s.trust.verifyBookingToken(t, { amountUsd: 0.1 + 0.2, source: "travala" });
  assert.equal(r.ok, false, "0.30000000000000004 is not the $0.30 the agent signed");
  assert.equal((await s.trust.verifyBookingToken(t, { amountUsd: 0.3, source: "travala" })).ok, true);
});

// ── concurrency ────────────────────────────────────────────────────────────

test("concurrent bookings cannot together exceed the cap", async () => {
  const { book } = setup({ maxTotalUsd: 100 });
  const results = await Promise.all([60, 60, 60].map((a) => book(a)));
  assert.equal(results.filter((r) => r.ok).length, 1, "only $60 of three $60 bookings fits under $100");
});

test("a single-use mandate is consumed exactly once under concurrency", async () => {
  const { book } = setup({ maxTotalUsd: 100, singleUse: true });
  const results = await Promise.all([10, 10, 10].map((a) => book(a)));
  assert.equal(results.filter((r) => r.ok).length, 1);
});

/** A nonce store with network latency, like Redis SET NX. */
function slowNonceStore({ failOn } = {}) {
  const seen = new Set();
  const tick = () => new Promise((r) => setTimeout(r, Math.random() * 5));
  return {
    has: async (n) => (await tick(), seen.has(n)),
    add: async (n) => {
      await tick();
      if (failOn?.(n)) throw new Error("store unavailable");
      if (seen.has(n)) return false;
      seen.add(n);
      return true;
    },
  };
}

test("with a slow shared nonce store, concurrent bookings still respect the cap", async () => {
  const { book } = setup({ maxTotalUsd: 1 }, { nonceStore: slowNonceStore() });
  const results = await Promise.all(Array.from({ length: 20 }, () => book(0.1)));
  assert.equal(results.filter((r) => r.ok).length, 10);
});

test("a replayed token gives its reservation back", async () => {
  const s = setup({ maxTotalUsd: 0.3 }, { nonceStore: slowNonceStore() });
  const t = s.token(0.2);
  const [a, b] = await Promise.all([s.book(0.2, t), s.book(0.2, t)]);
  assert.deepEqual([a.ok, b.ok].sort(), [false, true]);
  assert.equal((await s.book(0.1)).ok, true, "the replay did not keep $0.20 reserved");
});

test("a nonce store that throws approves nothing and spends nothing", async () => {
  let fail = true;
  const s = setup({ maxTotalUsd: 0.3, singleUse: true }, { nonceStore: slowNonceStore({ failOn: () => fail }) });
  await assert.rejects(s.book(0.3), /store unavailable/);
  fail = false;
  const r = await s.book(0.3);
  assert.equal(r.ok, true, "neither the budget nor the single use was kept by the failed attempt");
});

test("budget accounting is per AgentTrust instance (documented limitation)", async () => {
  // Spend lives in memory on one verifier. Two verifiers each enforce the cap
  // on their own, so one mandate must be routed to one verifier.
  const s = setup({ maxTotalUsd: 0.3 });
  const other = new AgentTrust();
  other.registerUser(s.user.publicKeyPem);
  other.registerAgent(s.agent.publicKeyPem);
  assert.equal((await s.book(0.3)).ok, true);
  assert.equal((await other.verifyBookingToken(s.token(0.3), { amountUsd: 0.3, source: "travala" })).ok, true);
});

// ── capability ceilings ────────────────────────────────────────────────────

test("capability ceilings compare exact amounts and fail closed on unreadable ones", async () => {
  const s = setup();
  const cap = (maxUsd) => mintCapability({ agentPrivateKeyPem: s.agent.privateKeyPem, agentPublicKeyPem: s.agent.publicKeyPem, audience: "srv", action: "pay", maxUsd });
  assert.equal((await s.trust.verifyCapability(cap(0.3), { audience: "srv", maxUsd: 0.3 })).ok, true);
  const over = await s.trust.verifyCapability(cap(0.300001), { audience: "srv", maxUsd: 0.3 });
  assert.equal(over.reason, "capability maxUsd $0.300001 exceeds server ceiling $0.30");
  const fuzzy = await s.trust.verifyCapability(cap(0.3), { audience: "srv", maxUsd: 0.1 + 0.2 });
  assert.equal(fuzzy.ok, false);
  assert.throws(() => cap(0.1234567), /maxUsd/);
});
