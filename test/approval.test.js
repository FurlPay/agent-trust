import test from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import { generateKeypair } from "../dist/src/index.js";
import {
  issueApproval,
  verifyApproval,
  approvalFromExtra,
  X402_APPROVAL_EXTRA_KEY,
  APPROVAL_SIGNING_DOMAIN,
} from "../dist/src/approval.js";

// ---------------------------------------------------------------------------
// Step-up approval evidence for bare x402.
//
// Every test here is really one question: does this prove a human approved THIS
// payment, or only that a human once approved something? The difference is the
// whole value of the format, and it is invisible unless the tests attack the
// binding rather than the happy path.
// ---------------------------------------------------------------------------

const user = generateKeypair("user");
const other = generateKeypair("user");
const MANDATE = "mnd_abc";
const HASH = "0xpaymenthash";

const base = {
  userPrivateKeyPem: user.privateKeyPem,
  userPublicKeyPem: user.publicKeyPem,
  mandateId: MANDATE,
  paymentHash: HASH,
};

const check = (over = {}) =>
  verifyApproval(over.approval ?? issueApproval(base), {
    userPublicKeyPem: user.publicKeyPem,
    paymentHash: HASH,
    mandateId: MANDATE,
    maxAgeSeconds: 300,
    ...over,
  });

test("a fresh approval for this payment verifies", () => {
  const r = check();
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.userKeyId, user.keyId);
});

test("AN APPROVAL FOR ANOTHER PAYMENT DOES NOT TRANSFER", () => {
  // Without this the format proves only that the user approved something, and
  // one approval would step up every above-threshold payment thereafter.
  const approval = issueApproval({ ...base, paymentHash: "0xsomeotherpayment" });
  assert.strictEqual(check({ approval }).reason, "payment_mismatch");
});

test("an approval issued under another mandate does not transfer", () => {
  // Stops evidence minted under a $50 mandate being presented under a $5000 one.
  const approval = issueApproval({ ...base, mandateId: "mnd_different" });
  assert.strictEqual(check({ approval }).reason, "mandate_mismatch");
});

test("a valid signature from the WRONG user is refused", () => {
  // The signature proves someone signed. The key id inside the claims is what
  // proves it was the user this mandate names.
  const approval = issueApproval({
    ...base,
    userPrivateKeyPem: other.privateKeyPem,
    userPublicKeyPem: other.publicKeyPem,
  });
  // Verified against the OTHER key it is internally consistent...
  assert.strictEqual(
    verifyApproval(approval, {
      userPublicKeyPem: other.publicKeyPem,
      paymentHash: HASH,
      mandateId: MANDATE,
      maxAgeSeconds: 300,
    }).ok,
    true
  );
  // ...but presented for our mandate's user, it fails at the signature.
  assert.strictEqual(check({ approval }).reason, "signature_invalid");
});

test("an approval whose claimed key id is not the verifying key is refused", () => {
  // Hand-built: correct signature over claims naming a DIFFERENT key id. The
  // signature check alone would pass this.
  const claims = {
    v: 1, m: MANDATE, h: HASH, k: other.keyId,
    t: Math.floor(Date.now() / 1000), n: "abc",
  };
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  // Signed over the DOMAIN-separated input, so this reaches the key check
  // rather than stopping at the signature — the point is that a structurally
  // valid approval still fails on the key id inside it.
  const signature = crypto
    .sign(null, Buffer.from(`x402-approval/v1|${payload}`), user.privateKeyPem)
    .toString("base64url");
  assert.strictEqual(check({ approval: { payload, signature } }).reason, "key_mismatch");
});

test("a tampered payload does not verify", () => {
  const approval = issueApproval(base);
  const claims = JSON.parse(Buffer.from(approval.payload, "base64url").toString("utf8"));
  claims.h = "0xattacker-chosen";
  const tampered = Buffer.from(JSON.stringify(claims)).toString("base64url");
  assert.strictEqual(check({ approval: { ...approval, payload: tampered } }).reason, "signature_invalid");
});

test("stale evidence expires", () => {
  // An approval with no age bound authorizes above-threshold payments forever,
  // which is the thing a threshold exists to prevent.
  const now = Math.floor(Date.now() / 1000);
  const approval = issueApproval({ ...base, nowSeconds: now - 600 });
  assert.strictEqual(check({ approval, maxAgeSeconds: 300 }).reason, "expired");
  assert.strictEqual(check({ approval, maxAgeSeconds: 900 }).ok, true);
});

test("future-dated evidence is refused, not treated as very fresh", () => {
  const now = Math.floor(Date.now() / 1000);
  const approval = issueApproval({ ...base, nowSeconds: now + 3600 });
  assert.strictEqual(check({ approval }).reason, "future_dated");
});

test("a little clock skew is tolerated", () => {
  const now = Math.floor(Date.now() / 1000);
  const approval = issueApproval({ ...base, nowSeconds: now + 30 });
  assert.strictEqual(check({ approval }).ok, true);
});

test("malformed input is refused rather than throwing", () => {
  // `null` is now "missing" — see the MISSING-vs-MALFORMED test below.
  assert.strictEqual(verifyApproval(null, { userPublicKeyPem: user.publicKeyPem, paymentHash: HASH, mandateId: MANDATE, maxAgeSeconds: 300 }).reason, "missing");
  assert.strictEqual(check({ approval: { payload: "!!!", signature: "!!!" } }).reason, "signature_invalid");
  assert.strictEqual(check({ approval: { payload: 5, signature: "x" } }).reason, "malformed");
});

test("two approvals of the same payment are distinguishable", () => {
  // The nonce exists so an operator can tell a re-approval from a replay.
  const a = issueApproval(base);
  const b = issueApproval(base);
  assert.notStrictEqual(a.payload, b.payload);
});

// ── transport ──────────────────────────────────────────────────────────────

test("it rides in x402 `extra` with no new transport", () => {
  const approval = issueApproval(base);
  const xPaymentExtra = { [X402_APPROVAL_EXTRA_KEY]: approval };
  assert.deepStrictEqual(approvalFromExtra(xPaymentExtra), approval);
});

test("extraction never trusts what it finds", () => {
  assert.strictEqual(approvalFromExtra(undefined), null);
  assert.strictEqual(approvalFromExtra({}), null);
  assert.strictEqual(approvalFromExtra({ approval: "a-string" }), null);
  assert.strictEqual(approvalFromExtra({ approval: { payload: 1, signature: 2 } }), null);
});

test("the wire form is two base64url strings and nothing else", () => {
  // "Minimal and portable" as an assertion: anything that can carry two short
  // strings can carry this, which is why it needs no AP2 envelope.
  const approval = issueApproval(base);
  assert.deepStrictEqual(Object.keys(approval).sort(), ["payload", "signature"]);
  assert.match(approval.payload, /^[A-Za-z0-9_-]+$/);
  assert.match(approval.signature, /^[A-Za-z0-9_-]+$/);
});

// ── domain separation ──────────────────────────────────────────────────────

test("THE DOMAIN ACTUALLY BITES: a bare-payload signature no longer verifies", () => {
  // This is the previous format, byte for byte: sign the payload alone. If the
  // domain were cosmetic — appended to the wire form but not to the signed
  // bytes — this would still verify and the test would pass vacuously.
  const approval = issueApproval(base);
  const bareSignature = crypto
    .sign(null, Buffer.from(approval.payload), user.privateKeyPem)
    .toString("base64url");

  assert.strictEqual(
    check({ approval: { payload: approval.payload, signature: bareSignature } }).reason,
    "signature_invalid"
  );
  // ...while the domain-separated one verifies, so the key and payload are fine
  // and the ONLY difference is the prefix.
  assert.strictEqual(check({ approval }).ok, true);
});

test("a signature over a DIFFERENT domain does not verify as an approval", () => {
  // The cross-protocol case, made concrete. The same user key signs mandates in
  // this package over the same `b64url(JSON)` shape; a domain is what makes one
  // object type's signature structurally unusable as another's, rather than
  // relying on their field names happening to differ.
  const approval = issueApproval(base);
  const otherDomain = crypto
    .sign(null, Buffer.from(`x402-mandate/v1|${approval.payload}`), user.privateKeyPem)
    .toString("base64url");

  assert.strictEqual(
    check({ approval: { payload: approval.payload, signature: otherDomain } }).reason,
    "signature_invalid"
  );
});

test("a future domain version cannot verify as v1", () => {
  const approval = issueApproval(base);
  const v2 = crypto
    .sign(null, Buffer.from(`x402-approval/v2|${approval.payload}`), user.privateKeyPem)
    .toString("base64url");
  assert.strictEqual(
    check({ approval: { payload: approval.payload, signature: v2 } }).reason,
    "signature_invalid"
  );
});

test("the domain is a stable, published constant", () => {
  // Two implementations have to agree on this string exactly or neither can
  // verify the other's approvals, so it is exported rather than inlined.
  assert.strictEqual(APPROVAL_SIGNING_DOMAIN, "x402-approval/v1");
});

test("the separator cannot occur in the payload it separates", () => {
  // `|` is outside the base64url alphabet, so DOMAIN + "|" + payload has
  // exactly one parse — no payload can smuggle a separator and shift the
  // boundary between the two.
  const approval = issueApproval(base);
  assert.ok(!approval.payload.includes("|"));
  assert.match(approval.payload, /^[A-Za-z0-9_-]+$/);
});

test("MISSING is distinct from MALFORMED", () => {
  // Different next steps for the caller: fetch an approval, versus fix the one
  // you have.
  const params = {
    userPublicKeyPem: user.publicKeyPem,
    paymentHash: HASH,
    mandateId: MANDATE,
    maxAgeSeconds: 300,
  };
  assert.strictEqual(verifyApproval(null, params).reason, "missing");
  assert.strictEqual(verifyApproval(undefined, params).reason, "missing");
  assert.strictEqual(verifyApproval({ payload: 5, signature: "x" }, params).reason, "malformed");
});

test("every failure mode has its own reason code", () => {
  // The full set Radeonares32 asked to keep separable, asserted as a set rather
  // than one-by-one so a future collapse into a generic failure is caught here.
  const reasons = new Set([
    verifyApproval(null, { userPublicKeyPem: user.publicKeyPem, paymentHash: HASH, mandateId: MANDATE, maxAgeSeconds: 300 }).reason,
    check({ approval: { payload: "x", signature: "y" } }).reason,
    check({ approval: issueApproval({ ...base, paymentHash: "0xother" }) }).reason,
    check({ approval: issueApproval({ ...base, mandateId: "mnd_other" }) }).reason,
    check({ approval: issueApproval({ ...base, nowSeconds: Math.floor(Date.now() / 1000) - 9999 }) }).reason,
    check({ approval: issueApproval({ ...base, nowSeconds: Math.floor(Date.now() / 1000) + 9999 }) }).reason,
  ]);
  assert.deepStrictEqual(
    [...reasons].sort(),
    ["expired", "future_dated", "mandate_mismatch", "missing", "payment_mismatch", "signature_invalid"]
  );
});
