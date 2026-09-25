import crypto from "crypto";
import { keyIdOf } from "./index.js";

// ---------------------------------------------------------------------------
// Step-up approval evidence — the minimal portable proof that a human approved
// THIS payment, for flows that are not AP2 end to end.
//
// THE PROBLEM. A mandate can carry `requireApprovalAbove`, but a facilitator
// cannot act on it by asking anyone: by settlement time the approval either
// happened or it did not, and the facilitator's only moves are settle and
// refuse. So the threshold is only enforceable if the payment ARRIVES carrying
// proof. AP2 expresses that structurally — a closed mandate signed by the user
// on a Trusted Surface versus an open one closed by the agent — but that
// presumes AP2 envelopes on both ends, and most x402 traffic has none.
//
// THE MINIMUM. Two base64url strings, `{ payload, signature }`, riding in the
// x402 `extra` field that the spec already carries. No new transport, no new
// header, and no requirement that either end speak AP2.
//
// WHAT MAKES IT PROOF rather than decoration is what the signature covers:
//
//   paymentHash  binds it to ONE payment. Without this it proves only that the
//                user once approved something, which every replayed approval
//                would also prove.
//   mandateId    ties it to the authority being stepped up, so an approval
//                issued under a $50 mandate cannot be presented under a $5000
//                one.
//   keyId        names the approving key INSIDE the signed bytes, so a
//                verifier cannot be handed a valid signature from some other
//                user's key and told it belongs to this mandate's user.
//   approvedAt   makes staleness checkable. An approval with no time in it
//                authorizes above-threshold payments forever.
//
// Everything else is deliberately absent. Amount, resource, seller and asset
// are already inside `paymentHash` at the layer that computes it; repeating
// them here would create a second copy that can disagree with the first.
// ---------------------------------------------------------------------------

/**
 * Domain separator. Signed bytes are `DOMAIN + "|" + payload`, never the
 * payload alone.
 *
 * WHY, CONCRETELY. The user's key in this package signs more than one kind of
 * object, and every one of them signs `Buffer.from(base64urlJSON)`:
 *
 *   issueMandate   signs b64url(JSON(mandate))    with the USER key
 *   issueApproval  signs b64url(JSON(claims))     with the USER key
 *
 * Without a domain, a signature is a signature over "some base64url JSON", and
 * nothing structural stops one object type's signature being presented as
 * another's. Today that is caught only because a mandate's field names
 * (`mandateId`, `constraints`) are not an approval's (`m`, `h`, `k`, `t`), so
 * the claim checks fail — which is an accident of naming, not a property anyone
 * designed or could rely on. A future field rename could silently remove it.
 *
 * Prefixing makes the verifier's question "is this a signature over an
 * x402-approval/v1?" rather than "is this a signature over some bytes?". The
 * version lives inside the domain so v2 signatures cannot verify as v1 even if
 * every claim happens to line up.
 *
 * The separator is `|`, which cannot appear in base64url, so DOMAIN + payload
 * has exactly one parse and no length-extension ambiguity between the two.
 */
export const APPROVAL_SIGNING_DOMAIN = "x402-approval/v1";

/** The exact bytes signed and verified. One definition, used by both sides. */
function signingInput(payload: string): Buffer {
  return Buffer.from(`${APPROVAL_SIGNING_DOMAIN}|${payload}`);
}

/** Claim names are single letters because this rides on the wire per payment. */
interface ApprovalClaims {
  v: 1;
  /** Mandate this approval steps up. */
  m: string;
  /** The one payment approved. */
  h: string;
  /** Key id of the approving user, committed inside the signature. */
  k: string;
  /** Epoch seconds at approval. */
  t: number;
  /** Random, so two approvals of one payment are distinguishable. */
  n: string;
}

/** As transmitted: base64url(JSON claims) + detached signature over it. */
export interface SignedApproval {
  payload: string;
  signature: string;
}

export interface IssueApprovalParams {
  userPrivateKeyPem: string;
  userPublicKeyPem: string;
  mandateId: string;
  /** The canonical hash of the payment being approved. */
  paymentHash: string;
  /** Override for tests. */
  nowSeconds?: number;
}

/**
 * The human approves one payment.
 *
 * Signed by the USER key, never the agent's — an agent that could mint its own
 * step-up evidence would be approving its own above-threshold spending, which
 * is the entire thing the threshold exists to stop.
 */
export function issueApproval(p: IssueApprovalParams): SignedApproval {
  const claims: ApprovalClaims = {
    v: 1,
    m: p.mandateId,
    h: p.paymentHash,
    k: keyIdOf(p.userPublicKeyPem, "user"),
    t: p.nowSeconds ?? Math.floor(Date.now() / 1000),
    n: crypto.randomBytes(9).toString("base64url"),
  };
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = crypto.sign(null, signingInput(payload), p.userPrivateKeyPem).toString("base64url");
  return { payload, signature };
}

export type ApprovalRejection =
  /** Nothing was presented. Distinct from a malformed one: "the payer sent no
   *  approval" and "the payer sent something broken" lead a caller to different
   *  next steps — go and get one, versus fix the one you have. */
  | "missing"
  | "malformed"
  | "unsupported_version"
  | "signature_invalid"
  | "key_mismatch"
  | "payment_mismatch"
  | "mandate_mismatch"
  | "expired"
  | "future_dated";

export type ApprovalVerification =
  | { ok: true; approvedAtSeconds: number; userKeyId: string }
  | { ok: false; reason: ApprovalRejection };

export interface VerifyApprovalParams {
  /** The user key the MANDATE names. Not one taken from the approval itself. */
  userPublicKeyPem: string;
  /** The payment actually being settled. */
  paymentHash: string;
  mandateId: string;
  /**
   * How stale approval evidence may be. Required, with no default: a default
   * here would be a security parameter chosen by whoever forgot to set it.
   */
  maxAgeSeconds: number;
  nowSeconds?: number;
}

/**
 * Verify that this payment carries a human approval.
 *
 * Order matters. The signature is checked before any claim is compared,
 * because the claims of an unverified approval are attacker-controlled and
 * comparing them first is deciding on unauthenticated data.
 */
export function verifyApproval(
  approval: SignedApproval | undefined | null,
  p: VerifyApprovalParams
): ApprovalVerification {
  if (!approval) return { ok: false, reason: "missing" };
  if (typeof approval.payload !== "string" || typeof approval.signature !== "string") {
    return { ok: false, reason: "malformed" };
  }

  let ok = false;
  try {
    ok = crypto.verify(
      null,
      signingInput(approval.payload),
      crypto.createPublicKey(p.userPublicKeyPem),
      Buffer.from(approval.signature, "base64url")
    );
  } catch {
    ok = false;
  }
  if (!ok) return { ok: false, reason: "signature_invalid" };

  let claims: ApprovalClaims;
  try {
    claims = JSON.parse(Buffer.from(approval.payload, "base64url").toString("utf8"));
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (claims.v !== 1) return { ok: false, reason: "unsupported_version" };

  // The signature proves the holder of SOME key signed these bytes. This proves
  // it was the key the mandate names — the claim and the verifying key have to
  // agree, or a valid approval from an unrelated user would pass.
  if (claims.k !== keyIdOf(p.userPublicKeyPem, "user")) {
    return { ok: false, reason: "key_mismatch" };
  }
  if (claims.h !== p.paymentHash) return { ok: false, reason: "payment_mismatch" };
  if (claims.m !== p.mandateId) return { ok: false, reason: "mandate_mismatch" };

  const now = p.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (typeof claims.t !== "number" || !Number.isFinite(claims.t)) {
    return { ok: false, reason: "malformed" };
  }
  // A future-dated approval is not unusually fresh; it is wrong, and accepting
  // it would let a clock-skewed or malicious signer mint evidence that stays
  // valid past any age bound.
  if (claims.t > now + 60) return { ok: false, reason: "future_dated" };
  if (now - claims.t > p.maxAgeSeconds) return { ok: false, reason: "expired" };

  return { ok: true, approvedAtSeconds: claims.t, userKeyId: claims.k };
}

/**
 * The x402 field this rides in.
 *
 * Named so both ends agree without a spec: a payer puts the approval at
 * `X-PAYMENT`'s `extra.approval`, and a facilitator reads it from the same
 * place. That is the whole transport story — the point of the format is that
 * it needs no more than this.
 */
export const X402_APPROVAL_EXTRA_KEY = "approval";

/** Pull an approval out of an x402 payload's `extra`, without trusting it. */
export function approvalFromExtra(extra: unknown): SignedApproval | null {
  if (!extra || typeof extra !== "object") return null;
  const raw = (extra as Record<string, unknown>)[X402_APPROVAL_EXTRA_KEY];
  if (!raw || typeof raw !== "object") return null;
  const { payload, signature } = raw as Record<string, unknown>;
  if (typeof payload !== "string" || typeof signature !== "string") return null;
  return { payload, signature };
}
