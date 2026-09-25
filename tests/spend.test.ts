import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MICROS_PER_UNIT,
  SpendLimiter,
  authorize,
  formatMicros,
  priceFor,
  toMicros,
} from "../src/spend.js";

// ---------------------------------------------------------------------------
// Agent spend policy.
//
// The test that matters most is the concurrency one. Every naive implementation
// of a spend cap passes the simple cases and fails that, because check-then-act
// lets N parallel requests all read the counter before any of them writes it.
// An agent capped at $1 then spends $2, and the money is gone before the
// counter catches up.
//
// Everything else here is about failing closed: an unknown agent, a revoked
// one, an unpriced endpoint and a nonsensical amount must all deny rather than
// default.
// ---------------------------------------------------------------------------

const $ = toMicros;

function limiter(now = { t: 1_000_000 }) {
  let n = 0;
  return new SpendLimiter({ now: () => now.t, newId: () => `r${n++}` });
}

test("money is integer micro-units, parsed exactly", () => {
  assert.equal($("1"), 1_000_000);
  assert.equal($("0.001"), 1_000);
  assert.equal($("0.000001"), 1);
  assert.equal($("12.5"), 12_500_000);
  // The float trap this representation exists to avoid.
  assert.equal($("0.1") + $("0.2"), $("0.3"));
});

test("malformed amounts are refused rather than coerced", () => {
  for (const bad of ["", "-1", "1.2345678", "1e6", "abc", "1,000", " "]) {
    assert.throws(() => $(bad), RangeError, `"${bad}" should be refused`);
  }
});

test("formatting round-trips", () => {
  assert.equal(formatMicros($("0.001")), "0.001000");
  assert.equal(formatMicros(MICROS_PER_UNIT), "1.000000");
});

// ── the critical one ───────────────────────────────────────────────────────

test("100 concurrent requests cannot exceed the cap — the check-then-act bug", () => {
  // The brief's exact scenario: $1 of allowance, 100 requests at $0.02.
  // $1 / $0.02 = 50 may pass. A check-then-act implementation lets all 100
  // through, because each reads `spent` before any of them writes it.
  const l = limiter();
  l.register("agent_1", { maxTotal: $("1") });

  const decisions = Array.from({ length: 100 }, () =>
    l.reserve("agent_1", "/api/search", $("0.02"))
  );

  const granted = decisions.filter((d) => d.ok);
  assert.equal(granted.length, 50, "exactly 50 requests fit in $1 at $0.02");

  const usage = l.usage("agent_1")!;
  assert.equal(usage.spentTotal, $("1"), "not one micro-unit over the cap");
  assert.equal(usage.pendingReservations, 50);

  for (const d of decisions.filter((x) => !x.ok)) {
    assert.equal(d.reason, "exceeds_total");
  }
});

test("headroom is taken at reserve, not at commit", () => {
  // The property the concurrency test depends on. If counters only moved on
  // commit, a burst of reservations would all see zero spent.
  const l = limiter();
  l.register("a", { maxPerDay: $("0.10") });
  const first = l.reserve("a", "/x", $("0.06"));
  assert.ok(first.ok);
  // Nothing committed yet — but the second must still be refused.
  const second = l.reserve("a", "/x", $("0.06"));
  assert.equal(second.ok, false);
  assert.equal(second.ok === false && second.reason, "exceeds_per_day");
});

test("a released reservation returns its headroom", () => {
  const l = limiter();
  l.register("a", { maxTotal: $("0.10") });
  const r = l.reserve("a", "/x", $("0.10"));
  assert.ok(r.ok);
  assert.equal(l.reserve("a", "/x", $("0.01")).ok, false);

  assert.equal(l.release(r.reservation.id), true);
  assert.equal(l.usage("a")!.spentTotal, 0);
  assert.equal(l.reserve("a", "/x", $("0.10")).ok, true, "budget is usable again");
});

test("a committed reservation does not return its headroom", () => {
  const l = limiter();
  l.register("a", { maxTotal: $("0.10") });
  const r = l.reserve("a", "/x", $("0.10"));
  assert.ok(r.ok);
  assert.equal(l.commit(r.reservation.id), true);
  assert.equal(l.usage("a")!.spentTotal, $("0.10"));
  assert.equal(l.reserve("a", "/x", $("0.01")).ok, false, "spend is permanent");
});

test("committing or releasing twice is a no-op, not a crash or a refund", () => {
  // A double-release that refunded twice would hand out free budget.
  const l = limiter();
  l.register("a", { maxTotal: $("1") });
  const r = l.reserve("a", "/x", $("0.50"));
  assert.ok(r.ok);
  assert.equal(l.release(r.reservation.id), true);
  assert.equal(l.release(r.reservation.id), false, "second release does nothing");
  assert.equal(l.usage("a")!.spentTotal, 0, "refunded once, not twice");
});

// ── windows ────────────────────────────────────────────────────────────────

test("each window is enforced independently", () => {
  const now = { t: 1_000_000 };
  const l = limiter(now);
  l.register("a", { maxPerMinute: $("0.05"), maxPerHour: $("0.10"), maxPerDay: $("1") });

  // Committed as we go. An UNcommitted reservation self-releases after its TTL
  // (120s by default), and this test travels further than that — so without
  // committing, the first spend would silently refund itself mid-test and the
  // hour window would never fill.
  const commit = (d: ReturnType<typeof l.reserve>) => {
    assert.ok(d.ok);
    if (d.ok) assert.equal(l.commit(d.reservation.id), true);
  };

  // Exhaust the minute.
  commit(l.reserve("a", "/x", $("0.05")));
  const denied = l.reserve("a", "/x", $("0.01"));
  assert.equal(denied.ok === false && denied.reason, "exceeds_per_minute");

  // A minute later the minute window resets; the hour has not.
  now.t += 60_001;
  commit(l.reserve("a", "/x", $("0.05")));

  // The hour is now exhausted too (0.05 + 0.05 = 0.10). To observe the HOUR
  // denial specifically, the next request must fit inside the minute — both
  // windows are full, and the checks run tightest-first, so a request that also
  // breaches the minute would be reported as exceeds_per_minute.
  now.t += 60_001;
  const hourDenied = l.reserve("a", "/x", $("0.01"));
  assert.equal(hourDenied.ok === false && hourDenied.reason, "exceeds_per_hour");
});

test("denials name the soonest-resetting window that is breached", () => {
  // Ordering is deliberate: when the minute and the hour are both exhausted,
  // "wait a minute" is the actionable answer, so the minute is reported.
  const l = limiter();
  l.register("a", { maxPerMinute: $("0.01"), maxPerHour: $("0.01") });
  assert.ok(l.reserve("a", "/x", $("0.01")).ok);
  const d = l.reserve("a", "/x", $("0.01"));
  assert.equal(d.ok === false && d.reason, "exceeds_per_minute");
});

test("the lifetime cap never resets", () => {
  const now = { t: 1_000_000 };
  const l = limiter(now);
  l.register("a", { maxTotal: $("0.02") });
  const r = l.reserve("a", "/x", $("0.02"));
  assert.ok(r.ok);
  // COMMITTED, deliberately. An uncommitted reservation self-releases after its
  // TTL — that is the crash-recovery behaviour tested above — so a lifetime cap
  // is only permanent for spend that actually happened.
  assert.equal(l.commit(r.reservation.id), true);

  now.t += DAY * 30;
  const denied = l.reserve("a", "/x", $("0.000001"));
  assert.equal(denied.ok === false && denied.reason, "exceeds_total");
});
const DAY = 86_400_000;

test("an absent limit means unlimited for that window only", () => {
  const l = limiter();
  l.register("a", { maxPerRequest: $("0.10") });
  // No window caps — many requests pass.
  for (let i = 0; i < 500; i++) assert.ok(l.reserve("a", "/x", $("0.10")).ok);
  // But the per-request cap still bites.
  assert.equal(l.reserve("a", "/x", $("0.11")).ok, false);
});

test("a stale reservation expires and frees its headroom", () => {
  // A crashed process must leak budget for one TTL, not forever.
  const now = { t: 1_000_000 };
  const l = new SpendLimiter({ now: () => now.t, reservationTtlMs: 1_000 });
  l.register("a", { maxTotal: $("0.10") });
  assert.ok(l.reserve("a", "/x", $("0.10")).ok);
  assert.equal(l.reserve("a", "/x", $("0.01")).ok, false);

  now.t += 1_001;
  assert.equal(l.reserve("a", "/x", $("0.10")).ok, true, "stale hold released");
});

// ── failing closed ─────────────────────────────────────────────────────────

test("an unregistered agent is denied, never defaulted", () => {
  const l = limiter();
  const d = l.reserve("ghost", "/x", $("0.001"));
  assert.equal(d.ok, false);
  assert.equal(d.ok === false && d.reason, "unknown_agent");
});

test("a revoked agent is denied and its in-flight work is released", () => {
  // Revoking a runaway agent means "stop now", including the requests already
  // in the air — not merely the next ones.
  const l = limiter();
  l.register("a", { maxTotal: $("1") });
  const r = l.reserve("a", "/x", $("0.50"));
  assert.ok(r.ok);

  l.revoke("a");
  assert.equal(l.isRevoked("a"), true);
  assert.equal(l.usage("a")!.pendingReservations, 0, "in-flight reservations dropped");

  const denied = l.reserve("a", "/x", $("0.01"));
  assert.equal(denied.ok === false && denied.reason, "revoked");
});

test("re-registering an agent clears revocation but keeps spend history", () => {
  const l = limiter();
  l.register("a", { maxTotal: $("1") });
  const r = l.reserve("a", "/x", $("0.30"));
  assert.ok(r.ok);
  l.commit(r.reservation.id);
  l.revoke("a");

  l.register("a", { maxTotal: $("1") });
  assert.equal(l.isRevoked("a"), false);
  // History survives — re-registering must not be a way to reset a cap.
  assert.equal(l.usage("a")!.spentTotal, $("0.30"));
});

test("a nonsensical amount is refused rather than reasoned about", () => {
  const l = limiter();
  l.register("a", { maxTotal: $("1") });
  for (const bad of [NaN, Infinity, -1]) {
    const d = l.reserve("a", "/x", bad);
    assert.equal(d.ok, false, `${bad} must be refused`);
  }
});

test("a zero-price request is allowed and consumes nothing", () => {
  // A free endpoint is legitimate; it must not be treated as an error.
  const l = limiter();
  l.register("a", { maxTotal: $("0.01") });
  const d = l.reserve("a", "/health", 0);
  assert.ok(d.ok);
  assert.equal(l.usage("a")!.spentTotal, 0);
});

// ── pricing ────────────────────────────────────────────────────────────────

test("an unpriced endpoint is refused, never given a default", () => {
  // A default price either gives the endpoint away or overcharges for it.
  const prices = { "/api/search": $("0.001") };
  assert.equal(priceFor("/api/search", prices), $("0.001"));
  assert.equal(priceFor("/api/unknown", prices), null);

  const l = limiter();
  l.register("a", { maxTotal: $("1") });
  const d = authorize(l, { agentId: "a", endpoint: "/api/unknown", prices });
  assert.equal(d.ok, false);
  assert.equal(d.ok === false && d.reason, "unpriced_endpoint");
});

test("authorize prices then reserves, in that order", () => {
  const prices = { "/api/inference": $("0.05") };
  const l = limiter();
  l.register("a", { maxTotal: $("0.05") });

  const first = authorize(l, { agentId: "a", endpoint: "/api/inference", prices });
  assert.ok(first.ok);
  assert.equal(first.reservation.amount, $("0.05"));

  const second = authorize(l, { agentId: "a", endpoint: "/api/inference", prices });
  assert.equal(second.ok, false);
});

test("an unpriced endpoint consumes no budget on the way to being denied", () => {
  // If authorize reserved before pricing, a denial would still cost the agent.
  const l = limiter();
  l.register("a", { maxTotal: $("1") });
  authorize(l, { agentId: "a", endpoint: "/nope", prices: {} });
  assert.equal(l.usage("a")!.spentTotal, 0);
});

test("every denial carries a message safe to return to the caller", () => {
  const l = limiter();
  l.register("a", { maxPerRequest: $("0.001") });
  const d = l.reserve("a", "/x", $("1"));
  assert.equal(d.ok, false);
  if (!d.ok) {
    assert.ok(d.message.length > 10);
    // No policy internals leak to whoever is being denied.
    assert.doesNotMatch(d.message, /\d{4,}|micros|maxPer/i);
  }
});
