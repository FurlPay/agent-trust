// ---------------------------------------------------------------------------
// Per-request spend policy for agents paying an API.
//
// WHY THIS IS NOT THE MANDATE SYSTEM NEXT DOOR. `AgentTrust` in ./index.ts
// governs BOOKINGS: a user signs a mandate, an agent spends it on discrete
// purchases with an MCC allowlist and a per-booking cap. That shape assumes a
// handful of large, deliberate transactions.
//
// An agent hitting a paid API is the opposite: thousands of sub-cent calls an
// hour, no per-call human intent, and the operator's real question is "how much
// can this agent burn before I notice?". Rate windows, not booking caps.
//
// THE ONE HARD PROBLEM HERE IS CONCURRENCY, AND IT IS WHY THIS FILE EXISTS.
// The obvious implementation is check-then-act:
//
//     if (spentToday + price <= dailyCap) { await charge(); spentToday += price }
//
// With one agent issuing 100 parallel requests, every one of them reads
// `spentToday` before any of them writes it, so all 100 pass a cap that should
// have stopped the sixth. The money is gone before the counter catches up. This
// is the same class of bug as the idempotency race, and it is the single most
// likely way an operator gets a surprise bill.
//
// So spending is RESERVED BEFORE THE WORK, not recorded after it:
//
//     reserve(price)  -> counters move immediately, atomically
//        ...serve the request, take the payment...
//     commit(id)      -> the reservation becomes permanent spend
//     release(id)     -> the reservation is rolled back (payment failed)
//
// A reservation held by a request that never completes expires on its own, so a
// crashed process leaks headroom for one TTL rather than forever.
//
// FAIL CLOSED, ALWAYS. An unknown agent, a revoked agent, an unpriced endpoint,
// a store that throws — every one of them denies. An authorisation layer that
// cannot evaluate its policy has exactly one safe answer.
// ---------------------------------------------------------------------------

/** Amounts are integer micro-units (1_000_000 = $1). Floats are not money:
 *  0.1 + 0.2 !== 0.3, and a spend cap that drifts is a cap that fails open. */
export type Micros = number;

export const MICROS_PER_UNIT = 1_000_000;

/** Parse a decimal string like "0.001" into micro-units, exactly. */
export function toMicros(amount: string): Micros {
  const text = amount.trim();
  if (!/^\d+(\.\d{1,6})?$/.test(text)) {
    throw new RangeError(
      `invalid amount "${amount}": expected a non-negative decimal with at most 6 places`
    );
  }
  const [whole, frac = ""] = text.split(".");
  return Number(whole) * MICROS_PER_UNIT + Number(frac.padEnd(6, "0"));
}

export function formatMicros(micros: Micros): string {
  const sign = micros < 0 ? "-" : "";
  const abs = Math.abs(micros);
  return `${sign}${Math.floor(abs / MICROS_PER_UNIT)}.${String(abs % MICROS_PER_UNIT).padStart(6, "0")}`;
}

/**
 * What an agent is allowed to spend.
 *
 * Every field is optional and an absent field means UNLIMITED for that window.
 * That is a deliberate choice and the reason `SpendPolicy` is never constructed
 * implicitly: a policy object that materialised out of a partial config would
 * silently grant unlimited spend. Callers build one explicitly, and an agent
 * with no policy is denied rather than defaulted.
 */
export interface SpendPolicy {
  maxPerRequest?: Micros;
  maxPerMinute?: Micros;
  maxPerHour?: Micros;
  maxPerDay?: Micros;
  /** Lifetime cap. Never resets. */
  maxTotal?: Micros;
}

/** Price per endpoint. The key is matched exactly against `endpoint`. */
export type EndpointPrices = Record<string, Micros>;

export type DenialReason =
  | "unknown_agent"
  | "revoked"
  | "no_policy"
  | "unpriced_endpoint"
  | "exceeds_per_request"
  | "exceeds_per_minute"
  | "exceeds_per_hour"
  | "exceeds_per_day"
  | "exceeds_total"
  | "policy_unavailable";

export interface Reservation {
  id: string;
  agentId: string;
  endpoint: string;
  amount: Micros;
  createdAt: number;
}

export type SpendDecision =
  | { ok: true; reservation: Reservation }
  | { ok: false; reason: DenialReason; message: string };

/** Human-readable, and safe to return to a caller — no policy internals. */
const DENIAL_MESSAGES: Record<DenialReason, string> = {
  unknown_agent: "This agent is not registered.",
  revoked: "This agent's access has been revoked.",
  no_policy: "No spend policy is configured for this agent.",
  unpriced_endpoint: "This endpoint has no price configured.",
  exceeds_per_request: "This request costs more than the agent's per-request limit.",
  exceeds_per_minute: "The agent's per-minute spend limit is exhausted.",
  exceeds_per_hour: "The agent's hourly spend limit is exhausted.",
  exceeds_per_day: "The agent's daily spend limit is exhausted.",
  exceeds_total: "The agent's total spend allowance is exhausted.",
  policy_unavailable: "Spend policy could not be evaluated, so the request was refused.",
};

/** A window's worth of spend, and when it resets. */
interface Window {
  spent: Micros;
  resetsAt: number;
}

interface AgentState {
  policy: SpendPolicy;
  revoked: boolean;
  minute: Window;
  hour: Window;
  day: Window;
  total: Micros;
  /** Reservations not yet committed or released, by id. */
  pending: Map<string, Reservation>;
}

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/** How long an uncommitted reservation holds headroom before it self-releases.
 *  Long enough for a slow settlement, short enough that a crashed process does
 *  not strand an agent's budget. */
const DEFAULT_RESERVATION_TTL_MS = 120_000;

export interface SpendLimiterOptions {
  /** Injected for deterministic tests. */
  now?: () => number;
  reservationTtlMs?: number;
  /** Injected for deterministic tests; must be unique per call. */
  newId?: () => string;
}

/**
 * In-process spend limiter.
 *
 * SINGLE PROCESS ONLY, and the docs say so rather than leaving an operator to
 * discover it. Two API instances each hold their own counters, so an agent
 * capped at $1/day can spend $1 per instance. For a self-hosted single-process
 * gateway — the shape this product ships in first — that is correct and needs
 * no infrastructure. A distributed deployment needs a shared store, and the
 * reserve/commit/release contract below is deliberately the shape that maps
 * onto a Redis Lua script or a SQL row lock without changing any caller.
 */
export class SpendLimiter {
  private readonly agents = new Map<string, AgentState>();
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly newId: () => string;
  private counter = 0;

  constructor(opts: SpendLimiterOptions = {}) {
    this.now = opts.now ?? Date.now;
    this.ttlMs = opts.reservationTtlMs ?? DEFAULT_RESERVATION_TTL_MS;
    this.newId =
      opts.newId ??
      (() => `rsv_${Date.now().toString(36)}_${(this.counter++).toString(36)}`);
  }

  /** Register or replace an agent's policy. Registering clears revocation. */
  register(agentId: string, policy: SpendPolicy): void {
    const existing = this.agents.get(agentId);
    const t = this.now();
    this.agents.set(agentId, {
      policy,
      revoked: false,
      minute: existing?.minute ?? { spent: 0, resetsAt: t + MINUTE_MS },
      hour: existing?.hour ?? { spent: 0, resetsAt: t + HOUR_MS },
      day: existing?.day ?? { spent: 0, resetsAt: t + DAY_MS },
      total: existing?.total ?? 0,
      pending: existing?.pending ?? new Map(),
    });
  }

  /**
   * Revoke an agent immediately.
   *
   * Outstanding reservations are RELEASED rather than committed: revocation
   * during traffic should stop the in-flight requests too, not merely the next
   * ones. An operator revoking a runaway agent means "stop now".
   */
  revoke(agentId: string): void {
    const state = this.agents.get(agentId);
    if (!state) return;
    state.revoked = true;
    for (const reservation of state.pending.values()) {
      this.rollBack(state, reservation);
    }
    state.pending.clear();
  }

  isRevoked(agentId: string): boolean {
    return this.agents.get(agentId)?.revoked ?? false;
  }

  /**
   * Ask permission to spend, and take the headroom if granted.
   *
   * THE COUNTERS MOVE HERE, before the request is served. That is what makes
   * concurrent requests safe: the Nth caller sees the first N-1 reservations
   * already deducted, because JavaScript's single-threaded execution means this
   * whole method runs without interleaving. There is no await inside it, and
   * there must never be one — an await would reintroduce exactly the
   * check-then-act window this design exists to close.
   */
  reserve(agentId: string, endpoint: string, amount: Micros): SpendDecision {
    const state = this.agents.get(agentId);
    if (!state) return this.deny("unknown_agent");
    if (state.revoked) return this.deny("revoked");
    if (!state.policy) return this.deny("no_policy");
    if (!Number.isFinite(amount) || amount < 0) return this.deny("policy_unavailable");

    const t = this.now();
    this.rollWindows(state, t);
    this.expireStale(state, t);

    const p = state.policy;
    if (p.maxPerRequest !== undefined && amount > p.maxPerRequest) {
      return this.deny("exceeds_per_request");
    }
    if (p.maxPerMinute !== undefined && state.minute.spent + amount > p.maxPerMinute) {
      return this.deny("exceeds_per_minute");
    }
    if (p.maxPerHour !== undefined && state.hour.spent + amount > p.maxPerHour) {
      return this.deny("exceeds_per_hour");
    }
    if (p.maxPerDay !== undefined && state.day.spent + amount > p.maxPerDay) {
      return this.deny("exceeds_per_day");
    }
    if (p.maxTotal !== undefined && state.total + amount > p.maxTotal) {
      return this.deny("exceeds_total");
    }

    // Granted — take the headroom now.
    state.minute.spent += amount;
    state.hour.spent += amount;
    state.day.spent += amount;
    state.total += amount;

    const reservation: Reservation = {
      id: this.newId(),
      agentId,
      endpoint,
      amount,
      createdAt: t,
    };
    state.pending.set(reservation.id, reservation);
    return { ok: true, reservation };
  }

  /**
   * The request succeeded and the payment settled. The reservation becomes
   * permanent spend — which means dropping it from `pending`, since the
   * counters were already moved at reserve time.
   */
  commit(reservationId: string): boolean {
    for (const state of this.agents.values()) {
      if (state.pending.delete(reservationId)) return true;
    }
    return false;
  }

  /**
   * The request failed, or the payment did not settle. Give the headroom back.
   *
   * Releasing an unknown id is a no-op returning false rather than an error: a
   * double-release is a caller bug, but throwing here would turn a failed
   * request into a crashed process.
   */
  release(reservationId: string): boolean {
    for (const state of this.agents.values()) {
      const reservation = state.pending.get(reservationId);
      if (!reservation) continue;
      state.pending.delete(reservationId);
      this.rollBack(state, reservation);
      return true;
    }
    return false;
  }

  /** What an agent has spent and what is still available. For the ledger and
   *  for an operator answering "why was I denied?". */
  usage(agentId: string): {
    spentThisMinute: Micros;
    spentThisHour: Micros;
    spentToday: Micros;
    spentTotal: Micros;
    pendingReservations: number;
    revoked: boolean;
  } | null {
    const state = this.agents.get(agentId);
    if (!state) return null;
    const t = this.now();
    this.rollWindows(state, t);
    this.expireStale(state, t);
    return {
      spentThisMinute: state.minute.spent,
      spentThisHour: state.hour.spent,
      spentToday: state.day.spent,
      spentTotal: state.total,
      pendingReservations: state.pending.size,
      revoked: state.revoked,
    };
  }

  // ── internals ────────────────────────────────────────────────────────────

  private deny(reason: DenialReason): SpendDecision {
    return { ok: false, reason, message: DENIAL_MESSAGES[reason] };
  }

  private rollBack(state: AgentState, r: Reservation): void {
    // Clamped at zero. A window that rolled between reserve and release would
    // otherwise be driven negative, which then grants free headroom on the
    // next request — a rollback that hands out money.
    state.minute.spent = Math.max(0, state.minute.spent - r.amount);
    state.hour.spent = Math.max(0, state.hour.spent - r.amount);
    state.day.spent = Math.max(0, state.day.spent - r.amount);
    state.total = Math.max(0, state.total - r.amount);
  }

  private rollWindows(state: AgentState, t: number): void {
    if (t >= state.minute.resetsAt) state.minute = { spent: 0, resetsAt: t + MINUTE_MS };
    if (t >= state.hour.resetsAt) state.hour = { spent: 0, resetsAt: t + HOUR_MS };
    if (t >= state.day.resetsAt) state.day = { spent: 0, resetsAt: t + DAY_MS };
    // `total` is lifetime and deliberately never rolls.
  }

  private expireStale(state: AgentState, t: number): void {
    for (const [id, r] of state.pending) {
      if (t - r.createdAt < this.ttlMs) continue;
      state.pending.delete(id);
      this.rollBack(state, r);
    }
  }
}

/**
 * Price an endpoint, or refuse.
 *
 * There is no default price and there must not be one. A missing entry means
 * the operator has not decided what this endpoint costs, and inventing a
 * default there either gives the endpoint away or overcharges for it.
 */
export function priceFor(endpoint: string, prices: EndpointPrices): Micros | null {
  const price = prices[endpoint];
  return typeof price === "number" && Number.isFinite(price) && price >= 0 ? price : null;
}

/**
 * The whole authorisation step, as one call: price the endpoint, then reserve.
 *
 * This is what a gateway middleware calls. It exists so the ordering — price
 * first, then reserve, never the reverse — lives in one place rather than in
 * every adapter.
 */
export function authorize(
  limiter: SpendLimiter,
  input: { agentId: string; endpoint: string; prices: EndpointPrices }
): SpendDecision {
  const price = priceFor(input.endpoint, input.prices);
  if (price === null) {
    return { ok: false, reason: "unpriced_endpoint", message: DENIAL_MESSAGES.unpriced_endpoint };
  }
  return limiter.reserve(input.agentId, input.endpoint, price);
}
