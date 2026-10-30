// ---------------------------------------------------------------------------
// Redis-backed nonce and budget stores for @furlpay/agent-trust.
//
// The default in-memory NonceStore and budget Map are correct within one
// process, but a fleet of verifiers (multiple Next.js instances, edge
// workers) each track independently — a nonce burned in one instance is
// unknown to the others, and a budget reserved in one does not count against
// the others.
//
// These Redis-backed stores close that gap using Upstash REST API (Edge-
// compatible, no TCP dependency). They are optional: import from
// "@furlpay/agent-trust/redis" only when you need multi-instance
// coordination.
//
// Failure mode: FAIL CLOSED. If Redis is unreachable, nonce.add() throws
// and budget.reserve() returns { ok: false }. A rate-limiter can afford to
// fail open (briefly allowing extra requests is better than blocking all
// traffic), but a nonce/budget store cannot: failing open on a nonce check
// means accepting replayed tokens, and failing open on a budget check means
// exceeding a mandate's spending cap. Both are security violations.
// ---------------------------------------------------------------------------

import crypto from "node:crypto";

// ── Upstash REST helper ─────────────────────────────────────────────────────

/** Configuration for Redis-backed stores. */
export interface RedisStoreConfig {
  /** Upstash REST API URL. */
  url: string;
  /** Upstash REST API token. */
  token: string;
  /** Nonce TTL in seconds. Default: 86400 (24h). */
  nonceTtlSeconds?: number;
  /** Key prefix. Default: "furlpay:". */
  prefix?: string;
}

interface UpstashResult<T> {
  result: T;
}

async function upstashExec<T>(
  url: string,
  token: string,
  command: (string | number)[]
): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(command),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Upstash Redis error (${res.status}): ${text}`);
  }

  const data = (await res.json()) as UpstashResult<T>;
  return data.result;
}

async function upstashPipeline<T>(
  url: string,
  token: string,
  commands: (string | number)[][]
): Promise<T[]> {
  const res = await fetch(`${url}/pipeline`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(commands),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Upstash Redis pipeline error (${res.status}): ${text}`);
  }

  const data = (await res.json()) as UpstashResult<T>[];
  return data.map((d) => d.result);
}

// ── NonceStore ──────────────────────────────────────────────────────────────

/**
 * Nonce store interface matching @furlpay/agent-trust's NonceStore.
 *
 * Duplicated here to avoid a runtime dependency on the agent-trust package.
 * The interface is the same: add() returns true if the nonce was fresh,
 * false if it was a replay.
 */
export interface NonceStore {
  add(nonce: string): boolean | Promise<boolean>;
  has?(nonce: string): boolean | Promise<boolean>;
}

/**
 * Redis-backed nonce store for multi-instance replay protection.
 *
 * Uses Redis SET with NX (set-if-not-exists) and EX (expiry) for atomic
 * add-if-absent. The nonce key is a SHA-256 hash of the nonce value so
 * keys have constant length regardless of input.
 *
 * Failure mode: THROWS on Redis errors (fail closed). A nonce check that
 * silently succeeds on a Redis outage would accept replayed tokens.
 */
export class RedisNonceStore implements NonceStore {
  private readonly url: string;
  private readonly token: string;
  private readonly ttl: number;
  private readonly prefix: string;

  constructor(config: RedisStoreConfig) {
    this.url = config.url.replace(/\/$/, "");
    this.token = config.token;
    this.ttl = config.nonceTtlSeconds ?? 86_400;
    this.prefix = (config.prefix ?? "furlpay:") + "nonce:";
  }

  /** Hash a nonce to a constant-length Redis key. */
  private key(nonce: string): string {
    const hash = crypto.createHash("sha256").update(nonce).digest("hex");
    return `${this.prefix}${hash}`;
  }

  /**
   * Atomically record a nonce. Returns true if the nonce was fresh (first
   * time seen), false if it already existed (replay).
   *
   * @throws On Redis errors — fail closed.
   */
  async add(nonce: string): Promise<boolean> {
    // SET key 1 NX EX ttl — returns "OK" if set, null if already existed
    const result = await upstashExec<string | null>(
      this.url,
      this.token,
      ["SET", this.key(nonce), "1", "NX", "EX", this.ttl]
    );
    return result === "OK";
  }

  /**
   * Check if a nonce has been seen before, without recording it.
   *
   * @throws On Redis errors — fail closed.
   */
  async has(nonce: string): Promise<boolean> {
    const result = await upstashExec<number>(
      this.url,
      this.token,
      ["EXISTS", this.key(nonce)]
    );
    return result === 1;
  }
}

// ── BudgetStore ─────────────────────────────────────────────────────────────

/** Result of a budget reservation attempt. */
export interface BudgetReserveResult {
  /** Whether the reservation was accepted. */
  ok: boolean;
  /** Current total spent after this reservation (in micro-dollars). */
  spent: bigint;
  /** Remaining allowance after this reservation. */
  remaining: bigint;
  /** Reason for rejection, if ok is false. */
  reason?: string;
}

/**
 * Redis-backed mandate budget store for multi-instance spend tracking.
 *
 * Budgets are tracked in micro-dollars (bigint) to match the precision of
 * @furlpay/agent-trust. The atomic reserve operation uses a Lua script
 * executed via EVAL to prevent race conditions between concurrent bookings
 * across instances.
 *
 * Failure mode: FAIL CLOSED. If Redis is unreachable, reserve() returns
 * { ok: false, reason: "Redis unavailable" }. Exceeding a mandate's
 * spending cap is a security violation — failing open is not acceptable.
 */
export class RedisBudgetStore {
  private readonly url: string;
  private readonly token: string;
  private readonly prefix: string;

  constructor(config: RedisStoreConfig) {
    this.url = config.url.replace(/\/$/, "");
    this.token = config.token;
    this.prefix = (config.prefix ?? "furlpay:") + "budget:";
  }

  private spentKey(mandateId: string): string {
    return `${this.prefix}spent:${mandateId}`;
  }

  private consumedKey(mandateId: string): string {
    return `${this.prefix}consumed:${mandateId}`;
  }

  /**
   * Atomically check-and-reserve an amount against a mandate's budget.
   *
   * The Lua script:
   *   1. Reads the current spent amount.
   *   2. Checks if spent + amount > cap.
   *   3. If within cap, increments spent and returns the new total.
   *   4. If over cap, returns -1 (rejection).
   *
   * This is atomic: two concurrent bookings cannot both read the same
   * spent value and both pass the cap check.
   */
  async reserve(
    mandateId: string,
    amountMicros: bigint,
    capMicros: bigint
  ): Promise<BudgetReserveResult> {
    const key = this.spentKey(mandateId);
    const luaScript = `
      local spent = tonumber(redis.call('GET', KEYS[1]) or '0')
      local amount = tonumber(ARGV[1])
      local cap = tonumber(ARGV[2])
      if spent + amount > cap then
        return -1
      end
      local newSpent = redis.call('INCRBY', KEYS[1], ARGV[1])
      return newSpent
    `;

    try {
      const result = await upstashExec<number>(
        this.url,
        this.token,
        ["EVAL", luaScript, "1", key, String(amountMicros), String(capMicros)]
      );

      if (result === -1) {
        // Read current spent for the error message
        const currentSpent = await this.getSpent(mandateId);
        return {
          ok: false,
          spent: currentSpent,
          remaining: capMicros - currentSpent,
          reason: `Amount exceeds remaining allowance`,
        };
      }

      const spent = BigInt(result);
      return {
        ok: true,
        spent,
        remaining: capMicros - spent,
      };
    } catch (e) {
      return {
        ok: false,
        spent: 0n,
        remaining: 0n,
        reason: `Redis unavailable: ${(e as Error).message}`,
      };
    }
  }

  /** Get the current spent amount for a mandate. */
  async getSpent(mandateId: string): Promise<bigint> {
    const result = await upstashExec<string | null>(
      this.url,
      this.token,
      ["GET", this.spentKey(mandateId)]
    );
    return result ? BigInt(result) : 0n;
  }

  /**
   * Release a reservation (rollback).
   *
   * Used when a downstream operation fails after a successful reserve().
   * Decrements the spent amount, never below zero.
   */
  async release(mandateId: string, amountMicros: bigint): Promise<void> {
    const key = this.spentKey(mandateId);
    const luaScript = `
      local spent = tonumber(redis.call('GET', KEYS[1]) or '0')
      local amount = tonumber(ARGV[1])
      local newSpent = math.max(0, spent - amount)
      redis.call('SET', KEYS[1], tostring(newSpent))
      return newSpent
    `;
    await upstashExec(
      this.url,
      this.token,
      ["EVAL", luaScript, "1", key, String(amountMicros)]
    );
  }

  /** Check if a single-use mandate has been consumed. */
  async isConsumed(mandateId: string): Promise<boolean> {
    const result = await upstashExec<number>(
      this.url,
      this.token,
      ["EXISTS", this.consumedKey(mandateId)]
    );
    return result === 1;
  }

  /** Mark a single-use mandate as consumed. */
  async markConsumed(mandateId: string): Promise<void> {
    // No expiry — consumed mandates stay consumed forever. An operational
    // cleanup job can expire them after the mandate's own expiry + a buffer.
    await upstashExec(
      this.url,
      this.token,
      ["SET", this.consumedKey(mandateId), "1"]
    );
  }
}
