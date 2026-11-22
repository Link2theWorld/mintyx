import type { Client } from "../api/schemas";
import { daysUntil, quotaFraction } from "./format";

export type ClientState = "active" | "manual" | "quota" | "expired";

export interface ClientStatus {
  state: ClientState;
  /** Active client that has used at least NEAR_QUOTA of its quota. */
  nearQuota: boolean;
  /** Active client expiring within NEAR_EXPIRY_DAYS. */
  nearExpiry: boolean;
  used: number;
  /** used / quota, or null when unlimited. */
  fraction: number | null;
}

export const NEAR_QUOTA = 0.9;
export const NEAR_EXPIRY_DAYS = 3;

export function clientStatus(c: Client, now: Date = new Date()): ClientStatus {
  const used = c.usedUp + c.usedDown;
  const fraction = quotaFraction(used, c.quotaBytes);
  const state: ClientState = c.disabled === "" ? "active" : c.disabled;
  const active = state === "active";
  return {
    state,
    used,
    fraction,
    nearQuota: active && fraction !== null && fraction >= NEAR_QUOTA,
    nearExpiry: active && c.expiresAt !== null && daysUntil(c.expiresAt, now) <= NEAR_EXPIRY_DAYS,
  };
}
