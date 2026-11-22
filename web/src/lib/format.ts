import dayjs from "dayjs";

/** Quotas are entered in GB where 1 GB = 1024³ bytes, matching what proxy clients display. */
export const BYTES_PER_GB = 1024 ** 3;
/** Largest quota the form accepts; keeps bytes well inside Number.MAX_SAFE_INTEGER. */
export const MAX_QUOTA_GB = 1_000_000;

const units = ["B", "KB", "MB", "GB", "TB", "PB"] as const;

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  let value = bytes;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  const unit = units[i] ?? "B";
  if (i === 0) return `${Math.round(value)} ${unit}`;
  const digits = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  // Trim trailing zeros so 1.50 GB reads as 1.5 GB.
  return `${String(Number(value.toFixed(digits)))} ${unit}`;
}

/** GB (as typed in the form) to bytes. 0 means "no limit". */
export function gbToBytes(gb: number | null | undefined): number {
  if (gb === null || gb === undefined || !Number.isFinite(gb) || gb <= 0) return 0;
  return Math.round(Math.min(gb, MAX_QUOTA_GB) * BYTES_PER_GB);
}

/**
 * Bytes to GB for the edit form: 2 decimals, or 2 significant digits for tiny
 * quotas so a non-zero quota never shows as 0 (which would read as unlimited).
 */
export function bytesToGb(bytes: number): number {
  if (bytes <= 0) return 0;
  const gb = bytes / BYTES_PER_GB;
  return gb >= 0.01 ? Math.round(gb * 100) / 100 : Number(gb.toPrecision(2));
}

/** Fraction of quota used, or null when there is no quota. */
export function quotaFraction(used: number, quota: number): number | null {
  if (quota <= 0) return null;
  return used / quota;
}

export function formatDateTime(iso: string): string {
  const d = dayjs(iso);
  return d.isValid() ? d.format("YYYY-MM-DD HH:mm") : iso;
}

export function formatDate(iso: string): string {
  const d = dayjs(iso);
  return d.isValid() ? d.format("YYYY-MM-DD") : iso;
}

/** Calendar days from today until iso's local date: 0 = today, negative = an earlier day. */
export function daysUntil(iso: string, now: Date = new Date()): number {
  return dayjs(iso).startOf("day").diff(dayjs(now).startOf("day"), "day");
}
