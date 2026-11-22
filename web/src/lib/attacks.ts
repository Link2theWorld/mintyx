import { attackKinds, type AttackKind, type AttackReport, type AttackSummary } from "../api/schemas";
import type { Lang } from "../i18n/translate";
import type { ThemeName } from "../theme/themes";

/**
 * One colour per attack kind, in a fixed order so a kind keeps its colour whatever else is on
 * screen. Neighbouring colours were checked to stay apart for colour-blind readers on each
 * theme's card background; the two dark themes share the darker steps. Three of the light
 * colours are below 3:1 against white, so a colour never appears without its label.
 */
const palette: Record<"light" | "dark", Record<AttackKind, string>> = {
  light: { ssh_login: "#2a78d6", ssh_invalid_user: "#eb6834", ssh_scan: "#1baf7a", line_probe: "#eda100", line_bad_auth: "#e87ba4" },
  dark: { ssh_login: "#3987e5", ssh_invalid_user: "#d95926", ssh_scan: "#199e70", line_probe: "#c98500", line_bad_auth: "#d55181" },
};
const UNKNOWN_COLOR = "#8a8f8c";

export function isAttackKind(kind: string): kind is AttackKind {
  return (attackKinds as readonly string[]).includes(kind);
}

/** A kind this build does not know (from a newer server) is grey, never a borrowed colour. */
export function kindColor(kind: string, theme: ThemeName): string {
  return isAttackKind(kind) ? palette[theme === "day" ? "light" : "dark"][kind] : UNKNOWN_COLOR;
}

export function kindLabelKey(kind: string): `attacks.kind.${AttackKind}` | null {
  return isAttackKind(kind) ? `attacks.kind.${kind}` : null;
}

/** Display order: the fixed palette order, then anything unknown. */
export function sortKinds<T extends { kind: string }>(list: readonly T[]): T[] {
  const rank = (k: string) => (isAttackKind(k) ? attackKinds.indexOf(k) : attackKinds.length);
  return [...list].sort((a, b) => rank(a.kind) - rank(b.kind) || a.kind.localeCompare(b.kind));
}

/** The registries give a two-letter code for most networks and free text for the rest. */
export function countryName(country: string, lang: Lang): string {
  if (!/^[A-Z]{2}$/.test(country)) return country;
  try {
    return new Intl.DisplayNames([lang === "zh" ? "zh-CN" : "en"], { type: "region" }).of(country) ?? country;
  } catch {
    return country;
  }
}

export interface TrendDay {
  day: string;
  total: number;
  /** Bottom-to-top segments in palette order, zero-hit kinds left out. */
  segments: { kind: string; hits: number }[];
}

export function trendDays(daily: AttackSummary["daily"]): TrendDay[] {
  return daily.map((d) => {
    const segments = sortKinds(Object.entries(d.hits).map(([kind, hits]) => ({ kind, hits }))).filter((s) => s.hits > 0);
    return { day: d.day, total: segments.reduce((n, s) => n + s.hits, 0), segments };
  });
}

/** A round number at or above max for the top of the y-axis, so the tallest bar never touches it. */
export function niceCeil(max: number): number {
  if (max <= 5) return 5;
  const pow = 10 ** Math.floor(Math.log10(max));
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (m * pow >= max) return m * pow;
  }
  return 10 * pow;
}

/** mailto: with the draft filled in; null when no abuse address is known. */
export function reportMailto(r: AttackReport): string | null {
  if (r.to === "") return null;
  return `mailto:${encodeURIComponent(r.to)}?subject=${encodeURIComponent(r.subject)}&body=${encodeURIComponent(r.body)}`;
}

/** Everything a webmail user needs to paste, in one block. */
export function reportText(r: AttackReport): string {
  return `To: ${r.to}\nSubject: ${r.subject}\n\n${r.body}`;
}

export function compactNumber(n: number, lang: Lang): string {
  return new Intl.NumberFormat(lang === "zh" ? "zh-CN" : "en", { notation: n >= 10_000 ? "compact" : "standard", maximumFractionDigits: 1 }).format(n);
}
