import { attackKinds, type AttackKind, type AttackReport, type AttackSummary } from "../api/schemas";
import type { Lang } from "../i18n/translate";
import type { ThemeName } from "../theme/themes";

/**
 * One colour per attack kind, in a fixed order so a kind keeps its colour whatever else is on
 * screen. Drawn from Flover Diary: the first and third are its sky-deep and blossom, the rest
 * are an amber, a lilac and a teal that sit with them. Each set passes the data-viz palette
 * checks (lightness band, chroma, neighbours apart under protan/deutan simulation, and 3:1
 * against the card) on its theme's paper; night and midnight share the darker steps. A colour
 * never appears without its label.
 */
const palette: Record<"light" | "dark", Record<AttackKind, string>> = {
  light: { ssh_login: "#2f6fb5", ssh_invalid_user: "#cc7a24", ssh_scan: "#b83a73", line_probe: "#8a7fd6", line_bad_auth: "#2a9d8f" },
  dark: { ssh_login: "#3f80d0", ssh_invalid_user: "#c57a2a", ssh_scan: "#c9508a", line_probe: "#8478da", line_bad_auth: "#22967f" },
};
/** Flover's line colour: a quiet blue-grey that no kind uses. */
const UNKNOWN_COLOR = "#7f95b0";

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
