import { theme, type ThemeConfig } from "antd";

export type ThemeName = "day" | "night" | "midnight";
export type ThemePref = ThemeName | "system";
export const themePrefs: readonly ThemePref[] = ["system", "day", "night", "midnight"];

/** "Follow system" maps light → day and dark → night (midnight is opt-in for OLED). */
export function resolveTheme(pref: ThemePref, systemDark: boolean): ThemeName {
  if (pref !== "system") return pref;
  return systemDark ? "night" : "day";
}

/**
 * The Flover Diary palette: a sky-blue page with paper, ink, and a little blossom pink.
 * Day is the design system's own values; night and midnight carry the same roles onto dark
 * paper. Every text pair is at least 4.5:1 except Flover's own skyDeep on sky (4.45:1), which
 * is only used for handwritten headings of 24px and more, where 3:1 is enough.
 */
export interface Palette {
  /** Page background, under the dotted pattern. */
  sky: string;
  /** Cards, tables, the sidebar: everything sits on paper. */
  paper: string;
  /** Text and the solid primary button. */
  ink: string;
  inkMuted: string;
  /** Text on ink (the primary button). */
  onInk: string;
  /** The accent, kept for a few places: sticker tags, active nav, switches, usage bars. */
  blossom: string;
  onBlossom: string;
  /** Text on note and blossomSoft. */
  blossomDeep: string;
  blossomSoft: string;
  /** Sticky-note paper. */
  note: string;
  /** Handwritten headings and the blue tape. */
  skyDeep: string;
  /** Photo placeholders and quiet fills. */
  skyPhoto: string;
  /** Decorative only, never text. */
  lilac: string;
  /** Dashed borders and unchecked boxes (3:1 against paper). */
  line: string;
  /** Hairlines between table rows. */
  hairline: string;
  /** The dots of the page pattern. */
  dot: string;
  shadowPaper: string;
  ok: string;
  warning: string;
  error: string;
}

export const palettes: Record<ThemeName, Palette> = {
  day: {
    sky: "#e6eff8", paper: "#ffffff", ink: "#1b2738", inkMuted: "#40516a", onInk: "#ffffff",
    blossom: "#b83a73", onBlossom: "#ffffff", blossomDeep: "#7a2149", blossomSoft: "#f6d3e2", note: "#fbe3ee",
    skyDeep: "#2f6fb5", skyPhoto: "#cfdff0", lilac: "#b9b4e0", line: "#7f95b0", hairline: "#e3ebf5",
    dot: "rgba(127, 149, 176, 0.28)", shadowPaper: "0 6px 14px rgba(27, 39, 56, 0.16)",
    ok: "#1f7a55", warning: "#8f5400", error: "#b42318",
  },
  night: {
    sky: "#121a29", paper: "#1c2638", ink: "#e8eef7", inkMuted: "#aab7ca", onInk: "#121a29",
    blossom: "#f08bb7", onBlossom: "#2a0d1b", blossomDeep: "#ffd3e6", blossomSoft: "#4a2438", note: "#3b2232",
    skyDeep: "#8fbcf0", skyPhoto: "#22324a", lilac: "#8a85c2", line: "#647a99", hairline: "#26334a",
    dot: "rgba(143, 188, 240, 0.14)", shadowPaper: "0 6px 16px rgba(0, 0, 0, 0.45)",
    ok: "#64d6a0", warning: "#f2b866", error: "#f49a8a",
  },
  midnight: {
    sky: "#000000", paper: "#0e131c", ink: "#e6ecf5", inkMuted: "#9eabbf", onInk: "#000000",
    blossom: "#f07fae", onBlossom: "#22091a", blossomDeep: "#ffcbe0", blossomSoft: "#3d1c2e", note: "#2e1a26",
    skyDeep: "#82b3ec", skyPhoto: "#141e2d", lilac: "#7c77b5", line: "#55688a", hairline: "#1a2230",
    dot: "rgba(130, 179, 236, 0.12)", shadowPaper: "0 6px 16px rgba(0, 0, 0, 0.7)",
    ok: "#5ad18f", warning: "#f0b35b", error: "#f08c6b",
  },
};

/** Body text uses the reader's own system fonts; only headings and numbers are bundled. */
const sans =
  '-apple-system, BlinkMacSystemFont, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans CJK SC", "Noto Sans SC", "Segoe UI", system-ui, sans-serif';

export function themeConfig(name: ThemeName): ThemeConfig {
  const p = palettes[name];
  const dark = name !== "day";
  return {
    algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
    token: {
      fontFamily: sans,
      fontFamilyCode: '"SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
      fontSize: 14,
      borderRadius: 6,
      borderRadiusLG: 6,
      borderRadiusSM: 4,
      controlHeight: 36,
      lineWidth: 1,
      wireframe: false,
      boxShadow: "none",
      boxShadowSecondary: p.shadowPaper,
      motionDurationMid: "0.18s",
      colorPrimary: p.ink,
      colorInfo: p.skyDeep,
      colorSuccess: p.ok,
      colorWarning: p.warning,
      colorError: p.error,
      colorLink: p.skyDeep,
      colorLinkHover: p.blossom,
      colorBgLayout: p.sky,
      colorBgContainer: p.paper,
      colorBgElevated: p.paper,
      colorBorder: p.line,
      colorBorderSecondary: p.hairline,
      colorText: p.ink,
      colorTextSecondary: p.inkMuted,
      colorTextTertiary: p.inkMuted,
      colorTextQuaternary: p.line,
      colorFillSecondary: p.skyPhoto,
      colorFillTertiary: p.hairline,
      colorFillQuaternary: p.hairline,
    },
    components: {
      Button: {
        borderRadius: 30, borderRadiusLG: 30, borderRadiusSM: 30,
        primaryColor: p.onInk, primaryShadow: "none", defaultShadow: "none", dangerShadow: "none",
        defaultBg: "transparent", defaultBorderColor: p.line,
      },
      Layout: { siderBg: "transparent", headerBg: "transparent", bodyBg: "transparent" },
      Menu: {
        itemBg: "transparent", activeBarBorderWidth: 0, itemBorderRadius: 30,
        itemSelectedBg: p.blossomSoft, itemSelectedColor: p.blossomDeep, itemHoverBg: p.hairline, itemColor: p.inkMuted,
      },
      Card: { headerFontSize: 24, headerBg: "transparent", colorBorderSecondary: "transparent" },
      Table: {
        headerBg: "transparent", headerColor: p.skyDeep, headerSplitColor: "transparent",
        borderColor: p.hairline, rowHoverBg: p.hairline,
      },
      Switch: { colorPrimary: p.blossom, colorPrimaryHover: p.blossom },
      Progress: { defaultColor: p.blossom, remainingColor: p.hairline },
      Tag: { borderRadiusSM: 30, defaultBg: p.skyPhoto, defaultColor: p.ink },
      Segmented: { itemSelectedBg: p.blossomSoft, itemSelectedColor: p.blossomDeep, trackBg: p.hairline },
      Input: { borderRadius: 8 },
      InputNumber: { borderRadius: 8 },
      Select: { borderRadius: 8 },
      DatePicker: { borderRadius: 8 },
      Drawer: { colorBgElevated: p.paper },
      Modal: { contentBg: p.paper, headerBg: p.paper },
      Statistic: { contentFontSize: 44 },
      Badge: { colorSuccess: p.ok },
    },
  };
}

export function themeBackground(name: ThemeName): string {
  return palettes[name].sky;
}

/** The palette as CSS custom properties: --sky, --paper, --ink-muted, ... */
export function paletteVariables(name: ThemeName): Record<string, string> {
  const vars: Record<string, string> = {};
  for (const [k, v] of Object.entries(palettes[name]) as [string, string][]) {
    vars["--" + k.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase())] = v;
  }
  return vars;
}
