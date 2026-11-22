import { theme, type ThemeConfig } from "antd";

export type ThemeName = "day" | "night" | "midnight";
export type ThemePref = ThemeName | "system";
export const themePrefs: readonly ThemePref[] = ["system", "day", "night", "midnight"];

/** "Follow system" maps light → day and dark → night (midnight is opt-in for OLED). */
export function resolveTheme(pref: ThemePref, systemDark: boolean): ThemeName {
  if (pref !== "system") return pref;
  return systemDark ? "night" : "day";
}

const shared: ThemeConfig["token"] = {
  borderRadius: 10,
  borderRadiusLG: 16,
  fontFamily:
    '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans SC", sans-serif',
  fontFamilyCode: '"JetBrains Mono", "SF Mono", Menlo, Consolas, monospace',
  boxShadow: "none",
  boxShadowSecondary: "0 6px 24px rgba(20, 40, 30, 0.10)",
  lineWidth: 1,
  wireframe: false,
  controlHeight: 36,
  motionDurationMid: "0.18s",
};

// Colours were checked for WCAG AA (4.5:1) text contrast against their backgrounds.
const palettes: Record<ThemeName, { algorithm: ThemeConfig["algorithm"]; token: ThemeConfig["token"]; onPrimary: string }> = {
  day: {
    algorithm: theme.defaultAlgorithm,
    onPrimary: "#ffffff",
    token: {
      colorPrimary: "#107c5a",
      colorInfo: "#107c5a",
      colorSuccess: "#16804f",
      colorWarning: "#b25e09",
      colorError: "#b42318",
      colorLink: "#107c5a",
      colorBgLayout: "#f8f7f3",
      colorBgContainer: "#ffffff",
      colorBgElevated: "#ffffff",
      colorBorder: "#dedcd3",
      colorBorderSecondary: "#ebe9e2",
      colorText: "#1f2a26",
      colorTextSecondary: "#4b5550",
      colorTextTertiary: "#5f6863",
      colorTextQuaternary: "#858c88",
      colorFillSecondary: "#f1f0ea",
    },
  },
  night: {
    algorithm: theme.darkAlgorithm,
    onPrimary: "#0b1f17",
    token: {
      colorPrimary: "#4fd1a5",
      colorInfo: "#4fd1a5",
      colorSuccess: "#5ad18f",
      colorWarning: "#f0b35b",
      colorError: "#f08c6b",
      colorLink: "#4fd1a5",
      colorBgLayout: "#151917",
      colorBgContainer: "#1b201e",
      colorBgElevated: "#222826",
      colorBorder: "#36403c",
      colorBorderSecondary: "#2a322f",
      colorText: "#e6ebe8",
      colorTextSecondary: "#b7c1bc",
      colorTextTertiary: "#9aa5a0",
      colorTextQuaternary: "#77817c",
    },
  },
  midnight: {
    algorithm: theme.darkAlgorithm,
    onPrimary: "#0b1f17",
    token: {
      colorPrimary: "#4fd1a5",
      colorInfo: "#4fd1a5",
      colorSuccess: "#5ad18f",
      colorWarning: "#f0b35b",
      colorError: "#f08c6b",
      colorLink: "#4fd1a5",
      colorBgLayout: "#000000",
      colorBgContainer: "#000000",
      colorBgElevated: "#0e100f",
      colorBorder: "#2e3431",
      colorBorderSecondary: "#1d2220",
      colorText: "#e3e8e5",
      colorTextSecondary: "#adb7b2",
      colorTextTertiary: "#8e9893",
      colorTextQuaternary: "#6c7571",
    },
  },
};

export function themeConfig(name: ThemeName): ThemeConfig {
  const p = palettes[name];
  return {
    algorithm: p.algorithm,
    token: { ...shared, ...p.token },
    components: {
      // Light mint needs dark text on dark themes to keep primary buttons readable.
      Button: { primaryColor: p.onPrimary, primaryShadow: "none", defaultShadow: "none", dangerShadow: "none" },
      Layout: { siderBg: p.token?.colorBgContainer, headerBg: p.token?.colorBgLayout, bodyBg: p.token?.colorBgLayout },
      Menu: { itemBg: "transparent", activeBarBorderWidth: 0, itemBorderRadius: 10 },
      Card: { headerFontSize: 15 },
    },
  };
}

export function themeBackground(name: ThemeName): string {
  return palettes[name].token?.colorBgLayout ?? "#ffffff";
}
