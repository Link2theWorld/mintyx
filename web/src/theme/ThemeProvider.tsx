import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useMediaQuery } from "../lib/useMediaQuery";
import { readPref, writePref } from "../lib/storage";
import { paletteVariables, resolveTheme, themeBackground, themePrefs, type ThemeName, type ThemePref } from "./themes";

export const THEME_KEY = "mintyx.theme";
const DARK_QUERY = "(prefers-color-scheme: dark)";

interface ThemeValue {
  pref: ThemePref;
  setPref: (p: ThemePref) => void;
  resolved: ThemeName;
}

const ThemeContext = createContext<ThemeValue | null>(null);

function initialPref(): ThemePref {
  const saved = readPref(THEME_KEY);
  return themePrefs.find((p) => p === saved) ?? "system";
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [pref, setPrefState] = useState<ThemePref>(initialPref);
  const dark = useMediaQuery(DARK_QUERY);

  const setPref = useCallback((p: ThemePref) => {
    writePref(THEME_KEY, p);
    setPrefState(p);
  }, []);

  const resolved = resolveTheme(pref, dark);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = resolved;
    root.style.colorScheme = resolved === "day" ? "light" : "dark";
    // The page itself (dotted sky, paper, ink) is drawn by app.css from these variables.
    for (const [name, value] of Object.entries(paletteVariables(resolved))) root.style.setProperty(name, value);
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", themeBackground(resolved));
  }, [resolved]);

  const value = useMemo(() => ({ pref, setPref, resolved }), [pref, setPref, resolved]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useThemePref(): ThemeValue {
  const v = useContext(ThemeContext);
  if (!v) throw new Error("useThemePref outside ThemeProvider");
  return v;
}
