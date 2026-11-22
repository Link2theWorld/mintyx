import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { setMedia } from "../test/matchMedia";
import { THEME_KEY, ThemeProvider, useThemePref } from "./ThemeProvider";
import type { ThemePref } from "./themes";

function Probe() {
  const { pref, resolved, setPref } = useThemePref();
  return (
    <div>
      <output aria-label="pref">{pref}</output>
      <output aria-label="resolved">{resolved}</output>
      {(["system", "day", "night", "midnight"] as ThemePref[]).map((p) => (
        <button key={p} onClick={() => setPref(p)}>{p}</button>
      ))}
    </div>
  );
}

const value = (label: string) => screen.getByLabelText(label).textContent;

describe("theme preference", () => {
  it("defaults to following the system", () => {
    render(<ThemeProvider><Probe /></ThemeProvider>);
    expect([value("pref"), value("resolved")]).toEqual(["system", "day"]);
  });

  it("remembers an explicit choice across reloads", async () => {
    const first = render(<ThemeProvider><Probe /></ThemeProvider>);
    await userEvent.click(screen.getByRole("button", { name: "midnight" }));
    expect(localStorage.getItem(THEME_KEY)).toBe("midnight");
    first.unmount();

    render(<ThemeProvider><Probe /></ThemeProvider>);
    expect([value("pref"), value("resolved")]).toEqual(["midnight", "midnight"]);
    expect(document.documentElement.dataset.theme).toBe("midnight");
  });

  it("ignores a corrupt stored value", () => {
    localStorage.setItem(THEME_KEY, "neon");
    render(<ThemeProvider><Probe /></ThemeProvider>);
    expect(value("pref")).toBe("system");
  });

  it("follow-system tracks prefers-color-scheme as it changes", () => {
    setMedia({ dark: true });
    render(<ThemeProvider><Probe /></ThemeProvider>);
    expect(value("resolved")).toBe("night");
    act(() => setMedia({ dark: false }));
    expect(value("resolved")).toBe("day");
    act(() => setMedia({ dark: true }));
    expect(value("resolved")).toBe("night");
  });

  it("an explicit choice ignores the system setting", async () => {
    render(<ThemeProvider><Probe /></ThemeProvider>);
    await userEvent.click(screen.getByRole("button", { name: "day" }));
    act(() => setMedia({ dark: true }));
    expect(value("resolved")).toBe("day");
  });
});
