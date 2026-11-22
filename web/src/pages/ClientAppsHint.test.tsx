import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { LANG_KEY } from "../i18n/I18nProvider";
import { guideUrl } from "../lib/guides";
import { renderWithProviders } from "../test/render";
import { ClientAppsHint } from "./ClientAppsHint";

const androidUA = "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36";

const appNames = () => screen.getAllByRole("listitem").map((li) => li.querySelector("strong")?.textContent);

describe("ClientAppsHint", () => {
  it("opens on the apps for the device in hand and switches on request", async () => {
    localStorage.setItem(LANG_KEY, "en");
    vi.spyOn(window.navigator, "userAgent", "get").mockReturnValue(androidUA);
    renderWithProviders(<ClientAppsHint />);

    expect(appNames()).toEqual(["v2rayNG", "FlClash"]);
    const [links, mihomo] = screen.getAllByRole("listitem");
    expect(links).toHaveTextContent("Universal (most apps)");
    expect(mihomo).toHaveTextContent("Clash Meta / mihomo");

    await userEvent.click(screen.getByText("iPhone / iPad"));
    expect(appNames()).toEqual(["Shadowrocket", "Streisand"]);
  });

  it("links to the client guide in a new tab without leaking the panel address", () => {
    renderWithProviders(<ClientAppsHint />);
    const link = screen.getByRole("link");
    expect([link.getAttribute("href"), link.getAttribute("target"), link.getAttribute("rel")])
      .toEqual([guideUrl("clients"), "_blank", "noopener noreferrer"]);
  });
});
