import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { LANG_KEY } from "../i18n/I18nProvider";
import { guideIds, guideUrl } from "../lib/guides";
import { setMedia } from "../test/matchMedia";
import { renderWithProviders } from "../test/render";
import { Shell } from "./Shell";

describe("Shell guides entry", () => {
  it.each([["desktop sidebar", false], ["phone header", true]] as const)("%s lists every guide", async (_, mobile) => {
    localStorage.setItem(LANG_KEY, "en");
    setMedia({ mobile });
    renderWithProviders(<MemoryRouter><Shell /></MemoryRouter>);

    await userEvent.click(screen.getByRole("button", { name: /Guides$/ }));
    const hrefs = (await screen.findAllByRole("link")).map((a) => a.getAttribute("href")).filter((h) => h?.startsWith("https://"));
    expect(hrefs).toEqual(guideIds.map(guideUrl));
  });
});
