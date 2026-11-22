import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { LineDraft, Region } from "../api/schemas";
import { LANG_KEY } from "../i18n/I18nProvider";
import { renderWithProviders } from "../test/render";
import { LinesPage, REGION_KEY } from "./LinesPage";

const siteFor = (region?: Region) => (region ? `www.${region}.example` : "www.campus.example");

function draftFor(region?: Region): LineDraft {
  const site = siteFor(region);
  return {
    protocol: "vless-reality", name: "REALITY 443", port: 443, enabled: true, host: "",
    reality: { publicKey: "", shortId: "ab12", serverName: site, target: `${site}:443` },
  };
}

async function openNewLine() {
  localStorage.setItem(LANG_KEY, "en");
  vi.spyOn(api, "lines").mockResolvedValue([]);
  const lineDraft = vi.spyOn(api, "lineDraft").mockImplementation((_protocol, region) => Promise.resolve(draftFor(region)));
  renderWithProviders(<LinesPage />);
  await userEvent.click(await screen.findByRole("button", { name: /New line/ }));
  await screen.findByLabelText("Cover website");
  return lineDraft;
}

describe("new line server region", () => {
  it("re-requests the draft for the picked region, keeping what was typed", async () => {
    const lineDraft = await openNewLine();
    expect(lineDraft.mock.calls).toEqual([["vless-reality", undefined]]);
    expect(screen.getByLabelText("Cover website")).toHaveValue("www.campus.example");

    const name = screen.getByLabelText("Name");
    await userEvent.clear(name);
    await userEvent.type(name, "My Tokyo box");
    await userEvent.click(screen.getByRole("combobox", { name: "Server region" }));
    await userEvent.click(await screen.findByText("Japan"));

    await waitFor(() => expect(screen.getByLabelText("Cover website")).toHaveValue("www.jp.example"));
    expect(screen.getByLabelText("Forward target")).toHaveValue("www.jp.example:443");
    expect(lineDraft.mock.calls[1]).toEqual(["vless-reality", "jp"]);
    // A form remounted for the new draft would have reset the name to the draft's.
    expect(screen.getByLabelText("Name")).toHaveValue("My Tokyo box");
    expect(localStorage.getItem(REGION_KEY)).toBe("jp");
  });

  it.each([
    ["a remembered region", "kr", "kr"],
    ["a stored value that is no longer a region", "mars", undefined],
  ])("starts from %s", async (_name, stored, want) => {
    localStorage.setItem(REGION_KEY, stored);
    const lineDraft = await openNewLine();
    expect(lineDraft.mock.calls).toEqual([["vless-reality", want]]);
    expect(screen.getByLabelText("Cover website")).toHaveValue(siteFor(want as Region | undefined));
  });
});
