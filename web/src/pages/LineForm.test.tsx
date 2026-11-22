import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type { LineDraft } from "../api/schemas";
import { LANG_KEY } from "../i18n/I18nProvider";
import { renderWithProviders } from "../test/render";
import { LineForm, formPathFor } from "./LineForm";

const drafts: Record<LineDraft["protocol"], LineDraft> = {
  "vless-reality": {
    protocol: "vless-reality", name: "Tokyo", port: 443, enabled: true, host: "",
    reality: { publicKey: "", shortId: "ab12", serverName: "www.example.com", target: "www.example.com:443" },
  },
  "vless-xhttp": {
    protocol: "vless-xhttp", name: "CDN", port: 8443, enabled: true, host: "",
    xhttp: { path: "/p", domain: "a.example.com", security: "none", certFile: "", keyFile: "" },
  },
  hysteria2: {
    protocol: "hysteria2", name: "UDP", port: 9443, enabled: true, host: "",
    hysteria2: { domain: "h.example.com", certFile: "/c.pem", keyFile: "/k.pem", obfsPassword: "" },
  },
};

function renderForm(initial: LineDraft, onSubmit = vi.fn(() => Promise.resolve())) {
  localStorage.setItem(LANG_KEY, "en");
  renderWithProviders(<LineForm mode="create" initial={initial} onSubmit={onSubmit} onCancel={() => undefined} />);
  return onSubmit;
}

// Optional fields carry an "(optional)" suffix in their accessible name.
const has = (label: string) => screen.queryByLabelText(new RegExp(`^${label}( \\(optional\\))?$`)) !== null;

describe("LineForm fields per protocol", () => {
  it("REALITY shows cover website and forward target, no certificate", () => {
    renderForm(drafts["vless-reality"]);
    expect([has("Cover website"), has("Forward target"), has("Short ID")]).toEqual([true, true, true]);
    expect([has("Certificate file path"), has("Obfuscation password"), has("Path")]).toEqual([false, false, false]);
    expect(screen.getByText("Generated when you save")).toBeInTheDocument();
  });

  it("XHTTP behind a CDN hides certificate fields until HTTPS-on-this-server is chosen", async () => {
    renderForm(drafts["vless-xhttp"]);
    expect([has("Domain"), has("Path"), has("Certificate file path")]).toEqual([true, true, false]);
    await userEvent.click(screen.getByLabelText("HTTPS on this server (direct)"));
    expect([has("Certificate file path"), has("Private key file path")]).toEqual([true, true]);
    expect(has("Cover website")).toBe(false);
  });

  it("Hysteria2 shows certificate and obfuscation password with its explanation", () => {
    renderForm(drafts.hysteria2);
    expect([has("Certificate file path"), has("Private key file path"), has("Obfuscation password")]).toEqual([true, true, true]);
    expect(screen.getByText(/block UDP by its fingerprint/)).toBeInTheDocument();
    expect([has("Cover website"), has("Path")]).toEqual([false, false]);
  });
});

describe("LineForm server region", () => {
  const regionSelect = () => screen.queryByRole("combobox", { name: "Server region" });

  it("is offered only while drafting a REALITY line", () => {
    localStorage.setItem(LANG_KEY, "en");
    const props = { region: "" as const, onRegionChange: () => undefined, onSubmit: () => Promise.resolve(), onCancel: () => undefined };
    const shown = (mode: "create" | "edit", initial: LineDraft) => {
      const view = renderWithProviders(<LineForm mode={mode} initial={initial} {...props} />);
      const found = regionSelect() !== null;
      view.unmount();
      return found;
    };
    // An edit has no draft to re-request, and only REALITY has a cover site to suggest.
    expect([shown("create", drafts["vless-reality"]), shown("edit", drafts["vless-reality"]), shown("create", drafts.hysteria2)])
      .toEqual([true, false, false]);
  });

  it("reports the picked region", async () => {
    localStorage.setItem(LANG_KEY, "en");
    const onRegionChange = vi.fn();
    renderWithProviders(
      <LineForm mode="create" initial={drafts["vless-reality"]} region="" onRegionChange={onRegionChange} onSubmit={() => Promise.resolve()} onCancel={() => undefined} />,
    );
    await userEvent.click(screen.getByRole("combobox", { name: "Server region" }));
    await userEvent.click(await screen.findByText("Japan"));
    expect(onRegionChange).toHaveBeenCalledWith("jp");
  });
});

describe("LineForm server errors", () => {
  it("places a port conflict under the port field", async () => {
    const onSubmit = vi.fn(() => Promise.reject(new ApiError(409, "conflict", "port in use", "port")));
    renderForm(drafts.hysteria2, onSubmit);
    await userEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    const port = screen.getByLabelText("Port");
    const item = port.closest(".ant-form-item");
    await waitFor(() => expect(item).toHaveTextContent("Another line is already using this port"));
    expect(screen.getByLabelText("Name").closest(".ant-form-item")).not.toHaveTextContent("Another line");
  });

  it("submits the merged line, keeping fields the form does not render", async () => {
    const onSubmit = renderForm(drafts["vless-reality"]);
    await userEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith(drafts["vless-reality"]));
  });
});

describe("formPathFor", () => {
  it.each([
    ["port", "hysteria2", "port"],
    ["reality.serverName", "vless-reality", ["reality", "serverName"]],
    ["serverName", "vless-reality", ["reality", "serverName"]],
    ["obfsPassword", "vless-reality", null],
    ["xhttp.path", "hysteria2", null],
  ] as const)("%s on %s → %j", (field, protocol, want) => {
    expect(formPathFor(field, protocol)).toEqual(want);
  });
});
