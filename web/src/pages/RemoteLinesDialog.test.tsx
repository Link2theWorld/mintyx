import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
import type { Client, RemoteLine } from "../api/schemas";
import { LANG_KEY } from "../i18n/I18nProvider";
import { fakeApi } from "../test/fakeApi";
import { renderWithProviders } from "../test/render";
import { RemoteLinesDialog, remoteLineSummary } from "./RemoteLinesDialog";

const client: Client = {
  id: 4, name: "phone", disabled: "", quotaBytes: 0, expiresAt: null, usedUp: 0, usedDown: 0,
  createdAt: "2026-11-01T00:00:00Z", quotaResetDay: 0, nextResetAt: null,
};

const summary = {
  protocol: "vless", host: "198.51.100.8", port: 443, network: "raw", security: "reality", serverName: "www.example.com",
  flow: "xtls-rprx-vision", method: "", auth: false, obfs: false, pinned: false, plaintext: false, udp: false,
} as const;
const seoul: RemoteLine = { id: 7, name: "Seoul", createdAt: "2026-11-02T00:00:00Z", summary };

describe("remoteLineSummary", () => {
  it("names the kind of line and where it is without any credential", () => {
    expect(remoteLineSummary(seoul)).toBe("VLESS · REALITY · 198.51.100.8:443");
    expect(remoteLineSummary({ ...seoul, summary: { ...summary, network: "xhttp", security: "tls", host: "2001:db8::1", port: 2083 } }))
      .toBe("VLESS · XHTTP · [2001:db8::1]:2083");
    expect(remoteLineSummary({ ...seoul, summary: { ...summary, protocol: "hysteria2", network: "", security: "tls", udp: true } }))
      .toBe("Hysteria2 · 198.51.100.8:443");
  });
});

describe("RemoteLinesDialog", () => {
  beforeEach(() => localStorage.setItem(LANG_KEY, "en"));

  it("lists the merged lines and adds one from a pasted link", async () => {
    let lines: RemoteLine[] = [seoul];
    const calls = fakeApi({
      "GET /api/clients/4/remote-lines": () => ({ body: { remoteLines: lines } }),
      "POST /api/clients/4/remote-lines": () => {
        const hk: RemoteLine = { id: 8, name: "HK", createdAt: "2026-11-03T00:00:00Z", summary: { ...summary, protocol: "hysteria2", network: "", security: "tls", udp: true } };
        lines = [...lines, hk];
        return { status: 201, body: hk };
      },
    });
    renderWithProviders(<RemoteLinesDialog client={client} onClose={() => undefined} />);

    const list = await screen.findByRole("list", { name: "Merged lines" });
    expect(within(list).getByText("Seoul")).toBeInTheDocument();

    const link = "hysteria2://auth@hk.example.net:8443/?sni=hk.example.net#HK";
    await userEvent.type(screen.getByLabelText("Share link"), link);
    await userEvent.click(screen.getByRole("button", { name: /Add/ }));

    await waitFor(() => expect(within(screen.getByRole("list", { name: "Merged lines" })).getByText("HK")).toBeInTheDocument());
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "", link });
  });

  it("shows a link the server refuses under the link field", async () => {
    fakeApi({
      "GET /api/clients/4/remote-lines": { body: { remoteLines: [] } },
      "POST /api/clients/4/remote-lines": {
        status: 400,
        body: { error: { code: "invalid", message: "trojan lines cannot join a subscription", field: "link.scheme" } },
      },
    });
    renderWithProviders(<RemoteLinesDialog client={client} onClose={() => undefined} />);

    expect(await screen.findByText("No lines from other servers yet.")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Share link"), "trojan://pw@t.example.com:443");
    await userEvent.click(screen.getByRole("button", { name: /Add/ }));
    expect(await screen.findByText("trojan lines cannot join a subscription")).toBeInTheDocument();
  });
});
