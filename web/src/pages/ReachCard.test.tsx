import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import type { ReachStatus, ReachTarget } from "../api/schemas";
import { LANG_KEY } from "../i18n/I18nProvider";
import { fakeApi } from "../test/fakeApi";
import { renderWithProviders } from "../test/render";
import { ReachCard } from "./ReachCard";

const target = (over: Partial<ReachTarget>): ReachTarget => ({
  lineId: 1, lineName: "Tokyo", protocol: "vless-reality", host: "vps.example.com", port: 443, ipOnly: false,
  verdict: "ok", since: "2026-06-01T12:00:00Z", lastResult: "ok",
  chinaReached: 5, chinaAnswered: 5, controlReached: 3, controlAnswered: 3, ...over,
});

const status = (over: Partial<ReachStatus> = {}): ReachStatus => ({
  enabled: true, configured: true, running: false, lastCheckAt: "2026-06-01T12:00:00Z", nextCheckAt: "2026-06-01T12:30:00Z",
  lastError: "", lastErrorDetail: "", alertError: "", targets: [target({})], ...over,
});

function renderCard(routes: Parameters<typeof fakeApi>[0]) {
  localStorage.setItem(LANG_KEY, "en");
  const calls = fakeApi(routes);
  renderWithProviders(<MemoryRouter><ReachCard /></MemoryRouter>);
  return calls;
}

const row = (name: string) => {
  const li = screen.getByText(name).closest("li");
  if (!li) throw new Error(`no row for ${name}`);
  return within(li);
};

describe("ReachCard", () => {
  it("while off, explains the feature and points to Settings instead of offering a check", async () => {
    renderCard({ "GET /api/reach/status": { body: status({ enabled: false, lastCheckAt: null, nextCheckAt: null }) } });
    expect(await screen.findByText(/Not turned on yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Turn it on in Settings" })).toHaveAttribute("href", "/settings");
    expect(screen.queryByRole("button", { name: /Check now/ })).toBeNull();
    expect(screen.queryByText("Tokyo")).toBeNull();
  });

  it("says which setting is missing when there is no address to test", async () => {
    renderCard({ "GET /api/reach/status": { body: status({ configured: false, targets: [] }) } });
    expect(await screen.findByText(/Fill in the public address under Settings/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Check now/ })).toBeNull();
  });

  it("shows each line's verdict with what to do about it", async () => {
    renderCard({
      "GET /api/reach/status": {
        body: status({
          targets: [
            target({}),
            target({ lineId: 2, lineName: "Osaka", port: 8443, verdict: "port_blocked", lastResult: "port_blocked", chinaReached: 0 }),
            target({ lineId: 3, lineName: "Seoul", host: "203.0.113.9", verdict: "ip_blocked", lastResult: "ip_blocked", chinaReached: 0 }),
            target({ lineId: 4, lineName: "Hy", port: 9443, ipOnly: true }),
            target({ lineId: 5, lineName: "Flaky", port: 2053, lastResult: "down", chinaReached: 0, controlReached: 0 }),
          ],
        }),
      },
    });
    await screen.findByText("Tokyo");

    expect(row("Tokyo").getByText("Reachable")).toBeInTheDocument();
    expect(row("Tokyo").getByText("vps.example.com:443")).toBeInTheDocument();
    expect(row("Tokyo").getByText(/5 of 5 mainland probes got through, 3 of 3 elsewhere/)).toBeInTheDocument();

    expect(row("Osaka").getByText("Port looks blocked")).toBeInTheDocument();
    expect(row("Osaka").getByText(/Try moving the line to another port first/)).toBeInTheDocument();
    expect(row("Seoul").getByText("IP looks blocked")).toBeInTheDocument();
    expect(row("Seoul").getByText(/ask your provider for a new IP address/)).toBeInTheDocument();

    // A UDP line must not look as if its port was tested.
    expect(row("Hy").getByText("IP only")).toBeInTheDocument();
    expect(row("Hy").getByText("vps.example.com")).toBeInTheDocument();
    expect(row("Hy").getByText(/can't test UDP ports/)).toBeInTheDocument();

    // One bad round is shown as waiting for confirmation, not as a verdict.
    expect(row("Flaky").getByText("Reachable")).toBeInTheDocument();
    expect(row("Flaky").getByText(/latest round said “Line is down”/)).toBeInTheDocument();
  });

  it("tells a rate limit apart from a block, and surfaces an unsent alert", async () => {
    renderCard({
      "GET /api/reach/status": {
        body: status({
          lastError: "rate_limited", alertError: "535 bad credentials",
          targets: [target({ verdict: "unknown", lastResult: "unknown", since: null, chinaAnswered: 0, chinaReached: 0, controlAnswered: 0, controlReached: 0 })],
        }),
      },
    });
    expect(await screen.findByText(/free allowance ran out.*doesn't mean a line is blocked/)).toBeInTheDocument();
    expect(screen.getByText(/alert email couldn't be sent.*535 bad credentials/)).toBeInTheDocument();
    expect(row("Tokyo").getByText("Can't tell yet")).toBeInTheDocument();
    expect(row("Tokyo").queryByText(/mainland probes/)).toBeNull();
  });

  it("checks on demand and shows the fresh result", async () => {
    const blocked = status({ targets: [target({ verdict: "ip_blocked", lastResult: "ip_blocked", chinaReached: 0 })] });
    const calls = renderCard({
      "GET /api/reach/status": { body: status() },
      "POST /api/reach/check": { body: blocked },
    });
    await userEvent.click(await screen.findByRole("button", { name: /Check now/ }));
    expect(await screen.findByText("IP looks blocked")).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST");
    expect([post?.path, post?.headers["X-Mintyx"]]).toEqual(["/api/reach/check", "1"]);
  });

  it("explains a refusal to check again so soon", async () => {
    renderCard({
      "GET /api/reach/status": { body: status() },
      "POST /api/reach/check": { status: 429, body: { error: { code: "rate_limited", message: "checked moments ago" } } },
    });
    await userEvent.click(await screen.findByRole("button", { name: /Check now/ }));
    await waitFor(() => expect(screen.getByText("Checked a moment ago. Wait a minute and try again.")).toBeInTheDocument());
    expect(row("Tokyo").getByText("Reachable")).toBeInTheDocument();
  });
});
