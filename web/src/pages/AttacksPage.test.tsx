import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import type { Attacker, AttackSummary } from "../api/schemas";
import { LANG_KEY } from "../i18n/I18nProvider";
import { fakeApi } from "../test/fakeApi";
import { renderWithProviders } from "../test/render";
import { AttacksPage } from "./AttacksPage";

const summary = (over: Partial<AttackSummary> = {}): AttackSummary => ({
  sources: 2, hits: 15, retentionDays: 30,
  kinds: [{ kind: "ssh_login", hits: 12, sources: 1 }, { kind: "line_probe", hits: 3, sources: 1 }],
  countries: [{ country: "NL", sources: 1, hits: 12 }],
  networks: [{ network: "Example B.V.", country: "NL", abuseEmail: "abuse@example.nl", sources: 1, hits: 12 }],
  daily: [{ day: "2026-11-20", hits: {} }, { day: "2026-11-21", hits: { ssh_login: 12, line_probe: 3 } }],
  lookup: { enabled: true, lookedUp: 1, pending: 1, error: "", pausedUntil: null },
  sshLog: "ok", ...over,
});

const attacker = (over: Partial<Attacker>): Attacker => ({
  ip: "203.0.113.5", firstAt: "2026-11-20T08:00:00Z", lastAt: "2026-11-21T09:00:00Z", hits: 12,
  kinds: [{ kind: "ssh_login", hits: 12, firstAt: "2026-11-20T08:00:00Z", lastAt: "2026-11-21T09:00:00Z" }],
  lookedUp: true, lookupError: "", country: "NL", network: "Example B.V.", netRange: "203.0.113.0/24",
  abuseEmail: "abuse@example.nl", registry: "RIPE NCC", ...over,
});

const probe = attacker({
  ip: "198.51.100.9", hits: 3, kinds: [{ kind: "line_probe", hits: 3, firstAt: "2026-11-21T08:00:00Z", lastAt: "2026-11-21T08:30:00Z" }],
  lookedUp: false, country: "", network: "", netRange: "", abuseEmail: "", registry: "",
});

const list = (...attackers: Attacker[]) => ({ body: { attackers, total: attackers.length } });

function renderPage(routes: Parameters<typeof fakeApi>[0]) {
  localStorage.setItem(LANG_KEY, "en");
  const calls = fakeApi(routes);
  renderWithProviders(<MemoryRouter><AttacksPage /></MemoryRouter>);
  return calls;
}

const rowOf = (ip: string) => {
  const tr = screen.getByText(ip).closest("tr");
  if (!tr) throw new Error(`no row for ${ip}`);
  return within(tr);
};

describe("AttacksPage", () => {
  it("shows the totals, every kind with its name, and each source with where it is from", async () => {
    renderPage({
      "GET /api/attacks/summary": { body: summary() },
      "GET /api/attacks?limit=50&offset=0": list(attacker({}), probe),
    });
    expect(await screen.findByText("203.0.113.5")).toBeInTheDocument();
    // All five kinds are in the legend, including the ones with no attacks.
    for (const name of ["SSH password guessing", "SSH user name guessing", "SSH scan", "Line probe", "Invalid line credentials"]) {
      expect(screen.getByRole("button", { name: new RegExp(`^${name}`) })).toBeInTheDocument();
    }
    expect(within(screen.getByRole("button", { name: /^SSH password guessing/ })).getByText("12")).toBeInTheDocument();
    expect(rowOf("203.0.113.5").getByText("Netherlands · Example B.V.")).toBeInTheDocument();
    expect(rowOf("198.51.100.9").getByText("Waiting for lookup")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Netherlands/ })).toBeInTheDocument();
    expect(screen.getByText(/abuse@example\.nl/)).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "2026-11-21: 15 attacks" })).toBeInTheDocument();
  });

  it("filters the sources by the kind picked in the legend", async () => {
    const calls = renderPage({
      "GET /api/attacks/summary": { body: summary() },
      "GET /api/attacks?limit=50&offset=0": list(attacker({}), probe),
      "GET /api/attacks?limit=50&offset=0&kind=line_probe": list(probe),
    });
    await screen.findByText("203.0.113.5");
    const legend = screen.getByRole("button", { name: /^Line probe/ });
    await userEvent.click(legend);
    await waitFor(() => expect(screen.queryByText("203.0.113.5")).toBeNull());
    expect(screen.getByText("198.51.100.9")).toBeInTheDocument();
    expect(legend).toHaveAttribute("aria-pressed", "true");
    expect(calls.some((c) => c.path.endsWith("kind=line_probe"))).toBe(true);
  });

  it("drafts a report addressed to the network's abuse contact, for the owner to send", async () => {
    renderPage({
      "GET /api/attacks/summary": { body: summary() },
      "GET /api/attacks?limit=50&offset=0": list(attacker({})),
      "GET /api/attacks/203.0.113.5/report": {
        body: { ip: "203.0.113.5", to: "abuse@example.nl", network: "Example B.V.", subject: "Abuse report: SSH from 203.0.113.5", body: "Hello,\nSource IP: 203.0.113.5\n" },
      },
    });
    await screen.findByText("203.0.113.5");
    await userEvent.click(rowOf("203.0.113.5").getByRole("button", { name: /Report/ }));
    const dialog = within(await screen.findByRole("dialog"));
    expect(await dialog.findByDisplayValue("abuse@example.nl")).toBeInTheDocument();
    expect(dialog.getByDisplayValue("Abuse report: SSH from 203.0.113.5")).toBeInTheDocument();
    expect(dialog.getByRole("textbox", { name: "Message" })).toHaveValue("Hello,\nSource IP: 203.0.113.5\n");
    expect(dialog.getByRole("link", { name: /Open in mail app/ })).toHaveAttribute(
      "href", "mailto:abuse%40example.nl?subject=Abuse%20report%3A%20SSH%20from%20203.0.113.5&body=Hello%2C%0ASource%20IP%3A%20203.0.113.5%0A",
    );
  });

  it("without lookups, says why there are no origins and still drafts the report without a recipient", async () => {
    renderPage({
      "GET /api/attacks/summary": { body: summary({ countries: [], networks: [], lookup: { enabled: false, lookedUp: 0, pending: 2, error: "", pausedUntil: null } }) },
      "GET /api/attacks?limit=50&offset=0": list(probe),
      "GET /api/attacks/198.51.100.9/report": { body: { ip: "198.51.100.9", to: "", network: "", subject: "Abuse report", body: "Hello" } },
    });
    expect(await screen.findByText(/Origin lookup is off, so there are only IP addresses here/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Turn it on in Settings" })).toHaveAttribute("href", "/settings");
    await userEvent.click((await screen.findAllByRole("button", { name: /Report/ }))[0] as HTMLElement);
    const dialog = within(await screen.findByRole("dialog"));
    expect(await dialog.findByText(/so there is no one to address this to/)).toBeInTheDocument();
    expect(dialog.queryByRole("link", { name: /Open in mail app/ })).toBeNull();
    expect(dialog.getByRole("button", { name: /Copy everything/ })).toBeEnabled();
  });

  it("explains an empty page, and a server whose SSH log cannot be read", async () => {
    renderPage({
      "GET /api/attacks/summary": { body: summary({ sources: 0, hits: 0, kinds: [], countries: [], networks: [], sshLog: "unavailable" }) },
    });
    expect(await screen.findByText(/No attacks recorded yet/)).toBeInTheDocument();
    expect(screen.getByText(/has no systemd journal/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Clear records/ })).toBeNull();
  });
});
