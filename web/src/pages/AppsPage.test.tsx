import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError, api } from "../api/client";
import type { AppJob, Apps, HostApp } from "../api/schemas";
import { LANG_KEY } from "../i18n/I18nProvider";
import { renderWithProviders } from "../test/render";
import { AppsPage } from "./AppsPage";

const app = (id: string, over: Partial<HostApp> = {}): HostApp => ({
  id, category: "web", ports: [], service: true, installed: false, version: "", status: "", ...over,
});

const reply = (apps: HostApp[], job: AppJob | null = null, over: Partial<Apps> = {}): Apps => ({
  supported: true, reason: "", apps, job, ...over,
});

const jobOf = (over: Partial<AppJob>): AppJob => ({
  app: "nginx", action: "install", state: "running", startedAt: "2026-06-01T12:00:00Z", endedAt: null, error: "", log: [], ...over,
});

function renderPage(first: Apps) {
  localStorage.setItem(LANG_KEY, "en");
  const apps = vi.spyOn(api, "apps").mockResolvedValue(first);
  const appAction = vi.spyOn(api, "appAction").mockResolvedValue(undefined);
  renderWithProviders(<AppsPage />);
  return { apps, appAction };
}

const card = (id: string) => within(screen.getByTestId(`app-${id}`));

describe("AppsPage", () => {
  it("offers the actions that fit each app's state", async () => {
    renderPage(reply([
      app("nginx", { installed: true, version: "1.26.3-3", status: "running", ports: [80] }),
      app("caddy"),
      app("vnstat", { category: "tools", installed: true, status: "stopped" }),
      app("htop", { category: "tools", service: false, installed: true }),
    ]));
    await screen.findByTestId("app-nginx");
    const names = (id: string) => card(id).getAllByRole("button").map((b) => b.getAttribute("aria-label"));
    expect(names("nginx")).toEqual(["Restart Nginx", "Stop Nginx", "Uninstall Nginx"]);
    expect(names("caddy")).toEqual(["Install Caddy"]);
    expect(names("vnstat")).toEqual(["Start vnStat", "Uninstall vnStat"]);
    expect(names("htop")).toEqual(["Uninstall htop"]);
    expect(card("nginx").getByText("Running")).toBeInTheDocument();
    expect(card("nginx").getByText("Version 1.26.3-3")).toBeInTheDocument();
    expect(card("caddy").getByText("Not installed")).toBeInTheDocument();
  });

  it("installs, locks every other action while the job runs, then reports it done", async () => {
    const { apps, appAction } = renderPage(reply([app("nginx"), app("caddy")]));
    // The server has the job running by the time it accepts the request.
    appAction.mockImplementation(() => {
      apps.mockResolvedValue(reply([app("nginx"), app("caddy")], jobOf({})));
      return Promise.resolve();
    });
    await userEvent.click(await screen.findByRole("button", { name: "Install Nginx" }));
    expect(appAction).toHaveBeenCalledWith("nginx", "install");
    await waitFor(() => expect(card("nginx").getByRole("status")).toHaveTextContent("Installing…"));
    expect(screen.getByRole("button", { name: "Install Caddy" })).toBeDisabled();

    apps.mockResolvedValue(reply([app("nginx", { installed: true, status: "running" }), app("caddy")], jobOf({ state: "done", endedAt: "2026-06-01T12:01:00Z" })));
    expect(await screen.findByText("Nginx is installed", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(card("nginx").getByText("Running")).toBeInTheDocument();
  });

  it("explains a taken port instead of a generic conflict", async () => {
    const { appAction } = renderPage(reply([app("nginx", { ports: [80] })]));
    appAction.mockRejectedValue(new ApiError(409, "conflict", "hostapps: port 80 is already in use", "port"));
    await userEvent.click(await screen.findByRole("button", { name: "Install Nginx" }));
    expect(await screen.findByText(/Port 80 is already in use/)).toBeInTheDocument();
  });

  it("shows why the last job failed, with the command output", async () => {
    renderPage(reply([app("nginx")], jobOf({
      state: "failed", endedAt: "2026-06-01T12:01:00Z", error: "apt-get install: exit status 100", log: ["E: Unable to locate package nginx"],
    })));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Installing Nginx failed");
    expect(alert).toHaveTextContent("apt-get install: exit status 100");
    expect(alert).toHaveTextContent("E: Unable to locate package nginx");
    // A failed job does not hold the lock.
    expect(screen.getByRole("button", { name: "Install Nginx" })).toBeEnabled();
  });

  it("says why apps cannot be managed and disables the actions", async () => {
    renderPage(reply([app("nginx")], null, { supported: false, reason: "root" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("not running as root");
    expect(screen.getByRole("button", { name: "Install Nginx" })).toBeDisabled();
  });
});
