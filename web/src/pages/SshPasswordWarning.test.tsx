import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { HostSsh } from "../api/schemas";
import { LANG_KEY } from "../i18n/I18nProvider";
import { guideUrl } from "../lib/guides";
import { renderWithProviders } from "../test/render";
import { SshPasswordWarning } from "./SshPasswordWarning";

function renderWith(passwordLogin: HostSsh["passwordLogin"]) {
  localStorage.setItem(LANG_KEY, "en");
  // A second render in one test gets the same spy back, so start its call count afresh.
  const hostSsh = vi.spyOn(api, "hostSsh").mockClear().mockResolvedValue({ passwordLogin });
  return { hostSsh, ...renderWithProviders(<SshPasswordWarning />) };
}

describe("SshPasswordWarning", () => {
  it("warns while sshd accepts passwords and points at the key-login guide", async () => {
    renderWith("on");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("SSH on this server still accepts password logins");
    expect(screen.getByRole("link").getAttribute("href")).toBe(guideUrl("sshKey"));
  });

  it.each(["off", "unknown"] as const)("stays silent when the answer is %s", async (answer) => {
    const { hostSsh } = renderWith(answer);
    await waitFor(() => expect(hostSsh).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  });

  it("stays dismissed after a reload", async () => {
    const first = renderWith("on");
    await screen.findByRole("alert");
    await userEvent.click(screen.getByRole("button", { name: "Don't remind me again" }));
    expect(screen.queryByRole("alert")).toBeNull();
    first.unmount();

    // Once dismissed there is nothing to show, so sshd is not asked either.
    const { hostSsh } = renderWith("on");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(hostSsh).not.toHaveBeenCalled();
  });
});
