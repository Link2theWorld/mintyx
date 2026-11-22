import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import dayjs from "dayjs";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type { Client } from "../api/schemas";
import { LANG_KEY } from "../i18n/I18nProvider";
import { renderWithProviders } from "../test/render";
import { ClientForm, toClientInput } from "./ClientForm";

describe("ClientForm preserves existing limits", () => {
  it.each([1_000_000, 1_500_000_000])("does not change a %d-byte quota or exact expiry when renaming", async (quotaBytes) => {
    localStorage.setItem(LANG_KEY, "en");
    const client: Client = {
      id: 1, name: "Phone", disabled: "expired", quotaBytes,
      expiresAt: "2026-01-01T12:34:56.123456789Z", usedUp: 0, usedDown: 0,
      createdAt: "2025-01-01T00:00:00Z",
    };
    const onSubmit = vi.fn(() => Promise.resolve());
    renderWithProviders(<ClientForm client={client} onSubmit={onSubmit} onCancel={() => undefined} />);
    await userEvent.clear(screen.getByLabelText("Name"));
    await userEvent.type(screen.getByLabelText("Name"), "Tablet");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith({ name: "Tablet", quotaBytes, expiresAt: client.expiresAt }));
  });

  it("converts new limits and handles unlimited clients", () => {
    expect(toClientInput({ name: " Phone ", quotaGb: 2, expires: dayjs("2027-06-01") })).toEqual({
      name: "Phone", quotaBytes: 2 * 1024 ** 3, expiresAt: dayjs("2027-06-01").endOf("day").toISOString(),
    });
    expect(toClientInput({ name: "Phone", quotaGb: null, expires: null })).toEqual({
      name: "Phone", quotaBytes: 0, expiresAt: null,
    });
  });

  it("allows removing existing limits", async () => {
    localStorage.setItem(LANG_KEY, "en");
    const onSubmit = vi.fn(() => Promise.resolve());
    const client: Client = {
      id: 1, name: "Phone", disabled: "", quotaBytes: 1024 ** 3,
      expiresAt: "2027-01-01T12:34:56Z", usedUp: 0, usedDown: 0,
      createdAt: "2025-01-01T00:00:00Z",
    };
    renderWithProviders(<ClientForm client={client} onSubmit={onSubmit} onCancel={() => undefined} />);
    await userEvent.clear(screen.getByRole("spinbutton"));
    await userEvent.type(screen.getByRole("spinbutton"), "0");
    await userEvent.click(screen.getByRole("button", { name: "Never" }));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith({ name: "Phone", quotaBytes: 0, expiresAt: null }));
  });

  it("keeps server validation errors on their form field", async () => {
    localStorage.setItem(LANG_KEY, "en");
    const onSubmit = vi.fn(() => Promise.reject(new ApiError(400, "invalid", "invalid quota", "quotaBytes")));
    renderWithProviders(<ClientForm client={null} onSubmit={onSubmit} onCancel={() => undefined} />);
    await userEvent.type(screen.getByLabelText("Name"), "Phone");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(screen.getByRole("spinbutton")).toHaveAttribute("aria-invalid", "true"));
  });
});
