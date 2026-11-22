import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { ReachConfig } from "../api/schemas";
import { LANG_KEY } from "../i18n/I18nProvider";
import { fakeApi } from "../test/fakeApi";
import { renderWithProviders } from "../test/render";
import { ReachSettingsCard, needsPasswordAgain, plainSignIn, reachFieldPath } from "./ReachSettingsCard";

const config = (smtp: Partial<ReachConfig["smtp"]> = {}): ReachConfig => ({
  enabled: false, intervalMinutes: 30, confirmRounds: 2,
  smtp: {
    host: "smtp.example.com", port: 587, security: "starttls", username: "me@example.com",
    passwordSet: true, from: "me@example.com", to: "me@example.com", ...smtp,
  },
});

function renderCard(routes: Parameters<typeof fakeApi>[0]) {
  localStorage.setItem(LANG_KEY, "en");
  const calls = fakeApi({ "GET /api/reach/config": { body: config() }, ...routes });
  renderWithProviders(<ReachSettingsCard />);
  return calls;
}

const savedBody = {
  enabled: false, intervalMinutes: 30, confirmRounds: 2,
  smtp: { host: "smtp.example.com", port: 587, security: "starttls", username: "me@example.com", from: "me@example.com", to: "me@example.com", password: "" },
};

describe("ReachSettingsCard", () => {
  it("discloses that Globalping sees the server address and that nothing else is contacted", async () => {
    renderCard({});
    expect(screen.getByText(/sends your server's address and line ports to Globalping, which will see them/)).toBeInTheDocument();
    expect(screen.getByText(/nothing operated by the Mintyx project/)).toBeInTheDocument();
    await screen.findByLabelText("Mail server (SMTP)");
  });

  it("never shows a stored password and saves an empty one to keep it", async () => {
    const calls = renderCard({ "PUT /api/reach/config": (call) => ({ body: { ...config(), enabled: (call.body as ReachConfig).enabled } }) });
    const password = await screen.findByLabelText("Password or app password");
    expect(password).toHaveValue("");
    expect(password).toHaveAttribute("placeholder", "Saved. Leave empty to keep it.");

    await userEvent.click(screen.getByRole("switch", { name: "Check on a schedule" }));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toEqual({ ...savedBody, enabled: true });
    expect(put?.headers["X-Mintyx"]).toBe("1");
  });

  it("asks for the password again before reusing it for another mail server", async () => {
    const calls = renderCard({});
    const host = await screen.findByLabelText("Mail server (SMTP)");
    await userEvent.clear(host);
    await userEvent.type(host, "smtp.other.example");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));

    const item = screen.getByLabelText("Password or app password").closest(".ant-form-item");
    await waitFor(() => expect(item).toHaveTextContent("Enter the password again after changing the mail server or account"));
    expect(calls.filter((c) => c.method !== "GET")).toEqual([]);
  });

  it("places a server validation error under the field it names", async () => {
    renderCard({
      "PUT /api/reach/config": { status: 400, body: { error: { code: "invalid", message: "recipient must be an email address", field: "smtp.to" } } },
    });
    await screen.findByLabelText("Send alerts to");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    const item = screen.getByLabelText("Send alerts to").closest(".ant-form-item");
    await waitFor(() => expect(item).toHaveTextContent("recipient must be an email address"));
    expect(screen.getByLabelText("From address").closest(".ant-form-item")).not.toHaveTextContent("recipient must be");
  });

  it("sends the form's current SMTP values as a test and shows the server's reply when it fails", async () => {
    const calls = renderCard({
      "POST /api/reach/test-email": { body: { sent: false, error: "notify: sign-in: 535 Authentication failed" } },
    });
    const password = await screen.findByLabelText("Password or app password");
    await userEvent.type(password, "app-pass");
    await userEvent.click(screen.getByRole("button", { name: "Send a test email" }));

    expect(await screen.findByText("notify: sign-in: 535 Authentication failed")).toBeInTheDocument();
    expect(screen.getByText("It wasn't sent. The mail server answered:")).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST");
    expect(post?.body).toEqual({ ...savedBody.smtp, password: "app-pass" });
    // Testing must not save anything.
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
  });

  it("confirms a test email that went out", async () => {
    renderCard({ "POST /api/reach/test-email": { body: { sent: true, error: "" } } });
    await screen.findByLabelText("Mail server (SMTP)");
    await userEvent.click(screen.getByRole("button", { name: "Send a test email" }));
    expect(await screen.findByText(/Test email sent/)).toBeInTheDocument();
    expect(screen.queryByText("It wasn't sent. The mail server answered:")).toBeNull();
  });
});

describe("needsPasswordAgain", () => {
  const saved = config().smtp;
  const next = { host: saved.host, port: 587, security: "starttls" as const, username: saved.username, password: "", from: "", to: "" };
  it.each([
    ["nothing changed", saved, next, false],
    ["host changed, no password typed", saved, { ...next, host: "smtp.other.example" }, true],
    ["username changed, no password typed", saved, { ...next, username: "other@example.com" }, true],
    ["host changed and a password typed", saved, { ...next, host: "smtp.other.example", password: "new" }, false],
    ["username cleared: no sign-in, nothing to reuse", saved, { ...next, username: "" }, false],
    ["no stored password to misuse", { ...saved, passwordSet: false }, { ...next, host: "smtp.other.example" }, false],
  ] as const)("%s", (_, a, b, want) => {
    expect(needsPasswordAgain(a, b)).toBe(want);
  });
});

describe("plainSignIn", () => {
  const next = { host: "smtp.example.com", port: 25, security: "none" as const, username: "me", password: "", from: "", to: "" };
  it.each([
    ["sign-in without encryption to a remote server", next, true],
    ["no sign-in", { ...next, username: "" }, false],
    ["encrypted", { ...next, security: "starttls" as const }, false],
    ["a mail server on this machine", { ...next, host: "127.0.0.1" }, false],
    ["host cleared to turn mail off", { ...next, host: "" }, false],
  ] as const)("%s", (_, b, want) => {
    expect(plainSignIn(b)).toBe(want);
  });
});

describe("reachFieldPath", () => {
  it.each([
    ["intervalMinutes", "intervalMinutes"],
    ["smtp.host", ["smtp", "host"]],
    ["smtp.password", ["smtp", "password"]],
    ["smtp.nope", null],
    ["publicHost", null],
  ] as const)("%s → %j", (field, want) => {
    expect(reachFieldPath(field)).toEqual(want);
  });
});
