import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, errorFromResponse, setUnauthorizedHandler } from "./client";

type Call = { url: string; init: RequestInit };

function stubFetch(status: number, body: unknown): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal("fetch", (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const text = body === undefined ? null : JSON.stringify(body);
    return Promise.resolve(new Response(status === 204 ? null : text, { status, headers: { "Content-Type": "application/json" } }));
  });
  return calls;
}

function header(call: Call | undefined, name: string): string | undefined {
  const h = call?.init.headers as Record<string, string> | undefined;
  return h?.[name];
}

afterEach(() => setUnauthorizedHandler(() => undefined));

describe("X-Mintyx header", () => {
  it("is sent on POST, PUT and DELETE", async () => {
    const calls = stubFetch(204, undefined);
    await api.disableClient(3);
    await api.saveSettings({ publicHost: "h", subscriptionBaseUrl: "" });
    await api.deleteLine(7);
    expect(calls.map((c) => [c.init.method, c.url, header(c, "X-Mintyx")])).toEqual([
      ["POST", "/api/clients/3/disable", "1"],
      ["PUT", "/api/settings", "1"],
      ["DELETE", "/api/lines/7", "1"],
    ]);
  });

  it("is not sent on GET", async () => {
    const calls = stubFetch(200, { publicHost: "h", subscriptionBaseUrl: "" });
    await api.settings();
    expect(calls[0]?.init.method).toBe("GET");
    expect(header(calls[0], "X-Mintyx")).toBeUndefined();
  });
});

describe("line draft request", () => {
  const draft = {
    protocol: "vless-reality", name: "REALITY 443", port: 443, enabled: true, host: "",
    reality: { publicKey: "", shortId: "ab12", serverName: "", target: "" },
  };

  it("names the region only when one was picked", async () => {
    const calls = stubFetch(200, draft);
    await api.lineDraft("vless-reality");
    await api.lineDraft("vless-reality", "jp");
    // The server reads an absent region as "not sure"; an empty or null one must not be sent in its place.
    expect(calls.map((c) => c.init.body)).toEqual(['{"protocol":"vless-reality"}', '{"protocol":"vless-reality","region":"jp"}']);
  });
});

describe("error envelope", () => {
  it("becomes an ApiError carrying code, field and message", async () => {
    stubFetch(409, { error: { code: "conflict", message: "port 443 is in use", field: "port" } });
    const err = await api.createLine({
      protocol: "hysteria2", name: "x", port: 443, enabled: true, host: "",
      hysteria2: { domain: "d", certFile: "c", keyFile: "k", obfsPassword: "" },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    const e = err as ApiError;
    expect([e.status, e.code, e.field, e.message]).toEqual([409, "conflict", "port", "port 443 is in use"]);
  });

  it("falls back to a status-derived code when the body is not an envelope", () => {
    const e = errorFromResponse(502, "<html>Bad gateway</html>");
    expect([e.code, e.field]).toEqual(["engine", undefined]);
  });

  it("maps an unknown server code by status rather than trusting it", () => {
    const e = errorFromResponse(400, { error: { code: "weird", message: "m", field: "name" } });
    expect([e.code, e.field, e.message]).toEqual(["invalid", "name", "m"]);
  });

  it("rejects a 200 whose body does not match the schema", async () => {
    stubFetch(200, { needsSetup: "yes" });
    const err = await api.session().catch((e: unknown) => e);
    expect((err as ApiError).code).toBe("bad_response");
  });
});

describe("401 handling", () => {
  it("calls the unauthorized handler for an expired session", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    stubFetch(401, { error: { code: "unauthorized", message: "login required" } });
    await expect(api.clients()).rejects.toMatchObject({ code: "unauthorized" });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("does not redirect when the login itself fails", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    stubFetch(401, { error: { code: "unauthorized", message: "bad credentials" } });
    await expect(api.login("a", "b")).rejects.toMatchObject({ code: "unauthorized" });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});
