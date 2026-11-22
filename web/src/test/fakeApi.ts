import { vi } from "vitest";

export type FakeCall = { method: string; path: string; body: unknown; headers: Record<string, string> };
type Reply = { status?: number; body?: unknown } | ((call: FakeCall) => { status?: number; body?: unknown });

/** Replaces fetch with canned replies keyed "METHOD /path" and returns the calls it saw. */
export function fakeApi(routes: Record<string, Reply>): FakeCall[] {
  const calls: FakeCall[] = [];
  vi.stubGlobal("fetch", (url: string, init: RequestInit = {}) => {
    const call: FakeCall = {
      method: init.method ?? "GET",
      path: url,
      body: typeof init.body === "string" ? (JSON.parse(init.body) as unknown) : undefined,
      headers: (init.headers ?? {}) as Record<string, string>,
    };
    calls.push(call);
    const route = routes[`${call.method} ${call.path}`];
    if (!route) return Promise.resolve(new Response(JSON.stringify({ error: { code: "not_found", message: "no route" } }), { status: 404 }));
    const { status = 200, body } = typeof route === "function" ? route(call) : route;
    return Promise.resolve(new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
  });
  return calls;
}
