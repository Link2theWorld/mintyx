// In-memory stand-in for the backend, for `MINTYX_MOCK=1 npm run dev` while
// the Go API is unavailable. Follows API.md; never bundled into the build.
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Plugin } from "vite";

type Json = Record<string, unknown>;

const now = Date.now();
const iso = (offsetMs: number) => new Date(now + offsetMs).toISOString();
const DAY = 86_400_000;
const GB = 1024 ** 3;

const state = {
  needsSetup: process.env.MINTYX_MOCK_SETUP === "1",
  username: null as string | null,
  nextId: 100,
  lines: [
    {
      id: 1, name: "东京直连", protocol: "vless-reality", port: 443, enabled: true, host: "", createdAt: iso(-40 * DAY),
      reality: { publicKey: "Zk3m9mVq0b2R0E1pT8yXl3hX6qJ4wq1cUu8b1C2d3E4", shortId: "6ba85179e30d4fc2", serverName: "www.stanford.edu", target: "www.stanford.edu:443" },
    },
    {
      id: 2, name: "CDN 备用", protocol: "vless-xhttp", port: 8080, enabled: true, host: "", createdAt: iso(-20 * DAY),
      xhttp: { path: "/a9f3c1", domain: "cdn.example.com", security: "none", certFile: "", keyFile: "" },
    },
    {
      id: 3, name: "UDP 加速", protocol: "hysteria2", port: 8443, enabled: false, host: "", createdAt: iso(-3 * DAY),
      hysteria2: { domain: "hy.example.com", certFile: "/etc/ssl/hy/fullchain.pem", keyFile: "/etc/ssl/hy/privkey.pem", obfsPassword: "" },
    },
  ] as Json[],
  clients: [
    { id: 1, name: "我的手机", disabled: "", quotaBytes: 0, expiresAt: null, usedUp: 3.1 * GB, usedDown: 48.7 * GB, createdAt: iso(-40 * DAY) },
    { id: 2, name: "妈妈的平板", disabled: "", quotaBytes: 50 * GB, expiresAt: iso(2 * DAY), usedUp: 2 * GB, usedDown: 44 * GB, createdAt: iso(-30 * DAY) },
    { id: 3, name: "小王", disabled: "quota", quotaBytes: 20 * GB, expiresAt: iso(60 * DAY), usedUp: 1 * GB, usedDown: 19.2 * GB, createdAt: iso(-25 * DAY) },
    { id: 4, name: "旧笔记本", disabled: "expired", quotaBytes: 0, expiresAt: iso(-5 * DAY), usedUp: 0.2 * GB, usedDown: 3 * GB, createdAt: iso(-90 * DAY) },
    { id: 5, name: "办公室电脑", disabled: "manual", quotaBytes: 100 * GB, expiresAt: iso(200 * DAY), usedUp: 0, usedDown: 12 * GB, createdAt: iso(-10 * DAY) },
  ].map((c) => ({ ...c, usedUp: Math.round(c.usedUp), usedDown: Math.round(c.usedDown) })) as Json[],
  settings: { publicHost: "vps.example.com", subscriptionBaseUrl: "" },
  audit: Array.from({ length: 120 }, (_, i) => {
    const actions = ["login.ok", "client.update", "line.create", "client.rotate", "login.fail", "engine.restart", "backup.export"];
    const action = actions[i % actions.length] ?? "login.ok";
    return { id: 120 - i, at: iso(-i * 3_600_000), action, target: action.startsWith("client") ? "妈妈的平板" : action.startsWith("line") ? "东京直连" : "", detail: "", remoteIp: "203.0.113." + String(i % 250) };
  }),
};

function send(res: ServerResponse, status: number, body?: unknown): void {
  res.statusCode = status;
  if (body !== undefined) res.setHeader("Content-Type", "application/json");
  res.end(body === undefined ? undefined : JSON.stringify(body));
}

const fail = (res: ServerResponse, status: number, code: string, message: string, field?: string): void =>
  send(res, status, { error: { code, message, ...(field ? { field } : {}) } });

async function readBody(req: IncomingMessage): Promise<Json> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const text = Buffer.concat(chunks).toString();
  return text ? (JSON.parse(text) as Json) : {};
}

function draft(protocol: string): Json {
  const used = new Set(state.lines.map((l) => l.port));
  let port = 20000;
  while (used.has(port)) port++;
  const base = { name: "", protocol, port, enabled: true, host: "" };
  if (protocol === "vless-xhttp") return { ...base, xhttp: { path: "/x" + Math.random().toString(16).slice(2, 8), domain: "", security: "tls", certFile: "", keyFile: "" } };
  if (protocol === "hysteria2") return { ...base, hysteria2: { domain: "", certFile: "", keyFile: "", obfsPassword: "" } };
  return { ...base, reality: { publicKey: "", shortId: Math.random().toString(16).slice(2, 10), serverName: "www.stanford.edu", target: "www.stanford.edu:443" } };
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://mock");
  const path = url.pathname;
  const method = req.method ?? "GET";
  if (method !== "GET" && req.headers["x-mintyx"] !== "1") return fail(res, 403, "forbidden", "missing X-Mintyx header");

  if (path === "/api/session") return send(res, 200, { needsSetup: state.needsSetup, username: state.username });
  if (path === "/api/setup" && method === "POST") {
    if (!state.needsSetup) return fail(res, 409, "conflict", "admin exists");
    const b = await readBody(req);
    state.needsSetup = false;
    state.username = String(b.username);
    return send(res, 204);
  }
  if (path === "/api/login" && method === "POST") {
    const b = await readBody(req);
    if (b.password !== "correct-horse") return fail(res, 401, "unauthorized", "bad credentials");
    state.username = String(b.username);
    return send(res, 204);
  }
  if (!state.username) return fail(res, 401, "unauthorized", "login required");
  if (path === "/api/logout") { state.username = null; return send(res, 204); }
  if (path === "/api/password") {
    const b = await readBody(req);
    return b.current === "correct-horse" ? send(res, 204) : fail(res, 401, "unauthorized", "wrong password");
  }

  if (path === "/api/lines" && method === "GET") return send(res, 200, { lines: state.lines });
  if (path === "/api/lines/draft") return send(res, 200, draft(String((await readBody(req)).protocol)));
  if (path === "/api/lines" && method === "POST") {
    const b = await readBody(req);
    if (state.lines.some((l) => l.port === b.port)) return fail(res, 409, "conflict", "port already used", "port");
    state.lines.push({ ...b, id: state.nextId++, createdAt: new Date().toISOString() });
    return send(res, 201, state.lines[state.lines.length - 1]);
  }
  const lineMatch = /^\/api\/lines\/(\d+)$/.exec(path);
  if (lineMatch) {
    const id = Number(lineMatch[1]);
    const i = state.lines.findIndex((l) => l.id === id);
    if (i < 0) return fail(res, 404, "not_found", "no such line");
    if (method === "DELETE") { state.lines.splice(i, 1); return send(res, 204); }
    const b = await readBody(req);
    if (state.lines.some((l) => l.port === b.port && l.id !== id)) return fail(res, 409, "conflict", "port already used", "port");
    state.lines[i] = { ...state.lines[i], ...b };
    return send(res, 200, state.lines[i]);
  }

  if (path === "/api/clients" && method === "GET") return send(res, 200, { clients: state.clients });
  if (path === "/api/clients" && method === "POST") {
    const b = await readBody(req);
    state.clients.push({ ...b, id: state.nextId++, disabled: "", usedUp: 0, usedDown: 0, createdAt: new Date().toISOString() });
    return send(res, 201, state.clients[state.clients.length - 1]);
  }
  const clientMatch = /^\/api\/clients\/(\d+)(?:\/([a-z-]+))?$/.exec(path);
  if (clientMatch) {
    const id = Number(clientMatch[1]);
    const op = clientMatch[2];
    const c = state.clients.find((x) => x.id === id);
    if (!c) return fail(res, 404, "not_found", "no such client");
    if (op === "share") {
      const token = "tok" + String(id) + "x7Kp2";
      const base = state.settings.subscriptionBaseUrl || "https://" + state.settings.publicHost;
      const omitted = state.lines.filter((l) => !l.enabled).map((l) => ({ lineId: l.id, lineName: l.name, reason: "line is disabled" }));
      return send(res, 200, {
        subscriptions: [
          { format: "links", url: `${base}/sub/${token}`, omitted },
          { format: "mihomo", url: `${base}/sub/${token}?format=mihomo`, omitted: [...omitted, { lineId: 2, lineName: "CDN 备用", reason: "XHTTP is not supported by mihomo" }] },
        ],
        links: state.lines.filter((l) => l.enabled).map((l) => ({ lineId: l.id, lineName: l.name, uri: `vless://0b6c1e2a-7f2d-4d3c-9a51-4c2f1e7d8b90@${state.settings.publicHost}:${String(l.port)}?security=reality#${encodeURIComponent(String(l.name))}` })),
      });
    }
    if (method === "DELETE") { state.clients = state.clients.filter((x) => x.id !== id); return send(res, 204); }
    if (op === "disable") { c.disabled = "manual"; return send(res, 204); }
    if (op === "enable") { c.disabled = ""; return send(res, 204); }
    if (op === "reset-traffic") { c.usedUp = 0; c.usedDown = 0; if (c.disabled === "quota") c.disabled = ""; return send(res, 204); }
    if (op === "rotate") return send(res, 204);
    Object.assign(c, await readBody(req));
    return send(res, 200, c);
  }

  if (path === "/api/engine" && method === "GET") {
    return send(res, 200, { running: true, pid: 48213, startedAt: iso(-26 * 3_600_000), lastExit: "exit status 2: config reload failed", restarts: 1, version: "Xray 26.1.0", binaryFound: true });
  }
  if (path === "/api/engine/restart") return send(res, 204);
  if (path === "/api/engine/logs") {
    return send(res, 200, { lines: Array.from({ length: 30 }, (_, i) => `2026/11/21 09:${String(10 + i).padStart(2, "0")}:00 [Info] proxy/vless/inbound: connection from 203.0.113.${String(i)} accepted`) });
  }
  if (path === "/api/status") {
    return send(res, 200, { panelStartedAt: iso(-26 * 3_600_000), lineCount: state.lines.length, clientCount: state.clients.length, activeClientCount: state.clients.filter((c) => c.disabled === "").length, totalUp: Math.round(6.3 * GB), totalDown: Math.round(127.4 * GB) });
  }
  if (path === "/api/audit") {
    const limit = Number(url.searchParams.get("limit") ?? 50);
    const before = url.searchParams.get("before");
    const rows = state.audit.filter((e) => before === null || e.id < Number(before)).slice(0, limit);
    return send(res, 200, { entries: rows });
  }
  if (path === "/api/settings" && method === "GET") return send(res, 200, state.settings);
  if (path === "/api/settings" && method === "PUT") {
    const b = await readBody(req);
    state.settings = { publicHost: String(b.publicHost), subscriptionBaseUrl: String(b.subscriptionBaseUrl) };
    return send(res, 204);
  }
  return fail(res, 404, "not_found", "no route");
}

export function mockApi(): Plugin {
  return {
    name: "mintyx-mock-api",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (!req.url?.startsWith("/api/")) return next();
        handle(req, res).catch((e: unknown) => fail(res, 500, "internal", String(e)));
      });
    },
  };
}
