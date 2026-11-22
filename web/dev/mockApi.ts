// In-memory stand-in for the backend, for `MINTYX_MOCK=1 npm run dev` while
// the Go API is unavailable. Follows API.md; never bundled into the build.
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Plugin } from "vite";

type Json = Record<string, unknown>;

const now = Date.now();
const iso = (offsetMs: number) => new Date(now + offsetMs).toISOString();
const DAY = 86_400_000;
const GB = 1024 ** 3;

/** Fills nextResetAt the way the panel does, close enough for a mock (local midnight). */
function withCycle(c: Json): Json {
  const day = Number(c.quotaResetDay ?? 0);
  if (!day) return { ...c, quotaResetDay: 0, nextResetAt: null };
  const now = new Date();
  const at = (y: number, m: number) => new Date(y, m, Math.min(day, new Date(y, m + 1, 0).getDate()));
  let next = at(now.getFullYear(), now.getMonth());
  if (next <= now) next = at(now.getFullYear(), now.getMonth() + 1);
  return { ...c, nextResetAt: next.toISOString() };
}

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
  ].map((l) => ({ ...l, exitId: l.id === 1 ? 1 : null })) as Json[],
  clients: [
    { id: 1, name: "我的手机", disabled: "", quotaBytes: 0, expiresAt: null, usedUp: 3.1 * GB, usedDown: 48.7 * GB, createdAt: iso(-40 * DAY) },
    { id: 2, name: "妈妈的平板", disabled: "", quotaBytes: 50 * GB, expiresAt: iso(2 * DAY), usedUp: 2 * GB, usedDown: 44 * GB, createdAt: iso(-30 * DAY) },
    { id: 3, name: "小王", disabled: "quota", quotaBytes: 20 * GB, expiresAt: iso(60 * DAY), usedUp: 1 * GB, usedDown: 19.2 * GB, createdAt: iso(-25 * DAY) },
    { id: 4, name: "旧笔记本", disabled: "expired", quotaBytes: 0, expiresAt: iso(-5 * DAY), usedUp: 0.2 * GB, usedDown: 3 * GB, createdAt: iso(-90 * DAY) },
    { id: 5, name: "办公室电脑", disabled: "manual", quotaBytes: 100 * GB, expiresAt: iso(200 * DAY), usedUp: 0, usedDown: 12 * GB, createdAt: iso(-10 * DAY) },
  ].map((c) => withCycle({ ...c, usedUp: Math.round(c.usedUp), usedDown: Math.round(c.usedDown), quotaResetDay: c.id === 2 ? 1 : 0 })),
  exits: [
    { id: 1, name: "大阪中转", region: "jp", nextId: 2, createdAt: iso(-3 * DAY), summary: { protocol: "shadowsocks", host: "203.0.113.20", port: 8388, network: "", security: "none", serverName: "", flow: "", method: "2022-blake3-aes-128-gcm", auth: false, obfs: false, pinned: false, plaintext: false, udp: false } },
    { id: 2, name: "首尔落地", region: "kr", nextId: null, createdAt: iso(-3 * DAY), summary: { protocol: "vless", host: "198.51.100.8", port: 443, network: "raw", security: "reality", serverName: "www.samsung.com", flow: "xtls-rprx-vision", method: "", auth: false, obfs: false, pinned: false, plaintext: false, udp: false } },
    { id: 3, name: "新加坡 HY2", region: "sg", nextId: null, createdAt: iso(-1 * DAY), summary: { protocol: "hysteria2", host: "sg.example.net", port: 443, network: "", security: "tls", serverName: "sg.example.net", flow: "", method: "", auth: false, obfs: true, pinned: false, plaintext: false, udp: true } },
  ] as Json[],
  layout: {} as Json,
  settings: { publicHost: "vps.example.com", subscriptionBaseUrl: "", timeZone: "Asia/Seoul", serverRegion: "jp" },
  reach: {
    config: {
      enabled: true, intervalMinutes: 30, confirmRounds: 2,
      smtp: { host: "smtp.example.com", port: 587, security: "starttls", username: "me@example.com", from: "me@example.com", to: "me@example.com" },
    } as Json,
    password: "app-password",
    lastCheckAt: iso(-12 * 60_000),
    // Line id -> [confirmed verdict, latest round]; lines not listed are fine.
    verdicts: { 2: ["port_blocked", "port_blocked"] } as Record<number, [string, string]>,
  },
  audit: Array.from({ length: 120 }, (_, i) => {
    const actions = ["login.ok", "client.update", "line.create", "client.rotate", "login.fail", "engine.restart", "reach.check", "backup.export"];
    const action = actions[i % actions.length] ?? "login.ok";
    return { id: 120 - i, at: iso(-i * 3_600_000), action, target: action.startsWith("client") ? "妈妈的平板" : action.startsWith("line") ? "东京直连" : "", detail: "", remoteIp: "203.0.113." + String(i % 250) };
  }),
};

// In the mock, installing Caddy hits a taken port and installing iPerf3 fails, to show both paths.
const hostApps = [
  { id: "nginx", category: "web", ports: [80], service: true, installed: true, version: "1.26.3-3", status: "running" },
  { id: "caddy", category: "web", ports: [80], service: true, installed: false, version: "", status: "" },
  { id: "docker", category: "container", ports: [] as number[], service: true, installed: false, version: "", status: "" },
  { id: "vnstat", category: "tools", ports: [] as number[], service: true, installed: true, version: "2.12-1", status: "stopped" },
  { id: "iperf3", category: "tools", ports: [] as number[], service: false, installed: false, version: "", status: "" },
  { id: "htop", category: "tools", ports: [] as number[], service: false, installed: true, version: "3.4.1-5", status: "" },
];
let appJob: { app: string; action: string; state: string; startedAt: string; endedAt: string | null; error: string; log: string[] } | null = null;
const appsReply = () => ({ supported: true, reason: "", apps: hostApps, job: appJob });

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

const coverSites: Record<string, string> = {
  "": "www.stanford.edu", jp: "www.kyoto-u.ac.jp", kr: "www.snu.ac.kr", hk: "www.gov.hk", tw: "www.ncku.edu.tw",
  sg: "www.ntu.edu.sg", us: "www.berkeley.edu", eu: "www.cam.ac.uk", other: "www.nvidia.com",
};

function draft(protocol: string, site: string): Json {
  const used = new Set(state.lines.map((l) => l.port));
  let port = 20000;
  while (used.has(port)) port++;
  const base = { name: "", protocol, port, enabled: true, host: "" };
  if (protocol === "vless-xhttp") return { ...base, xhttp: { path: "/x" + Math.random().toString(16).slice(2, 8), domain: "", security: "tls", certFile: "", keyFile: "" } };
  if (protocol === "hysteria2") return { ...base, hysteria2: { domain: "", certFile: "", keyFile: "", obfsPassword: "" } };
  return { ...base, reality: { publicKey: "", shortId: Math.random().toString(16).slice(2, 10), serverName: site, target: site + ":443" } };
}

function reachConfig(): Json {
  const { config, password } = state.reach;
  return { ...config, smtp: { ...(config.smtp as Json), passwordSet: password !== "" } };
}

function reachStatus(): Json {
  const enabled = state.reach.config.enabled === true;
  const host = state.settings.publicHost;
  const targets = state.lines.filter((l) => l.enabled && (l.host !== "" || host !== "")).map((l) => {
    const [verdict, lastResult] = state.reach.verdicts[Number(l.id)] ?? ["ok", "ok"];
    const blocked = lastResult !== "ok";
    return {
      lineId: l.id, lineName: l.name, protocol: l.protocol, host: l.host || host, port: l.port, ipOnly: l.protocol === "hysteria2",
      verdict, since: iso(-3 * 3_600_000), lastResult,
      chinaReached: blocked ? 0 : 5, chinaAnswered: 5, controlReached: 3, controlAnswered: 3,
    };
  });
  return {
    enabled, configured: host !== "" || state.lines.every((l) => !l.enabled || l.host !== ""), running: false,
    lastCheckAt: state.reach.lastCheckAt,
    nextCheckAt: enabled && targets.length > 0 ? new Date(Date.parse(state.reach.lastCheckAt) + Number(state.reach.config.intervalMinutes) * 60_000).toISOString() : null,
    lastError: "", lastErrorDetail: "", alertError: "", targets,
  };
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
  if (path === "/api/lines/draft") {
    const b = await readBody(req);
    const site = coverSites[typeof b.region === "string" ? b.region : ""];
    return site === undefined ? fail(res, 400, "invalid", "unknown region", "region") : send(res, 200, draft(String(b.protocol), site));
  }
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
    state.clients.push(withCycle({ ...b, id: state.nextId++, disabled: "", usedUp: 0, usedDown: 0, createdAt: new Date().toISOString() }));
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
    Object.assign(c, withCycle({ ...c, ...(await readBody(req)) }));
    return send(res, 200, c);
  }

  if (path === "/api/reach/config" && method === "GET") return send(res, 200, reachConfig());
  if (path === "/api/reach/config" && method === "PUT") {
    const b = await readBody(req);
    const { password, ...smtp } = b.smtp as Json;
    if (typeof b.intervalMinutes !== "number" || b.intervalMinutes < 10 || b.intervalMinutes > 1440) return fail(res, 400, "invalid", "interval must be between 10 and 1440 minutes", "intervalMinutes");
    if (smtp.username === "") state.reach.password = "";
    else if (typeof password === "string" && password !== "") state.reach.password = password;
    state.reach.config = { ...b, smtp };
    return send(res, 200, reachConfig());
  }
  if (path === "/api/reach/status" && method === "GET") return send(res, 200, reachStatus());
  if (path === "/api/reach/check" && method === "POST") {
    if (state.reach.config.enabled !== true) return fail(res, 409, "conflict", "the reachability check is turned off");
    if (Date.now() - Date.parse(state.reach.lastCheckAt) < 60_000) return fail(res, 429, "rate_limited", "checked moments ago; wait a minute before checking again");
    await new Promise((r) => setTimeout(r, 1500));
    state.reach.lastCheckAt = new Date().toISOString();
    return send(res, 200, reachStatus());
  }
  if (path === "/api/reach/test-email" && method === "POST") {
    const b = await readBody(req);
    if (b.host === "") return fail(res, 400, "invalid", "SMTP host is required", "smtp.host");
    return String(b.host).includes("fail")
      ? send(res, 200, { sent: false, error: "notify: sign-in: 535 \"5.7.8 Authentication credentials invalid\"" })
      : send(res, 200, { sent: true, error: "" });
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
  if (path === "/api/exits" && method === "GET") return send(res, 200, { exits: state.exits });
  if (path === "/api/exits/parse" && method === "POST") {
    const b = await readBody(req);
    const link = typeof b.link === "string" ? b.link : "";
    const m = /^(vless|trojan|ss|socks5?|hysteria2|hy2):\/\/(?:[^@]*@)?([^:/?#]+):(\d+)/.exec(link);
    if (!m) return fail(res, 400, "invalid", "unsupported link", "link.scheme");
    const proto = m[1] === "ss" ? "shadowsocks" : m[1] === "hy2" ? "hysteria2" : m[1]?.startsWith("socks") ? "socks" : m[1];
    const name = decodeURIComponent(link.split("#")[1] ?? "");
    return send(res, 200, { name, summary: { protocol: proto, host: m[2], port: Number(m[3]), network: proto === "vless" || proto === "trojan" ? "raw" : "", security: link.includes("security=reality") ? "reality" : proto === "hysteria2" || proto === "trojan" || link.includes("security=tls") ? "tls" : "none", serverName: "", flow: "", method: "", auth: false, obfs: link.includes("obfs="), pinned: false, plaintext: proto === "socks", udp: proto === "hysteria2" } });
  }
  if (path === "/api/exits" && method === "POST") {
    const b = await readBody(req);
    const link = typeof b.link === "string" ? b.link : "";
    const host = /@([^:/?#]+):(\d+)/.exec(link);
    const e = { id: state.nextId++, name: (typeof b.name === "string" && b.name) || decodeURIComponent(link.split("#")[1] ?? "") || "出口", region: typeof b.region === "string" ? b.region : "", nextId: null, createdAt: new Date().toISOString(),
      summary: { protocol: link.startsWith("ss") ? "shadowsocks" : link.startsWith("hy") ? "hysteria2" : link.startsWith("trojan") ? "trojan" : link.startsWith("socks") ? "socks" : "vless", host: host?.[1] ?? "203.0.113.99", port: Number(host?.[2] ?? 443), network: "", security: "tls", serverName: "", flow: "", method: "", auth: false, obfs: false, pinned: false, plaintext: false, udp: link.startsWith("hy") } };
    state.exits.push(e);
    return send(res, 201, e);
  }
  if (path === "/api/exits/latency") {
    return send(res, 200, { refreshing: false, exits: state.exits.map((e) => {
      const s = e.summary as Json;
      if (s.udp) return { id: e.id, rttMs: null, measuredAt: null, unmeasured: "udp" };
      if (state.exits.some((o) => o.nextId === e.id) && !state.lines.some((l) => l.exitId === e.id)) return { id: e.id, rttMs: null, measuredAt: null, unmeasured: "inner" };
      return { id: e.id, rttMs: 40 + Number(e.id) * 37, measuredAt: new Date().toISOString() };
    }) });
  }
  const exitMatch = /^\/api\/exits\/(\d+)(?:\/(copy))?$/.exec(path);
  if (exitMatch) {
    const id = Number(exitMatch[1]);
    const e = state.exits.find((x) => x.id === id);
    if (!e) return fail(res, 404, "not_found", "no such exit");
    if (exitMatch[2] === "copy") {
      const c = { ...e, id: state.nextId++, name: `${String(e.name)} (2)`, nextId: null };
      state.exits.push(c);
      return send(res, 201, c);
    }
    if (method === "DELETE") {
      const used = state.lines.some((l) => l.exitId === id) || state.exits.some((x) => x.nextId === id);
      if (used && url.searchParams.get("unlink") !== "1") return fail(res, 409, "conflict", "still used by line 东京直连", "exit");
      for (const l of state.lines) if (l.exitId === id) l.exitId = null;
      for (const x of state.exits) if (x.nextId === id) x.nextId = null;
      state.exits = state.exits.filter((x) => x.id !== id);
      return send(res, 204);
    }
    const b = await readBody(req);
    Object.assign(e, { name: typeof b.name === "string" && b.name ? b.name : e.name, region: typeof b.region === "string" ? b.region : e.region });
    return send(res, 200, e);
  }
  if (path === "/api/routing" && method === "PUT") {
    const b = await readBody(req) as { lines?: { id: number; exitId: number | null }[]; exits?: { id: number; nextId: number | null }[] };
    for (const r of b.lines ?? []) { const l = state.lines.find((x) => x.id === r.id); if (l) l.exitId = r.exitId; }
    for (const r of b.exits ?? []) { const x = state.exits.find((y) => y.id === r.id); if (x) x.nextId = r.nextId; }
    return send(res, 200, { lines: state.lines.map((l) => ({ id: l.id, exitId: l.exitId })), exits: state.exits.map((x) => ({ id: x.id, nextId: x.nextId })) });
  }
  if (path === "/api/graph/layout" && method === "GET") return send(res, 200, { positions: state.layout });
  if (path === "/api/graph/layout" && method === "PUT") {
    const b = await readBody(req);
    state.layout = (b.positions ?? {}) as Json;
    return send(res, 204);
  }
  if (path === "/api/settings" && method === "GET") return send(res, 200, state.settings);
  if (path === "/api/settings" && method === "PUT") {
    const b = await readBody(req);
    state.settings = { publicHost: String(b.publicHost), subscriptionBaseUrl: String(b.subscriptionBaseUrl), timeZone: typeof b.timeZone === "string" ? b.timeZone : state.settings.timeZone, serverRegion: typeof b.serverRegion === "string" ? b.serverRegion : state.settings.serverRegion };
    return send(res, 204);
  }
  if (path === "/api/host/ssh" && method === "GET") return send(res, 200, { passwordLogin: "on" });
  if (path === "/api/attacks/config" && method === "GET") return send(res, 200, { lookup: attacks.lookup });
  if (path === "/api/attacks/config" && method === "PUT") {
    attacks.lookup = (await readBody(req)).lookup === true;
    return send(res, 200, { lookup: attacks.lookup });
  }
  if (path === "/api/attacks/summary") return send(res, 200, attackSummary());
  if (path === "/api/attacks" && method === "DELETE") {
    attacks.sources = [];
    return send(res, 204);
  }
  if (path === "/api/attacks" && method === "GET") {
    const kind = url.searchParams.get("kind") ?? "";
    const country = url.searchParams.get("country") ?? "";
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 50);
    const rows = attacks.sources
      .filter((a) => (kind === "" || a.kinds.some((k) => k.kind === kind)) && (country === "" || (attacks.lookup && a.country === country)))
      .sort((a, b) => b.lastAt.localeCompare(a.lastAt));
    return send(res, 200, { attackers: rows.slice(offset, offset + limit).map(attackerView), total: rows.length });
  }
  const report = /^\/api\/attacks\/(.+)\/report$/.exec(path);
  if (report && method === "GET") {
    const a = attacks.sources.find((x) => x.ip === decodeURIComponent(report[1] ?? ""));
    if (!a) return fail(res, 404, "not_found", "not found");
    const v = attackerView(a);
    return send(res, 200, {
      ip: a.ip, to: v.abuseEmail, network: v.network, subject: `Abuse report: SSH brute-force attempts from ${a.ip}`,
      body: `Hello,\n\nA server I operate has been receiving unsolicited connection attempts from an IP address in your network. Please investigate and take appropriate action.\n\nSource IP:   ${a.ip}\nDestination: ${state.settings.publicHost}\n\nActivity (all times are UTC):\n${a.kinds.map((k) => `- ${k.kind}: ${String(k.hits)}`).join("\n")}\n\nThank you for your help.\n`,
    });
  }
  if (path === "/api/apps" && method === "GET") return send(res, 200, appsReply());
  const appMatch = /^\/api\/apps\/([a-z0-9]+)\/(install|remove|start|stop|restart)$/.exec(path);
  if (appMatch && method === "POST") {
    const app = hostApps.find((a) => a.id === appMatch[1]);
    const action = appMatch[2] ?? "";
    if (!app) return fail(res, 404, "not_found", "not found");
    if (appJob?.state === "running") return fail(res, 409, "conflict", "another app job is still running", "job");
    if (action === "install" && app.id === "caddy") return fail(res, 409, "conflict", "port 80 is already in use", "port");
    const job = { app: app.id, action, state: "running", startedAt: new Date().toISOString(), endedAt: null as string | null, error: "", log: [] as string[] };
    appJob = job;
    setTimeout(() => {
      job.endedAt = new Date().toISOString();
      if (app.id === "iperf3" && action === "install") {
        job.state = "failed";
        job.error = "apt-get install: exit status 100";
        job.log = ["$ apt-get install --no-remove -y iperf3", "E: Unable to locate package iperf3", "! exit status 100"];
        return;
      }
      job.state = "done";
      if (action === "install") Object.assign(app, { installed: true, version: "1.0-1", status: app.service ? "running" : "" });
      if (action === "remove") Object.assign(app, { installed: false, version: "", status: "" });
      if (action === "start" || action === "restart") app.status = "running";
      if (action === "stop") app.status = "stopped";
    }, 3000);
    return send(res, 202);
  }
  return fail(res, 404, "not_found", "no route");
}

const attackNets = [
  { country: "CN", network: "Example Cloud Computing Co., Ltd.", netRange: "203.0.113.0/24", abuseEmail: "abuse@cloud.example", registry: "APNIC" },
  { country: "US", network: "Example Hosting LLC", netRange: "198.51.100.0/24", abuseEmail: "abuse@hosting.example", registry: "ARIN" },
  { country: "NL", network: "Example B.V.", netRange: "192.0.2.0/24", abuseEmail: "abuse@example.nl", registry: "RIPE NCC" },
  { country: "BR", network: "Exemplo Telecom S.A.", netRange: "2001:db8::/32", abuseEmail: "", registry: "LACNIC" },
  { country: "", network: "UNKNOWN-NET", netRange: "", abuseEmail: "", registry: "rdap.example" },
];
const attackKindNames = ["ssh_login", "ssh_invalid_user", "ssh_scan", "line_probe", "line_bad_auth"];
const attacks = {
  lookup: true,
  sources: Array.from({ length: 87 }, (_, i) => {
    const net = attackNets[(i * 7) % 11 % attackNets.length] ?? { country: "", network: "", netRange: "", abuseEmail: "", registry: "" };
    const kinds = attackKindNames
      .filter((_, k) => (i + k * 3) % 4 === 0 || k === i % 5)
      .map((kind, k) => ({ kind, hits: 1 + ((i * 37 + k * 11) % 400), firstAt: iso(-(i + 2) * 5 * 3_600_000), lastAt: iso(-i * 23 * 60_000) }));
    const ip = i % 9 === 4 ? `2001:db8:${i.toString(16)}::${(i * 3).toString(16)}` : `${["203.0.113", "198.51.100", "192.0.2"][i % 3] ?? ""}.${String(3 + i * 2)}`;
    return { ip, firstAt: iso(-(i + 2) * 5 * 3_600_000), lastAt: iso(-i * 23 * 60_000), hits: kinds.reduce((n, k) => n + k.hits, 0), kinds, ...net, pending: i % 13 === 5 };
  }),
};

function attackerView(a: (typeof attacks.sources)[number]) {
  const known = attacks.lookup && !a.pending;
  return {
    ip: a.ip, firstAt: a.firstAt, lastAt: a.lastAt, hits: a.hits, kinds: a.kinds, lookedUp: known, lookupError: "",
    country: known ? a.country : "", network: known ? a.network : "", netRange: known ? a.netRange : "",
    abuseEmail: known ? a.abuseEmail : "", registry: known ? a.registry : "",
  };
}

function attackSummary(): Json {
  const views = attacks.sources.map(attackerView);
  const kinds = attackKindNames.map((kind) => {
    const with_ = views.filter((a) => a.kinds.some((k) => k.kind === kind));
    return { kind, sources: with_.length, hits: with_.reduce((n, a) => n + (a.kinds.find((k) => k.kind === kind)?.hits ?? 0), 0) };
  }).filter((k) => k.sources > 0);
  const group = (key: (a: (typeof views)[number]) => string) => {
    const m = new Map<string, { sources: number; hits: number; a: (typeof views)[number] }>();
    for (const a of views.filter((v) => v.lookedUp)) {
      const g = m.get(key(a)) ?? { sources: 0, hits: 0, a };
      m.set(key(a), { ...g, sources: g.sources + 1, hits: g.hits + a.hits });
    }
    return [...m.values()];
  };
  return {
    sources: views.length, hits: views.reduce((n, a) => n + a.hits, 0), retentionDays: 30, kinds,
    countries: group((a) => a.country).sort((x, y) => y.sources - x.sources).map((g) => ({ country: g.a.country, sources: g.sources, hits: g.hits })),
    networks: group((a) => a.network).sort((x, y) => y.hits - x.hits).map((g) => ({ network: g.a.network, country: g.a.country, abuseEmail: g.a.abuseEmail, sources: g.sources, hits: g.hits })),
    daily: Array.from({ length: 14 }, (_, i) => ({
      day: iso((i - 13) * DAY).slice(0, 10),
      hits: Object.fromEntries(attackKindNames
        .map((k, j): [string, number] => [k, views.length === 0 || i === 4 ? 0 : Math.round((60 + 50 * Math.sin(i * 0.9 + j)) * (5 - j) * (i === 10 ? 3 : 1))])
        .filter(([, n]) => n > 0)),
    })),
    lookup: { enabled: attacks.lookup, lookedUp: views.filter((v) => v.lookedUp).length, pending: attacks.lookup ? views.filter((v) => !v.lookedUp).length : views.length, error: "", pausedUntil: null },
    sshLog: "ok",
  };
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
