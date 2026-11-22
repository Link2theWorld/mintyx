import type { z } from "zod";
import {
  appsSchema,
  attackConfigSchema,
  attackReportSchema,
  attacksResponseSchema,
  attackSummarySchema,
  auditResponseSchema,
  clientsResponseSchema,
  engineLogsSchema,
  engineSchema,
  exitLatencySchema,
  exitParseSchema,
  exitSchema,
  exitsResponseSchema,
  graphLayoutSchema,
  routingSchema,
  errorEnvelopeSchema,
  hostSshSchema,
  lineDraftSchema,
  linesResponseSchema,
  reachConfigSchema,
  reachStatusSchema,
  reachTestEmailSchema,
  sessionSchema,
  settingsSchema,
  shareSchema,
  statusSchema,
  type AppAction,
  type AttackConfig,
  type ClientInput,
  type ExitInput,
  type GraphPositions,
  type Routing,
  type LineDraft,
  type Protocol,
  type Region,
  type ReachConfigInput,
  type ReachSmtpInput,
  type Settings,
} from "./schemas";

export const serverErrorCodes = [
  "unauthorized",
  "forbidden",
  "not_found",
  "conflict",
  "invalid",
  "rate_limited",
  "engine",
  "internal",
] as const;
/** Server codes from API.md plus two the client produces itself. */
export type ErrorCode = (typeof serverErrorCodes)[number] | "network" | "bad_response";

export class ApiError extends Error {
  readonly status: number;
  readonly code: ErrorCode;
  readonly field: string | undefined;

  constructor(status: number, code: ErrorCode, message: string, field?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.field = field;
  }
}

function isServerCode(code: string): code is (typeof serverErrorCodes)[number] {
  return (serverErrorCodes as readonly string[]).includes(code);
}

function codeFromStatus(status: number): ErrorCode {
  switch (status) {
    case 400: return "invalid";
    case 401: return "unauthorized";
    case 403: return "forbidden";
    case 404: return "not_found";
    case 409: return "conflict";
    case 429: return "rate_limited";
    case 502: return "engine";
    default: return "internal";
  }
}

/** Turns a non-2xx response body into an ApiError, tolerating bodies that are not the envelope. */
export function errorFromResponse(status: number, body: unknown): ApiError {
  const parsed = errorEnvelopeSchema.safeParse(body);
  if (!parsed.success) {
    return new ApiError(status, codeFromStatus(status), `HTTP ${status}`);
  }
  const { code, message, field } = parsed.data.error;
  return new ApiError(
    status,
    isServerCode(code) ? code : codeFromStatus(status),
    message,
    field === "" ? undefined : field,
  );
}

let onUnauthorized: () => void = () => {
  if (!window.location.pathname.startsWith("/login")) window.location.assign("/login");
};

/** Lets the router replace the default full-page redirect on 401. */
export function setUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler;
}

// 401 from these means "wrong credentials", not "session expired".
const noRedirectPaths = new Set(["/api/login", "/api/password"]);

type Method = "GET" | "POST" | "PUT" | "DELETE";

async function request<S extends z.ZodType>(method: Method, path: string, schema: S, body?: unknown): Promise<z.infer<S>>;
async function request(method: Method, path: string, schema: null, body?: unknown): Promise<void>;
async function request(method: Method, path: string, schema: z.ZodType | null, body?: unknown): Promise<unknown> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") headers["X-Mintyx"] = "1";
  if (body !== undefined) headers["Content-Type"] = "application/json";

  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (e) {
    throw new ApiError(0, "network", e instanceof Error ? e.message : String(e));
  }

  if (!res.ok) {
    const data: unknown = await res.json().catch(() => null);
    const err = errorFromResponse(res.status, data);
    if (res.status === 401 && !noRedirectPaths.has(path)) onUnauthorized();
    throw err;
  }

  if (schema === null) return undefined;
  const data: unknown = await res.json().catch(() => null);
  const parsed = schema.safeParse(data);
  if (!parsed.success) {
    throw new ApiError(res.status, "bad_response", `Unexpected response from ${method} ${path}: ${parsed.error.message}`);
  }
  return parsed.data;
}

// API.md does not specify response bodies for create/update, so those calls
// ignore the body and callers refetch the list instead.
export const api = {
  session: () => request("GET", "/api/session", sessionSchema),
  setup: (username: string, password: string) => request("POST", "/api/setup", null, { username, password }),
  login: (username: string, password: string) => request("POST", "/api/login", null, { username, password }),
  logout: () => request("POST", "/api/logout", null),
  changePassword: (current: string, next: string) => request("PUT", "/api/password", null, { current, new: next }),

  lines: async () => (await request("GET", "/api/lines", linesResponseSchema)).lines,
  lineDraft: (protocol: Protocol, region?: Region) =>
    request("POST", "/api/lines/draft", lineDraftSchema, region ? { protocol, region } : { protocol }),
  createLine: (line: LineDraft) => request("POST", "/api/lines", null, line),
  updateLine: (id: number, line: LineDraft) => request("PUT", `/api/lines/${id}`, null, line),
  deleteLine: (id: number) => request("DELETE", `/api/lines/${id}`, null),

  clients: async () => (await request("GET", "/api/clients", clientsResponseSchema)).clients,
  createClient: (c: ClientInput) => request("POST", "/api/clients", null, c),
  updateClient: (id: number, c: ClientInput) => request("PUT", `/api/clients/${id}`, null, c),
  deleteClient: (id: number) => request("DELETE", `/api/clients/${id}`, null),
  disableClient: (id: number) => request("POST", `/api/clients/${id}/disable`, null),
  enableClient: (id: number) => request("POST", `/api/clients/${id}/enable`, null),
  resetClientTraffic: (id: number) => request("POST", `/api/clients/${id}/reset-traffic`, null),
  rotateClient: (id: number) => request("POST", `/api/clients/${id}/rotate`, null),
  share: (id: number) => request("GET", `/api/clients/${id}/share`, shareSchema),

  engine: () => request("GET", "/api/engine", engineSchema),
  restartEngine: () => request("POST", "/api/engine/restart", null),
  engineLogs: async () => (await request("GET", "/api/engine/logs", engineLogsSchema)).lines,
  status: () => request("GET", "/api/status", statusSchema),

  audit: async (limit: number, before?: number) => {
    const q = new URLSearchParams({ limit: String(limit) });
    if (before !== undefined) q.set("before", String(before));
    return (await request("GET", `/api/audit?${q.toString()}`, auditResponseSchema)).entries;
  },

  settings: () => request("GET", "/api/settings", settingsSchema),
  saveSettings: (s: Settings) => request("PUT", "/api/settings", null, s),

  exits: async () => (await request("GET", "/api/exits", exitsResponseSchema)).exits,
  parseExit: (link: string) => request("POST", "/api/exits/parse", exitParseSchema, { link }),
  createExit: (e: ExitInput) => request("POST", "/api/exits", exitSchema, e),
  updateExit: (id: number, e: ExitInput) => request("PUT", `/api/exits/${id}`, exitSchema, e),
  copyExit: (id: number) => request("POST", `/api/exits/${id}/copy`, exitSchema),
  deleteExit: (id: number, unlink: boolean) => request("DELETE", `/api/exits/${id}${unlink ? "?unlink=1" : ""}`, null),
  routing: () => request("GET", "/api/routing", routingSchema),
  saveRouting: (r: Routing) => request("PUT", "/api/routing", routingSchema, r),
  exitLatency: () => request("GET", "/api/exits/latency", exitLatencySchema),
  refreshExitLatency: () => request("POST", "/api/exits/latency", exitLatencySchema),
  graphLayout: async () => (await request("GET", "/api/graph/layout", graphLayoutSchema)).positions,
  saveGraphLayout: (positions: GraphPositions) => request("PUT", "/api/graph/layout", null, { positions }),

  hostSsh: () => request("GET", "/api/host/ssh", hostSshSchema),
  apps: () => request("GET", "/api/apps", appsSchema),
  // Only accepts the job; its progress and outcome come from apps().
  appAction: (id: string, action: AppAction) => request("POST", `/api/apps/${id}/${action}`, null),
  reachConfig: () => request("GET", "/api/reach/config", reachConfigSchema),
  saveReachConfig: (c: ReachConfigInput) => request("PUT", "/api/reach/config", reachConfigSchema, c),
  reachStatus: () => request("GET", "/api/reach/status", reachStatusSchema),
  // Runs a whole round before answering, which can take half a minute.
  reachCheck: () => request("POST", "/api/reach/check", reachStatusSchema),
  reachTestEmail: (smtp: ReachSmtpInput) => request("POST", "/api/reach/test-email", reachTestEmailSchema, smtp),

  attackSummary: () => request("GET", "/api/attacks/summary", attackSummarySchema),
  attacks: (f: { kind?: string; country?: string; limit: number; offset: number }) => {
    const q = new URLSearchParams({ limit: String(f.limit), offset: String(f.offset) });
    if (f.kind) q.set("kind", f.kind);
    if (f.country) q.set("country", f.country);
    return request("GET", `/api/attacks?${q.toString()}`, attacksResponseSchema);
  },
  attackReport: (ip: string) => request("GET", `/api/attacks/${encodeURIComponent(ip)}/report`, attackReportSchema),
  clearAttacks: () => request("DELETE", "/api/attacks", null),
  attackConfig: () => request("GET", "/api/attacks/config", attackConfigSchema),
  saveAttackConfig: (c: AttackConfig) => request("PUT", "/api/attacks/config", attackConfigSchema, c),
};
