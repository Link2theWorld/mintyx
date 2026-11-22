import { z } from "zod";

export const protocols = ["vless-reality", "vless-xhttp", "hysteria2"] as const;
export const protocolSchema = z.enum(protocols);
export type Protocol = z.infer<typeof protocolSchema>;

/** Where the server is, for picking a REALITY cover site near it. */
export const regions = ["jp", "kr", "hk", "tw", "sg", "us", "eu", "other"] as const;
export const regionSchema = z.enum(regions);
export type Region = z.infer<typeof regionSchema>;

export const sessionSchema = z.object({
  needsSetup: z.boolean(),
  username: z.string().nullable(),
});
export type Session = z.infer<typeof sessionSchema>;

export const realitySchema = z.object({
  publicKey: z.string(),
  shortId: z.string(),
  serverName: z.string(),
  target: z.string(),
});

export const xhttpSchema = z.object({
  path: z.string(),
  domain: z.string(),
  security: z.enum(["tls", "none"]),
  certFile: z.string(),
  keyFile: z.string(),
});

export const hysteria2Schema = z.object({
  domain: z.string(),
  certFile: z.string(),
  keyFile: z.string(),
  obfsPassword: z.string(),
});

const lineCommon = {
  name: z.string(),
  port: z.number().int(),
  enabled: z.boolean(),
  host: z.string(),
};

const lineVariants = [
  z.object({ ...lineCommon, protocol: z.literal("vless-reality"), reality: realitySchema }),
  z.object({ ...lineCommon, protocol: z.literal("vless-xhttp"), xhttp: xhttpSchema }),
  z.object({ ...lineCommon, protocol: z.literal("hysteria2"), hysteria2: hysteria2Schema }),
] as const;

/** A line as sent to the server on create/update, and as returned by the draft endpoint. */
export const lineDraftSchema = z.discriminatedUnion("protocol", [...lineVariants]);
export type LineDraft = z.infer<typeof lineDraftSchema>;

/** exitId is read-only on lines: the first exit the line leaves through, null for straight out. */
const saved = { id: z.number().int(), createdAt: z.string(), exitId: z.number().int().nullable().default(null) };
export const lineSchema = z.discriminatedUnion("protocol", [
  lineVariants[0].extend(saved),
  lineVariants[1].extend(saved),
  lineVariants[2].extend(saved),
]);
export type Line = z.infer<typeof lineSchema>;

export const linesResponseSchema = z.object({ lines: z.array(lineSchema) });

export const disabledReasons = ["", "manual", "quota", "expired"] as const;
export const clientSchema = z.object({
  id: z.number().int(),
  name: z.string(),
  disabled: z.enum(disabledReasons),
  quotaBytes: z.number().int().nonnegative(),
  expiresAt: z.string().nullable(),
  usedUp: z.number().int().nonnegative(),
  usedDown: z.number().int().nonnegative(),
  createdAt: z.string(),
  /** 0: the quota never resets; 1–31: usage goes back to zero on that day each month. */
  quotaResetDay: z.number().int().min(0).max(31),
  nextResetAt: z.string().nullable(),
});
export type Client = z.infer<typeof clientSchema>;
export const clientsResponseSchema = z.object({ clients: z.array(clientSchema) });

export type ClientInput = { name: string; quotaBytes: number; expiresAt: string | null; quotaResetDay: number };

export const omittedLineSchema = z.object({
  lineId: z.number().int(),
  lineName: z.string(),
  reason: z.string(),
});
export const shareSchema = z.object({
  subscriptions: z.array(
    z.object({ format: z.string(), url: z.string(), omitted: z.array(omittedLineSchema) }),
  ),
  links: z.array(z.object({ lineId: z.number().int(), lineName: z.string(), uri: z.string() })),
});
export type Share = z.infer<typeof shareSchema>;

export const engineSchema = z.object({
  running: z.boolean(),
  pid: z.number().int(),
  startedAt: z.string().nullable(),
  lastExit: z.string(),
  restarts: z.number().int(),
  version: z.string(),
  binaryFound: z.boolean(),
});
export type Engine = z.infer<typeof engineSchema>;

export const engineLogsSchema = z.object({ lines: z.array(z.string()) });

export const statusSchema = z.object({
  panelStartedAt: z.string(),
  lineCount: z.number().int(),
  clientCount: z.number().int(),
  activeClientCount: z.number().int(),
  totalUp: z.number().int(),
  totalDown: z.number().int(),
});
export type Status = z.infer<typeof statusSchema>;

export const auditEntrySchema = z.object({
  id: z.number().int(),
  at: z.string(),
  action: z.string(),
  target: z.string(),
  detail: z.string(),
  remoteIp: z.string(),
});
export type AuditEntry = z.infer<typeof auditEntrySchema>;
export const auditResponseSchema = z.object({ entries: z.array(auditEntrySchema) });

export const settingsSchema = z.object({
  publicHost: z.string(),
  subscriptionBaseUrl: z.string(),
  /** IANA zone monthly quota days are read in. */
  timeZone: z.string(),
  /** Where this server is: "" or a region code. Shown on the route graph. */
  serverRegion: z.union([z.literal(""), regionSchema]),
});
export type Settings = z.infer<typeof settingsSchema>;

export const hostSshSchema = z.object({ passwordLogin: z.enum(["on", "off", "unknown"]) });
export type HostSsh = z.infer<typeof hostSshSchema>;

export const appActions = ["install", "remove", "start", "stop", "restart"] as const;
export type AppAction = (typeof appActions)[number];
export const hostAppSchema = z.object({
  id: z.string(),
  category: z.string(),
  ports: z.array(z.number().int()),
  service: z.boolean(),
  installed: z.boolean(),
  version: z.string(),
  // "" for a plain tool or an app that is not installed.
  status: z.enum(["", "running", "stopped", "failed"]),
});
export type HostApp = z.infer<typeof hostAppSchema>;
export const appJobSchema = z.object({
  app: z.string(),
  action: z.enum(appActions),
  state: z.enum(["running", "done", "failed"]),
  startedAt: z.string(),
  endedAt: z.string().nullable(),
  error: z.string(),
  log: z.array(z.string()),
});
export type AppJob = z.infer<typeof appJobSchema>;
export const appsSchema = z.object({
  supported: z.boolean(),
  // Why not, when unsupported: "os" | "root" | "systemd" | "apt".
  reason: z.string(),
  apps: z.array(hostAppSchema),
  job: appJobSchema.nullable(),
});
export type Apps = z.infer<typeof appsSchema>;

export const reachSecurities = ["starttls", "tls", "none"] as const;
export const reachSmtpSchema = z.object({
  host: z.string(),
  port: z.number().int(),
  security: z.enum(reachSecurities),
  username: z.string(),
  passwordSet: z.boolean(),
  from: z.string(),
  to: z.string(),
});
export const reachConfigSchema = z.object({
  enabled: z.boolean(),
  intervalMinutes: z.number().int(),
  confirmRounds: z.number().int(),
  smtp: reachSmtpSchema,
});
export type ReachConfig = z.infer<typeof reachConfigSchema>;
/** What the server accepts: the password is write-only, and empty means "keep the stored one". */
export type ReachSmtpInput = Omit<ReachConfig["smtp"], "passwordSet"> & { password: string };
export type ReachConfigInput = Omit<ReachConfig, "smtp"> & { smtp: ReachSmtpInput };

export const reachVerdicts = ["ok", "port_blocked", "ip_blocked", "down", "unknown"] as const;
export const reachVerdictSchema = z.enum(reachVerdicts);
export type ReachVerdict = z.infer<typeof reachVerdictSchema>;
export const reachTargetSchema = z.object({
  lineId: z.number().int(),
  lineName: z.string(),
  protocol: z.string(),
  host: z.string(),
  port: z.number().int(),
  ipOnly: z.boolean(),
  verdict: reachVerdictSchema,
  since: z.string().nullable(),
  // "" until the line has been through a round.
  lastResult: z.union([reachVerdictSchema, z.literal("")]),
  chinaReached: z.number().int(),
  chinaAnswered: z.number().int(),
  controlReached: z.number().int(),
  controlAnswered: z.number().int(),
});
export type ReachTarget = z.infer<typeof reachTargetSchema>;
export const reachStatusSchema = z.object({
  enabled: z.boolean(),
  configured: z.boolean(),
  running: z.boolean(),
  lastCheckAt: z.string().nullable(),
  nextCheckAt: z.string().nullable(),
  lastError: z.string(),
  lastErrorDetail: z.string(),
  alertError: z.string(),
  targets: z.array(reachTargetSchema),
});
export type ReachStatus = z.infer<typeof reachStatusSchema>;
export const reachTestEmailSchema = z.object({ sent: z.boolean(), error: z.string() });

export const attackKinds = ["ssh_login", "ssh_invalid_user", "ssh_scan", "line_probe", "line_bad_auth"] as const;
export type AttackKind = (typeof attackKinds)[number];
const count = z.number().int().nonnegative();
export const attackSummarySchema = z.object({
  sources: count,
  hits: count,
  retentionDays: z.number().int(),
  // Kinds are plain strings so a newer server's extra kind does not break the page.
  kinds: z.array(z.object({ kind: z.string(), hits: count, sources: count })),
  countries: z.array(z.object({ country: z.string(), sources: count, hits: count })),
  networks: z.array(z.object({ network: z.string(), country: z.string(), abuseEmail: z.string(), sources: count, hits: count })),
  daily: z.array(z.object({ day: z.string(), hits: z.record(z.string(), count) })),
  lookup: z.object({ enabled: z.boolean(), lookedUp: count, pending: count, error: z.string(), pausedUntil: z.string().nullable() }),
  sshLog: z.string(),
});
export type AttackSummary = z.infer<typeof attackSummarySchema>;
export const attackerSchema = z.object({
  ip: z.string(),
  firstAt: z.string(),
  lastAt: z.string(),
  hits: count,
  kinds: z.array(z.object({ kind: z.string(), hits: count, firstAt: z.string(), lastAt: z.string() })),
  lookedUp: z.boolean(),
  lookupError: z.string(),
  country: z.string(),
  network: z.string(),
  netRange: z.string(),
  abuseEmail: z.string(),
  registry: z.string(),
});
export type Attacker = z.infer<typeof attackerSchema>;
export const attacksResponseSchema = z.object({ attackers: z.array(attackerSchema), total: count });
export const attackReportSchema = z.object({ ip: z.string(), to: z.string(), network: z.string(), subject: z.string(), body: z.string() });
export type AttackReport = z.infer<typeof attackReportSchema>;
export const attackConfigSchema = z.object({ lookup: z.boolean() });
export type AttackConfig = z.infer<typeof attackConfigSchema>;

export const errorEnvelopeSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    field: z.string().optional(),
  }),
});

export const exitSummarySchema = z.object({
  protocol: z.enum(["vless", "trojan", "shadowsocks", "socks", "hysteria2"]),
  host: z.string(),
  port: z.number().int(),
  network: z.string(),
  security: z.string(),
  serverName: z.string(),
  flow: z.string(),
  method: z.string(),
  auth: z.boolean(),
  obfs: z.boolean(),
  pinned: z.boolean(),
  plaintext: z.boolean(),
  udp: z.boolean(),
});
export type ExitSummary = z.infer<typeof exitSummarySchema>;

/** Another proxy server lines can leave through. Its credentials never reach the browser. */
export const exitSchema = z.object({
  id: z.number().int(),
  name: z.string(),
  region: z.union([z.literal(""), regionSchema]),
  nextId: z.number().int().nullable(),
  createdAt: z.string(),
  summary: exitSummarySchema,
});
export type Exit = z.infer<typeof exitSchema>;
export const exitsResponseSchema = z.object({ exits: z.array(exitSchema) });
export const exitParseSchema = z.object({ name: z.string(), summary: exitSummarySchema });
export type ExitInput = { name: string; region: string; link: string };

export const routingSchema = z.object({
  lines: z.array(z.object({ id: z.number().int(), exitId: z.number().int().nullable() })),
  exits: z.array(z.object({ id: z.number().int(), nextId: z.number().int().nullable() })),
});
export type Routing = z.infer<typeof routingSchema>;

export const exitLatencySchema = z.object({
  refreshing: z.boolean(),
  exits: z.array(z.object({
    id: z.number().int(),
    rttMs: z.number().nullable(),
    measuredAt: z.string().nullable(),
    unmeasured: z.enum(["udp", "inner"]).optional(),
    error: z.string().optional(),
  })),
});
export type ExitLatency = z.infer<typeof exitLatencySchema>;

export const graphLayoutSchema = z.object({ positions: z.record(z.string(), z.object({ x: z.number(), y: z.number() })) });
export type GraphPositions = z.infer<typeof graphLayoutSchema>["positions"];
