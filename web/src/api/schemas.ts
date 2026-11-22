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

const saved = { id: z.number().int(), createdAt: z.string() };
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
});
export type Client = z.infer<typeof clientSchema>;
export const clientsResponseSchema = z.object({ clients: z.array(clientSchema) });

export type ClientInput = { name: string; quotaBytes: number; expiresAt: string | null };

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

export const errorEnvelopeSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    field: z.string().optional(),
  }),
});
