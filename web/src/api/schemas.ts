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

export const errorEnvelopeSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    field: z.string().optional(),
  }),
});
