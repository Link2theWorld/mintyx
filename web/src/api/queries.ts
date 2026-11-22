import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api } from "./client";

export const keys = {
  session: ["session"] as const,
  lines: ["lines"] as const,
  clients: ["clients"] as const,
  share: (id: number) => ["share", id] as const,
  engine: ["engine"] as const,
  engineLogs: ["engine", "logs"] as const,
  status: ["status"] as const,
  audit: ["audit"] as const,
  settings: ["settings"] as const,
  hostSsh: ["host", "ssh"] as const,
  apps: ["apps"] as const,
  reachConfig: ["reach", "config"] as const,
  reachStatus: ["reach", "status"] as const,
  exits: ["exits"] as const,
  exitLatency: ["exits", "latency"] as const,
  graphLayout: ["graph", "layout"] as const,
  attacks: ["attacks"] as const,
  attackSummary: ["attacks", "summary"] as const,
  attackList: (kind: string, country: string) => ["attacks", "list", kind, country] as const,
  attackReport: (ip: string) => ["attacks", "report", ip] as const,
  attackConfig: ["attacks", "config"] as const,
};

export const AUDIT_PAGE = 50;

export const useSession = () => useQuery({ queryKey: keys.session, queryFn: api.session, staleTime: 60_000 });
export const useLines = () => useQuery({ queryKey: keys.lines, queryFn: api.lines });
export const useClients = () => useQuery({ queryKey: keys.clients, queryFn: api.clients, refetchInterval: 30_000 });
export const useShare = (id: number | null) =>
  useQuery({ queryKey: keys.share(id ?? -1), queryFn: () => api.share(id ?? -1), enabled: id !== null, gcTime: 0 });
export const useEngine = () => useQuery({ queryKey: keys.engine, queryFn: api.engine, refetchInterval: 5_000 });
export const useEngineLogs = () => useQuery({ queryKey: keys.engineLogs, queryFn: api.engineLogs, refetchInterval: 5_000 });
export const useStatus = () => useQuery({ queryKey: keys.status, queryFn: api.status, refetchInterval: 15_000 });
export const useSettings = () => useQuery({ queryKey: keys.settings, queryFn: api.settings });
// sshd's configuration rarely changes; one look per visit is plenty.
export const useHostSsh = (enabled: boolean) =>
  useQuery({ queryKey: keys.hostSsh, queryFn: () => api.hostSsh(), enabled, staleTime: 5 * 60_000, retry: false });
// Polls quickly only while an install or other job is in flight.
export const useApps = () =>
  useQuery({
    queryKey: keys.apps,
    queryFn: api.apps,
    refetchInterval: (q) => (q.state.data?.job?.state === "running" ? 2_000 : 30_000),
  });
export const useReachConfig = () => useQuery({ queryKey: keys.reachConfig, queryFn: api.reachConfig });
export const useReachStatus = () => useQuery({ queryKey: keys.reachStatus, queryFn: api.reachStatus, refetchInterval: 30_000 });

export const useAudit = () =>
  useInfiniteQuery({
    queryKey: keys.audit,
    queryFn: ({ pageParam }) => api.audit(AUDIT_PAGE, pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.length < AUDIT_PAGE ? undefined : last[last.length - 1]?.id),
  });

export const useExits = () => useQuery({ queryKey: keys.exits, queryFn: api.exits });
/** Latency is measured from the server on demand; polling only while the route map is open. */
export const useExitLatency = () =>
  useQuery({
    queryKey: keys.exitLatency,
    queryFn: api.exitLatency,
    // While a round is running, look again soon; otherwise every 15 seconds.
    refetchInterval: (q) => (q.state.data?.refreshing ? 1_500 : 15_000),
  });
export const useGraphLayout = () => useQuery({ queryKey: keys.graphLayout, queryFn: api.graphLayout, staleTime: Infinity });
export const ATTACK_PAGE = 50;
export const useAttackSummary = () => useQuery({ queryKey: keys.attackSummary, queryFn: api.attackSummary, refetchInterval: 30_000 });
export const useAttackConfig = () => useQuery({ queryKey: keys.attackConfig, queryFn: api.attackConfig });
export const useAttackReport = (ip: string | null) =>
  useQuery({ queryKey: keys.attackReport(ip ?? ""), queryFn: () => api.attackReport(ip ?? ""), enabled: ip !== null, gcTime: 0 });
export const useAttackers = (kind: string, country: string) =>
  useInfiniteQuery({
    queryKey: keys.attackList(kind, country),
    queryFn: ({ pageParam }) => api.attacks({ kind, country, limit: ATTACK_PAGE, offset: pageParam }),
    initialPageParam: 0,
    getNextPageParam: (last, pages) => {
      const loaded = pages.reduce((n, p) => n + p.attackers.length, 0);
      return last.attackers.length < ATTACK_PAGE || loaded >= last.total ? undefined : loaded;
    },
  });
