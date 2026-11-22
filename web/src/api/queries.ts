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
  reachConfig: ["reach", "config"] as const,
  reachStatus: ["reach", "status"] as const,
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
export const useReachConfig = () => useQuery({ queryKey: keys.reachConfig, queryFn: api.reachConfig });
export const useReachStatus = () => useQuery({ queryKey: keys.reachStatus, queryFn: api.reachStatus, refetchInterval: 30_000 });

export const useAudit = () =>
  useInfiniteQuery({
    queryKey: keys.audit,
    queryFn: ({ pageParam }) => api.audit(AUDIT_PAGE, pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.length < AUDIT_PAGE ? undefined : last[last.length - 1]?.id),
  });
