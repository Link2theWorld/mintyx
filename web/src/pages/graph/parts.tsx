import { GlobalOutlined, TeamOutlined } from "@ant-design/icons";
import { BaseEdge, Handle, Position, getBezierPath, type EdgeProps, type Node, type NodeProps } from "@xyflow/react";
import type { Exit, ExitLatency, Line } from "../../api/schemas";
import { useI18n } from "../../i18n/I18nProvider";

export type VisitorsData = { total: number; active: number };
export type ServerData = { region: string };
export type LineData = { line: Line };
export type ExitData = { exit: Exit; latency?: ExitLatency["exits"][number]; refreshing: boolean };
export type EdgeData = { live: boolean; pending: boolean; broken: boolean; fixed: boolean; dim: boolean };

export type VisitorsNode = Node<VisitorsData, "visitors">;
export type ServerNode = Node<ServerData, "server">;
export type LineNode = Node<LineData, "line">;
export type ExitNode = Node<ExitData, "exit">;
export type InternetNode = Node<Record<string, never>, "internet">;

/** Everyone the panel serves, as one node: they may use every enabled line. */
export function VisitorsCard({ data }: NodeProps<VisitorsNode>) {
  const { t } = useI18n();
  return (
    <div className="graph-node paper tilt-3">
      <span className="tape" aria-hidden="true" />
      <div className="graph-node-head"><TeamOutlined aria-hidden="true" /> <span className="hand">{t("graph.visitors")}</span></div>
      <div className="script graph-big">{data.total}</div>
      <div className="meta">{t("graph.visitorsActive", { n: data.active })}</div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  );
}

/** A frame around this server's lines, labelled with where the server is. */
export function ServerFrame({ data }: NodeProps<ServerNode>) {
  const { t } = useI18n();
  return (
    <div className="graph-server">
      <span className="graph-server-label hand">
        {t("graph.server")}{data.region && <> · {t(`lines.region.${data.region}` as "lines.region.jp")}</>}
      </span>
    </div>
  );
}

export function LineCard({ data }: NodeProps<LineNode>) {
  const { t } = useI18n();
  const l = data.line;
  return (
    <div className={`graph-node graph-line paper${l.enabled ? "" : " off"}`}>
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="graph-node-title">{l.name}</div>
      <div className="meta">{t(`protocol.${l.protocol}`)} · {l.port}</div>
      {!l.enabled && <span className="sticker quiet graph-tag">{t("graph.lineOff")}</span>}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

function LatencyBadge({ data }: { data: ExitData }) {
  const { t } = useI18n();
  const l = data.latency;
  if (l?.unmeasured === "udp") return <span className="graph-latency quiet">{t("graph.latencyUdp")}</span>;
  if (l?.unmeasured === "inner") return <span className="graph-latency quiet">{t("graph.latencyInner")}</span>;
  if (l?.error) return <span className="graph-latency bad" title={l.error}>{t("graph.latencyFail")}</span>;
  if (l?.rttMs !== null && l?.rttMs !== undefined) {
    const slow = l.rttMs > 250;
    return <span className={`graph-latency script${slow ? " slow" : ""}`}>{l.rttMs} ms</span>;
  }
  return <span className="graph-latency quiet">{data.refreshing ? t("graph.latencyPending") : "—"}</span>;
}

export function ExitCard({ data }: NodeProps<ExitNode>) {
  const { t } = useI18n();
  const e = data.exit;
  const s = e.summary;
  const security = s.security === "none" ? "" : ` · ${s.security.toUpperCase()}`;
  return (
    <div className="graph-node graph-exit paper">
      <Handle type="target" position={Position.Left} />
      <div className="graph-node-row">
        <div className="graph-node-title">{e.name}</div>
        {e.region && <span className="sticker quiet graph-tag">{t(`lines.region.${e.region}`)}</span>}
      </div>
      <div className="meta">{s.protocol.toUpperCase()}{security}{s.network && s.network !== "raw" ? ` · ${s.network}` : ""}</div>
      <div className="graph-node-row">
        <span className="meta mono">{s.host}:{s.port}</span>
        <LatencyBadge data={data} />
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

export function InternetCard() {
  const { t } = useI18n();
  return (
    <div className="graph-node graph-internet sticky-note">
      <Handle type="target" position={Position.Left} />
      <GlobalOutlined aria-hidden="true" style={{ fontSize: 22 }} />
      <span className="hand" style={{ fontSize: 24 }}>{t("graph.internet")}</span>
    </div>
  );
}

/** A wire with dots running along it while traffic flows; dashed when idle or not applied yet. */
export function FlowEdge(props: EdgeProps) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, selected } = props;
  const d = props.data as EdgeData;
  const [path] = getBezierPath({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition });
  const color = d.broken ? "var(--error)" : d.pending ? "var(--blossom)" : d.live ? "var(--sky-deep)" : "var(--line)";
  const flowing = d.live && !d.broken;
  return (
    <g opacity={d.dim ? 0.18 : 1}>
      <BaseEdge
        id={id}
        path={path}
        style={{ stroke: color, strokeWidth: selected ? 3.5 : 2.2, strokeDasharray: flowing && !d.pending ? undefined : "7 6" }}
      />
      {flowing && [0, 0.6, 1.2].map((begin) => (
        <circle key={begin} className="flow-dot" r={3.6} fill={color}>
          {/* A negative begin starts each dot part-way along the wire, so none waits at the origin. */}
          <animateMotion dur="1.8s" begin={`-${String(begin)}s`} repeatCount="indefinite" path={path} />
        </circle>
      ))}
    </g>
  );
}
