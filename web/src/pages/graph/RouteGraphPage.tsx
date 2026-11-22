import "@xyflow/react/dist/style.css";
import "./graph.css";
import { PlusOutlined, ReloadOutlined, UndoOutlined } from "@ant-design/icons";
import { useQueryClient } from "@tanstack/react-query";
import {
  Background, BackgroundVariant, Controls, MiniMap, Panel, ReactFlow, ReactFlowProvider, useReactFlow,
  type Connection, type Edge, type EdgeChange, type Node, type NodeChange, type NodeSelectionChange,
  type OnEdgesChange, type OnNodesChange,
} from "@xyflow/react";
import { App, Button, Card, Typography } from "antd";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../api/client";
import { keys, useClients, useExitLatency, useExits, useGraphLayout, useLines, useSettings } from "../../api/queries";
import type { GraphPositions } from "../../api/schemas";
import { PageHeader } from "../../components/PageHeader";
import { QueryState } from "../../components/QueryState";
import { useI18n } from "../../i18n/I18nProvider";
import { errorText, isEngineError } from "../../lib/errors";
import { useIsMobile } from "../../lib/useIsMobile";
import { useThemePref } from "../../theme/ThemeProvider";
import { palettes } from "../../theme/themes";
import { ExitDrawer } from "./ExitDrawer";
import {
  MAX_HOPS, changeCount, changes, connect, defaultLayout, disconnect, draftFrom, edgesFor, editCount, editsBetween, nodeId,
  noEdits, overlay, parseEdits, parseNodeId, pathThrough, settle, type ChainProblem, type Draft, type Edits, type Position,
} from "./model";
import { ExitCard, FlowEdge, InternetCard, LineCard, ServerFrame, VisitorsCard, type EdgeData } from "./parts";

const nodeTypes = { visitors: VisitorsCard, server: ServerFrame, line: LineCard, exit: ExitCard, internet: InternetCard };
const edgeTypes = { flow: FlowEdge };
const EDITS_KEY = "mintyx.graph.edits";

/** Unapplied edits survive a visit to another page and a reload, until applied or discarded. */
function loadEdits(): Edits {
  try {
    const raw = sessionStorage.getItem(EDITS_KEY);
    return raw ? parseEdits(JSON.parse(raw)) : noEdits;
  } catch {
    return noEdits;
  }
}

function saveEdits(e: Edits) {
  try {
    if (editCount(e) > 0) sessionStorage.setItem(EDITS_KEY, JSON.stringify(e));
    else sessionStorage.removeItem(EDITS_KEY);
  } catch {
    /* the edits then live for this visit only */
  }
}

function Graph() {
  const { t } = useI18n();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const mobile = useIsMobile();
  // SVG fill attributes cannot read CSS variables, so the minimap gets the palette's own colours.
  const palette = palettes[useThemePref().resolved];
  const lines = useLines();
  const exits = useExits();
  const clients = useClients();
  const latency = useExitLatency();
  const settings = useSettings();
  const layout = useGraphLayout();

  const base = useMemo(
    () => (lines.data && exits.data ? draftFrom(lines.data, exits.data) : null),
    [lines.data, exits.data],
  );
  const [edits, setEdits] = useState<Edits>(loadEdits);
  // When the server's wiring changes, edits it overtook or that no longer fit are dropped for
  // good, so they cannot come back if the server later returns to the value they replaced.
  const [seenBase, setSeenBase] = useState<Draft | null>(null);
  if (base && base !== seenBase) {
    setSeenBase(base);
    const live = settle(edits, base);
    if (editCount(live) !== editCount(edits)) setEdits(live);
  }
  useEffect(() => saveEdits(edits), [edits]);
  const current = useMemo(() => (base ? overlay(base, edits) : null), [edits, base]);
  const pending = current && base ? changeCount(current, base) : 0;
  // A new draft (or null to discard) is kept as just its differences from the server's wiring.
  const setDraft = useCallback((d: Draft | null) => {
    setEdits(d && base ? editsBetween(d, base) : noEdits);
  }, [base]);

  // Positions: dragged in this visit, else saved, else the automatic layout for anything new.
  const [moved, setMoved] = useState<Record<string, Position>>({});
  // Sizes React Flow measures; the minimap and fit-view need them handed back on every node.
  const [sizes, setSizes] = useState<Record<string, { width: number; height: number }>>({});
  const placed = useMemo(() => ({ ...layout.data, ...moved }), [layout.data, moved]);
  const auto = useMemo(
    () => (lines.data && exits.data && current ? defaultLayout(lines.data, exits.data, current) : {}),
    // The automatic spots only matter for nodes never placed; recomputing per edit would make them jump.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [lines.data, exits.data],
  );
  const pos = useCallback((id: string): Position => placed[id] ?? auto[id] ?? { x: 0, y: 0 }, [placed, auto]);

  const saveTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const persistPositions = useCallback((all: Record<string, Position>) => {
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      void api.saveGraphLayout(all as GraphPositions).then(() => qc.setQueryData(keys.graphLayout, all));
    }, 600);
  }, [qc]);

  const [hover, setHover] = useState<string | null>(null);
  // Nodes and edges are controlled, so selection has to be kept here for Delete to find it.
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const applySelection = useCallback((list: (NodeChange | EdgeChange)[]) => {
    const picks = list.filter((c): c is NodeSelectionChange => c.type === "select");
    if (picks.length === 0) return;
    setSelected((cur) => {
      const next = new Set(cur);
      for (const c of picks) {
        if (c.selected) next.add(c.id);
        else next.delete(c.id);
      }
      return next;
    });
  }, []);
  const [drawer, setDrawer] = useState<{ exitId: number | null } | null>(null);
  const [applying, setApplying] = useState(false);

  const graphEdges = useMemo(
    () => (lines.data && exits.data && current && base ? edgesFor(lines.data, exits.data, current, base, latency.data) : []),
    [lines.data, exits.data, current, base, latency.data],
  );
  const lit = hover ? pathThrough(hover, graphEdges) : null;

  const nodes: Node[] = useMemo(() => {
    if (!lines.data || !exits.data) return [];
    const total = clients.data?.length ?? 0;
    const active = clients.data?.filter((c) => c.disabled === "").length ?? 0;
    const byExit = new Map((latency.data?.exits ?? []).map((l) => [l.id, l]));
    const serverHeight = Math.max(1, lines.data.length) * 120 + 50;
    const dim = (id: string) => (lit && !lit.has(id) ? { opacity: 0.35 } : undefined);
    const list: Node[] = [
      { id: nodeId.visitors, type: "visitors", position: pos(nodeId.visitors), data: { total, active }, style: dim(nodeId.visitors) },
      {
        id: nodeId.server, type: "server", position: pos(nodeId.server), data: { region: settings.data?.serverRegion ?? "" },
        style: { width: 280, height: serverHeight }, selectable: false, zIndex: -1,
      },
      ...lines.data.map((l) => ({
        id: nodeId.line(l.id), type: "line", parentId: nodeId.server, extent: "parent" as const,
        position: pos(nodeId.line(l.id)), data: { line: l }, style: dim(nodeId.line(l.id)),
      })),
      ...exits.data.map((e) => ({
        id: nodeId.exit(e.id), type: "exit", position: pos(nodeId.exit(e.id)),
        data: { exit: e, latency: byExit.get(e.id), refreshing: latency.data?.refreshing ?? false }, style: dim(nodeId.exit(e.id)),
      })),
      { id: nodeId.internet, type: "internet", position: pos(nodeId.internet), data: {}, style: dim(nodeId.internet) },
    ];
    return list.map((n) => ({
      ...n, deletable: false, selected: selected.has(n.id), ...(sizes[n.id] ? { measured: sizes[n.id] } : {}),
    }));
  }, [lines.data, exits.data, clients.data, latency.data, settings.data, pos, lit, sizes, selected]);

  // The first fit happens before React Flow has measured the nodes; fit again once it has.
  const flow = useReactFlow();
  const fitted = useRef(false);
  useEffect(() => {
    if (fitted.current || nodes.length === 0) return;
    if (nodes.every((n) => n.type === "server" || sizes[n.id])) {
      fitted.current = true;
      void flow.fitView({ padding: 0.15 });
    }
  }, [nodes, sizes, flow]);

  const edges: Edge[] = graphEdges.map((e) => ({
    id: e.id, source: e.source, target: e.target, type: "flow", deletable: !e.fixed, focusable: !e.fixed,
    selectable: !e.fixed, selected: selected.has(e.id),
    data: { live: e.live, pending: e.pending, broken: e.broken, fixed: e.fixed, dim: lit !== null && !lit.has(e.id) } satisfies EdgeData,
  }));

  const onNodesChange: OnNodesChange = useCallback((changesList: NodeChange[]) => {
    applySelection(changesList);
    const movedNow: Record<string, Position> = {};
    const measured: Record<string, { width: number; height: number }> = {};
    let done = false;
    for (const c of changesList) {
      if (c.type === "dimensions" && c.dimensions) measured[c.id] = c.dimensions;
      if (c.type === "position" && c.position) {
        movedNow[c.id] = c.position;
        if (c.dragging === false) done = true;
      }
    }
    if (Object.keys(measured).length > 0) setSizes((s) => ({ ...s, ...measured }));
    if (Object.keys(movedNow).length === 0 && !done) return;
    setMoved((m) => ({ ...m, ...movedNow }));
    if (done) persistPositions({ ...placed, ...movedNow });
  }, [persistPositions, placed, applySelection]);

  const onEdgesChange: OnEdgesChange = useCallback((changesList: EdgeChange[]) => applySelection(changesList), [applySelection]);

  const problemText = (p: ChainProblem) => {
    const name = (id: number) => exits.data?.find((e) => e.id === id)?.name ?? String(id);
    return p.kind === "loop"
      ? t("graph.loop", { path: p.ids.map(name).join(" → ") })
      : t("graph.tooLong", { n: MAX_HOPS });
  };

  const onConnect = (c: Connection) => {
    if (!current) return;
    const r = connect(current, c.source, c.target);
    if (r.problem) void message.warning(problemText(r.problem));
    else if (r.draft) setDraft(r.draft);
  };

  const isValidConnection = (c: Connection | Edge) => {
    const s = parseNodeId(c.source);
    const tt = parseNodeId(c.target);
    return (s.kind === "line" || s.kind === "exit") && (tt.kind === "exit" || tt.kind === "internet") && c.source !== c.target;
  };

  const onEdgesDelete = (deleted: Edge[]) => {
    if (!current) return;
    let d = current;
    for (const e of deleted) d = disconnect(d, e.source);
    setDraft(d);
    setSelected(new Set());
  };

  const apply = async () => {
    if (!current || !base) return;
    const body = changes(current, base);
    if (!body) return;
    setApplying(true);
    try {
      await api.saveRouting(body);
      setDraft(null);
      await Promise.all([qc.invalidateQueries({ queryKey: keys.lines }), qc.invalidateQueries({ queryKey: keys.exits }),
        qc.invalidateQueries({ queryKey: keys.exitLatency })]);
      void message.success(t("graph.applied"));
    } catch (e) {
      if (isEngineError(e)) {
        // The wiring is saved even though Xray rejected it: drop the draft and show what is stored.
        setDraft(null);
        await Promise.all([qc.invalidateQueries({ queryKey: keys.lines }), qc.invalidateQueries({ queryKey: keys.exits })]);
        void message.warning(errorText(e, t), 8);
      } else void message.error(errorText(e, t));
    } finally {
      setApplying(false);
    }
  };

  useEffect(() => {
    if (pending === 0) return;
    const warn = (ev: BeforeUnloadEvent) => { ev.preventDefault(); };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [pending]);

  const refreshLatency = async () => {
    try {
      qc.setQueryData(keys.exitLatency, await api.refreshExitLatency());
    } catch (e) {
      void message.info(errorText(e, t));
    }
  };

  const loading = lines.isPending || exits.isPending || layout.isPending;
  const failed = lines.error ?? exits.error ?? layout.error;
  const openExit = drawer?.exitId != null ? exits.data?.find((e) => e.id === drawer.exitId) ?? null : null;

  return (
    <>
      <PageHeader
        title={t("graph.title")}
        subtitle={t("graph.subtitle")}
        extra={
          <div className="graph-toolbar">
            {pending > 0 && (
              <>
                <Button icon={<UndoOutlined />} onClick={() => setDraft(null)}>{t("graph.discard")}</Button>
                <Button type="primary" loading={applying} onClick={() => void apply()} title={t("graph.applyHint")}>
                  {t("graph.apply", { n: pending })}
                </Button>
              </>
            )}
            <Button icon={<ReloadOutlined />} onClick={() => void refreshLatency()}>{t("graph.refreshLatency")}</Button>
            <Button icon={<PlusOutlined />} onClick={() => setDrawer({ exitId: null })}>{t("graph.addExit")}</Button>
          </div>
        }
      />
      {(loading || failed) && (
        <Card><QueryState isPending={loading} error={failed} refetch={() => { void lines.refetch(); void exits.refetch(); void layout.refetch(); }} /></Card>
      )}
      {!loading && !failed && (
        <div className="graph-wrap" aria-label={t("graph.title")}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            isValidConnection={isValidConnection}
            onEdgesDelete={onEdgesDelete}
            onNodeClick={(_, n) => { const p = parseNodeId(n.id); if (p.kind === "exit") setDrawer({ exitId: p.id }); }}
            onNodeMouseEnter={(_, n) => setHover(n.id)}
            onNodeMouseLeave={() => setHover(null)}
            deleteKeyCode={["Backspace", "Delete"]}
            fitView
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.1}
            proOptions={{ hideAttribution: true }}
          >
            <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} color="var(--dot)" />
            <Controls showInteractive={false} />
            {!mobile && (
              <MiniMap
                pannable
                zoomable
                nodeStrokeWidth={2}
                bgColor={palette.paper}
                maskColor={palette.sky + "99"}
                nodeColor={(n) => (n.type === "server" ? "transparent" : n.type === "internet" ? palette.note : palette.skyPhoto)}
                nodeStrokeColor={(n) => (n.type === "server" ? palette.line : palette.skyDeep)}
              />
            )}
            <Panel position={mobile ? "top-left" : "bottom-left"}>
              <div className="graph-legend paper">
                <span><i style={{ borderColor: "var(--sky-deep)" }} />{t("graph.legend.live")}</span>
                <span><i className="dashed" style={{ borderColor: "var(--blossom)" }} />{t("graph.legend.pending")}</span>
                <span><i className="dashed" style={{ borderColor: "var(--error)" }} />{t("graph.legend.broken")}</span>
                <span><i className="dashed" style={{ borderColor: "var(--line)" }} />{t("graph.legend.idle")}</span>
              </div>
            </Panel>
            {exits.data?.length === 0 && (
              <Panel position="top-center">
                <Typography.Text className="paper" style={{ display: "block", maxWidth: 360 }}>{t("graph.empty")}</Typography.Text>
              </Panel>
            )}
          </ReactFlow>
        </div>
      )}
      <ExitDrawer
        key={drawer ? String(drawer.exitId ?? "new") : "closed"}
        open={drawer !== null}
        exit={openExit}
        latency={openExit ? latency.data?.exits.find((l) => l.id === openExit.id) : undefined}
        onClose={() => setDrawer(null)}
      />
    </>
  );
}

/** The route map: visitors → this server's lines → exits → the internet, editable by dragging wires. */
export default function RouteGraphPage() {
  return (
    <ReactFlowProvider>
      <Graph />
    </ReactFlowProvider>
  );
}
