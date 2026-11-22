import { ReloadOutlined } from "@ant-design/icons";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert, App, Badge, Button, Card, Flex, Popconfirm, Statistic, Typography, theme } from "antd";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import { api } from "../api/client";
import { keys, useEngine, useEngineLogs, useStatus } from "../api/queries";
import type { Engine } from "../api/schemas";
import { PageHeader } from "../components/PageHeader";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { errorText } from "../lib/errors";
import { GuidesCard } from "../components/Guides";
import { formatBytes, formatDateTime } from "../lib/format";
import { SshPasswordWarning } from "./SshPasswordWarning";
import { ReachCard } from "./ReachCard";

dayjs.extend(relativeTime);

type EngineState = "running" | "stopped" | "noBinary";
function engineState(e: Engine): EngineState {
  if (!e.binaryFound) return "noBinary";
  return e.running ? "running" : "stopped";
}

function EngineCard() {
  const { t } = useI18n();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const q = useEngine();
  const restart = useMutation({
    mutationFn: api.restartEngine,
    onSuccess: () => void message.success(t("overview.restarted")),
    onError: (e) => void message.error(errorText(e, t)),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.engine }),
  });

  const e = q.data;
  const state = e ? engineState(e) : null;
  const badge = { running: "success", stopped: "warning", noBinary: "error" } as const;

  return (
    <Card
      title={t("overview.engine")}
      extra={
        <Popconfirm title={t("overview.restartConfirm")} onConfirm={() => restart.mutate()} okText={t("overview.restart")} cancelText={t("common.cancel")}>
          <Button icon={<ReloadOutlined />} loading={restart.isPending} disabled={e?.binaryFound === false}>
            {t("overview.restart")}
          </Button>
        </Popconfirm>
      }
    >
      <QueryState isPending={q.isPending} error={q.error} refetch={q.refetch} />
      {e && state && (
        <Flex vertical gap={16}>
          <Badge status={badge[state]} text={<Typography.Text strong style={{ fontSize: 16 }}>{t(`overview.${state}`)}</Typography.Text>} />
          {state === "noBinary" && <Alert type="error" showIcon title={t("overview.noBinaryHint")} />}
          <dl className="kv">
            <dt><Typography.Text type="secondary">{t("overview.version")}</Typography.Text></dt>
            <dd>{e.version || "—"}</dd>
            {e.running && (
              <>
                <dt><Typography.Text type="secondary">{t("overview.pid")}</Typography.Text></dt>
                <dd>{e.pid}</dd>
              </>
            )}
            {e.running && e.startedAt && (
              <>
                <dt><Typography.Text type="secondary">{t("overview.uptime")}</Typography.Text></dt>
                <dd title={formatDateTime(e.startedAt)}>{dayjs(e.startedAt).fromNow(true)}</dd>
              </>
            )}
            <dt><Typography.Text type="secondary">{t("overview.restarts")}</Typography.Text></dt>
            <dd>{e.restarts}</dd>
            {e.lastExit && (
              <>
                <dt><Typography.Text type="secondary">{t("overview.lastExit")}</Typography.Text></dt>
                <dd><Typography.Text code>{e.lastExit}</Typography.Text></dd>
              </>
            )}
          </dl>
        </Flex>
      )}
    </Card>
  );
}

function StatsRow() {
  const { t } = useI18n();
  const q = useStatus();
  const s = q.data;
  if (!s) return <Card><QueryState isPending={q.isPending} error={q.error} refetch={q.refetch} /></Card>;
  return (
    <>
      <div className="stat-grid">
        <Card><Statistic title={t("overview.lines")} value={s.lineCount} /></Card>
        <Card>
          <Statistic title={t("overview.clients")} value={s.clientCount} />
          <Typography.Text type="secondary">{t("overview.activeClients", { active: s.activeClientCount })}</Typography.Text>
        </Card>
        <Card>
          <Statistic title={t("overview.traffic")} value={formatBytes(s.totalUp + s.totalDown)} />
          <Typography.Text type="secondary">
            {t("overview.up")} {formatBytes(s.totalUp)} · {t("overview.down")} {formatBytes(s.totalDown)}
          </Typography.Text>
        </Card>
      </div>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {t("overview.panelSince", { time: formatDateTime(s.panelStartedAt) })}
      </Typography.Text>
    </>
  );
}

function LogsCard() {
  const { t } = useI18n();
  const { token } = theme.useToken();
  const q = useEngineLogs();
  return (
    <Card title={t("overview.logs")}>
      <QueryState isPending={q.isPending} error={q.error} refetch={q.refetch} />
      {q.data && (q.data.length === 0 ? (
        <Typography.Text type="secondary">{t("overview.logsEmpty")}</Typography.Text>
      ) : (
        <pre
          className="log-box"
          tabIndex={0}
          aria-label={t("overview.logs")}
          style={{ background: token.colorFillTertiary, color: token.colorText, fontFamily: token.fontFamilyCode }}
        >
          {q.data.join("\n")}
        </pre>
      ))}
    </Card>
  );
}

export function OverviewPage() {
  const { t } = useI18n();
  return (
    <>
      <PageHeader title={t("overview.title")} />
      <SshPasswordWarning />
      <Flex vertical gap={16}>
        <StatsRow />
        <EngineCard />
        <ReachCard />
        <LogsCard />
        <GuidesCard />
      </Flex>
    </>
  );
}
