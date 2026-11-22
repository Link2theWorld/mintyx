import { RadarChartOutlined } from "@ant-design/icons";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert, App, Button, Card, Flex, Tag, Typography, theme } from "antd";
import { Link } from "react-router";
import { ApiError, api } from "../api/client";
import { keys, useReachStatus } from "../api/queries";
import type { ReachStatus, ReachTarget } from "../api/schemas";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import type { Translate } from "../i18n/translate";
import { errorText } from "../lib/errors";
import { formatDateTime } from "../lib/format";
import { adviceKey, pendingResult, reachView, roundErrorKey, targetAddress, verdictColor } from "../lib/reach";

function checkErrorText(err: unknown, t: Translate): string {
  if (err instanceof ApiError && err.code === "rate_limited") return t("reach.checkTooSoon");
  if (err instanceof ApiError && err.code === "conflict") return t("reach.checkBusy");
  return errorText(err, t);
}

function TargetRow({ target }: { target: ReachTarget }) {
  const { t } = useI18n();
  const { token } = theme.useToken();
  const advice = adviceKey(target);
  const pending = pendingResult(target);
  const probed = target.chinaAnswered + target.controlAnswered > 0;
  return (
    <li style={{ borderBottom: `1px solid ${token.colorBorderSecondary}` }}>
      <Flex justify="space-between" align="center" gap={8} wrap>
        <Flex gap={8} align="baseline" wrap>
          <Typography.Text strong>{target.lineName}</Typography.Text>
          <Typography.Text type="secondary">{targetAddress(target)}</Typography.Text>
          {target.ipOnly && <Tag>{t("reach.ipOnly")}</Tag>}
        </Flex>
        <Tag color={verdictColor[target.verdict]} style={{ marginInlineEnd: 0 }}>
          {t(`reach.verdict.${target.verdict}`)}
        </Tag>
      </Flex>
      {advice && <div><Typography.Text>{t(advice)}</Typography.Text></div>}
      {pending && (
        <div><Typography.Text type="warning">{t("reach.pending", { result: t(`reach.verdict.${pending}`) })}</Typography.Text></div>
      )}
      {target.ipOnly && <div><Typography.Text type="secondary">{t("reach.ipOnlyHint")}</Typography.Text></div>}
      {probed && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {t("reach.probes", {
            cn: target.chinaReached, cnTotal: target.chinaAnswered, ctl: target.controlReached, ctlTotal: target.controlAnswered,
          })}
          {target.since && target.verdict !== "unknown" ? ` · ${t("reach.since", { time: formatDateTime(target.since) })}` : ""}
        </Typography.Text>
      )}
    </li>
  );
}

function Schedule({ status }: { status: ReachStatus }) {
  const { t } = useI18n();
  const parts = [
    status.lastCheckAt ? t("reach.lastCheck", { time: formatDateTime(status.lastCheckAt) }) : t("reach.neverChecked"),
    ...(status.nextCheckAt ? [t("reach.nextCheck", { time: formatDateTime(status.nextCheckAt) })] : []),
  ];
  return <Typography.Text type="secondary" style={{ fontSize: 12 }}>{parts.join(" · ")}</Typography.Text>;
}

/** Overview card: can mainland China still reach each line, and what to do when it cannot. */
export function ReachCard() {
  const { t } = useI18n();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const q = useReachStatus();
  const check = useMutation({
    mutationFn: api.reachCheck,
    onSuccess: (s) => {
      qc.setQueryData(keys.reachStatus, s);
      void message.success(t("reach.checked"));
    },
    onError: (e) => void message.error(checkErrorText(e, t)),
  });

  const s = q.data;
  const view = s ? reachView(s) : null;
  const roundError = s ? roundErrorKey(s.lastError) : null;
  const busy = check.isPending || s?.running === true;

  return (
    <Card
      title={t("reach.title")}
      extra={view === "list" && (
        <Button icon={<RadarChartOutlined />} loading={busy} onClick={() => check.mutate()}>{t("reach.checkNow")}</Button>
      )}
    >
      <QueryState isPending={q.isPending} error={q.error} refetch={q.refetch} />
      {s && view === "off" && (
        <Flex vertical gap={12} align="flex-start">
          <Typography.Text type="secondary">{t("reach.off")}</Typography.Text>
          <Link to="/settings">{t("reach.goSettings")}</Link>
        </Flex>
      )}
      {s && view === "noHost" && <Alert type="warning" showIcon title={t("reach.noHost")} />}
      {s && view === "noLines" && <Typography.Text type="secondary">{t("reach.noLines")}</Typography.Text>}
      {s && view === "list" && (
        <Flex vertical gap={12}>
          {busy && <Alert type="info" showIcon title={t("reach.checking")} />}
          {roundError && <Alert type="warning" showIcon title={t(roundError, { detail: s.lastErrorDetail })} />}
          {s.alertError && <Alert type="warning" showIcon title={t("reach.alertError", { error: s.alertError })} />}
          <ul className="reach-list">
            {s.targets.map((target) => <TargetRow key={target.lineId} target={target} />)}
          </ul>
          <Schedule status={s} />
        </Flex>
      )}
    </Card>
  );
}
