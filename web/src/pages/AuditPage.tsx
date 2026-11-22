import { Button, Card, Empty, Flex, Table, Typography, theme } from "antd";
import { useAudit } from "../api/queries";
import type { AuditEntry } from "../api/schemas";
import { PageHeader } from "../components/PageHeader";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { auditActionLabel } from "../i18n/translate";
import { formatDateTime } from "../lib/format";
import { useIsMobile } from "../lib/useIsMobile";

export function AuditPage() {
  const { t } = useI18n();
  const mobile = useIsMobile();
  const { token } = theme.useToken();
  const audit = useAudit();
  const entries = audit.data?.pages.flat() ?? [];
  const isFail = (e: AuditEntry) => e.action.endsWith(".fail");

  return (
    <>
      <PageHeader title={t("audit.title")} subtitle={t("audit.subtitle")} />
      <QueryState isPending={audit.isPending} error={audit.error} refetch={audit.refetch} />
      {audit.data && entries.length === 0 && <Card><Empty description={t("audit.empty")} /></Card>}
      {entries.length > 0 && (
        <Card styles={{ body: { padding: mobile ? "4px 16px" : 0 } }}>
          {mobile ? (
            <ul className="audit-list">
              {entries.map((e) => (
                <li key={e.id} style={{ borderBottom: `1px solid ${token.colorBorderSecondary}` }}>
                  <Flex justify="space-between" gap={8}>
                    <Typography.Text strong type={isFail(e) ? "danger" : undefined}>{auditActionLabel(e.action, t)}</Typography.Text>
                    <Typography.Text type="secondary" style={{ fontSize: 12, whiteSpace: "nowrap" }}>{formatDateTime(e.at)}</Typography.Text>
                  </Flex>
                  {e.target && <div><Typography.Text>{e.target}</Typography.Text></div>}
                  {e.detail && <div><Typography.Text type="secondary">{e.detail}</Typography.Text></div>}
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>{e.remoteIp}</Typography.Text>
                </li>
              ))}
            </ul>
          ) : (
            <Table<AuditEntry>
              rowKey="id"
              dataSource={entries}
              pagination={false}
              columns={[
                { title: t("audit.col.time"), dataIndex: "at", width: 170, render: (v: string) => formatDateTime(v) },
                {
                  title: t("audit.col.action"),
                  key: "action",
                  render: (_, e) => (
                    <Typography.Text type={isFail(e) ? "danger" : undefined} title={e.action}>{auditActionLabel(e.action, t)}</Typography.Text>
                  ),
                },
                { title: t("audit.col.target"), dataIndex: "target" },
                { title: t("audit.col.detail"), dataIndex: "detail", render: (v: string) => <Typography.Text type="secondary">{v}</Typography.Text> },
                { title: t("audit.col.ip"), dataIndex: "remoteIp", width: 150 },
              ]}
            />
          )}
        </Card>
      )}
      {entries.length > 0 && (
        <Flex justify="center" style={{ marginTop: 16 }}>
          {audit.hasNextPage ? (
            <Button onClick={() => void audit.fetchNextPage()} loading={audit.isFetchingNextPage}>{t("audit.loadMore")}</Button>
          ) : (
            <Typography.Text type="secondary">{t("audit.noMore")}</Typography.Text>
          )}
        </Flex>
      )}
    </>
  );
}
