import {
  DeleteOutlined,
  EditOutlined,
  KeyOutlined,
  MoreOutlined,
  PauseCircleOutlined,
  PlayCircleOutlined,
  PlusOutlined,
  ShareAltOutlined,
  UndoOutlined,
} from "@ant-design/icons";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { App, Button, Card, Drawer, Dropdown, Empty, Flex, Progress, Space, Table, Tag, Typography, theme } from "antd";
import type { MenuProps } from "antd";
import { useState } from "react";
import { api } from "../api/client";
import { keys, useClients, useSettings } from "../api/queries";
import type { Client, ClientInput } from "../api/schemas";
import { PageHeader } from "../components/PageHeader";
import { Ticket } from "../components/Paper";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import type { Translate } from "../i18n/translate";
import { clientStatus, type ClientState, type ClientStatus } from "../lib/clientStatus";
import { errorText, isEngineError } from "../lib/errors";
import { daysUntil, formatBytes, formatDate, formatDateInZone } from "../lib/format";
import { useIsMobile } from "../lib/useIsMobile";
import { ClientForm } from "./ClientForm";
import { ShareDialog } from "./ShareDialog";

const stateColor: Record<ClientState, string> = {
  active: "success",
  manual: "default",
  quota: "warning",
  expired: "error",
};

function StatusTags({ status }: { status: ClientStatus }) {
  const { t } = useI18n();
  return (
    <Space size={4} wrap>
      <Tag color={stateColor[status.state]}>{t(`clients.state.${status.state}`)}</Tag>
      {status.nearQuota && <Tag color="warning">{t("clients.nearQuota")}</Tag>}
      {status.nearExpiry && <Tag color="warning">{t("clients.nearExpiry")}</Tag>}
    </Space>
  );
}

function Usage({ client, status }: { client: Client; status: ClientStatus }) {
  const { t } = useI18n();
  // The reset day is a day in the panel's time zone, not the browser's.
  const zone = useSettings().data?.timeZone;
  const { token } = theme.useToken();
  const used = formatBytes(status.used);
  const reset = client.nextResetAt ? (
    <Typography.Text type="secondary" style={{ fontSize: 12, display: "block" }}>
      {t("clients.nextReset", { date: zone ? formatDateInZone(client.nextResetAt, zone) : formatDate(client.nextResetAt) })}
    </Typography.Text>
  ) : null;
  if (status.fraction === null) {
    return <div><Typography.Text>{t("clients.usageUnlimited", { used })}</Typography.Text>{reset}</div>;
  }
  const pct = Math.min(100, Math.round(status.fraction * 100));
  const label = t("clients.usage", { used, quota: formatBytes(client.quotaBytes) });
  return (
    <div style={{ minWidth: 140 }}>
      <Typography.Text>{label}</Typography.Text>
      <Progress
        percent={pct}
        size="small"
        showInfo={false}
        status={status.state === "quota" ? "exception" : "normal"}
        strokeColor={status.nearQuota ? token.colorWarning : undefined}
        aria-label={label}
      />
      {reset}
    </div>
  );
}

function expiryText(expiresAt: string | null, t: Translate): string {
  if (!expiresAt) return t("common.never");
  if (new Date(expiresAt).getTime() <= Date.now()) return t("clients.expiredOn", { date: formatDate(expiresAt) });
  const days = daysUntil(expiresAt);
  if (days === 0) return t("clients.expiresToday");
  return t("clients.daysLeft", { days });
}

type Op = "disable" | "enable" | "reset" | "rotate" | "delete";

/** "46 GB" → value 46, unit GB, for a ticket stub. */
function unitSplit(v: string): { value: string; unit: string } {
  const i = v.lastIndexOf(" ");
  return i < 0 ? { value: v, unit: "" } : { value: v.slice(0, i), unit: v.slice(i + 1) };
}

export function ClientsPage() {
  const { t } = useI18n();
  const { message, modal } = App.useApp();
  const qc = useQueryClient();
  const mobile = useIsMobile();
  const clients = useClients();
  const [editing, setEditing] = useState<{ client: Client | null } | null>(null);
  const [sharing, setSharing] = useState<Client | null>(null);

  const refresh = () => Promise.all([
    qc.invalidateQueries({ queryKey: keys.clients }),
    qc.invalidateQueries({ queryKey: keys.status }),
  ]);

  const run = useMutation({
    mutationFn: async ({ op, client }: { op: Op; client: Client }) => {
      switch (op) {
        case "disable": return api.disableClient(client.id);
        case "enable": return api.enableClient(client.id);
        case "reset": return api.resetClientTraffic(client.id);
        case "rotate": return api.rotateClient(client.id);
        case "delete": return api.deleteClient(client.id);
      }
    },
    onSuccess: (_, { op }) => void message.success(t(`clients.done.${op}`)),
    onError: (e) => (isEngineError(e) ? void message.warning(errorText(e, t), 8) : void message.error(errorText(e, t))),
    onSettled: async (_, __, { client, op }) => {
      if (op === "rotate") qc.removeQueries({ queryKey: keys.share(client.id) });
      await refresh();
    },
  });

  const confirm = (op: Op, client: Client) => {
    const base = { okText: t("common.save"), cancelText: t("common.cancel"), onOk: () => run.mutateAsync({ op, client }).catch(() => undefined) };
    if (op === "rotate") {
      modal.confirm({ ...base, title: t("clients.rotateConfirmTitle", { name: client.name }), content: t("clients.rotateConfirm"), okText: t("clients.rotate"), okButtonProps: { danger: true } });
    } else if (op === "delete") {
      modal.confirm({ ...base, title: t("clients.deleteConfirm", { name: client.name }), okText: t("common.delete"), okButtonProps: { danger: true } });
    } else if (op === "reset") {
      modal.confirm({ ...base, title: t("clients.resetConfirm", { name: client.name }), okText: t("clients.resetTraffic") });
    } else {
      run.mutate({ op, client });
    }
  };

  const save = async (input: ClientInput) => {
    const current = editing;
    if (!current) return;
    try {
      if (current.client) await api.updateClient(current.client.id, input);
      else await api.createClient(input);
      void message.success(current.client ? t("common.saved") : t("clients.done.create"));
    } catch (e) {
      if (!isEngineError(e)) throw e;
      void message.warning(errorText(e, t), 8);
    }
    setEditing(null);
    await refresh();
  };

  const menu = (c: Client, status: ClientStatus): MenuProps["items"] => [
    { key: "edit", icon: <EditOutlined />, label: t("common.edit"), onClick: () => setEditing({ client: c }) },
    status.state === "manual"
      ? { key: "enable", icon: <PlayCircleOutlined />, label: t("clients.enable"), onClick: () => confirm("enable", c) }
      : status.state === "active"
        ? { key: "disable", icon: <PauseCircleOutlined />, label: t("clients.disable"), onClick: () => confirm("disable", c) }
        : {
            key: "enable",
            icon: <PlayCircleOutlined />,
            label: t("clients.enable"),
            onClick: () => void modal.info({ title: t("clients.enable"), content: t("clients.enableHint"), okText: t("common.close") }),
          },
    { key: "reset", icon: <UndoOutlined />, label: t("clients.resetTraffic"), onClick: () => confirm("reset", c) },
    { key: "rotate", icon: <KeyOutlined />, label: t("clients.rotate"), onClick: () => confirm("rotate", c) },
    { type: "divider" },
    { key: "delete", icon: <DeleteOutlined />, label: t("common.delete"), danger: true, onClick: () => confirm("delete", c) },
  ];

  const actions = (c: Client, status: ClientStatus) => (
    <Space size={4}>
      <Button icon={<ShareAltOutlined />} onClick={() => setSharing(c)} aria-label={`${t("clients.share")} ${c.name}`}>
        {t("clients.share")}
      </Button>
      <Dropdown menu={{ items: menu(c, status) }} trigger={["click"]}>
        <Button type="text" icon={<MoreOutlined />} aria-label={`${t("common.more")} ${c.name}`} />
      </Dropdown>
    </Space>
  );

  const rows = (clients.data ?? []).map((c) => ({ client: c, status: clientStatus(c) }));

  return (
    <>
      <PageHeader
        title={t("clients.title")}
        subtitle={t("clients.subtitle")}
        extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing({ client: null })}>{t("clients.new")}</Button>}
      />
      <QueryState isPending={clients.isPending} error={clients.error} refetch={clients.refetch} />
      {rows.length > 0 && (
        <div style={{ marginBottom: 18 }}>
          <Ticket items={[
            { label: t("clients.summary.total"), value: rows.length },
            { label: t("clients.summary.active"), value: rows.filter((r) => r.status.state === "active").length },
            { label: t("clients.summary.paused"), value: rows.filter((r) => r.status.state !== "active").length },
            { label: t("clients.summary.used"), ...unitSplit(formatBytes(rows.reduce((n, r) => n + r.client.usedUp + r.client.usedDown, 0))) },
          ]} />
        </div>
      )}
      {clients.data && rows.length === 0 && <Card><Empty description={t("clients.empty")} /></Card>}
      {rows.length > 0 && (mobile ? (
        <div className="card-list">
          {rows.map(({ client: c, status }) => (
            <Card key={c.id} size="small">
              <Flex justify="space-between" align="flex-start" gap={8}>
                <Typography.Text strong style={{ fontSize: 16, minWidth: 0 }} ellipsis>{c.name}</Typography.Text>
                <StatusTags status={status} />
              </Flex>
              <div style={{ marginTop: 8 }}><Usage client={c} status={status} /></div>
              <Flex justify="space-between" align="center" style={{ marginTop: 8 }} gap={8}>
                <Typography.Text type="secondary">{t("clients.col.expiry")}：{expiryText(c.expiresAt, t)}</Typography.Text>
                {actions(c, status)}
              </Flex>
            </Card>
          ))}
        </div>
      ) : (
        <Card styles={{ body: { padding: 0 } }}>
          <Table
            rowKey={(r) => r.client.id}
            dataSource={rows}
            pagination={rows.length > 50 ? { pageSize: 50 } : false}
            columns={[
              { title: t("clients.col.name"), key: "name", render: (_, r) => <Typography.Text strong style={{ whiteSpace: "nowrap" }}>{r.client.name}</Typography.Text> },
              { title: t("clients.col.status"), key: "status", render: (_, r) => <StatusTags status={r.status} /> },
              { title: t("clients.col.usage"), key: "usage", render: (_, r) => <Usage client={r.client} status={r.status} /> },
              {
                title: t("clients.col.expiry"),
                key: "expiry",
                render: (_, r) => (
                  <span title={r.client.expiresAt ? formatDate(r.client.expiresAt) : undefined}>{expiryText(r.client.expiresAt, t)}</span>
                ),
              },
              { title: t("clients.col.actions"), key: "actions", align: "right", render: (_, r) => actions(r.client, r.status) },
            ]}
          />
        </Card>
      ))}

      <Drawer
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={editing?.client ? t("clients.editTitle") : t("clients.newTitle")}
        size={mobile ? "100%" : 460}
        destroyOnHidden
      >
        {editing && <ClientForm client={editing.client} onSubmit={save} onCancel={() => setEditing(null)} />}
      </Drawer>
      <ShareDialog client={sharing} onClose={() => setSharing(null)} />
    </>
  );
}
