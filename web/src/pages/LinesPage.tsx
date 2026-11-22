import { DeleteOutlined, EditOutlined, PlusOutlined } from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { App, Button, Card, Drawer, Empty, Flex, Popconfirm, Space, Table, Tag, Typography } from "antd";
import { useState } from "react";
import { api } from "../api/client";
import { keys, useLines } from "../api/queries";
import { lineDraftSchema, type Line, type LineDraft, type Protocol } from "../api/schemas";
import { PageHeader } from "../components/PageHeader";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { errorText, isEngineError } from "../lib/errors";
import { useIsMobile } from "../lib/useIsMobile";
import { LineForm } from "./LineForm";

type Editing = { mode: "create"; protocol: Protocol } | { mode: "edit"; line: Line } | null;

/** Drops id/createdAt (zod strips unknown keys) to get the update payload shape. */
function toDraft(line: Line): LineDraft {
  return lineDraftSchema.parse(line);
}

function CreateLine({ protocol, onProtocolChange, onSubmit, onCancel }: {
  protocol: Protocol;
  onProtocolChange: (p: Protocol) => void;
  onSubmit: (l: LineDraft) => Promise<void>;
  onCancel: () => void;
}) {
  const draft = useQuery({
    queryKey: ["lineDraft", protocol],
    queryFn: () => api.lineDraft(protocol),
    gcTime: 0,
    staleTime: Infinity,
  });
  if (!draft.data) return <QueryState isPending={draft.isPending} error={draft.error} refetch={draft.refetch} />;
  return (
    <LineForm key={protocol} mode="create" initial={draft.data} onProtocolChange={onProtocolChange} onSubmit={onSubmit} onCancel={onCancel} />
  );
}

export function LinesPage() {
  const { t } = useI18n();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const mobile = useIsMobile();
  const lines = useLines();
  const [editing, setEditing] = useState<Editing>(null);

  const refresh = () => Promise.all([
    qc.invalidateQueries({ queryKey: keys.lines }),
    qc.invalidateQueries({ queryKey: keys.status }),
  ]);

  // An "engine" error means the line was saved but Xray rejected it: close and warn.
  const save = async (line: LineDraft) => {
    const current = editing;
    if (!current) return;
    try {
      if (current.mode === "create") await api.createLine(line);
      else await api.updateLine(current.line.id, line);
      void message.success(current.mode === "create" ? t("lines.created") : t("common.saved"));
    } catch (e) {
      if (!isEngineError(e)) throw e;
      void message.warning(errorText(e, t), 8);
    }
    setEditing(null);
    await refresh();
  };

  const remove = useMutation({
    mutationFn: (id: number) => api.deleteLine(id),
    onSuccess: () => void message.success(t("lines.deleted")),
    onError: (e) => (isEngineError(e) ? void message.warning(errorText(e, t), 8) : void message.error(errorText(e, t))),
    onSettled: refresh,
  });

  const actions = (l: Line) => (
    <Space size={4}>
      <Button type="text" icon={<EditOutlined />} onClick={() => setEditing({ mode: "edit", line: l })} aria-label={`${t("common.edit")} ${l.name}`}>
        {mobile ? t("common.edit") : null}
      </Button>
      <Popconfirm
        title={t("lines.deleteConfirm", { name: l.name })}
        okText={t("common.delete")}
        okButtonProps={{ danger: true }}
        cancelText={t("common.cancel")}
        onConfirm={() => remove.mutate(l.id)}
      >
        <Button type="text" danger icon={<DeleteOutlined />} aria-label={`${t("common.delete")} ${l.name}`}>
          {mobile ? t("common.delete") : null}
        </Button>
      </Popconfirm>
    </Space>
  );

  const statusTag = (l: Line) => (l.enabled ? <Tag color="success">{t("common.enabled")}</Tag> : <Tag>{t("common.disabled")}</Tag>);
  const data = lines.data ?? [];

  return (
    <>
      <PageHeader
        title={t("lines.title")}
        subtitle={t("lines.subtitle")}
        extra={
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing({ mode: "create", protocol: "vless-reality" })}>
            {t("lines.new")}
          </Button>
        }
      />
      <QueryState isPending={lines.isPending} error={lines.error} refetch={lines.refetch} />
      {lines.data && data.length === 0 && <Card><Empty description={t("lines.empty")} /></Card>}
      {data.length > 0 && (mobile ? (
        <div className="card-list">
          {data.map((l) => (
            <Card key={l.id} size="small">
              <Flex justify="space-between" align="flex-start" gap={8}>
                <div style={{ minWidth: 0 }}>
                  <Typography.Text strong style={{ fontSize: 16 }}>{l.name}</Typography.Text>
                  <div>
                    <Typography.Text type="secondary">{t(`protocol.${l.protocol}`)} · {t("lines.col.port")} {l.port}</Typography.Text>
                  </div>
                </div>
                {statusTag(l)}
              </Flex>
              <Flex justify="flex-end" style={{ marginTop: 8 }}>{actions(l)}</Flex>
            </Card>
          ))}
        </div>
      ) : (
        <Card styles={{ body: { padding: 0 } }}>
          <Table<Line>
            rowKey="id"
            dataSource={data}
            pagination={false}
            columns={[
              { title: t("lines.col.name"), dataIndex: "name", render: (v: string) => <Typography.Text strong>{v}</Typography.Text> },
              { title: t("lines.col.protocol"), dataIndex: "protocol", render: (p: Protocol) => t(`protocol.${p}`) },
              { title: t("lines.col.port"), dataIndex: "port", width: 100 },
              { title: t("lines.col.status"), key: "status", width: 100, render: (_, l) => statusTag(l) },
              { title: t("lines.col.actions"), key: "actions", width: 120, align: "right", render: (_, l) => actions(l) },
            ]}
          />
        </Card>
      ))}

      <Drawer
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={editing?.mode === "edit" ? t("lines.editTitle") : t("lines.newTitle")}
        size={mobile ? "100%" : 520}
        destroyOnHidden
      >
        {editing?.mode === "create" && (
          <CreateLine
            protocol={editing.protocol}
            onProtocolChange={(p) => setEditing({ mode: "create", protocol: p })}
            onSubmit={save}
            onCancel={() => setEditing(null)}
          />
        )}
        {editing?.mode === "edit" && (
          <LineForm key={editing.line.id} mode="edit" initial={toDraft(editing.line)} onSubmit={save} onCancel={() => setEditing(null)} />
        )}
      </Drawer>
    </>
  );
}
