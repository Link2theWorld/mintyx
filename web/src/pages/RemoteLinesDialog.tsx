import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import { useQueryClient } from "@tanstack/react-query";
import { App, Button, Flex, Form, Input, Modal, Typography } from "antd";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import { keys, useRemoteLines } from "../api/queries";
import type { Client, RemoteLine } from "../api/schemas";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { errorText } from "../lib/errors";
import { useIsMobile } from "../lib/useIsMobile";

interface Values { link: string; name: string }

/** One line of what the panel read from a remote line's link, without its credential. */
export function remoteLineSummary(r: RemoteLine): string {
  const s = r.summary;
  const kind = s.protocol === "hysteria2" ? "Hysteria2" : `VLESS · ${s.network === "xhttp" ? "XHTTP" : "REALITY"}`;
  const host = s.host.includes(":") ? `[${s.host}]` : s.host;
  return `${kind} · ${host}:${String(s.port)}`;
}

/** The visitor's lines on other servers, which its subscription lists after this server's own. */
export function RemoteLinesDialog({ client, onClose }: { client: Client | null; onClose: () => void }) {
  const { t } = useI18n();
  const { message, modal } = App.useApp();
  const qc = useQueryClient();
  const mobile = useIsMobile();
  const remotes = useRemoteLines(client?.id ?? null);
  const [form] = Form.useForm<Values>();
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    if (!client) return;
    await Promise.all([
      qc.invalidateQueries({ queryKey: keys.remoteLines(client.id) }),
      qc.invalidateQueries({ queryKey: keys.share(client.id) }),
    ]);
  };

  const add = async (v: Values) => {
    if (!client) return;
    setBusy(true);
    try {
      await api.createRemoteLine(client.id, { name: v.name.trim(), link: v.link.trim() });
      void message.success(t("remote.added"));
      form.resetFields();
      await refresh();
    } catch (e) {
      if (e instanceof ApiError && e.field && /^(name|link)/.test(e.field)) {
        form.setFields([{ name: e.field.startsWith("link") ? "link" : "name", errors: [e.message] }]);
      } else void message.error(errorText(e, t));
    } finally {
      setBusy(false);
    }
  };

  const remove = (r: RemoteLine) => {
    if (!client) return;
    modal.confirm({
      title: t("remote.deleteConfirm", { name: r.name }),
      okText: t("common.delete"),
      okButtonProps: { danger: true },
      cancelText: t("common.cancel"),
      onOk: async () => {
        try {
          await api.deleteRemoteLine(client.id, r.id);
          void message.success(t("remote.deleted"));
        } catch (e) {
          void message.error(errorText(e, t));
        }
        await refresh();
      },
    });
  };

  const list = remotes.data ?? [];

  return (
    <Modal
      open={client !== null}
      onCancel={onClose}
      footer={null}
      title={client ? t("remote.title", { name: client.name }) : ""}
      width={mobile ? "100%" : 600}
      style={mobile ? { top: 0, maxWidth: "100%", margin: 0, paddingBottom: 0 } : undefined}
      styles={mobile ? { container: { minHeight: "100vh", borderRadius: 0 } } : undefined}
      destroyOnHidden
    >
      <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>{t("remote.hint")}</Typography.Paragraph>
      <QueryState isPending={remotes.isPending} error={remotes.error} refetch={remotes.refetch} />
      {remotes.data && (list.length === 0 ? (
        <Typography.Paragraph type="secondary">{t("remote.empty")}</Typography.Paragraph>
      ) : (
        <>
          <Flex vertical gap={8} style={{ marginBottom: 12 }} role="list" aria-label={t("remote.listLabel")}>
            {list.map((r) => (
              <div key={r.id} className="paper" role="listitem" style={{ padding: "10px 14px" }}>
                <Flex justify="space-between" align="center" gap={8}>
                  <div style={{ minWidth: 0 }}>
                    <Typography.Text strong ellipsis style={{ display: "block" }}>{r.name}</Typography.Text>
                    <Typography.Text type="secondary" className="mono" style={{ fontSize: 12 }}>{remoteLineSummary(r)}</Typography.Text>
                  </div>
                  <Button type="text" danger icon={<DeleteOutlined />} onClick={() => remove(r)} aria-label={`${t("common.delete")} ${r.name}`} />
                </Flex>
              </div>
            ))}
          </Flex>
          <Typography.Paragraph type="secondary">{t("remote.balanceHint")}</Typography.Paragraph>
        </>
      ))}

      <div className="hand" style={{ fontSize: 20, color: "var(--sky-deep)", margin: "8px 0" }}>{t("remote.addTitle")}</div>
      <Form<Values> form={form} layout="vertical" initialValues={{ link: "", name: "" }} onFinish={(v) => void add(v)} requiredMark={false}>
        <Form.Item name="link" label={t("remote.link")} extra={t("remote.linkHelp")}
          rules={[{ required: true, whitespace: true, message: t("remote.linkRequired") }]}>
          <Input.TextArea rows={3} placeholder="vless://… / hysteria2://…" spellCheck={false} autoComplete="off" />
        </Form.Item>
        <Form.Item name="name" label={t("remote.name")} extra={t("remote.nameHelp")}>
          <Input maxLength={64} />
        </Form.Item>
        <Flex gap={8} justify="flex-end" wrap>
          <Button onClick={onClose}>{t("common.close")}</Button>
          <Button type="primary" htmlType="submit" icon={<PlusOutlined />} loading={busy}>{t("remote.add")}</Button>
        </Flex>
      </Form>
    </Modal>
  );
}
