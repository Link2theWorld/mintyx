import { CopyOutlined, DeleteOutlined } from "@ant-design/icons";
import { useQueryClient } from "@tanstack/react-query";
import { Alert, App, Button, Descriptions, Drawer, Flex, Form, Input, Select, Typography } from "antd";
import { useEffect, useState } from "react";
import { ApiError, api } from "../../api/client";
import { keys } from "../../api/queries";
import { regions, type Exit, type ExitLatency, type ExitSummary } from "../../api/schemas";
import { useI18n } from "../../i18n/I18nProvider";
import { errorText, isEngineError } from "../../lib/errors";
import { useIsMobile } from "../../lib/useIsMobile";

interface Values { name: string; region: string; link: string }

function Summary({ s }: { s: ExitSummary }) {
  const { t } = useI18n();
  const security = s.security === "none" ? t("exitForm.securityNone") : s.security.toUpperCase();
  return (
    <>
      <Descriptions size="small" column={1} items={[
        { key: "p", label: t("exitForm.protocol"), children: s.protocol.toUpperCase() + (s.method ? ` · ${s.method}` : "") + (s.flow ? ` · ${s.flow}` : "") },
        { key: "a", label: t("exitForm.address"), children: <span className="mono">{s.host}:{s.port}</span> },
        { key: "s", label: t("exitForm.security"), children: security + (s.serverName ? ` · ${s.serverName}` : "") + (s.pinned ? ` · ${t("exitForm.pinned")}` : "") },
        ...(s.network ? [{ key: "n", label: t("exitForm.transport"), children: s.network }] : []),
      ]} />
      {s.plaintext && <Alert type="warning" showIcon title={t("exitForm.plaintext")} style={{ marginTop: 8 }} />}
      {s.udp && <Alert type="info" showIcon title={t("exitForm.udp")} style={{ marginTop: 8 }} />}
    </>
  );
}

/** Adding an exit (exit null) or looking at and changing one. */
export function ExitDrawer({ open, exit, latency, onClose }: {
  open: boolean;
  exit: Exit | null;
  latency?: ExitLatency["exits"][number];
  onClose: () => void;
}) {
  const { t } = useI18n();
  const { message, modal } = App.useApp();
  const qc = useQueryClient();
  const mobile = useIsMobile();
  const [form] = Form.useForm<Values>();
  const [busy, setBusy] = useState(false);
  // The preview belongs to the link it was read from, so an edited link never shows a stale one.
  const [read, setRead] = useState<{ link: string; name: string; summary: ExitSummary } | null>(null);
  const link = (Form.useWatch<string | undefined>("link", form) ?? "").trim();
  const preview = read && read.link === link ? read : null;

  // Shows what the panel reads from a pasted link before anything is saved.
  useEffect(() => {
    if (!link) {
      form.setFields([{ name: "link", errors: [] }]);
      return;
    }
    // An answer for a link the admin has since changed is dropped, whenever it arrives.
    let current = true;
    const timer = setTimeout(() => {
      api.parseExit(link).then(
        (p) => { if (current) { setRead({ link, ...p }); form.setFields([{ name: "link", errors: [] }]); } },
        (e: unknown) => { if (current) form.setFields([{ name: "link", errors: [errorText(e, t)] }]); },
      );
    }, 350);
    return () => { current = false; clearTimeout(timer); };
  }, [link, form, t]);

  const refresh = () => Promise.all([qc.invalidateQueries({ queryKey: keys.exits }), qc.invalidateQueries({ queryKey: keys.lines })]);

  const save = async (v: Values) => {
    setBusy(true);
    try {
      const input = { name: v.name.trim(), region: v.region, link: v.link.trim() };
      if (exit) await api.updateExit(exit.id, input);
      else await api.createExit(input);
      void message.success(exit ? t("common.saved") : t("exitForm.created"));
      await refresh();
      onClose();
    } catch (e) {
      if (isEngineError(e)) {
        // Saved, but Xray did not take it: show where things stand and say why.
        void message.warning(errorText(e, t), 8);
        await refresh();
        onClose();
        return;
      }
      if (e instanceof ApiError && e.field && /^(name|region|link)/.test(e.field)) {
        const field = e.field.startsWith("link") ? "link" : (e.field as "name" | "region");
        form.setFields([{ name: field, errors: [e.message] }]);
      } else void message.error(errorText(e, t));
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    if (!exit) return;
    try {
      const c = await api.copyExit(exit.id);
      void message.success(t("exitForm.copied", { name: c.name }));
      await refresh();
      onClose();
    } catch (e) {
      void message.error(errorText(e, t));
    }
  };

  const remove = async (unlink: boolean) => {
    if (!exit) return;
    try {
      await api.deleteExit(exit.id, unlink);
      void message.success(t("exitForm.deleted"));
      await refresh();
      onClose();
    } catch (e) {
      if (isEngineError(e)) {
        void message.warning(errorText(e, t), 8);
        await refresh();
        onClose();
        return;
      }
      if (!unlink && e instanceof ApiError && e.code === "conflict") {
        modal.confirm({
          title: t("exitForm.deleteInUse"),
          content: e.message,
          okText: t("exitForm.deleteAnyway"),
          okButtonProps: { danger: true },
          cancelText: t("common.cancel"),
          onOk: () => remove(true),
        });
      } else void message.error(errorText(e, t));
    }
  };

  const regionOptions = [{ value: "", label: t("exitForm.regionUnknown") }, ...regions.map((r) => ({ value: r, label: t(`lines.region.${r}`) }))];

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={exit ? t("exitForm.titleEdit", { name: exit.name }) : t("exitForm.titleNew")}
      size={mobile ? "100%" : 460}
      placement={mobile ? "bottom" : "right"}
      destroyOnHidden
    >
      <Flex vertical gap={18}>
        {exit && (
          <div>
            <Summary s={exit.summary} />
            {latency && (
              <Typography.Paragraph type="secondary" style={{ margin: "8px 0 0" }}>
                {latency.unmeasured === "udp" ? t("graph.latencyUdp")
                  : latency.unmeasured === "inner" ? t("graph.latencyInnerHelp")
                    : latency.error ? `${t("graph.latencyFail")}：${latency.error}`
                      : latency.rttMs !== null ? t("exitForm.latency", { ms: latency.rttMs }) : t("graph.latencyPending")}
              </Typography.Paragraph>
            )}
          </div>
        )}
        <Form<Values>
          form={form}
          layout="vertical"
          initialValues={{ name: exit?.name ?? "", region: exit?.region ?? "", link: "" }}
          onFinish={(v) => void save(v)}
          requiredMark={false}
        >
          <Form.Item name="link" label={t("exitForm.link")} extra={exit ? t("exitForm.linkKeep") : t("exitForm.linkHelp")}
            rules={exit ? [] : [{ required: true, whitespace: true, message: t("exitForm.linkRequired") }]}>
            <Input.TextArea rows={3} placeholder="vless://… / hysteria2://… / ss://…" spellCheck={false} autoComplete="off" />
          </Form.Item>
          {preview && (
            <div className="paper" style={{ marginBottom: 18 }}>
              <div className="hand" style={{ fontSize: 20, color: "var(--sky-deep)", marginBottom: 6 }}>{t("exitForm.preview")}</div>
              <Summary s={preview.summary} />
            </div>
          )}
          <Form.Item name="name" label={t("exitForm.name")} extra={t("exitForm.nameHelp")}>
            <Input maxLength={64} placeholder={preview?.name || undefined} />
          </Form.Item>
          <Form.Item name="region" label={t("exitForm.region")}>
            <Select aria-label={t("exitForm.region")} options={regionOptions} />
          </Form.Item>
          <Flex gap={8} justify="flex-end" wrap>
            <Button onClick={onClose}>{t("common.cancel")}</Button>
            <Button type="primary" htmlType="submit" loading={busy}>{exit ? t("common.save") : t("common.create")}</Button>
          </Flex>
        </Form>
        {exit && (
          <Flex vertical gap={8}>
            <Typography.Text type="secondary">{t("exitForm.copyHelp")}</Typography.Text>
            <Flex gap={8} wrap>
              <Button icon={<CopyOutlined />} onClick={() => void copy()}>{t("exitForm.copy")}</Button>
              <Button danger icon={<DeleteOutlined />} onClick={() => modal.confirm({
                title: t("exitForm.deleteConfirm", { name: exit.name }),
                okText: t("common.delete"), okButtonProps: { danger: true }, cancelText: t("common.cancel"),
                onOk: () => remove(false),
              })}>{t("exitForm.delete")}</Button>
            </Flex>
          </Flex>
        )}
      </Flex>
    </Drawer>
  );
}
