import { App, Button, Flex, Form, Input, InputNumber, Radio, Select, Switch, Typography } from "antd";
import { useEffect, useState } from "react";
import { ApiError } from "../api/client";
import { lineDraftSchema, protocols, regions, type LineDraft, type Protocol, type Region } from "../api/schemas";
import { useI18n } from "../i18n/I18nProvider";
import type { MessageKey } from "../i18n/zh";
import { errorText, fieldErrorText } from "../lib/errors";

type Block = "reality" | "xhttp" | "hysteria2";
const blockOf: Record<Protocol, Block> = {
  "vless-reality": "reality",
  "vless-xhttp": "xhttp",
  hysteria2: "hysteria2",
};

const commonFields = ["name", "port", "enabled", "host"] as const;
const blockFields: Record<Block, readonly string[]> = {
  reality: ["serverName", "target", "shortId", "publicKey"],
  xhttp: ["domain", "path", "security", "certFile", "keyFile"],
  hysteria2: ["domain", "certFile", "keyFile", "obfsPassword"],
};

type CommonField = (typeof commonFields)[number];
export type LineFieldPath = CommonField | ["reality", string] | ["xhttp", string] | ["hysteria2", string];

function blockPath(block: Block, leaf: string): LineFieldPath {
  switch (block) {
    case "reality": return ["reality", leaf];
    case "xhttp": return ["xhttp", leaf];
    case "hysteria2": return ["hysteria2", leaf];
  }
}

function isCommon(field: string): field is CommonField {
  return (commonFields as readonly string[]).includes(field);
}

/**
 * Maps a server error `field` onto a form path. API.md does not say whether
 * nested fields arrive as "reality.serverName" or "serverName", so both work.
 */
export function formPathFor(field: string, protocol: Protocol): LineFieldPath | null {
  const block = blockOf[protocol];
  const parts = field.split(".");
  if (parts.length === 1) {
    if (isCommon(field)) return field;
    return blockFields[block].includes(field) ? blockPath(block, field) : null;
  }
  const [head, leaf] = parts;
  if (parts.length === 2 && head === block && leaf !== undefined && blockFields[block].includes(leaf)) return blockPath(block, leaf);
  return null;
}

interface FormValues {
  name?: string;
  port?: number | null;
  enabled?: boolean;
  host?: string;
  reality?: Record<string, string | undefined>;
  xhttp?: Record<string, string | undefined>;
  hysteria2?: Record<string, string | undefined>;
}

/** Merges edited values over the starting line so unrendered fields (e.g. publicKey) survive. */
export function buildLine(initial: LineDraft, v: FormValues): LineDraft {
  const block = blockOf[initial.protocol];
  const startBlock: Record<string, string> =
    initial.protocol === "vless-reality" ? initial.reality : initial.protocol === "vless-xhttp" ? initial.xhttp : initial.hysteria2;
  const edited = v[block] ?? {};
  const merged: Record<string, string> = { ...startBlock };
  for (const [k, val] of Object.entries(edited)) if (val !== undefined) merged[k] = val.trim();
  return lineDraftSchema.parse({
    protocol: initial.protocol,
    name: (v.name ?? initial.name).trim(),
    port: v.port ?? initial.port,
    enabled: v.enabled ?? initial.enabled,
    host: (v.host ?? initial.host).trim(),
    [block]: merged,
  });
}

function Optional({ k }: { k: MessageKey }) {
  const { t } = useI18n();
  return <>{t(k)} <Typography.Text type="secondary">({t("common.optional")})</Typography.Text></>;
}

function Help({ k }: { k: MessageKey }) {
  const { t } = useI18n();
  return <span className="field-help">{t(k)}</span>;
}

export interface LineFormProps {
  mode: "create" | "edit";
  initial: LineDraft;
  /** Create mode only: the user picked another protocol, so the parent fetches a new draft. */
  onProtocolChange?: (p: Protocol) => void;
  /** Create mode only: where the server is, "" for not sure. A change makes the parent fetch a draft for it. */
  region?: Region | "";
  onRegionChange?: (r: Region | "") => void;
  onSubmit: (line: LineDraft) => Promise<void>;
  onCancel: () => void;
}

export function LineForm({ mode, initial, onProtocolChange, region = "", onRegionChange, onSubmit, onCancel }: LineFormProps) {
  const { t } = useI18n();
  const { message } = App.useApp();
  const [form] = Form.useForm<FormValues>();
  const [busy, setBusy] = useState(false);
  const protocol = initial.protocol;
  const xhttpSecurity = Form.useWatch(["xhttp", "security"], form) as string | undefined;
  const required = [{ required: true, whitespace: true, message: t("auth.required") }];

  // A draft for another region arrives as a new `initial`; only its cover site may overwrite the form.
  useEffect(() => {
    if (mode !== "create" || initial.protocol !== "vless-reality") return;
    form.setFieldsValue({ reality: { serverName: initial.reality.serverName, target: initial.reality.target } });
  }, [form, mode, initial]);

  const finish = async (values: FormValues) => {
    setBusy(true);
    try {
      await onSubmit(buildLine(initial, values));
    } catch (e) {
      const path = e instanceof ApiError && e.field ? formPathFor(e.field, protocol) : null;
      if (e instanceof ApiError && path) {
        form.setFields([{ name: path, errors: [fieldErrorText(e, t)] }]);
        form.scrollToField(path, { block: "center" });
      } else {
        void message.error(errorText(e, t));
      }
    } finally {
      setBusy(false);
    }
  };

  const publicKey = initial.protocol === "vless-reality" ? initial.reality.publicKey : "";

  return (
    <Form<FormValues>
      form={form}
      layout="vertical"
      initialValues={initial}
      onFinish={(v) => void finish(v)}
      requiredMark={false}
      scrollToFirstError
    >
      <Form.Item label={t("lineForm.protocol")} extra={mode === "edit" ? t("lineForm.protocolLocked") : undefined}>
        <Radio.Group
          value={protocol}
          disabled={mode === "edit"}
          onChange={(e) => onProtocolChange?.(e.target.value as Protocol)}
          style={{ width: "100%" }}
        >
          <Flex vertical gap={8}>
            {protocols.map((p) => (
              <Radio key={p} value={p}>
                <Typography.Text strong>{t(`protocol.${p}`)}</Typography.Text>
                <br />
                <Typography.Text type="secondary" style={{ fontSize: 13 }}>{t(`protocol.${p}.desc`)}</Typography.Text>
              </Radio>
            ))}
          </Flex>
        </Radio.Group>
      </Form.Item>

      <Form.Item name="name" label={t("lineForm.name")} extra={<Help k="lineForm.nameHelp" />} rules={required}>
        <Input maxLength={64} />
      </Form.Item>
      <Form.Item
        name="port"
        label={t("lineForm.port")}
        extra={<Help k="lineForm.portHelp" />}
        rules={[{ required: true, message: t("auth.required") }]}
      >
        <InputNumber min={1} max={65535} precision={0} style={{ width: "100%" }} />
      </Form.Item>
      <Form.Item name="host" label={<Optional k="lineForm.host" />} extra={<Help k="lineForm.hostHelp" />}>
        <Input placeholder="example.com" />
      </Form.Item>

      {protocol === "vless-reality" && (
        <>
          {mode === "create" && onRegionChange && (
            <Form.Item label={t("lines.region")} htmlFor="line-region" extra={<Help k="lines.regionHelp" />}>
              <Select<Region | "">
                id="line-region"
                value={region}
                onChange={(r) => onRegionChange(r)}
                options={[
                  { value: "", label: t("lines.region.auto") },
                  ...regions.map((r) => ({ value: r, label: t(`lines.region.${r}`) })),
                ]}
              />
            </Form.Item>
          )}
          <Form.Item name={["reality", "serverName"]} label={t("lineForm.reality.serverName")} extra={<Help k="lineForm.reality.serverNameHelp" />} rules={required}>
            <Input placeholder="www.example.com" />
          </Form.Item>
          <Form.Item name={["reality", "target"]} label={t("lineForm.reality.target")} extra={<Help k="lineForm.reality.targetHelp" />} rules={required}>
            <Input placeholder="www.example.com:443" />
          </Form.Item>
          <Form.Item name={["reality", "shortId"]} label={<Optional k="lineForm.reality.shortId" />} extra={<Help k="lineForm.reality.shortIdHelp" />}>
            <Input />
          </Form.Item>
          <Form.Item label={t("lineForm.reality.publicKey")}>
            <Typography.Text code={publicKey !== ""} type={publicKey ? undefined : "secondary"} copyable={publicKey ? { text: publicKey } : false} style={{ overflowWrap: "anywhere" }}>
              {publicKey || t("lineForm.reality.publicKeyPending")}
            </Typography.Text>
          </Form.Item>
        </>
      )}

      {protocol === "vless-xhttp" && (
        <>
          <Form.Item name={["xhttp", "domain"]} label={t("lineForm.xhttp.domain")} extra={<Help k="lineForm.xhttp.domainHelp" />} rules={required}>
            <Input placeholder="example.com" />
          </Form.Item>
          <Form.Item name={["xhttp", "security"]} label={t("lineForm.xhttp.security")} extra={<Help k="lineForm.xhttp.securityHelp" />}>
            <Radio.Group>
              <Flex vertical gap={6}>
                <Radio value="tls">{t("lineForm.xhttp.tls")}</Radio>
                <Radio value="none">{t("lineForm.xhttp.none")}</Radio>
              </Flex>
            </Radio.Group>
          </Form.Item>
          {xhttpSecurity !== "none" && (
            <>
              <Form.Item name={["xhttp", "certFile"]} label={t("lineForm.certFile")} extra={<Help k="lineForm.certFileHelp" />} rules={required}>
                <Input placeholder="/etc/ssl/example.com/fullchain.pem" />
              </Form.Item>
              <Form.Item name={["xhttp", "keyFile"]} label={t("lineForm.keyFile")} extra={<Help k="lineForm.keyFileHelp" />} rules={required}>
                <Input placeholder="/etc/ssl/example.com/privkey.pem" />
              </Form.Item>
            </>
          )}
          <Form.Item name={["xhttp", "path"]} label={t("lineForm.xhttp.path")} extra={<Help k="lineForm.xhttp.pathHelp" />} rules={required}>
            <Input />
          </Form.Item>
        </>
      )}

      {protocol === "hysteria2" && (
        <>
          <Form.Item name={["hysteria2", "domain"]} label={t("lineForm.hy2.domain")} extra={<Help k="lineForm.hy2.domainHelp" />} rules={required}>
            <Input placeholder="example.com" />
          </Form.Item>
          <Form.Item name={["hysteria2", "certFile"]} label={t("lineForm.certFile")} extra={<Help k="lineForm.certFileHelp" />} rules={required}>
            <Input placeholder="/etc/ssl/example.com/fullchain.pem" />
          </Form.Item>
          <Form.Item name={["hysteria2", "keyFile"]} label={t("lineForm.keyFile")} extra={<Help k="lineForm.keyFileHelp" />} rules={required}>
            <Input placeholder="/etc/ssl/example.com/privkey.pem" />
          </Form.Item>
          <Form.Item name={["hysteria2", "obfsPassword"]} label={<Optional k="lineForm.hy2.obfs" />} extra={<Help k="lineForm.hy2.obfsHelp" />}>
            <Input.Password autoComplete="off" visibilityToggle />
          </Form.Item>
        </>
      )}

      <Form.Item name="enabled" label={t("lineForm.enabled")} valuePropName="checked">
        <Switch />
      </Form.Item>

      <Flex gap={8} justify="flex-end">
        <Button onClick={onCancel}>{t("common.cancel")}</Button>
        <Button type="primary" htmlType="submit" loading={busy}>
          {mode === "create" ? t("common.create") : t("common.save")}
        </Button>
      </Flex>
    </Form>
  );
}
