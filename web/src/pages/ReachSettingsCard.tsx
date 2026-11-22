import { useQueryClient } from "@tanstack/react-query";
import { Alert, App, Button, Card, Divider, Flex, Form, Input, InputNumber, Select, Switch, Typography } from "antd";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import { keys, useReachConfig } from "../api/queries";
import { reachSecurities, type ReachConfig, type ReachConfigInput, type ReachSmtpInput } from "../api/schemas";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { errorText } from "../lib/errors";

export const REACH_MIN_INTERVAL = 10;
export const REACH_MAX_INTERVAL = 1440;
export const REACH_MAX_CONFIRM = 10;

function toForm(cfg: ReachConfig): ReachConfigInput {
  const { host, port, security, username, from, to } = cfg.smtp;
  return { ...cfg, smtp: { host, port, security, username, from, to, password: "" } };
}

const smtpFields = ["host", "port", "security", "username", "password", "from", "to"] as const;
type SmtpField = (typeof smtpFields)[number];
type FormPath = "intervalMinutes" | "confirmRounds" | ["smtp", SmtpField];

/** Maps the server's `field` (e.g. "smtp.host") to the form item it belongs under, if there is one. */
export function reachFieldPath(field: string): FormPath | null {
  if (field === "intervalMinutes" || field === "confirmRounds") return field;
  const sub = smtpFields.find((f) => field === `smtp.${f}`);
  return sub ? ["smtp", sub] : null;
}

function cleanSmtp(v: ReachSmtpInput): ReachSmtpInput {
  return { ...v, host: v.host.trim(), username: v.username.trim(), from: v.from.trim(), to: v.to.trim() };
}

/** The server refuses to reuse a stored password for another server or account; say so before asking it. */
export function needsPasswordAgain(saved: ReachConfig["smtp"], next: ReachSmtpInput): boolean {
  return saved.passwordSet && next.username !== "" && next.password === "" &&
    (next.host !== saved.host || next.username !== saved.username);
}

/** Signing in is refused over an unencrypted connection except to this machine; catch it before the server does.
 *  An empty host turns mail off, so nothing is checked then. */
export function plainSignIn(next: ReachSmtpInput): boolean {
  if (next.host === "") return false;
  const local = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(next.host);
  return next.security === "none" && next.username !== "" && !local;
}

function ReachForm({ config }: { config: ReachConfig }) {
  const { t } = useI18n();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const [form] = Form.useForm<ReachConfigInput>();
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);

  const passwordPath: FormPath = ["smtp", "password"];
  const blockedByPassword = (smtp: ReachSmtpInput): boolean => {
    if (plainSignIn(smtp)) {
      form.setFields([{ name: ["smtp", "security"], errors: [t("reach.settings.security.noneSignIn")] }]);
      return true;
    }
    if (!needsPasswordAgain(config.smtp, smtp)) return false;
    form.setFields([{ name: passwordPath, errors: [t("reach.settings.passwordAgain")] }]);
    return true;
  };
  const showError = (e: unknown) => {
    const path = e instanceof ApiError && e.code === "invalid" && e.field ? reachFieldPath(e.field) : null;
    if (e instanceof ApiError && path) {
      form.setFields([{ name: path, errors: [e.message || t("err.invalid")] }]);
    } else {
      void message.error(errorText(e, t));
    }
  };

  const save = async (v: ReachConfigInput) => {
    const body = { ...v, smtp: cleanSmtp(v.smtp) };
    if (blockedByPassword(body.smtp)) return;
    setSaving(true);
    try {
      const saved = await api.saveReachConfig(body);
      qc.setQueryData(keys.reachConfig, saved);
      form.setFieldValue(passwordPath, "");
      void message.success(t("common.saved"));
      await qc.invalidateQueries({ queryKey: keys.reachStatus });
    } catch (e) {
      showError(e);
    } finally {
      setSaving(false);
    }
  };

  const sendTest = async () => {
    const smtp = cleanSmtp(form.getFieldValue("smtp") as ReachSmtpInput);
    if (blockedByPassword(smtp)) return;
    setTesting(true);
    setTestError(null);
    try {
      const res = await api.reachTestEmail(smtp);
      if (res.sent) void message.success(t("reach.settings.testSent"));
      else setTestError(res.error);
    } catch (e) {
      showError(e);
    } finally {
      setTesting(false);
    }
  };

  return (
    <Form<ReachConfigInput> form={form} layout="vertical" initialValues={toForm(config)} onFinish={(v) => void save(v)} style={{ maxWidth: 520 }}>
      <Form.Item name="enabled" label={t("reach.settings.enabled")} valuePropName="checked">
        <Switch />
      </Form.Item>
      <Form.Item name="intervalMinutes" label={t("reach.settings.interval")} extra={t("reach.settings.intervalHelp")}>
        <InputNumber min={REACH_MIN_INTERVAL} max={REACH_MAX_INTERVAL} precision={0} style={{ width: 160 }} />
      </Form.Item>
      <Form.Item name="confirmRounds" label={t("reach.settings.confirm")} extra={t("reach.settings.confirmHelp")}>
        <InputNumber min={1} max={REACH_MAX_CONFIRM} precision={0} style={{ width: 160 }} />
      </Form.Item>

      <Divider titlePlacement="start">{t("reach.settings.mail")}</Divider>
      <Typography.Paragraph type="secondary">{t("reach.settings.mailHint")}</Typography.Paragraph>
      <Form.Item name={["smtp", "host"]} label={t("reach.settings.smtpHost")} extra={t("reach.settings.smtpHostHelp")}>
        <Input placeholder="smtp.example.com" autoComplete="off" />
      </Form.Item>
      <Flex gap={16} wrap>
        <Form.Item name={["smtp", "security"]} label={t("reach.settings.security")} style={{ flex: "1 1 240px" }}>
          <Select options={reachSecurities.map((s) => ({ value: s, label: t(`reach.settings.security.${s}`) }))} />
        </Form.Item>
        <Form.Item name={["smtp", "port"]} label={t("reach.settings.smtpPort")}>
          <InputNumber min={1} max={65535} precision={0} style={{ width: 120 }} />
        </Form.Item>
      </Flex>
      <Form.Item name={["smtp", "username"]} label={t("reach.settings.username")} extra={t("reach.settings.usernameHelp")}>
        <Input autoComplete="off" />
      </Form.Item>
      <Form.Item name={passwordPath} label={t("reach.settings.password")} extra={t("reach.settings.passwordHelp")}>
        <Input.Password autoComplete="new-password" placeholder={config.smtp.passwordSet ? t("reach.settings.passwordKeep") : undefined} />
      </Form.Item>
      <Form.Item name={["smtp", "from"]} label={t("reach.settings.from")}>
        <Input placeholder="you@example.com" inputMode="email" autoComplete="off" />
      </Form.Item>
      <Form.Item name={["smtp", "to"]} label={t("reach.settings.to")} extra={t("reach.settings.toHelp")}>
        <Input placeholder="you@example.com" autoComplete="off" />
      </Form.Item>
      {testError !== null && (
        <Alert type="error" showIcon title={t("reach.settings.testFailed")} description={testError} style={{ marginBottom: 16 }} />
      )}
      <Flex gap={12} wrap>
        <Button type="primary" htmlType="submit" loading={saving}>{t("common.save")}</Button>
        <Button onClick={() => void sendTest()} loading={testing}>{t("reach.settings.test")}</Button>
      </Flex>
    </Form>
  );
}

/** Settings card for the from-China reachability check and its email alerts. */
export function ReachSettingsCard() {
  const { t } = useI18n();
  const config = useReachConfig();
  return (
    <Card title={t("reach.settings.title")}>
      <Typography.Paragraph>{t("reach.settings.intro")}</Typography.Paragraph>
      <Alert type="info" showIcon title={t("reach.settings.disclosure")} style={{ marginBottom: 16 }} />
      <QueryState isPending={config.isPending} error={config.error} refetch={config.refetch} />
      {config.data && <ReachForm config={config.data} />}
    </Card>
  );
}
