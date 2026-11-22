import { LogoutOutlined } from "@ant-design/icons";
import { useQueryClient } from "@tanstack/react-query";
import { App, Button, Card, Flex, Form, Input, Typography } from "antd";
import { useState } from "react";
import { ApiError, api } from "../api/client";
import { keys, useSession, useSettings } from "../api/queries";
import type { Settings } from "../api/schemas";
import { PageHeader } from "../components/PageHeader";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { useLogout } from "../layout/Shell";
import { PreferencesBlock } from "../layout/Preferences";
import { errorText } from "../lib/errors";
import { MIN_PASSWORD } from "./AuthPages";
import { ReachSettingsCard } from "./ReachSettingsCard";

function GeneralCard() {
  const { t } = useI18n();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const settings = useSettings();
  const [form] = Form.useForm<Settings>();
  const [busy, setBusy] = useState(false);

  const save = async (v: Settings) => {
    setBusy(true);
    try {
      await api.saveSettings({ publicHost: v.publicHost.trim(), subscriptionBaseUrl: v.subscriptionBaseUrl.trim() });
      void message.success(t("common.saved"));
      await qc.invalidateQueries({ queryKey: keys.settings });
    } catch (e) {
      if (e instanceof ApiError && e.field && (e.field === "publicHost" || e.field === "subscriptionBaseUrl")) {
        form.setFields([{ name: e.field, errors: [e.message || t("err.invalid")] }]);
      } else {
        void message.error(errorText(e, t));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title={t("settings.general")}>
      <QueryState isPending={settings.isPending} error={settings.error} refetch={settings.refetch} />
      {settings.data && (
        <Form<Settings> form={form} layout="vertical" initialValues={settings.data} onFinish={(v) => void save(v)}>
          <Form.Item name="publicHost" label={t("settings.publicHost")} extra={t("settings.publicHostHelp")}>
            <Input placeholder="example.com" />
          </Form.Item>
          <Form.Item name="subscriptionBaseUrl" label={t("settings.subBase")} extra={t("settings.subBaseHelp")}>
            <Input placeholder="https://example.com:8443" inputMode="url" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={busy}>{t("common.save")}</Button>
        </Form>
      )}
    </Card>
  );
}

interface PasswordValues { current: string; next: string; confirm: string }

function PasswordCard() {
  const { t } = useI18n();
  const { message } = App.useApp();
  const [form] = Form.useForm<PasswordValues>();
  const [busy, setBusy] = useState(false);

  const save = async (v: PasswordValues) => {
    setBusy(true);
    try {
      await api.changePassword(v.current, v.next);
      form.resetFields();
      void message.success(t("settings.passwordChanged"));
    } catch (e) {
      if (e instanceof ApiError && (e.code === "unauthorized" || (e.code === "invalid" && e.field === "current"))) {
        form.setFields([{ name: "current", errors: [t("settings.wrongPassword")] }]);
      } else if (e instanceof ApiError && e.code === "invalid" && e.field === "new") {
        form.setFields([{ name: "next", errors: [e.message || t("auth.passwordTooShort")] }]);
      } else {
        void message.error(errorText(e, t));
      }
    } finally {
      setBusy(false);
    }
  };

  const required = { required: true, message: t("auth.required") };
  return (
    <Card title={t("settings.password")}>
      <Typography.Paragraph type="secondary">{t("settings.passwordHint")}</Typography.Paragraph>
      <Form<PasswordValues> form={form} layout="vertical" onFinish={(v) => void save(v)} requiredMark={false} style={{ maxWidth: 420 }}>
        <input type="text" name="username" autoComplete="username" hidden readOnly />
        <Form.Item name="current" label={t("settings.currentPassword")} rules={[required]}>
          <Input.Password autoComplete="current-password" />
        </Form.Item>
        <Form.Item name="next" label={t("settings.newPassword")} extra={t("auth.passwordTooShort")} rules={[required, { min: MIN_PASSWORD, message: t("auth.passwordTooShort") }]}>
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Form.Item
          name="confirm"
          label={t("auth.passwordConfirm")}
          dependencies={["next"]}
          rules={[
            required,
            ({ getFieldValue }) => ({
              validator: (_, value: unknown) =>
                value === getFieldValue("next") ? Promise.resolve() : Promise.reject(new Error(t("auth.passwordMismatch"))),
            }),
          ]}
        >
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={busy}>{t("settings.password")}</Button>
      </Form>
    </Card>
  );
}

export function SettingsPage() {
  const { t } = useI18n();
  const session = useSession();
  const logout = useLogout();
  return (
    <>
      <PageHeader title={t("settings.title")} />
      <Flex vertical gap={16}>
        <GeneralCard />
        <ReachSettingsCard />
        <PasswordCard />
        <Card title={t("settings.appearance")}>
          <div style={{ maxWidth: 420 }}><PreferencesBlock /></div>
        </Card>
        <Card title={t("settings.account")}>
          <Flex justify="space-between" align="center" gap={12} wrap>
            <Typography.Text>{t("settings.signedInAs", { name: session.data?.username ?? "—" })}</Typography.Text>
            <Button icon={<LogoutOutlined />} onClick={() => void logout()}>{t("nav.logout")}</Button>
          </Flex>
        </Card>
      </Flex>
    </>
  );
}
