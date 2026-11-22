import { useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Card, Flex, Form, Input, Typography } from "antd";
import { useState } from "react";
import { useNavigate } from "react-router";
import { ApiError, api } from "../api/client";
import { keys } from "../api/queries";
import { useI18n } from "../i18n/I18nProvider";
import { Logo } from "../layout/Logo";
import { LangPicker, ThemePicker } from "../layout/Preferences";
import { errorText } from "../lib/errors";

export const MIN_PASSWORD = 10;

interface Credentials {
  username: string;
  password: string;
  confirm?: string;
}

function AuthCard({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  const { t } = useI18n();
  return (
    <div className="auth-wrap">
      <Card className="tilt-3" style={{ width: "100%", maxWidth: 400 }} styles={{ body: { padding: 28 } }}>
        <span className="tape" aria-hidden="true" />
        <Flex vertical gap={20}>
          <Flex align="center" gap={10}>
            <Logo size={32} />
            <span className="mobile-brand">{t("app.name")}</span>
          </Flex>
          <div>
            <h1 className="hand" style={{ fontSize: 34, lineHeight: "36px", margin: 0 }}>{title}</h1>
            {hint && <Typography.Paragraph type="secondary" style={{ margin: "6px 0 0" }}>{hint}</Typography.Paragraph>}
          </div>
          {children}
          <Flex justify="space-between" align="center" gap={8} wrap>
            <ThemePicker />
            <LangPicker />
          </Flex>
        </Flex>
      </Card>
    </div>
  );
}

export function LoginPage() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (v: Credentials) => {
    setBusy(true);
    setError(null);
    try {
      await api.login(v.username, v.password);
      await qc.invalidateQueries({ queryKey: keys.session });
      void navigate("/", { replace: true });
    } catch (e) {
      setError(e instanceof ApiError && e.code === "unauthorized" ? t("auth.loginFailed") : errorText(e, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthCard title={t("auth.loginTitle")}>
      <Form<Credentials> layout="vertical" onFinish={(v) => void submit(v)} requiredMark={false}>
        <Form.Item name="username" label={t("auth.username")} rules={[{ required: true, message: t("auth.required") }]}>
          <Input autoComplete="username" autoFocus size="large" />
        </Form.Item>
        <Form.Item name="password" label={t("auth.password")} rules={[{ required: true, message: t("auth.required") }]}>
          <Input.Password autoComplete="current-password" size="large" />
        </Form.Item>
        {error && <Alert type="error" showIcon title={error} style={{ marginBottom: 16 }} role="alert" />}
        <Button type="primary" htmlType="submit" block size="large" loading={busy}>{t("auth.login")}</Button>
      </Form>
    </AuthCard>
  );
}

export function SetupPage() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (v: Credentials) => {
    setBusy(true);
    setError(null);
    try {
      await api.setup(v.username, v.password);
      await qc.invalidateQueries({ queryKey: keys.session });
      void navigate("/", { replace: true });
    } catch (e) {
      if (e instanceof ApiError && e.code === "conflict") {
        await qc.invalidateQueries({ queryKey: keys.session });
        setError(t("auth.setupTaken"));
      } else {
        setError(errorText(e, t));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthCard title={t("auth.setupTitle")} hint={t("auth.setupHint")}>
      <Form<Credentials> layout="vertical" onFinish={(v) => void submit(v)} requiredMark={false}>
        <Form.Item name="username" label={t("auth.username")} rules={[{ required: true, whitespace: true, message: t("auth.required") }]}>
          <Input autoComplete="username" autoFocus size="large" />
        </Form.Item>
        <Form.Item
          name="password"
          label={t("auth.password")}
          extra={t("auth.passwordTooShort")}
          rules={[{ required: true, message: t("auth.required") }, { min: MIN_PASSWORD, message: t("auth.passwordTooShort") }]}
        >
          <Input.Password autoComplete="new-password" size="large" />
        </Form.Item>
        <Form.Item
          name="confirm"
          label={t("auth.passwordConfirm")}
          dependencies={["password"]}
          rules={[
            { required: true, message: t("auth.required") },
            ({ getFieldValue }) => ({
              validator: (_, value: unknown) =>
                value === getFieldValue("password") ? Promise.resolve() : Promise.reject(new Error(t("auth.passwordMismatch"))),
            }),
          ]}
        >
          <Input.Password autoComplete="new-password" size="large" />
        </Form.Item>
        {error && <Alert type="error" showIcon title={error} style={{ marginBottom: 16 }} role="alert" />}
        <Button type="primary" htmlType="submit" block size="large" loading={busy}>{t("auth.setupSubmit")}</Button>
      </Form>
    </AuthCard>
  );
}
