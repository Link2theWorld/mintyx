import { App, Button, DatePicker, Flex, Form, Input, InputNumber, Space } from "antd";
import dayjs, { type Dayjs } from "dayjs";
import { useState } from "react";
import { ApiError } from "../api/client";
import type { Client, ClientInput } from "../api/schemas";
import { useI18n } from "../i18n/I18nProvider";
import { errorText, fieldErrorText } from "../lib/errors";
import { MAX_QUOTA_GB, bytesToGb, gbToBytes } from "../lib/format";

interface Values {
  name: string;
  quotaGb: number | null;
  expires: Dayjs | null;
}

const serverFieldToForm: Record<string, keyof Values> = { name: "name", quotaBytes: "quotaGb", expiresAt: "expires" };

/** Expiry is stored as the end of the chosen local day, sent as UTC. */
export function toClientInput(v: Values): ClientInput {
  return {
    name: v.name.trim(),
    quotaBytes: gbToBytes(v.quotaGb),
    expiresAt: v.expires ? v.expires.endOf("day").toISOString() : null,
  };
}

export function ClientForm({ client, onSubmit, onCancel }: {
  client: Client | null;
  onSubmit: (c: ClientInput) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useI18n();
  const { message } = App.useApp();
  const [form] = Form.useForm<Values>();
  const [busy, setBusy] = useState(false);

  const initial: Values = {
    name: client?.name ?? "",
    quotaGb: client ? bytesToGb(client.quotaBytes) : 0,
    expires: client?.expiresAt ? dayjs(client.expiresAt) : null,
  };

  const finish = async (v: Values) => {
    setBusy(true);
    try {
      await onSubmit(toClientInput(v));
    } catch (e) {
      const name = e instanceof ApiError && e.field ? serverFieldToForm[e.field] : undefined;
      if (e instanceof ApiError && name) form.setFields([{ name, errors: [fieldErrorText(e, t)] }]);
      else void message.error(errorText(e, t));
    } finally {
      setBusy(false);
    }
  };

  const setExpiry = (d: Dayjs | null) => form.setFieldValue("expires", d);

  return (
    <Form<Values> form={form} layout="vertical" initialValues={initial} onFinish={(v) => void finish(v)} requiredMark={false}>
      <Form.Item name="name" label={t("clientForm.name")} extra={t("clientForm.nameHelp")} rules={[{ required: true, whitespace: true, message: t("auth.required") }]}>
        <Input maxLength={64} autoFocus />
      </Form.Item>
      <Form.Item name="quotaGb" label={t("clientForm.quota")} extra={t("clientForm.quotaHelp")}>
        <InputNumber min={0} max={MAX_QUOTA_GB} step={10} style={{ width: "100%" }} suffix="GB" />
      </Form.Item>
      <Form.Item label={t("clientForm.expiry")} extra={t("clientForm.expiryHelp")}>
        <Space wrap style={{ marginBottom: 8 }}>
          <Button size="small" onClick={() => setExpiry(dayjs().add(30, "day"))}>{t("clientForm.in30Days")}</Button>
          <Button size="small" onClick={() => setExpiry(dayjs().add(1, "year"))}>{t("clientForm.in1Year")}</Button>
          <Button size="small" onClick={() => setExpiry(null)}>{t("common.never")}</Button>
        </Space>
        <Form.Item name="expires" noStyle>
          <DatePicker
            style={{ width: "100%" }}
            placeholder={t("common.never")}
            aria-label={t("clientForm.expiry")}
            disabledDate={(d) => d.isBefore(dayjs(), "day")}
            inputReadOnly
          />
        </Form.Item>
      </Form.Item>
      <Flex gap={8} justify="flex-end">
        <Button onClick={onCancel}>{t("common.cancel")}</Button>
        <Button type="primary" htmlType="submit" loading={busy}>{client ? t("common.save") : t("common.create")}</Button>
      </Flex>
    </Form>
  );
}
