import { CopyOutlined } from "@ant-design/icons";
import { App, Button, Input, Space, Typography } from "antd";
import { useId } from "react";
import { useI18n } from "../i18n/I18nProvider";
import { copyText } from "../lib/clipboard";

/** A labelled read-only value with a copy button; CopyField without the QR code. */
export function CopyLine({ label, value }: { label: string; value: string }) {
  const { t } = useI18n();
  const { message } = App.useApp();
  const id = useId();
  const copy = async () => {
    if (await copyText(value)) void message.success(t("common.copied"));
    else void message.error(t("common.copyFailed"));
  };
  return (
    <div>
      <Typography.Text strong><label htmlFor={id}>{label}</label></Typography.Text>
      <Space.Compact style={{ width: "100%", marginTop: 6 }}>
        <Input id={id} value={value} readOnly onFocus={(e) => e.currentTarget.select()} />
        <Button icon={<CopyOutlined />} onClick={() => void copy()} aria-label={`${t("common.copy")} ${label}`} />
      </Space.Compact>
    </div>
  );
}
