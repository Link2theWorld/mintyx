import { CopyOutlined, QrcodeOutlined } from "@ant-design/icons";
import { App, Button, Flex, Input, QRCode, Space, Typography } from "antd";
import { useId, useState } from "react";
import { useI18n } from "../i18n/I18nProvider";
import { copyText } from "../lib/clipboard";

/** A read-only value with copy and QR buttons; the QR stays black-on-white so phones can scan it in any theme. */
export function CopyField({ label, value, extra }: { label: string; value: string; extra?: React.ReactNode }) {
  const { t } = useI18n();
  const { message } = App.useApp();
  const [showQr, setShowQr] = useState(false);
  const inputId = useId();

  const copy = async () => {
    if (await copyText(value)) void message.success(t("common.copied"));
    else void message.error(t("common.copyFailed"));
  };

  return (
    <div className="copy-field">
      <Flex justify="space-between" align="baseline" gap={8}>
        <Typography.Text strong>
          <label htmlFor={inputId}>{label}</label>
        </Typography.Text>
        {extra}
      </Flex>
      <Space.Compact style={{ width: "100%", marginTop: 6 }}>
        <Input id={inputId} value={value} readOnly onFocus={(e) => e.currentTarget.select()} style={{ fontFamily: "var(--ant-font-family-code)" }} />
        <Button icon={<CopyOutlined />} onClick={() => void copy()} aria-label={`${t("common.copy")} ${label}`}>
          <span className="hide-on-narrow">{t("common.copy")}</span>
        </Button>
        <Button
          icon={<QrcodeOutlined />}
          onClick={() => setShowQr((v) => !v)}
          aria-expanded={showQr}
          aria-label={showQr ? t("common.hideQr") : t("common.qr")}
        />
      </Space.Compact>
      {showQr && (
        <Flex justify="center" style={{ marginTop: 12 }}>
          <QRCode
            value={value}
            size={220}
            color="#000000"
            bgColor="#ffffff"
            errorLevel="M"
            type="svg"
            aria-label={t("share.qrFor", { name: label })}
            role="img"
          />
        </Flex>
      )}
    </div>
  );
}
