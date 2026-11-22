import { Segmented, Typography } from "antd";
import { useState } from "react";
import { GuideLink } from "../components/Guides";
import { useI18n } from "../i18n/I18nProvider";
import { shareFormatLabel } from "../i18n/translate";
import { clientApps, detectOS, deviceOSes, type DeviceOS } from "../lib/clientApps";

/** Tells whoever receives the share which app to install, opening on the device in hand. */
export function ClientAppsHint() {
  const { t } = useI18n();
  const [os, setOs] = useState<DeviceOS>(() => detectOS(navigator.userAgent, navigator.maxTouchPoints) ?? "ios");
  return (
    <section>
      <Typography.Title level={3} style={{ fontSize: 16 }}>{t("share.apps.title")}</Typography.Title>
      <Typography.Paragraph type="secondary">{t("share.apps.hint")}</Typography.Paragraph>
      <Segmented<DeviceOS>
        block
        aria-label={t("share.apps.os")}
        value={os}
        onChange={setOs}
        options={deviceOSes.map((o) => ({ value: o, label: t(`share.apps.os.${o}`) }))}
      />
      <ul style={{ margin: "12px 0", paddingInlineStart: 18 }}>
        {clientApps[os].map((app) => (
          <li key={app.name}>
            <strong>{app.name}</strong>
            <Typography.Text type="secondary"> · {t("share.apps.use", { format: shareFormatLabel(app.format, t) })}</Typography.Text>
          </li>
        ))}
      </ul>
      <GuideLink id="clients">{t("share.apps.guide")}</GuideLink>
    </section>
  );
}
