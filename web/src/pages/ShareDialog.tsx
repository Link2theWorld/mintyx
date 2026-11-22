import { Alert, Divider, Modal, Typography } from "antd";
import { useShare } from "../api/queries";
import type { Client } from "../api/schemas";
import { CopyField } from "../components/CopyField";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { shareFormatLabel } from "../i18n/translate";
import { useIsMobile } from "../lib/useIsMobile";
import { ClientAppsHint } from "./ClientAppsHint";

export function ShareDialog({ client, onClose }: { client: Client | null; onClose: () => void }) {
  const { t } = useI18n();
  const mobile = useIsMobile();
  const share = useShare(client?.id ?? null);

  return (
    <Modal
      open={client !== null}
      onCancel={onClose}
      footer={null}
      title={client ? t("share.title", { name: client.name }) : ""}
      width={mobile ? "100%" : 600}
      style={mobile ? { top: 0, maxWidth: "100%", margin: 0, paddingBottom: 0 } : undefined}
      styles={mobile ? { container: { minHeight: "100vh", borderRadius: 0 } } : undefined}
      destroyOnHidden
    >
      <QueryState isPending={share.isPending} error={share.error} refetch={share.refetch} />
      {share.data && (
        <>
          <Typography.Title level={3} style={{ fontSize: 16, marginTop: 8 }}>{t("share.subscriptions")}</Typography.Title>
          <Typography.Paragraph type="secondary">{t("share.subscriptionsHint")}</Typography.Paragraph>
          {share.data.subscriptions.map((s) => (
            <div key={s.format} className="copy-field">
              <CopyField label={shareFormatLabel(s.format, t)} value={s.url} />
              {s.omitted.length > 0 && (
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginTop: 8 }}
                  title={
                    <>
                      {t("share.omitted")}
                      <ul style={{ margin: "4px 0 0", paddingInlineStart: 18 }}>
                        {s.omitted.map((o) => (
                          <li key={o.lineId}><strong>{o.lineName}</strong>：{o.reason}</li>
                        ))}
                      </ul>
                    </>
                  }
                />
              )}
            </div>
          ))}

          <Divider />
          <Typography.Title level={3} style={{ fontSize: 16 }}>{t("share.links")}</Typography.Title>
          <Typography.Paragraph type="secondary">{t("share.linksHint")}</Typography.Paragraph>
          {share.data.links.length === 0 ? (
            <Typography.Text type="secondary">{t("share.noLinks")}</Typography.Text>
          ) : (
            share.data.links.map((l) => <CopyField key={l.lineId} label={l.lineName} value={l.uri} />)
          )}

          <Divider />
          <ClientAppsHint />
        </>
      )}
    </Modal>
  );
}
