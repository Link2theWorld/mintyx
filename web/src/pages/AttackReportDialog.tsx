import { CopyOutlined, MailOutlined } from "@ant-design/icons";
import { Alert, App, Button, Flex, Input, Modal, Typography } from "antd";
import { Link } from "react-router";
import { useAttackReport } from "../api/queries";
import { CopyLine } from "../components/CopyLine";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { reportMailto, reportText } from "../lib/attacks";
import { copyText } from "../lib/clipboard";

/**
 * The drafted complaint for one source. The panel never sends it: the owner mails it from their
 * own mailbox, either through the mail app or by pasting it into webmail.
 */
export function AttackReportDialog({ ip, lookupEnabled, onClose }: { ip: string | null; lookupEnabled: boolean; onClose: () => void }) {
  const { t } = useI18n();
  const { message } = App.useApp();
  const q = useAttackReport(ip);
  const r = q.data;
  const mailto = r ? reportMailto(r) : null;

  const copyAll = async () => {
    if (!r) return;
    if (await copyText(reportText(r))) void message.success(t("common.copied"));
    else void message.error(t("common.copyFailed"));
  };

  return (
    <Modal
      open={ip !== null}
      onCancel={onClose}
      title={t("attacks.report.title", { ip: ip ?? "" })}
      width={640}
      destroyOnHidden
      footer={
        <Flex gap={8} justify="flex-end" wrap>
          <Button onClick={onClose}>{t("common.close")}</Button>
          <Button icon={<CopyOutlined />} disabled={!r} onClick={() => void copyAll()}>{t("attacks.report.copyAll")}</Button>
          {/* A plain link: the browser hands it to whatever mail app the owner uses. */}
          <Button type="primary" icon={<MailOutlined />} disabled={!mailto} href={mailto ?? undefined}>{t("attacks.report.openMail")}</Button>
        </Flex>
      }
    >
      <QueryState isPending={ip !== null && q.isPending} error={q.error} refetch={q.refetch} />
      {r && (
        <Flex vertical gap={12}>
          <Typography.Text type="secondary">{t("attacks.report.intro")}</Typography.Text>
          {r.to === "" && (
            <Alert
              type="warning"
              showIcon
              title={lookupEnabled ? t("attacks.report.noAddress") : t("attacks.report.lookupOff")}
              action={lookupEnabled ? undefined : <Link to="/settings">{t("attacks.origins.goSettings")}</Link>}
            />
          )}
          {r.to !== "" && <CopyLine label={t("attacks.report.to")} value={r.to} />}
          <CopyLine label={t("attacks.report.subject")} value={r.subject} />
          <div>
            <Typography.Text strong>{t("attacks.report.body")}</Typography.Text>
            <Input.TextArea
              value={r.body}
              readOnly
              autoSize={{ minRows: 8, maxRows: 16 }}
              aria-label={t("attacks.report.body")}
              style={{ marginTop: 6, fontFamily: "var(--ant-font-family-code)", fontSize: 12 }}
            />
          </div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t("attacks.report.hint")}</Typography.Text>
        </Flex>
      )}
    </Modal>
  );
}
