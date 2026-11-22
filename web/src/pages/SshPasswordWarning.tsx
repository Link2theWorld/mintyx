import { Alert } from "antd";
import { useState } from "react";
import { useHostSsh } from "../api/queries";
import { GuideLink } from "../components/Guides";
import { useI18n } from "../i18n/I18nProvider";
import { readPref, writePref } from "../lib/storage";

export const SSH_HINT_DISMISSED_KEY = "mintyx.sshHintDismissed";

/** Nudges the owner off SSH password login; silent once dismissed or when the host cannot tell. */
export function SshPasswordWarning() {
  const { t } = useI18n();
  const [dismissed, setDismissed] = useState(() => readPref(SSH_HINT_DISMISSED_KEY) === "1");
  const q = useHostSsh(!dismissed);
  if (dismissed || q.data?.passwordLogin !== "on") return null;
  return (
    <Alert
      type="warning"
      showIcon
      style={{ marginBottom: 16 }}
      title={t("ssh.warn.title")}
      description={
        <>
          {t("ssh.warn.body")} <GuideLink id="sshKey">{t("ssh.warn.link")}</GuideLink>
        </>
      }
      closable={{
        "aria-label": t("ssh.warn.dismiss"),
        onClose: () => {
          writePref(SSH_HINT_DISMISSED_KEY, "1");
          setDismissed(true);
        },
      }}
    />
  );
}
