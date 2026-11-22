import { Alert, Button, Skeleton } from "antd";
import { useI18n } from "../i18n/I18nProvider";
import { errorText } from "../lib/errors";

/** Loading / error placeholder for a query; renders nothing once data is there. */
export function QueryState({ isPending, error, refetch }: { isPending: boolean; error: unknown; refetch: () => unknown }) {
  const { t } = useI18n();
  if (error) {
    return (
      <Alert
        type="error"
        showIcon
        title={t("common.loadFailed")}
        description={errorText(error, t)}
        action={<Button size="small" onClick={() => void refetch()}>{t("common.retry")}</Button>}
      />
    );
  }
  if (isPending) return <Skeleton active paragraph={{ rows: 4 }} />;
  return null;
}
