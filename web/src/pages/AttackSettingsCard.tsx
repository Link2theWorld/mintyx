import { useMutation, useQueryClient } from "@tanstack/react-query";
import { App, Card, Flex, Switch, Typography } from "antd";
import { useId } from "react";
import { api } from "../api/client";
import { keys, useAttackConfig } from "../api/queries";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { errorText } from "../lib/errors";

/** The one attack setting: whether the panel may ask the address registries about each source. */
export function AttackSettingsCard() {
  const { t } = useI18n();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const q = useAttackConfig();
  const labelId = useId();
  const save = useMutation({
    mutationFn: api.saveAttackConfig,
    onSuccess: async (cfg) => {
      qc.setQueryData(keys.attackConfig, cfg);
      void message.success(t("common.saved"));
      await qc.invalidateQueries({ queryKey: keys.attackSummary });
    },
    onError: (e) => void message.error(errorText(e, t)),
  });

  return (
    <Card title={t("attacks.settings.title")}>
      <QueryState isPending={q.isPending} error={q.error} refetch={q.refetch} />
      {q.data && (
        <Flex vertical gap={12}>
          <Typography.Text>{t("attacks.settings.intro")}</Typography.Text>
          <Typography.Text type="secondary">{t("attacks.settings.disclosure")}</Typography.Text>
          <Flex gap={12} align="center">
            <Switch
              checked={q.data.lookup}
              loading={save.isPending}
              aria-labelledby={labelId}
              onChange={(lookup) => save.mutate({ lookup })}
            />
            <Typography.Text id={labelId}>{t("attacks.settings.lookup")}</Typography.Text>
          </Flex>
        </Flex>
      )}
    </Card>
  );
}
