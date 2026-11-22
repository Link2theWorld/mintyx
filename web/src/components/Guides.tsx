import { ReadOutlined } from "@ant-design/icons";
import { Button, Card, Popover, Typography } from "antd";
import type { ReactNode } from "react";
import { useI18n } from "../i18n/I18nProvider";
import { guideIds, guideLinkProps, guideUrl, type GuideId } from "../lib/guides";

export function GuideLink({ id, children }: { id: GuideId; children: ReactNode }) {
  return <Typography.Link href={guideUrl(id)} {...guideLinkProps}>{children}</Typography.Link>;
}

export function GuideList() {
  const { t } = useI18n();
  return (
    <>
      <ul className="guide-list">
        {guideIds.map((id) => (
          <li key={id}>
            <GuideLink id={id}>{t(`guides.${id}.title`)}</GuideLink>
            <Typography.Text type="secondary" style={{ display: "block", fontSize: 13 }}>{t(`guides.${id}.desc`)}</Typography.Text>
          </li>
        ))}
      </ul>
      <Typography.Text type="secondary" style={{ display: "block", fontSize: 12, marginTop: 12 }}>{t("guides.intro")}</Typography.Text>
    </>
  );
}

/** Shell entry: a labelled button in the desktop sidebar, an icon in the phone header. */
export function GuidesButton({ compact }: { compact?: boolean }) {
  const { t } = useI18n();
  return (
    <Popover
      trigger="click"
      placement={compact ? "bottomRight" : "rightBottom"}
      title={t("guides.title")}
      content={<div className="guide-popover"><GuideList /></div>}
    >
      {compact ? (
        <Button type="text" icon={<ReadOutlined />} aria-label={t("guides.title")} />
      ) : (
        <Button block icon={<ReadOutlined />}>{t("guides.title")}</Button>
      )}
    </Popover>
  );
}

export function GuidesCard() {
  const { t } = useI18n();
  return (
    <Card title={t("guides.title")} size="small" className="guide-card">
      <GuideList />
    </Card>
  );
}
