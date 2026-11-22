import { Segmented, Select, Space, Typography } from "antd";
import { useI18n } from "../i18n/I18nProvider";
import type { Lang } from "../i18n/translate";
import { useThemePref } from "../theme/ThemeProvider";
import { themePrefs, type ThemePref } from "../theme/themes";

export function ThemePicker() {
  const { t } = useI18n();
  const { pref, setPref } = useThemePref();
  return (
    <Segmented<ThemePref>
      size="small"
      aria-label={t("theme.label")}
      value={pref}
      onChange={setPref}
      options={themePrefs.map((p) => ({ value: p, label: t(`theme.${p}`) }))}
    />
  );
}

/** Compact variant for narrow places such as the sidebar and the phone popover. */
export function ThemeSelect() {
  const { t } = useI18n();
  const { pref, setPref } = useThemePref();
  return (
    <Select<ThemePref>
      aria-label={t("theme.label")}
      value={pref}
      onChange={setPref}
      style={{ width: "100%" }}
      options={themePrefs.map((p) => ({ value: p, label: t(`theme.${p}`) }))}
    />
  );
}

export function LangPicker({ block }: { block?: boolean }) {
  const { t, lang, setLang } = useI18n();
  return (
    <Select<Lang>
      size={block ? "middle" : "small"}
      aria-label={t("lang.label")}
      value={lang}
      onChange={setLang}
      style={block ? { width: "100%" } : { minWidth: 104 }}
      options={[
        { value: "zh", label: "简体中文" },
        { value: "en", label: "English" },
      ]}
    />
  );
}

export function PreferencesBlock() {
  const { t } = useI18n();
  return (
    <Space orientation="vertical" size={10} style={{ width: "100%" }}>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t("theme.label")}</Typography.Text>
      <ThemeSelect />
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t("lang.label")}</Typography.Text>
      <LangPicker block />
    </Space>
  );
}
