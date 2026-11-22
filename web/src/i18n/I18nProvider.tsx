import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import dayjs from "dayjs";
import "dayjs/locale/zh-cn";
import "dayjs/locale/en";
import { readPref, writePref } from "../lib/storage";
import { langs, makeTranslate, type Lang, type Translate } from "./translate";

export const LANG_KEY = "mintyx.lang";

interface I18nValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: Translate;
}

const I18nContext = createContext<I18nValue | null>(null);

function initialLang(): Lang {
  const saved = readPref(LANG_KEY);
  return langs.find((l) => l === saved) ?? "zh";
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(initialLang);
  const setLang = useCallback((l: Lang) => {
    writePref(LANG_KEY, l);
    setLangState(l);
  }, []);

  useEffect(() => {
    dayjs.locale(lang === "zh" ? "zh-cn" : "en");
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
  }, [lang]);

  const value = useMemo(() => ({ lang, setLang, t: makeTranslate(lang) }), [lang, setLang]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  const v = useContext(I18nContext);
  if (!v) throw new Error("useI18n outside I18nProvider");
  return v;
}
