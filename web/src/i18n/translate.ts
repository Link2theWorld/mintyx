import { en } from "./en";
import { zh, type MessageKey } from "./zh";

export type Lang = "zh" | "en";
export const langs: readonly Lang[] = ["zh", "en"];
export const dictionaries: Record<Lang, Record<MessageKey, string>> = { zh, en };

export type Vars = Record<string, string | number>;
export type Translate = (key: MessageKey, vars?: Vars) => string;

export function isMessageKey(key: string): key is MessageKey {
  return Object.prototype.hasOwnProperty.call(zh, key);
}

export function makeTranslate(lang: Lang): Translate {
  const dict = dictionaries[lang];
  return (key, vars) => {
    const text = dict[key];
    if (!vars) return text;
    return text.replace(/\{(\w+)\}/g, (m, name: string) => (name in vars ? String(vars[name]) : m));
  };
}

/** Audit action ids are stable English identifiers; unknown ones are shown as-is. */
export function auditActionLabel(action: string, t: Translate): string {
  const key = `audit.action.${action}`;
  return isMessageKey(key) ? t(key) : action;
}

/** Subscription format names come from the server; one the UI has no label for is shown as-is. */
export function shareFormatLabel(format: string, t: Translate): string {
  const key = `share.format.${format}`;
  return isMessageKey(key) ? t(key) : format;
}
