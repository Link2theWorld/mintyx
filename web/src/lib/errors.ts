import { ApiError } from "../api/client";
import type { Translate } from "../i18n/translate";
import type { MessageKey } from "../i18n/zh";

const conflictKeys: Record<string, MessageKey> = {
  port: "err.portTaken",
  name: "err.nameTaken",
  secret: "err.secretTaken",
  subToken: "err.subTokenTaken",
};

/** A localized sentence for any thrown value. */
export function errorText(err: unknown, t: Translate): string {
  if (!(err instanceof ApiError)) return err instanceof Error ? err.message : String(err);
  switch (err.code) {
    case "network": return t("err.network");
    case "unauthorized": return t("err.unauthorized");
    case "forbidden": return t("err.forbidden");
    case "not_found": return t("err.notFound");
    case "conflict": {
      const key = err.field === undefined ? undefined : conflictKeys[err.field];
      return key ? t(key) : t("err.conflict");
    }
    case "invalid": return err.message ? `${t("err.invalid")}（${err.message}）` : t("err.invalid");
    case "rate_limited": return t("err.rateLimited");
    case "engine": return t("err.engine", { message: err.message });
    case "bad_response": return t("err.badResponse");
    case "internal": return t("err.internal");
  }
}

/** The message to show under a form field for a field-level error. */
export function fieldErrorText(err: ApiError, t: Translate): string {
  if (err.code === "conflict") return errorText(err, t);
  return err.message || t("err.invalid");
}

export function isEngineError(err: unknown): err is ApiError {
  return err instanceof ApiError && err.code === "engine";
}
