import { DeleteOutlined, MailOutlined } from "@ant-design/icons";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert, App, Button, Card, Empty, Flex, Popconfirm, Select, Table, Tag, Tooltip, Typography, theme } from "antd";
import { useState } from "react";
import { Link } from "react-router";
import { api } from "../api/client";
import { keys, useAttackers, useAttackSummary } from "../api/queries";
import { attackKinds, type Attacker, type AttackSummary } from "../api/schemas";
import { PageHeader } from "../components/PageHeader";
import { Ticket } from "../components/Paper";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { compactNumber, countryName, kindColor, kindLabelKey, niceCeil, sortKinds, trendDays } from "../lib/attacks";
import { copyText } from "../lib/clipboard";
import { errorText } from "../lib/errors";
import { formatDateTime } from "../lib/format";
import { useIsMobile } from "../lib/useIsMobile";
import { useThemePref } from "../theme/ThemeProvider";
import { AttackReportDialog } from "./AttackReportDialog";

/** "3.4万" → 3.4 with 万 as the ticket's small unit, the way the other pages write "133GB". */
function numberAndUnit(text: string): { value: string; unit?: string } {
  const m = /^([\d.,]+)(\D+)$/.exec(text);
  return m?.[1] && m[2] ? { value: m[1], unit: m[2] } : { value: text };
}

function useKindLabel() {
  const { t } = useI18n();
  return (kind: string) => {
    const key = kindLabelKey(kind);
    return key ? t(key) : kind;
  };
}

/** The colour is a swatch beside the name; the name itself stays in the normal text colour. */
function KindSwatch({ kind }: { kind: string }) {
  const { resolved } = useThemePref();
  return <span className="attack-swatch" style={{ background: kindColor(kind, resolved) }} aria-hidden="true" />;
}

function KindTag({ kind, hits }: { kind: string; hits?: number }) {
  const label = useKindLabel();
  const { lang } = useI18n();
  return (
    <Tag className="attack-kind-tag">
      <KindSwatch kind={kind} />
      {label(kind)}
      {hits !== undefined && <span className="attack-kind-count">{compactNumber(hits, lang)}</span>}
    </Tag>
  );
}

function Trend({ summary }: { summary: AttackSummary }) {
  const { t, lang } = useI18n();
  const { token } = theme.useToken();
  const { resolved } = useThemePref();
  const label = useKindLabel();
  const days = trendDays(summary.daily);
  const top = niceCeil(Math.max(...days.map((d) => d.total), 0));
  const tick = (i: number) => i === 0 || i === days.length - 1 || i === Math.floor((days.length - 1) / 2);

  return (
    <figure className="attack-trend" aria-label={t("attacks.trend.title", { days: days.length })}>
      <Flex justify="space-between" align="baseline">
        <span className="subhead">{t("attacks.trend.title", { days: days.length })}</span>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t("attacks.trend.utc")}</Typography.Text>
      </Flex>
      <div className="attack-trend-plot" style={{ borderBottom: `1px solid ${token.colorBorder}` }}>
        <span className="attack-trend-max" style={{ color: token.colorTextTertiary, borderTop: `1px dashed ${token.colorBorderSecondary}` }}>
          {compactNumber(top, lang)}
        </span>
        {days.map((d) => (
          <Tooltip
            key={d.day}
            title={
              <div>
                <div>{d.day} · {t("attacks.hits", { n: compactNumber(d.total, lang) })}</div>
                {d.segments.map((s) => (
                  <div key={s.kind}><KindSwatch kind={s.kind} /> {label(s.kind)} {compactNumber(s.hits, lang)}</div>
                ))}
              </div>
            }
          >
            <div
              className="attack-trend-col"
              tabIndex={0}
              role="img"
              aria-label={`${d.day}: ${t("attacks.hits", { n: d.total })}`}
            >
              {/* Stacked from the baseline up; the surface-coloured gap keeps neighbouring kinds apart. */}
              {[...d.segments].reverse().map((s, i) => (
                <div
                  key={s.kind}
                  style={{
                    height: `${(s.hits / top) * 100}%`,
                    minHeight: 2,
                    background: kindColor(s.kind, resolved),
                    borderRadius: i === 0 ? "4px 4px 0 0" : 0,
                    borderTop: i === 0 ? undefined : `2px solid ${token.colorBgContainer}`,
                  }}
                />
              ))}
            </div>
          </Tooltip>
        ))}
      </div>
      <div className="attack-trend-axis" style={{ color: token.colorTextTertiary }}>
        {days.map((d, i) => <span key={d.day}>{tick(i) ? d.day.slice(5) : ""}</span>)}
      </div>
    </figure>
  );
}

function KindsCard({ summary, kind, onKind }: { summary: AttackSummary; kind: string; onKind: (k: string) => void }) {
  const { t, lang } = useI18n();
  const { token } = theme.useToken();
  const label = useKindLabel();
  // Every known kind is listed, so the legend does not reshuffle as attacks come and go.
  const totals = new Map(summary.kinds.map((k) => [k.kind, k]));
  const rows = sortKinds([
    ...attackKinds.map((k) => totals.get(k) ?? { kind: k, hits: 0, sources: 0 }),
    ...summary.kinds.filter((k) => !(attackKinds as readonly string[]).includes(k.kind)),
  ]);
  return (
    <Card title={t("attacks.kinds.title")}>
      <div className="attack-kinds-grid">
        <ul className="attack-kind-list">
          {rows.map((k) => {
            const descKey = kindLabelKey(k.kind);
            const active = kind === k.kind;
            return (
              <li key={k.kind}>
                <button
                  type="button"
                  className="attack-kind-row"
                  aria-pressed={active}
                  onClick={() => onKind(active ? "" : k.kind)}
                  style={{ background: active ? token.colorFillSecondary : "transparent", color: token.colorText }}
                >
                  <KindSwatch kind={k.kind} />
                  <span className="attack-kind-text">
                    <Typography.Text strong>{label(k.kind)}</Typography.Text>
                    {descKey && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t(`${descKey}.desc`)}</Typography.Text>}
                  </span>
                  <span className="attack-kind-num">
                    <Typography.Text strong>{compactNumber(k.hits, lang)}</Typography.Text>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t("attacks.sources", { n: compactNumber(k.sources, lang) })}</Typography.Text>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
        <Trend summary={summary} />
      </div>
    </Card>
  );
}

function OriginsCard({ summary, country, onCountry }: { summary: AttackSummary; country: string; onCountry: (c: string) => void }) {
  const { t, lang } = useI18n();
  const { token } = theme.useToken();
  const { message } = App.useApp();
  const { lookup } = summary;
  const most = Math.max(...summary.countries.map((c) => c.sources), 1);

  const copy = async (text: string) => {
    if (await copyText(text)) void message.success(t("common.copied"));
    else void message.error(t("common.copyFailed"));
  };

  return (
    <Card title={t("attacks.origins.title")}>
      {!lookup.enabled ? (
        <Flex vertical gap={12} align="flex-start">
          <Typography.Text type="secondary">{t("attacks.origins.off")}</Typography.Text>
          <Link to="/settings">{t("attacks.origins.goSettings")}</Link>
        </Flex>
      ) : (
        <Flex vertical gap={16}>
          {lookup.pausedUntil && <Alert type="info" showIcon title={t("attacks.origins.paused", { time: formatDateTime(lookup.pausedUntil) })} />}
          {!lookup.pausedUntil && lookup.error && <Alert type="warning" showIcon title={t("attacks.origins.error", { error: lookup.error })} />}
          {summary.countries.length === 0 ? (
            <Typography.Text type="secondary">{lookup.pending > 0 ? t("attacks.origins.working") : t("attacks.origins.none")}</Typography.Text>
          ) : (
            <div className="attack-origins-grid">
              <div>
                <h3 className="subhead">{t("attacks.origins.countries")}</h3>
                <ul className="attack-bar-list">
                  {summary.countries.map((c) => {
                    const active = country !== "" && country === c.country;
                    return (
                      <li key={c.country}>
                        <button
                          type="button"
                          className="attack-bar-row"
                          aria-pressed={active}
                          disabled={c.country === ""}
                          onClick={() => onCountry(active ? "" : c.country)}
                          style={{ color: token.colorText, background: active ? token.colorFillSecondary : "transparent" }}
                        >
                          <span className="attack-bar-label">{c.country === "" ? t("attacks.unknown") : countryName(c.country, lang)}</span>
                          <span className="attack-bar-track">
                            <span className="attack-bar-fill" style={{ width: `${(c.sources / most) * 100}%` }} />
                          </span>
                          <span className="attack-bar-value">{t("attacks.sources", { n: compactNumber(c.sources, lang) })}</span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
              <div>
                <h3 className="subhead">{t("attacks.origins.networks")}</h3>
                <ul className="attack-net-list">
                  {summary.networks.map((n) => (
                    <li key={`${n.network}|${n.country}|${n.abuseEmail}`} style={{ borderBottom: `1px solid ${token.colorBorderSecondary}` }}>
                      <Flex justify="space-between" gap={8} align="baseline">
                        <Typography.Text>{n.network || t("attacks.unknown")}</Typography.Text>
                        <Typography.Text type="secondary" style={{ fontSize: 12, whiteSpace: "nowrap" }}>
                          {t("attacks.hits", { n: compactNumber(n.hits, lang) })} · {t("attacks.sources", { n: compactNumber(n.sources, lang) })}
                        </Typography.Text>
                      </Flex>
                      <Flex justify="space-between" gap={8} align="center" wrap>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          {n.country ? countryName(n.country, lang) : t("attacks.unknown")}
                          {" · "}
                          {n.abuseEmail || t("attacks.noAbuse")}
                        </Typography.Text>
                        {n.abuseEmail && (
                          <Button size="small" type="link" style={{ padding: 0 }} onClick={() => void copy(n.abuseEmail)}>
                            {t("attacks.copyEmail")}
                          </Button>
                        )}
                      </Flex>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("attacks.origins.note", { done: lookup.lookedUp, pending: lookup.pending })}
          </Typography.Text>
        </Flex>
      )}
    </Card>
  );
}

function origin(a: Attacker, lang: "zh" | "en", unknown: string): string {
  if (!a.lookedUp) return "";
  const parts = [a.country ? countryName(a.country, lang) : unknown, a.network].filter((p) => p !== "");
  return parts.join(" · ");
}

function SourcesCard({ summary, kind, country, onKind, onCountry, onReport }: {
  summary: AttackSummary;
  kind: string;
  country: string;
  onKind: (k: string) => void;
  onCountry: (c: string) => void;
  onReport: (ip: string) => void;
}) {
  const { t, lang } = useI18n();
  const mobile = useIsMobile();
  const { token } = theme.useToken();
  const label = useKindLabel();
  const q = useAttackers(kind, country);
  const rows = q.data?.pages.flatMap((p) => p.attackers) ?? [];
  const total = q.data?.pages[0]?.total ?? 0;
  const originText = (a: Attacker) =>
    origin(a, lang, t("attacks.unknown")) || (summary.lookup.enabled ? (a.lookupError ? t("attacks.lookupFailed") : t("attacks.lookupPending")) : "—");
  const reportButton = (a: Attacker) => (
    <Button size="small" icon={<MailOutlined />} onClick={() => onReport(a.ip)}>{t("attacks.report")}</Button>
  );

  return (
    <Card
      title={t("attacks.sourcesTitle")}
      styles={{ body: { padding: mobile ? "4px 16px 12px" : "0 0 12px" } }}
      extra={
        <Flex gap={8} align="center" wrap>
          {country !== "" && <Tag closable onClose={() => onCountry("")}>{countryName(country, lang)}</Tag>}
          <Select
            size="small"
            value={kind}
            onChange={onKind}
            style={{ minWidth: 132 }}
            aria-label={t("attacks.filter.kind")}
            options={[{ value: "", label: t("attacks.filter.all") }, ...attackKinds.map((k) => ({ value: k, label: label(k) }))]}
          />
        </Flex>
      }
    >
      <div style={{ padding: mobile ? 0 : "0 24px" }}>
        <QueryState isPending={q.isPending} error={q.error} refetch={q.refetch} />
      </div>
      {q.data && rows.length === 0 && <Empty style={{ padding: 24 }} description={t("attacks.empty.filtered")} />}
      {rows.length > 0 && (mobile ? (
        <ul className="audit-list">
          {rows.map((a) => (
            <li key={a.ip} style={{ borderBottom: `1px solid ${token.colorBorderSecondary}` }}>
              <Flex justify="space-between" gap={8} align="center">
                <Typography.Text strong style={{ fontFamily: token.fontFamilyCode, overflowWrap: "anywhere" }}>{a.ip}</Typography.Text>
                {reportButton(a)}
              </Flex>
              <div><Typography.Text type="secondary">{originText(a)}</Typography.Text></div>
              <Flex gap={4} wrap style={{ margin: "6px 0" }}>
                {sortKinds(a.kinds).map((k) => <KindTag key={k.kind} kind={k.kind} hits={k.hits} />)}
              </Flex>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t("attacks.lastSeen", { time: formatDateTime(a.lastAt) })}</Typography.Text>
            </li>
          ))}
        </ul>
      ) : (
        <Table<Attacker>
          rowKey="ip"
          dataSource={rows}
          pagination={false}
          columns={[
            { title: t("attacks.col.ip"), dataIndex: "ip", render: (v: string) => <Typography.Text style={{ fontFamily: token.fontFamilyCode, whiteSpace: "nowrap" }}>{v}</Typography.Text> },
            { title: t("attacks.col.kinds"), key: "kinds", render: (_, a) => <Flex gap={4} wrap>{sortKinds(a.kinds).map((k) => <KindTag key={k.kind} kind={k.kind} hits={k.hits} />)}</Flex> },
            { title: t("attacks.col.origin"), key: "origin", render: (_, a) => <Typography.Text type={a.lookedUp ? undefined : "secondary"}>{originText(a)}</Typography.Text> },
            { title: t("attacks.col.last"), dataIndex: "lastAt", width: 160, render: (v: string) => formatDateTime(v) },
            { title: "", key: "report", width: 110, align: "right", render: (_, a) => reportButton(a) },
          ]}
        />
      ))}
      {rows.length > 0 && (
        <Flex justify="center" style={{ marginTop: 16 }}>
          {q.hasNextPage ? (
            <Button onClick={() => void q.fetchNextPage()} loading={q.isFetchingNextPage}>{t("attacks.loadMore")}</Button>
          ) : (
            <Typography.Text type="secondary">{t("attacks.shown", { n: total })}</Typography.Text>
          )}
        </Flex>
      )}
    </Card>
  );
}

/** Who has been knocking on the server: what they tried, where they are from, and how to report them. */
export function AttacksPage() {
  const { t, lang } = useI18n();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const summary = useAttackSummary();
  const [kind, setKind] = useState("");
  const [country, setCountry] = useState("");
  const [reportIp, setReportIp] = useState<string | null>(null);
  const clear = useMutation({
    mutationFn: api.clearAttacks,
    onSuccess: async () => {
      void message.success(t("attacks.cleared"));
      await qc.invalidateQueries({ queryKey: keys.attacks });
    },
    onError: (e) => void message.error(errorText(e, t)),
  });
  const s = summary.data;

  return (
    <>
      <PageHeader
        title={t("attacks.title")}
        subtitle={t("attacks.subtitle", { days: s?.retentionDays ?? 30 })}
        extra={s && s.sources > 0 && (
          <Popconfirm title={t("attacks.clearConfirm")} okText={t("attacks.clear")} cancelText={t("common.cancel")} okButtonProps={{ danger: true }} onConfirm={() => clear.mutate()}>
            <Button icon={<DeleteOutlined />} loading={clear.isPending}>{t("attacks.clear")}</Button>
          </Popconfirm>
        )}
      />
      <QueryState isPending={summary.isPending} error={summary.error} refetch={summary.refetch} />
      {s && (
        <div className="card-list">
          {s.sshLog === "unavailable" && <Alert type="warning" showIcon title={t("attacks.sshUnavailable")} />}
          {s.sshLog === "error" && <Alert type="warning" showIcon title={t("attacks.sshError")} />}
          {s.sources === 0 ? (
            <Card><Empty description={s.sshLog === "starting" ? t("attacks.empty.starting") : t("attacks.empty")} /></Card>
          ) : (
            <>
              <Ticket items={[
                { label: t("attacks.stat.hits"), ...numberAndUnit(compactNumber(s.hits, lang)) },
                { label: t("attacks.stat.sources"), ...numberAndUnit(compactNumber(s.sources, lang)) },
              ]} />
              <KindsCard summary={s} kind={kind} onKind={setKind} />
              <OriginsCard summary={s} country={country} onCountry={setCountry} />
              <SourcesCard summary={s} kind={kind} country={country} onKind={setKind} onCountry={setCountry} onReport={setReportIp} />
            </>
          )}
        </div>
      )}
      <AttackReportDialog ip={reportIp} lookupEnabled={s?.lookup.enabled ?? false} onClose={() => setReportIp(null)} />
    </>
  );
}
