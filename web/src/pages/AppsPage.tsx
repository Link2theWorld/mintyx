import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert, App, Button, Card, Flex, Popconfirm, Spin, Tag, Typography } from "antd";
import { useEffect, useRef, useState } from "react";
import { ApiError, api } from "../api/client";
import { keys, useApps } from "../api/queries";
import type { AppAction, AppJob, HostApp } from "../api/schemas";
import { PageHeader } from "../components/PageHeader";
import { QueryState } from "../components/QueryState";
import { useI18n } from "../i18n/I18nProvider";
import { isMessageKey, type Translate } from "../i18n/translate";
import { errorText } from "../lib/errors";

/** The catalog is the server's; an app this build has no text for is shown by its id. */
function appName(id: string, t: Translate): string {
  const key = `apps.name.${id}`;
  return isMessageKey(key) ? t(key) : id;
}

function labelOr(key: string, fallback: string, t: Translate): string {
  return isMessageKey(key) ? t(key) : fallback;
}

function actionErrorText(err: unknown, app: HostApp, t: Translate): string {
  if (err instanceof ApiError && err.code === "conflict") {
    switch (err.field) {
      case "port": return t("apps.err.port", { port: app.ports[0] ?? "" });
      case "job": return t("apps.err.busy");
      case "state": return t("apps.err.state");
      case "host": return t("apps.err.host");
    }
  }
  return errorText(err, t);
}

function StatusTag({ app }: { app: HostApp }) {
  const { t } = useI18n();
  if (!app.installed) return <Tag>{t("apps.status.notInstalled")}</Tag>;
  switch (app.status) {
    case "running": return <Tag color="success">{t("apps.status.running")}</Tag>;
    case "stopped": return <Tag color="warning">{t("apps.status.stopped")}</Tag>;
    case "failed": return <Tag color="error">{t("apps.status.failed")}</Tag>;
    case "": return <Tag color="success">{t("apps.status.installed")}</Tag>;
  }
}

function FailedJob({ job, onClose }: { job: AppJob; onClose: () => void }) {
  const { t } = useI18n();
  return (
    <Alert
      type="error"
      showIcon
      closable={{ "aria-label": t("common.close"), onClose }}
      style={{ marginBottom: 16 }}
      title={t(`apps.failed.${job.action}`, { name: appName(job.app, t) })}
      description={
        <>
          <Typography.Text code>{job.error}</Typography.Text>
          {job.log.length > 0 && (
            <details style={{ marginTop: 8 }}>
              <summary style={{ cursor: "pointer" }}>{t("apps.failed.log")}</summary>
              <pre className="app-log">{job.log.join("\n")}</pre>
            </details>
          )}
        </>
      }
    />
  );
}

export function AppsPage() {
  const { t } = useI18n();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const apps = useApps();
  const [dismissed, setDismissed] = useState("");

  const act = useMutation({
    mutationFn: ({ app, action }: { app: HostApp; action: AppAction }) => api.appAction(app.id, action),
    onError: (e, { app }) => void message.error(actionErrorText(e, app, t), 8),
    onSettled: () => qc.invalidateQueries({ queryKey: keys.apps }),
  });

  // Announce a job this page watched from running to done; a failure gets the alert below instead.
  const job = apps.data?.job ?? null;
  const watching = useRef("");
  useEffect(() => {
    if (!job) return;
    if (job.state === "running") {
      watching.current = job.startedAt;
    } else if (watching.current === job.startedAt) {
      watching.current = "";
      if (job.state === "done") void message.success(t(`apps.done.${job.action}`, { name: appName(job.app, t) }));
    }
  }, [job, message, t]);

  const data = apps.data;
  const running = job?.state === "running" ? job : null;
  const locked = !data?.supported || running !== null || act.isPending;
  const categories = [...new Set((data?.apps ?? []).map((a) => a.category))];

  const actions = (app: HostApp) => {
    const name = appName(app.id, t);
    const run = (action: AppAction) => act.mutate({ app, action });
    const plain = (action: AppAction, primary = false) => (
      <Button type={primary ? "primary" : "default"} disabled={locked} onClick={() => run(action)} aria-label={`${t(`apps.action.${action}`)} ${name}`}>
        {t(`apps.action.${action}`)}
      </Button>
    );
    const confirmed = (action: "stop" | "remove") => (
      <Popconfirm
        title={t(action === "stop" ? "apps.stopConfirm" : "apps.removeConfirm", { name })}
        okText={t(`apps.action.${action}`)}
        okButtonProps={{ danger: true }}
        cancelText={t("common.cancel")}
        onConfirm={() => run(action)}
        disabled={locked}
      >
        <Button danger={action === "remove"} type={action === "remove" ? "text" : "default"} disabled={locked} aria-label={`${t(`apps.action.${action}`)} ${name}`}>
          {t(`apps.action.${action}`)}
        </Button>
      </Popconfirm>
    );
    if (running?.app === app.id) {
      return (
        <Flex align="center" gap={8} role="status">
          <Spin size="small" />
          <Typography.Text type="secondary">{t(`apps.busy.${running.action}`)}</Typography.Text>
        </Flex>
      );
    }
    if (!app.installed) return plain("install", true);
    return (
      <Flex gap={8} wrap>
        {app.service && (app.status === "running" ? <>{plain("restart")}{confirmed("stop")}</> : plain("start", true))}
        {confirmed("remove")}
      </Flex>
    );
  };

  return (
    <>
      <PageHeader title={t("apps.title")} subtitle={t("apps.subtitle")} />
      <QueryState isPending={apps.isPending} error={apps.error} refetch={apps.refetch} />
      {data && !data.supported && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          title={t("apps.unsupported.title")}
          description={labelOr(`apps.unsupported.${data.reason}`, data.reason, t)}
        />
      )}
      {job?.state === "failed" && dismissed !== job.startedAt && <FailedJob job={job} onClose={() => setDismissed(job.startedAt)} />}
      {data && categories.map((category) => (
        <section key={category} style={{ marginBottom: 24 }} aria-label={labelOr(`apps.category.${category}`, category, t)}>
          <Typography.Title level={3} style={{ fontSize: 16, margin: "0 0 12px" }}>
            {labelOr(`apps.category.${category}`, category, t)}
          </Typography.Title>
          <div className="app-grid">
            {data.apps.filter((a) => a.category === category).map((app) => (
              <Card key={app.id} size="small" data-testid={`app-${app.id}`}>
                <Flex vertical gap={8} style={{ height: "100%" }}>
                  <Flex justify="space-between" align="flex-start" gap={8}>
                    <Typography.Text strong style={{ fontSize: 16 }}>{appName(app.id, t)}</Typography.Text>
                    <StatusTag app={app} />
                  </Flex>
                  <Typography.Text type="secondary" style={{ flex: 1 }}>
                    {labelOr(`apps.desc.${app.id}`, "", t)}
                  </Typography.Text>
                  {app.installed && app.version && (
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t("apps.version", { version: app.version })}</Typography.Text>
                  )}
                  <div>{actions(app)}</div>
                </Flex>
              </Card>
            ))}
          </div>
        </section>
      ))}
      {data?.supported && <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t("apps.source")}</Typography.Text>}
    </>
  );
}
