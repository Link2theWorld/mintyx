import { QueryClient, QueryClientProvider, useQueryClient } from "@tanstack/react-query";
import { App as AntApp, ConfigProvider, Spin } from "antd";
import enUS from "antd/locale/en_US";
import zhCN from "antd/locale/zh_CN";
import { lazy, Suspense, useEffect, useMemo, useState, type ReactNode } from "react";
import { BrowserRouter, Navigate, Outlet, Route, Routes, useNavigate } from "react-router";
import { ApiError, setUnauthorizedHandler } from "./api/client";
import { keys, useSession } from "./api/queries";
import type { Session } from "./api/schemas";
import { QueryState } from "./components/QueryState";
import { I18nProvider, useI18n } from "./i18n/I18nProvider";
import { Shell } from "./layout/Shell";
import { AppsPage } from "./pages/AppsPage";
import { AttacksPage } from "./pages/AttacksPage";
import { AuditPage } from "./pages/AuditPage";
import { LoginPage, SetupPage } from "./pages/AuthPages";
import { ClientsPage } from "./pages/ClientsPage";
import { LinesPage } from "./pages/LinesPage";
import { OverviewPage } from "./pages/OverviewPage";
import { SettingsPage } from "./pages/SettingsPage";

// The route map brings a graph library along; it loads only when opened.
const RouteGraphPage = lazy(() => import("./pages/graph/RouteGraphPage"));
import { ThemeProvider, useThemePref } from "./theme/ThemeProvider";
import { themeConfig } from "./theme/themes";

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 2,
        refetchOnWindowFocus: true,
      },
    },
  });
}

/** Ant Design configuration driven by the current theme and language. */
export function AntProviders({ children }: { children: ReactNode }) {
  const { resolved } = useThemePref();
  const { lang } = useI18n();
  const config = useMemo(() => themeConfig(resolved), [resolved]);
  return (
    <ConfigProvider theme={config} locale={lang === "zh" ? zhCN : enUS}>
      <AntApp>{children}</AntApp>
    </ConfigProvider>
  );
}

function UnauthorizedRedirect() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  useEffect(() => {
    setUnauthorizedHandler(() => {
      qc.setQueryData<Session>(keys.session, (s) => (s ? { ...s, username: null } : s));
      void navigate("/login", { replace: true });
    });
  }, [navigate, qc]);
  return null;
}

function FullPageSpin() {
  return <div className="auth-wrap"><Spin size="large" /></div>;
}

/** Sends the visitor to setup, login or the panel depending on the session. */
function Gate({ want }: { want: "setup" | "login" | "panel" }) {
  const session = useSession();
  if (session.isPending) return <FullPageSpin />;
  if (!session.data) {
    return <div className="auth-wrap"><QueryState isPending={false} error={session.error} refetch={session.refetch} /></div>;
  }
  const s = session.data;
  const at = s.needsSetup ? "setup" : s.username === null ? "login" : "panel";
  if (at !== want) return <Navigate to={at === "panel" ? "/" : `/${at}`} replace />;
  return <Outlet />;
}

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Gate want="setup" />}>
        <Route path="/setup" element={<SetupPage />} />
      </Route>
      <Route element={<Gate want="login" />}>
        <Route path="/login" element={<LoginPage />} />
      </Route>
      <Route element={<Gate want="panel" />}>
        <Route element={<Shell />}>
          <Route index element={<OverviewPage />} />
          <Route path="lines" element={<LinesPage />} />
          <Route path="visitors" element={<ClientsPage />} />
          <Route path="clients" element={<Navigate to="/visitors" replace />} />
          <Route path="graph" element={<Suspense fallback={null}><RouteGraphPage /></Suspense>} />
          <Route path="apps" element={<AppsPage />} />
          <Route path="attacks" element={<AttacksPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}

export function App() {
  const [queryClient] = useState(makeQueryClient);
  return (
    <QueryClientProvider client={queryClient}>
      <I18nProvider>
        <ThemeProvider>
          <AntProviders>
            <BrowserRouter>
              <UnauthorizedRedirect />
              <AppRoutes />
            </BrowserRouter>
          </AntProviders>
        </ThemeProvider>
      </I18nProvider>
    </QueryClientProvider>
  );
}
