import { LogoutOutlined } from "@ant-design/icons";
import { useQueryClient } from "@tanstack/react-query";
import { Button, Flex, Layout, Menu, Popover, Typography, theme } from "antd";
import { BgColorsOutlined } from "@ant-design/icons";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { api } from "../api/client";
import { GuidesButton } from "../components/Guides";
import { useI18n } from "../i18n/I18nProvider";
import { useIsMobile } from "../lib/useIsMobile";
import { Logo } from "./Logo";
import { activeNavPath, navItems } from "./nav";
import { PreferencesBlock } from "./Preferences";

function useLogout() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  return async () => {
    try {
      await api.logout();
    } finally {
      qc.clear();
      void navigate("/login", { replace: true });
    }
  };
}

function Brand() {
  const { t } = useI18n();
  return (
    <Flex align="center" gap={10}>
      <Logo />
      <div>
        <Typography.Text strong style={{ fontSize: 17, display: "block", lineHeight: 1.2 }}>{t("app.name")}</Typography.Text>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>{t("app.tagline")}</Typography.Text>
      </div>
    </Flex>
  );
}

function DesktopShell() {
  const { t } = useI18n();
  const { token } = theme.useToken();
  const location = useLocation();
  const navigate = useNavigate();
  const logout = useLogout();
  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Layout.Sider
        width={232}
        style={{ borderRight: `1px solid ${token.colorBorderSecondary}`, position: "sticky", top: 0, height: "100vh" }}
      >
        <Flex vertical style={{ height: "100%", padding: "20px 12px" }} gap={20}>
          <div style={{ padding: "0 8px" }}><Brand /></div>
          <nav aria-label={t("nav.main")} style={{ flex: 1 }}>
            <Menu
              mode="inline"
              selectedKeys={[activeNavPath(location.pathname)]}
              onClick={({ key }) => void navigate(key)}
              items={navItems.map((i) => ({ key: i.path, icon: i.icon, label: t(i.label) }))}
            />
          </nav>
          <div style={{ padding: "0 8px" }}>
            <div style={{ marginBottom: 16 }}><GuidesButton /></div>
            <PreferencesBlock />
            <Button block icon={<LogoutOutlined />} style={{ marginTop: 16 }} onClick={() => void logout()}>
              {t("nav.logout")}
            </Button>
          </div>
        </Flex>
      </Layout.Sider>
      <Layout.Content>
        <main className="page">
          <Outlet />
        </main>
      </Layout.Content>
    </Layout>
  );
}

function MobileShell() {
  const { t } = useI18n();
  const { token } = theme.useToken();
  const location = useLocation();
  const active = activeNavPath(location.pathname);
  return (
    <Layout style={{ minHeight: "100vh" }}>
      <header
        className="mobile-header"
        style={{ background: token.colorBgLayout, borderBottom: `1px solid ${token.colorBorderSecondary}` }}
      >
        <Flex align="center" gap={8}>
          <Logo size={24} />
          <Typography.Text strong style={{ fontSize: 16 }}>{t("app.name")}</Typography.Text>
        </Flex>
        <Flex align="center" gap={4}>
          <GuidesButton compact />
          <Popover trigger="click" placement="bottomRight" content={<div style={{ width: 260 }}><PreferencesBlock /></div>}>
            <Button type="text" icon={<BgColorsOutlined />} aria-label={`${t("theme.label")} / ${t("lang.label")}`} />
          </Popover>
        </Flex>
      </header>
      <main className="page page-mobile">
        <Outlet />
      </main>
      <nav
        aria-label={t("nav.main")}
        className="tabbar"
        style={{ background: token.colorBgContainer, borderTop: `1px solid ${token.colorBorderSecondary}` }}
      >
        {navItems.map((i) => {
          const isActive = i.path === active;
          return (
            <NavLink
              key={i.path}
              to={i.path}
              end={i.path === "/"}
              className="tabbar-item"
              aria-current={isActive ? "page" : undefined}
              style={{ color: isActive ? token.colorPrimary : token.colorTextSecondary, outlineColor: token.colorPrimary }}
            >
              <span className="tabbar-icon" aria-hidden="true">{i.icon}</span>
              <span className="tabbar-label">{t(i.label)}</span>
            </NavLink>
          );
        })}
      </nav>
    </Layout>
  );
}

export function Shell() {
  return useIsMobile() ? <MobileShell /> : <DesktopShell />;
}

export { useLogout };
