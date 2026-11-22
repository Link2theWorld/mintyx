import { AppstoreOutlined, DashboardOutlined, HistoryOutlined, SettingOutlined, TeamOutlined } from "@ant-design/icons";
import type { ReactNode } from "react";
import type { MessageKey } from "../i18n/zh";

export interface NavItem {
  path: string;
  label: MessageKey;
  icon: ReactNode;
}

export const navItems: NavItem[] = [
  { path: "/", label: "nav.overview", icon: <DashboardOutlined /> },
  { path: "/lines", label: "nav.lines", icon: <AppstoreOutlined /> },
  { path: "/clients", label: "nav.clients", icon: <TeamOutlined /> },
  { path: "/audit", label: "nav.audit", icon: <HistoryOutlined /> },
  { path: "/settings", label: "nav.settings", icon: <SettingOutlined /> },
];

export function activeNavPath(pathname: string): string {
  const match = navItems.filter((i) => i.path !== "/" && pathname.startsWith(i.path))[0];
  return match ? match.path : "/";
}
