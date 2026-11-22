import { theme } from "antd";

export function Logo({ size = 28 }: { size?: number }) {
  const { token } = theme.useToken();
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <rect width="32" height="32" rx="9" fill={token.colorPrimary} />
      <path d="M9 22V10l7 7 7-7v12" stroke={token.colorBgContainer} strokeWidth="3" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
