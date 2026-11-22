import { Flex } from "antd";
import type { ReactNode } from "react";

/** A handwritten page title, an optional sticker beside it, and actions on the right. */
export function PageHeader({ title, subtitle, extra, sticker }: {
  title: string;
  subtitle?: string;
  extra?: ReactNode;
  sticker?: ReactNode;
}) {
  return (
    <div className="page-header">
      <h2>{title}</h2>
      {sticker}
      <Flex flex={1} justify="flex-end" gap={8} wrap>{extra}</Flex>
      {subtitle && <p className="subtitle">{subtitle}</p>}
    </div>
  );
}
