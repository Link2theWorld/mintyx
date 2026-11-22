import { Flex, Typography } from "antd";
import type { ReactNode } from "react";

export function PageHeader({ title, subtitle, extra }: { title: string; subtitle?: string; extra?: ReactNode }) {
  return (
    <Flex className="page-header" justify="space-between" align="flex-start" gap={16} wrap>
      <div>
        <Typography.Title level={2} style={{ margin: 0, fontSize: 24, fontWeight: 600 }}>
          {title}
        </Typography.Title>
        {subtitle && (
          <Typography.Paragraph type="secondary" style={{ margin: "4px 0 0" }}>
            {subtitle}
          </Typography.Paragraph>
        )}
      </div>
      {extra}
    </Flex>
  );
}
