# CLAUDE.md

Mintyx Next 是独立编写的 Xray 管理面板。功能范围见 `SPEC.md`。

## 代码来源规则（必须遵守）

- 不得打开、搜索、复制 3x-ui、x-ui 或 `/Users/mint/mintyx` 里的任何文件，
  包括代码、翻译 JSON、数据库结构、测试用例。
- 不得从 3x-ui 的 issue 或 PR 里复制代码片段。issue 只能用来了解用户需求。
- 设计依据只有三类：`SPEC.md`、Xray-core 官方文档与公开协议规范、
  各客户端公开的订阅格式文档。界面的视觉设计依据作者自己的 Flover Diary 设计系统
  （claude.ai 上的设计系统 artifact）；其中的 logo 贴纸与人物剪影仅限个人设计稿，不得放进仓库。
- 字体等非代码素材若为 SIL OFL 1.1，作为未修改的素材随附许可证文件即可。
- 数据模型、接口路径、文件结构按本项目的需求自行设计，不沿用 3x-ui 的命名。
- 引入第三方依赖前确认其许可证与 MIT 兼容（MIT、BSD、Apache-2.0、MPL-2.0
  作为未修改依赖均可）；不得引入 GPL 或 AGPL 依赖。

## 许可证

暂为 GPLv3。上面的规则是为了让作者日后能自行改为 MIT。
