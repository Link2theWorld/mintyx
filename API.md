# HTTP 接口约定

后端与前端都以本文件为准。JSON 字段一律 camelCase，时间为 RFC 3339 UTC 字符串，
字节数为整数。面板只有一个管理员。

## 通用规则

- 管理接口都在 `/api/` 下，除 `setup`、`login` 外都需要登录。
- 登录态是一个 `HttpOnly`、`SameSite=Strict` 的 cookie；HTTPS 下带 `Secure`。
- 所有会改动状态的请求（非 GET）必须带请求头 `X-Mintyx: 1`，且 `Origin` 存在时
  必须与 `Host` 同源（协议、主机、端口都一致），否则 403。面板放在终结 TLS 的反向
  代理后面时，必须加 `-trust-proxy` 启动，并让代理传 `X-Forwarded-Proto: https`；
  否则面板认为自己是 HTTP，浏览器发来的 `https://` Origin 会被判为跨源。
- 错误响应：`{"error": {"code": "<机器可读>", "message": "<英文说明>", "field": "<可选>"}}`。
  code 取值：`unauthorized`(401) `forbidden`(403) `not_found`(404) `conflict`(409，
  `field` 为 `port`/`name`/`secret`/`subToken`) `invalid`(400，`field` 为出错字段)
  `rate_limited`(429) `engine`(502，配置已保存但引擎应用失败) `internal`(500)。
- 改动线路或客户后，后端重建 Xray 配置并应用。保存成功但引擎应用失败时返回
  502 `engine`，数据保持已保存状态。

## 初始化与登录

| 方法 | 路径 | 请求 | 响应 |
|---|---|---|---|
| GET | `/api/session` | | `{"needsSetup": bool, "username": string \| null}` |
| POST | `/api/setup` | `{"username","password"}` | 204，同时登录。已有管理员时 409 |
| POST | `/api/login` | `{"username","password"}` | 204。失败 401；同一 IP 连续失败过多 429 |
| POST | `/api/logout` | | 204 |
| PUT | `/api/password` | `{"current","new"}` | 204，其余会话全部失效 |

密码至少 10 个字符。

## 线路

```jsonc
// Line
{
  "id": 1, "name": "东京直连", "protocol": "vless-reality", // | "vless-xhttp" | "hysteria2"
  "port": 443, "enabled": true, "host": "", "createdAt": "…",
  "reality":   {"publicKey","shortId","serverName","target"},      // 不返回私钥
  "xhttp":     {"path","domain","security","certFile","keyFile"},  // security: "tls" | "none"
  "hysteria2": {"domain","certFile","keyFile","obfsPassword"}
}
```
三个参数块只出现与 `protocol` 对应的那一个。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/lines` | `{"lines": [Line]}` |
| POST | `/api/lines/draft` | 请求 `{"protocol","region"}`，返回一个未保存、已填好默认值的 Line（含未被占用的建议端口，无 `id`）。REALITY 的 `publicKey` 留空，密钥对在保存时生成。`region` 可省略，是服务器所在地区：`jp` `kr` `hk` `tw` `sg` `us` `eu` `other`，REALITY 的 `serverName`/`target` 取该地区候选站点里从服务器握手最快的一个，当地都不可用时退回全球站点；省略时按美西高校站点挑选；一个可用站点都没有时两项留空。未知地区 400 `invalid`，`field` 为 `region` |
| POST | `/api/lines` | 请求为 Line（无 `id`）。REALITY 省略 `publicKey` 时后端生成一对密钥 |
| PUT | `/api/lines/{id}` | 整体更新。不能改 `protocol` |
| DELETE | `/api/lines/{id}` | 204 |

## 客户

```jsonc
// Client
{
  "id": 1, "name": "我的手机", "disabled": "", // "" | "manual" | "quota" | "expired"
  "quotaBytes": 0, "expiresAt": null, "usedUp": 0, "usedDown": 0, "createdAt": "…"
}
```
`secret` 与订阅令牌不出现在列表里，只通过 share 接口给出。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/clients` | `{"clients": [Client]}` |
| POST | `/api/clients` | 请求 `{"name","quotaBytes","expiresAt"}`，后端生成密钥与订阅令牌 |
| PUT | `/api/clients/{id}` | 请求同上 |
| DELETE | `/api/clients/{id}` | 204 |
| POST | `/api/clients/{id}/disable` | 手动停用 |
| POST | `/api/clients/{id}/enable` | 解除手动停用。超限或到期的停用由续期、重置流量自动解除 |
| POST | `/api/clients/{id}/reset-traffic` | 用量清零 |
| POST | `/api/clients/{id}/rotate` | 换新密钥和订阅令牌，旧链接立即失效 |
| GET | `/api/clients/{id}/share` | 见下 |

```jsonc
// GET /api/clients/{id}/share
{
  "subscriptions": [
    {"format": "links",  "url": "https://host/sub/<token>",
     "omitted": [{"lineId": 2, "lineName": "…", "reason": "…"}]},
    {"format": "mihomo", "url": "https://host/sub/<token>?format=mihomo",
     "omitted": [{"lineId": 2, "lineName": "…", "reason": "…"}]}
  ],
  "links": [{"lineId": 1, "lineName": "东京直连", "uri": "vless://…"}]
}
```
二维码由前端根据 `uri` 与 `url` 生成。

## 订阅（公开，不需登录）

`GET /sub/{token}`，可选 `?format=links|mihomo`，默认 `links`。
响应带 `Subscription-Userinfo` 头。令牌不存在时 404，响应体为空。

## 引擎与状态

| 方法 | 路径 | 响应 |
|---|---|---|
| GET | `/api/engine` | `{"running": bool, "pid": int, "startedAt": string \| null, "lastExit": string, "restarts": int, "version": string, "binaryFound": bool}` |
| POST | `/api/engine/restart` | 204 |
| GET | `/api/engine/logs` | `{"lines": [string]}`，最近若干行 |
| GET | `/api/status` | `{"panelStartedAt", "lineCount", "clientCount", "activeClientCount", "totalUp", "totalDown"}` |

## 审计日志

`GET /api/audit?limit=50&before=<id>` → `{"entries": [{"id","at","action","target","detail","remoteIp"}]}`，新的在前。

每个改动状态的管理请求、每次登录成功与失败都记一条。`action` 是稳定的英文标识
（如 `line.create`、`client.rotate`、`login.fail`），`target` 是对象名称，
前端负责把 `action` 翻译成界面语言。密码、密钥、令牌不得写入 `detail`。

## 设置

`GET /api/settings` / `PUT /api/settings`：
`{"publicHost": "客户端连接用的域名或 IP", "subscriptionBaseUrl": "订阅地址前缀，空则按请求推断"}`

## 主机检查

`GET /api/host/ssh` → `{"passwordLogin": "on" | "off" | "unknown"}`

面板所在服务器的 sshd 是否还接受密码登录。后端执行 `sshd -T` 读取生效配置：
`PasswordAuthentication` 为 yes，或 `KbdInteractiveAuthentication` 为 yes 且启用了 PAM，
即为 `on`。不是 Linux、找不到 sshd、无权执行或输出无法识别时为 `unknown`。
结果缓存一分钟；sshd 的原始输出不会返回给前端。前端只在 `on` 时提醒改用密钥登录。
