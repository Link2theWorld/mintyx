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

## 连通性检测与告警

从中国大陆境内的 Globalping 探测点检查服务器 IP 与各线路端口是否可达，状态变化时
用管理员自己的 SMTP 服务器发邮件。默认关闭。开启后面板只主动连接
`api.globalping.io` 和所填的 SMTP 服务器。

```jsonc
// ReachConfig
{
  "enabled": false,
  "intervalMinutes": 30,   // 10–1440。线路多时实际间隔会自动拉长，见下
  "confirmRounds": 2,      // 1–10，连续几轮异常才算数；恢复只需一轮
  "smtp": {
    "host": "", "port": 587, "security": "starttls", // "starttls" | "tls" | "none"
    "username": "",          // 空表示不登录
    "password": "",          // 只写：响应里没有这个字段
    "passwordSet": false,    // 只读：是否已存有密码
    "from": "", "to": ""     // to 可用逗号分隔多个地址
  }
}
```
`smtp.host` 为空表示不发邮件，此时 `from`、`to` 可以留空。

```jsonc
// ReachStatus
{
  "enabled": true,
  "configured": true,      // false：有已启用的线路没有可测的地址，需要先填「公共地址」
  "running": false,        // 是否正有一轮检测在进行
  "lastCheckAt": "…",      // 可为 null
  "nextCheckAt": "…",      // 可为 null（未开启或没有可测线路）
  "lastError": "",         // "" | "rate_limited" | "too_many_lines" | "probe_failed"
  "lastErrorDetail": "",   // 英文原始错误，仅供排查
  "alertError": "",        // 最近一次告警邮件的 SMTP 错误；发出后清空
  "targets": [{
    "lineId": 1, "lineName": "东京直连", "protocol": "vless-reality",
    "host": "vps.example.com", "port": 443,
    "ipOnly": false,       // true：UDP 线路，只测了 IP，没测端口
    "verdict": "ok",       // 已确认的结论："ok" | "port_blocked" | "ip_blocked" | "down" | "unknown"
    "since": "…",          // 该结论确认的时间，可为 null
    "lastResult": "ok",    // 最近一轮单独的结论，取值同 verdict；从未检测过为 ""
    "chinaReached": 5, "chinaAnswered": 5,     // 大陆探测点：连上的 / 有结果的
    "controlReached": 3, "controlAnswered": 3  // 对照探测点（大陆以外）
  }]
}
```
`targets` 只含已启用且有地址可测的线路；测的是分享链接里的那个地址和端口。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/reach/config` | ReachConfig |
| PUT | `/api/reach/config` | 整体更新，返回 ReachConfig。`smtp.password` 为空表示保留已存的密码；`username` 为空则清除密码；改了 `host` 或 `username` 必须重新填写密码，否则 400 `invalid`（`field` 为 `smtp.password`）。出错字段形如 `intervalMinutes`、`smtp.host` |
| GET | `/api/reach/status` | ReachStatus |
| POST | `/api/reach/check` | 立即检测一轮，结束后返回 ReachStatus（可能要等几十秒）。未开启、没有可测线路或已有一轮在进行时 409 `conflict`；距上一轮不足 1 分钟时 429 `rate_limited` |
| POST | `/api/reach/test-email` | 请求为 ReachConfig 里的 `smtp` 对象，用它发一封测试邮件，不保存。密码规则同上。返回 `{"sent": bool, "error": "SMTP 报错原文，成功时为空"}`，发信失败也是 200 |

结论的判定：每轮对每个地址做一次 ICMP ping，对每个 TCP 端口做一次 TCP ping，
都由同一批探测点执行（5 个大陆探测点加日本、美国、德国各 1 个对照点）。一组探测点
至少 2 个有结果、且严格过半一致才算数，否则该组视为没有结论。

- `ok`：大陆探测点能连上该端口。
- `port_blocked`：大陆连不上该端口，对照点能连上，且不足以认定整个 IP 不通。
- `ip_blocked`：大陆连不上该端口，对照点能连上，并且大陆没有任何一种测法能通，
  同时 ping 也被挡住（对照点 ping 得通、大陆 ping 不通），或者至少两个端口都是
  这种情况。单独一个端口不通不会判成 IP 被墙，因为只封端口的情况确实存在。
- `down`：对照点也连不上该端口。
- `unknown`：以上都无法确定，包括接口报错和被限流。

UDP 线路（Hysteria2）只按 IP 判定：大陆有任一种测法能通即 `ok`，按上面的条件
认定 IP 不通即 `ip_blocked`；同一地址的 TCP 线路在对照点全都不通、ping 也不通时为 `down`。
服务器不回应 ping 且没有 TCP 线路可参照时为 `unknown`。

Globalping 对匿名调用按来源 IP 限制每小时 250 次测试，一次测量每个探测点算一次，
即每次测量 8 次。一轮的测量数是「地址数 + TCP 端口数」，最多 12 次测量（96 次测试），
超出的线路本轮为 `unknown`，`lastError` 为 `too_many_lines`。定时检测每小时最多用
100 次测试，间隔太短时自动拉长到满足这个预算为止，其余额度留给手动检测。
收到限流响应后，下一轮不早于接口给出的重置时间。

`action` 取值：`reach.configure`（`detail` 是改动的字段名，如 `enabled, smtp.password`）、
`reach.check`、`reach.test_email`。

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
