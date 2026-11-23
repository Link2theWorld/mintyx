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
  `field` 为 `port`/`name`/`secret`/`subToken`，应用接口另有 `job`/`state`/`host`) `invalid`(400，`field` 为出错字段)
  `rate_limited`(429) `engine`(502，配置已保存但引擎应用失败) `internal`(500)。
- 改动线路或访客后，后端重建 Xray 配置并应用。保存成功但引擎应用失败时返回
  502 `engine`，数据保持已保存状态。例外：新建或修改线路、改走向（`PUT /api/routing`）、
  替换出口链接时，如果是 Xray 自己拒绝了新配置（`xray run -test` 不通过），这次改动会被撤回，
  返回 400 `invalid`（`field` 为 `line`、`routing` 或 `link`），数据库里不会留下 Xray 不接受的配置；
  否则下次启动时整个 Xray 都起不来。但如果改动之前的配置本来就被 Xray 拒绝（比如证书文件不见了），
  分不清是哪次改动的问题，撤回只会挡住管理员修复（比如停用出问题的线路），这时改动照常保存，返回 502。
  Xray 缺失、启动失败等其他故障也按 502 处理。

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
  "hysteria2": {"domain","certFile","keyFile","obfsPassword"},
  "exitId": null   // 只读：线路经过的第一个出口，null 表示从本机直接出网；改走向用 PUT /api/routing
}
```
三个参数块只出现与 `protocol` 对应的那一个。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/lines` | `{"lines": [Line]}` |
| POST | `/api/lines/draft` | 请求 `{"protocol","region"}`，返回一个未保存、已填好默认值的 Line（含建议端口，无 `id`）。端口：REALITY 固定为 443，即使 443 已被别的线路占用（保存时才 409）；XHTTP 取 8443、2053、2083、2087、2096 里第一个空闲的；Hysteria2 取 443/udp，与 REALITY 的 443/tcp 互不影响；都被占用时取随机高位端口。端口是否空闲按「端口号 + 传输层」判断。REALITY 的 `publicKey` 留空，密钥对在保存时生成。`region` 可省略，是服务器所在地区：`jp` `kr` `hk` `tw` `sg` `us` `eu` `other`，REALITY 的 `serverName`/`target` 从该地区的合格站点（TLS 1.3、HTTP/2、X25519、证书有效且覆盖该域名、首页不跳转）里挑：握手延迟不超过最快者 1.5 倍的几个中随机取一个，当地都不可用时退回全球站点及其他地区的站点（`other` 直接在这些站点里挑）；热门伪装站（微软、苹果、Cloudflare 系、lovelive-anime.jp、speedtest.net、Discord）不会被选中；开启连通性检测时候选还要通过 Globalping 的大陆 DNS / HTTPS 校验（规则见 SPEC §2，结论缓存 3 天，可能让这个请求多等几十秒）；省略时用设置里的 `serverRegion`，那也没有时按美西高校站点挑选；一个可用站点都没有时两项留空。未知地区 400 `invalid`，`field` 为 `region` |
| POST | `/api/lines` | 请求为 Line（无 `id`）。REALITY 省略 `publicKey` 时后端生成一对密钥 |
| PUT | `/api/lines/{id}` | 整体更新。不能改 `protocol` |

线路端口的规则：
- 端口按「端口号 + 传输层」计：REALITY、XHTTP 用 TCP，Hysteria2 用 UDP。同一传输层上两条线路不能用同一个端口，否则 409 `conflict`，`field` 为 `port`；REALITY 在 443/tcp、Hysteria2 在 443/udp 可以并存。面板自身和 Xray API 的保留端口只占 TCP。
- REALITY 线路的端口必须是 443，否则 400 `invalid`，`field` 为 `port`。之前已存在别的端口上的
  REALITY 线路，更新时可以保留原端口，或改到 443。一台服务器因此只有一条 REALITY 线路（443 上）。
- 保存后处于启用状态、端口为 443 的 REALITY 线路，在交给 Xray 之前先腾出 443/tcp：除面板自己
  和它的 Xray 以外，监听 443/tcp 的程序都会被停掉。属于 systemd 系统服务的执行
  `systemctl disable --now`（停止并取消开机自启），其他进程先发 SIGTERM，几秒内不退出再发 SIGKILL。
  停了什么记一条审计 `port.free`（对象 `443/tcp`，详情列出服务名或「进程名 (pid N)」）。
- 443/tcp 腾不出来时（占用者是 sshd 或 systemd 自己监听的套接字单元、看不到占用者、停止失败或
  停了仍被占用）不保存这次改动，返回 409 `conflict`，`field` 为 `port`，`message` 说明原因。
| DELETE | `/api/lines/{id}` | 204 |

## 访客

```jsonc
// Client
{
  "id": 1, "name": "我的手机", "disabled": "", // "" | "manual" | "quota" | "expired"
  "quotaBytes": 0, "expiresAt": null, "usedUp": 0, "usedDown": 0, "createdAt": "…",
  "quotaResetDay": 0,    // 0 = 流量不循环；1–31 = 每月这一天的 0 点清零（没有这一天的月份按月底）
  "nextResetAt": null    // 下次清零的时刻；不循环时为 null
}
```
`secret` 与订阅令牌不出现在列表里，只通过 share 接口给出。

按月循环：每月清零按设置里的 `timeZone` 计算 0 点。清零时用量归零，因超量停用的访客随即恢复，
审计日志记一条 `client.cycle-reset`（来源 IP 为空）。新设或改动重置日只确定周期起点，不会立刻清零。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/clients` | `{"clients": [Client]}` |
| POST | `/api/clients` | 请求 `{"name","quotaBytes","expiresAt","quotaResetDay"}`，后端生成密钥与订阅令牌 |
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

### 合并其他服务器的线路

访客在其他服务器上的线路，用那台服务器给这位访客的分享链接添加，之后出现在这位访客的订阅里
（本机线路在前）。只改订阅，不改 Xray 配置，不会重启 Xray；面板不连接这些服务器。

```jsonc
// RemoteLine
{
  "id": 7, "name": "首尔", "createdAt": "…",
  "summary": { /* 同 Exit 的 summary，不含任何密钥 */ }
}
```

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/clients/{id}/remote-lines` | `{"remoteLines": [RemoteLine]}`，按添加顺序。访客不存在时 404 |
| POST | `/api/clients/{id}/remote-lines` | 请求 `{"name","link"}`，201 RemoteLine。`name` 为空时取链接 `#` 后的备注，再没有就用“协议 地址”。只接受 `vless://`（`type=raw`/`tcp` 配 `security=reality`，或 `type=xhttp` 配 `security=tls`，`encryption=none`）和 `hysteria2://`；证书指纹（`pcs`、`vcn`、`pinSHA256`）、`pqv`、`xtls-rprx-vision-udp443` 不是每种订阅格式都能表达，一律拒绝。错误为 400 `invalid`，`field` 为 `link.<部分>`（如 `link.scheme`、`link.pcs`）；链接其实是本面板自己的线路时 `field` 为 `link`。每位访客最多 32 条 |
| PUT | `/api/clients/{id}/remote-lines/{rid}` | 请求同上；`link` 为空表示保留原链接 |
| DELETE | `/api/clients/{id}/remote-lines/{rid}` | 204 |

`{rid}` 不属于这位访客时 404。删除访客时一并删除。更换访客密钥（rotate）不影响这些链接，
那边的服务器换了密钥要删掉重加。审计动作为 `client.remote-line.create` / `update` / `delete`，
`target` 是访客名，`detail` 是线路名、协议与地址。

## 出口与走向

出口是另一台代理服务器，线路的流量可以经它（或一串出口）出网：线路 → 出口 A → 出口 B → 互联网。

```jsonc
// Exit
{
  "id": 3, "name": "首尔落地", "region": "kr",   // region: "" 或地区代码
  "nextId": null,                                 // 下一跳出口，null 表示从这里出网
  "createdAt": "…",
  "summary": {                                    // 从链接读出的概要，不含任何密钥
    "protocol": "vless",       // vless | trojan | shadowsocks | socks | hysteria2
    "host": "198.51.100.8", "port": 443,
    "network": "raw",          // vless/trojan：raw | xhttp | ws | grpc；其余为空
    "security": "reality",     // none | tls | reality
    "serverName": "www.samsung.com", "flow": "xtls-rprx-vision", "method": "",
    "auth": false,             // socks 带用户名
    "obfs": false,             // hysteria2 salamander
    "pinned": false,           // 固定了证书指纹
    "plaintext": false,        // 本机到出口之间不加密
    "udp": false               // 走 UDP（hysteria2）
  }
}
```

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/exits` | `{"exits": [Exit]}` |
| POST | `/api/exits/parse` | 请求 `{"link"}`，返回 `{"name","summary"}`：只预览，不保存 |
| POST | `/api/exits` | 请求 `{"name","region","link"}`，201 Exit。`name` 为空时取链接 `#` 后的备注，再没有就用“协议 地址”。链接错误为 400 `invalid`，`field` 为 `link.<部分>`（如 `link.pbk`、`link.scheme`）；指向本面板自己的线路时 `field` 为 `link`。新出口不接线，不会重启 Xray |
| PUT | `/api/exits/{id}` | 请求同上；`link` 为空表示保留原参数 |
| POST | `/api/exits/{id}/copy` | 在服务器端复制一份（含密钥），名称加“ (2)”，不接线。同一台服务器既当终点又当中间跳时用 |
| DELETE | `/api/exits/{id}` | 204。还有线路或出口经过它时 409 `conflict`（`field` 为 `exit`，`message` 列出引用者），带 `?unlink=1` 才删除并让引用者改为直接出网 |
| GET | `/api/routing` | `{"lines":[{"id","exitId"}],"exits":[{"id","nextId"}]}` |
| PUT | `/api/routing` | 请求同上，只需列出要改的项，`null` 表示直接出网；一次请求只重启一次 Xray，返回全部走向。未知 id、同一项列两次、成环（`message` 写出环路）或超过 4 跳为 400 `invalid`，`field` 如 `exits[0].nextId` |
| GET | `/api/exits/latency` | `{"refreshing": bool, "exits": [{"id","rttMs","measuredAt","unmeasured","error"}]}`。立即返回缓存（60 秒有效），过期时在后台刷新。`rttMs` 是从本机到出口的 TCP 握手时间；`unmeasured` 为 `udp`（hysteria2）或 `inner`（只在别的出口后面用到，本机不直接连它），这两种不测 |
| POST | `/api/exits/latency` | 立即重测，同上；两次之间至少隔 30 秒，否则 429 |
| GET | `/api/graph/layout` | `{"positions": {"<节点 id>": {"x","y"}}}`：线路图上的节点位置 |
| PUT | `/api/graph/layout` | 请求同上，204 |

生成的 Xray 配置：每个不同的出口路径前缀一个出站（标签 `via-3`、`via-3-7`），后一跳用
`streamSettings.sockopt.dialerProxy` 经前一跳连接；每条接了出口的线路一条路由规则，排在内网地址
拦截规则之后。有接线的出口时路由改用 `IPOnDemand`，让拦截规则先解析域名，指向内网地址的域名也在本机入口处拦下。只有接在启用线路上的出口会写进配置，所以没接线的出口增删改都不会重启 Xray。
出口不通时流量直接失败，不会改走直连。

## 订阅（公开，不需登录）

`GET /sub/{token}`，可选 `?format=links|mihomo`，默认 `links`。
响应带 `Subscription-Userinfo` 头。令牌不存在时 404，响应体为空。

内容是本机已启用且可用的线路，后面接着这位访客合并的其他服务器线路（见上）。停用的访客得到一份空订阅。

- `links`：每条线路一个分享链接，换行分隔后整体 base64。其他服务器的线路按存下的参数重新生成链接，名称用面板里的名称。
- `mihomo`：`proxies` 列出全部线路，名称重复时加 “ (2)”。代理组 `Proxy`（`select`）列出全部线路和 `DIRECT`，
  规则只有 `MATCH,Proxy`。合并了其他服务器的线路、且总共不止一条时，再加一个组：

  ```yaml
  - name: Load Balance
    type: load-balance
    strategy: consistent-hashing   # 同一目标（域名按主域）固定走同一条线路
    url: https://www.gstatic.com/generate_204   # 健康检查由客户端发起
    interval: 300
    proxies: [全部线路]
  ```
  并把 `Load Balance` 放在 `Proxy` 组的第一项，客户端默认就用它。

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

## 攻击记录

面板从本机日志里认出针对服务器的攻击，按来源 IP 汇总：sshd 的日志（经 systemd journal
读取）和 Xray 的输出。只读本机日志，不联网。通过密钥登录成功过的 IP 视为管理员自己，
不记录。来源在最后一次出现 30 天后删除。

攻击类型 `kind`：`ssh_login`（对存在的账号尝试登录）、`ssh_invalid_user`（用不存在的
用户名尝试登录）、`ssh_scan`（连上 SSH 端口但没到登录这一步）、`line_probe`（连到线路
端口但握手不对）、`line_bad_auth`（协议正确但凭证无效）。sshd 对同一条连接会写多行日志，
一条连接只算一次。

归属地查询默认关闭。开启后面板用 RDAP 向 IANA（`data.iana.org`）和各地区互联网注册
机构查询每个来源 IP 的注册国家、网络名称和举报邮箱，对方会看到被查询的 IP。

```jsonc
// AttackSummary
{
  "sources": 87, "hits": 34000, "retentionDays": 30,
  "kinds":     [{"kind": "ssh_login", "hits": 6728, "sources": 35}],
  "countries": [{"country": "NL", "sources": 15, "hits": 4180}],   // 只统计已查到归属的来源，最多 12 项
  "networks":  [{"network": "Example B.V.", "country": "NL", "abuseEmail": "abuse@example.nl", "sources": 15, "hits": 4180}], // 最多 10 项
  "daily":     [{"day": "2026-11-21", "hits": {"ssh_login": 120}}], // 最近 14 个 UTC 日期，从早到晚，没有攻击的日期也在
  "lookup": {
    "enabled": false, "lookedUp": 0, "pending": 87,
    "error": "",          // 最近一次查询的英文错误，成功后清空
    "pausedUntil": null   // 被注册机构限流时，暂停到这个时间
  },
  "sshLog": "ok"          // "starting"（还没读过）| "ok" | "unavailable"（本机没有 systemd journal）| "error"
}

// Attacker
{
  "ip": "203.0.113.5", "firstAt": "…", "lastAt": "…", "hits": 12,
  "kinds": [{"kind": "ssh_login", "hits": 12, "firstAt": "…", "lastAt": "…"}],
  "lookedUp": true,       // false：还没查，或没查到
  "lookupError": "",      // "" | "not_found" | "error"
  "country": "NL",        // 注册地，不一定是机器所在地。两位国家代码；注册机构只给了文字时为原文；可为 ""
  "network": "Example B.V.", "netRange": "203.0.113.0/24",
  "abuseEmail": "abuse@example.nl", "registry": "RIPE NCC"
}
```

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/attacks/summary` | AttackSummary |
| GET | `/api/attacks?kind=&country=&limit=&offset=` | `{"attackers": [Attacker], "total": n}`，最近出现的在前。`kind`、`country` 可省略；`limit` 1–200，默认 50。未知的 `kind` 400 `invalid` |
| GET | `/api/attacks/{ip}/report` | 给该来源所属网络的举报信草稿：`{"ip","to","network","subject","body"}`，英文。`to` 是举报邮箱，没查到时为 `""`。面板不发信，由管理员用自己的邮箱发出。没有这个来源时 404 |
| DELETE | `/api/attacks` | 清空全部记录，204 |
| GET | `/api/attacks/config` | `{"lookup": bool}` |
| PUT | `/api/attacks/config` | 请求与响应同上 |

## 审计日志

`GET /api/audit?limit=50&before=<id>` → `{"entries": [{"id","at","action","target","detail","remoteIp"}]}`，新的在前。

每个改动状态的管理请求、每次登录成功与失败都记一条。`action` 是稳定的英文标识
（如 `line.create`、`client.rotate`、`login.fail`、`exit.create`、`routing.update`），`target` 是对象名称，
前端负责把 `action` 翻译成界面语言。密码、密钥、令牌不得写入 `detail`。

## 设置

`GET /api/settings` / `PUT /api/settings`：
`{"publicHost": "客户端连接用的域名或 IP", "subscriptionBaseUrl": "订阅地址前缀，空则按请求推断", "timeZone": "Asia/Seoul", "serverRegion": ""}`

`timeZone` 是 IANA 时区名，默认 `Asia/Seoul`，决定按月清零流量的 0 点。PUT 时可以不带这个字段，
不带就保留原值。改时区时，所有按月循环的访客把周期起点移到新时区的 0 点，不额外清零。

`serverRegion` 是本机所在地区（`""` 或地区代码），显示在线路图上，也是新建线路草稿的默认地区。
PUT 时同样可以不带。

## 主机检查

`GET /api/host/ssh` → `{"passwordLogin": "on" | "off" | "unknown"}`

面板所在服务器的 sshd 是否还接受密码登录。后端执行 `sshd -T` 读取生效配置：
`PasswordAuthentication` 为 yes，或 `KbdInteractiveAuthentication` 为 yes 且启用了 PAM，
即为 `on`。不是 Linux、找不到 sshd、无权执行或输出无法识别时为 `unknown`。
结果缓存一分钟；sshd 的原始输出不会返回给前端。前端只在 `on` 时提醒改用密钥登录。

## 应用

在面板所在的服务器上安装、卸载、启停内置清单里的软件。清单固定在后端，接口不接受
清单之外的标识。

`GET /api/apps` →

```jsonc
{
  "supported": true,
  "reason": "",          // 不支持时的原因：os（不是 Linux）| root（面板不是 root）| systemd | apt
  "apps": [{
    "id": "nginx", "category": "web",   // web | container | tools
    "ports": [80],                       // 装好后立即占用的 TCP 端口
    "service": true,                     // 有后台服务，可以启动、停止、重启
    "installed": false, "version": "",
    "status": ""                         // running | stopped | failed；未安装或没有服务时为 ""
  }],
  "job": null            // 正在执行或最近一次结束的操作
  // {"app","action","state": "running" | "done" | "failed","startedAt","endedAt": string | null,
  //  "error": "失败的那一步","log": ["命令及其输出，最多 200 行"]}
}
```

`supported` 为 false 时 `apps` 仍列出清单，但不检查主机，各项都是未安装。

`POST /api/apps/{id}/{action}`，`action` 为 `install` `remove` `start` `stop` `restart`。
接受后立即返回 202，操作在后台执行，进度与结果从 `GET /api/apps` 的 `job` 读取。

| 情况 | 响应 |
|---|---|
| 应用或动作不存在 | 404 `not_found` |
| 另一个操作还在执行 | 409 `conflict`，`field` 为 `job` |
| 安装时所需端口已被占用 | 409 `conflict`，`field` 为 `port` |
| 动作与当前状态不符（重复安装、卸载未安装的、启动没有服务的应用） | 409 `conflict`，`field` 为 `state` |
| 这台服务器不能管理应用 | 409 `conflict`，`field` 为 `host` |

`start` 执行 `systemctl enable --now`，`stop` 执行 `systemctl disable --now`。
审计动作为 `app.<action>`，对象是应用标识；后台操作失败时再记一条 `app.<action>.fail`。
