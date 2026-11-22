# 本地部署器 mintyx-deploy

刚买了一台 VPS，不想碰命令行？在你自己的电脑上运行 `mintyx-deploy`，它会打开一个本地网页：
填入服务器的 IP、SSH 端口、用户名和密码（或粘贴私钥），选好服务器所在地区，点“开始部署”。
几分钟后页面上会出现一条 VLESS + REALITY 线路的二维码和分享链接。

支持的服务器：使用 systemd 的 64 位 Linux（x86_64 或 arm64）。登录用户需要是 root，或者能用 sudo。

## 它做什么

1. 通过 SSH 登录服务器。第一次连接时记住主机指纹；以后指纹变了会拒绝连接并提示
   （重装系统后属正常，可在页面上点“忘记旧指纹并重新连接”）。
2. 检查系统，上传面板程序，安装 Xray，注册并启动 `mintyx` 服务。
3. 通过 SSH 隧道调用面板自己的接口：创建管理员、填入服务器地址、新建一条 REALITY 线路和一个访客，
   取回分享链接。
4. 如果服务器上启用了 ufw 或 firewalld，放行这条线路的 TCP 端口。
5. 显示结果：二维码、链接、面板管理员密码（只在这时显示，部署器不保存）、该装哪个 App。

面板只监听服务器的 `127.0.0.1:8088`，不对公网开放。要打开面板，点页面上的“打开面板”，
部署器会建一条只有本机能用的 SSH 隧道；关掉部署器，隧道就断开。

如果服务器上已经装过并初始化过 Mintyx，部署器只会报告“已部署”，不会去动已有的账号和线路。

“改用密钥登录”的建议只在服务器仍接受密码登录时出现：连接时部署器以 root 运行 `sshd -T` 查看实际配置。
查不出结果时，如果你是用密码连上来的，照样给出建议。

## 忘了面板密码

部署器只在部署完成时显示一次管理员密码。丢了的话，用部署器重新连接服务器，点“部署”（已部署的服务器只会报告“已部署”），
再点“重置管理员密码”。新密码像首次部署时一样显示在页面上，直到你点“我已保存”。
旧密码立即失效，已登录的浏览器会被退出；线路、访客和流量记录都不受影响。

会用命令行的话，也可以在服务器上直接运行：

```sh
sudo mintyx reset-password -data /var/lib/mintyx
```

它会打印用户名和新密码，并在操作记录里留下一条“在服务器上重置密码”。

## 它在服务器上改了什么

| 位置 | 内容 |
|---|---|
| `/usr/local/bin/mintyx` | 面板程序 |
| `/usr/local/lib/mintyx/` | Xray（`xray`、`geoip.dat`、`geosite.dat`），来自 XTLS/Xray-core 官方发布的固定版本，下载后校验 SHA-256 |
| `/var/lib/mintyx/` | 面板数据（权限 0700） |
| `/etc/systemd/system/mintyx.service` | 开机自启的服务 |
| ufw / firewalld | 仅在已启用时，放行线路的 TCP 端口；从不放行面板端口 |
| 缺少时安装的软件包 | `curl`、`unzip`（只有在服务器上没有可用的下载或解压工具时） |

选择“一键改用密钥登录”时还会：

| 位置 | 内容 |
|---|---|
| 登录用户的 `~/.ssh/authorized_keys` | 追加一行新公钥 |
| `/etc/ssh/sshd_config.d/00-mintyx-keylogin.conf` | 关闭密码登录 |

顺序是：生成密钥 → 加到服务器 → **先确认密钥能登录** → 关闭密码登录 → `sshd -t` 校验、
`sshd -T` 确认生效、重载 sshd → **再确认一次密钥能登录**。第二次确认失败会自动删除该配置并重载，
密码登录照常可用。如果服务器上别的配置文件仍然保持着密码登录，部署器会如实告知，不会改动不属于它的文件。

卸载：`systemctl disable --now mintyx`，然后删除上面表格里的文件和目录。

## 它在你的电脑上存了什么

| 位置 | 内容 |
|---|---|
| 用户配置目录下的 `mintyx/known_hosts.json` | 连接过的服务器的主机指纹（macOS 在 `~/Library/Application Support`，Windows 在 `%AppData%`，Linux 在 `~/.config`） |
| `~/.ssh/mintyx_<服务器地址>_ed25519` 和 `.pub` | 只有在改用密钥登录时才生成；已有同名文件时换一个名字，从不覆盖 |

SSH 密码、私钥、面板管理员密码只存在于程序运行期间的内存里，不写入硬盘，也不写入日志。

本地网页只监听 `127.0.0.1` 上的随机端口，每次启动生成一个随机密钥（在地址的 `#` 之后），
没有这个密钥或来自其他站点的请求一律拒绝。页面不加载任何外部资源，用到的两款手写字体也由部署器自己提供，
部署器本身不访问任何第三方；页面上的教程链接只是普通链接，点了才会由浏览器打开。

## 使用

```sh
mintyx-deploy                 # 启动并打开浏览器
mintyx-deploy -no-browser     # 只打印地址，自己复制到浏览器
mintyx-deploy -panel-binary ./mintyx-linux-amd64   # 改用指定的面板程序
```

## 构建

需要 Go 和 Node 26。

```sh
scripts/build-deployer.sh
```

脚本依次构建网页前端、交叉编译两种架构的面板（纯 Go，`CGO_ENABLED=0`）、再把它们打包进部署器，
在 `dist/` 下生成 macOS（arm64、amd64）、Windows（amd64）、Linux（amd64）四个版本。
`dist/` 和打包用的面板文件都不提交到仓库。

直接 `go build ./cmd/mintyx-deploy` 也能编译，但得到的程序里没有面板文件，启动时会说明这一点，
此时需要用 `-panel-binary` 指定。

不连真服务器也能看部署器的每一步界面：下面的命令在本机起一台假的服务器和部署器页面，
按它打印的地址打开页面，再用它打印的 IP、端口、用户名和密码连接。

```sh
MINTYX_DEPLOY_DEMO=1 go test -v -run TestDemo -timeout 0 ./internal/deploy/localui
```

页面的外观跟面板一致（Flover Diary），配色抄自 `web/src/theme/themes.ts`，改面板配色时一起改；
手写字体就是面板那两个子集文件，加了部署器页面的文字后要重新运行 `node web/scripts/subset-fonts.mjs`。

升级 Xray 版本：改 `internal/deploy/scripts.go` 里的 `XrayVersion` 和两个资源文件的 SHA-256。
