# 本地部署器 mintyx-deploy

刚买了一台 VPS，不想碰命令行？在你自己的电脑上运行 `mintyx-deploy`，它会打开一个本地网页：
填入服务器的 IP、SSH 端口、用户名和密码（或粘贴私钥），选好服务器所在地区，点“开始部署”。
几分钟后页面上会出现一条 VLESS + REALITY 线路的二维码和分享链接。

支持的服务器：使用 systemd 的 64 位 Linux（x86_64 或 arm64）。登录用户需要是 root，或者能用 sudo。

## 下载

在 [Releases 页面](https://github.com/Link2theWorld/mintyx/releases/latest) 按自己电脑的系统下载：

| 你的电脑 | 下载这个文件 | 怎么打开 |
|---|---|---|
| Windows 10 / 11 | `mintyx-deploy-windows.exe` | 双击 |
| macOS（Apple 芯片和 Intel 都能用） | `mintyx-deploy-macos.zip` | 双击解压，再双击解压出来的 `mintyx-deploy` |
| Linux（x86_64） | `mintyx-deploy-linux.tar.gz` | 在终端里运行 `tar xzf mintyx-deploy-linux.tar.gz && ./mintyx-deploy` |

打开后先出现一个命令行窗口（macOS 上是“终端”），接着浏览器自动打开部署页面。
部署和使用面板期间别关这个窗口，关掉它部署器就退出了。

第一次打开时系统多半会拦一下，按下一节放行。

## 第一次打开被系统拦住

部署器没有购买微软和苹果的开发者签名，所以浏览器和系统会提示“不常下载”“无法验证开发者”。
按下面的步骤放行一次即可。想先确认文件没被改过，见本节最后的“核对文件”。

### 下载时浏览器拦截

- **Edge**：下载栏提示“通常不会下载”时，把鼠标移到这条下载上，点右边的“…”，选“保留”，
  再点“显示更多”，选“仍然保留”。
- **Chrome**：提示“不常被下载”或“可疑文件”时，在下载列表里点“保留”或“仍然下载”。
- **Safari**：一般不拦截，下载完会自动解压 zip。

### Windows

双击后出现蓝色的“Windows 已保护你的电脑”：

1. 点提示文字里的“更多信息”。
2. 点下面出现的“仍要运行”。

如果杀毒软件把文件删除或隔离了，先按“核对文件”确认它和发布页上的一致，再在杀毒软件里恢复它
（Windows 自带的是“Windows 安全中心 → 病毒和威胁防护 → 保护历史记录”，找到这条记录点“允许”）。

### macOS 15 及以后（Sequoia、Tahoe）

1. 双击 `mintyx-deploy`，提示“Apple 无法验证……”时点“完成”。
2. 打开“系统设置 → 隐私与安全性”，拉到最下面的“安全性”，那里会写着 `mintyx-deploy` 已被阻止，
   点旁边的“仍要打开”。
3. 在弹出的提示里再点“仍要打开”，输入开机密码或用触控 ID 确认。

### macOS 14 及更早

在访达里按住 Control 键点 `mintyx-deploy`（或者用右键点），选“打开”，在提示里再点“打开”。

### 会用终端的话

macOS 上一条命令就能放行，之后直接双击：

```sh
xattr -d com.apple.quarantine ~/Downloads/mintyx-deploy
```

（文件不在“下载”文件夹的话，把路径换成实际位置；也可以输入 `xattr -d com.apple.quarantine `
之后把文件拖进终端窗口。）

### 核对文件

每个版本的 Releases 页面都有 `SHA256SUMS.txt`，列出各个文件的 SHA-256。算出来的值和里面那一行一致，
文件就是发布时的原样：

| 系统 | 命令 |
|---|---|
| Windows（PowerShell） | `Get-FileHash .\mintyx-deploy-windows.exe` |
| macOS | `shasum -a 256 mintyx-deploy-macos.zip` |
| Linux | `sha256sum -c SHA256SUMS.txt --ignore-missing` |

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

在 Mac 上接着运行 `scripts/package-release.sh`，会在 `dist/release/` 下生成发布用的三个文件和
`SHA256SUMS.txt`：Windows 的 exe、把两种 CPU 合成一个程序的 macOS zip（要用 Xcode 命令行工具里的 `lipo`），
以及 Linux 的 tar.gz。

## 发布

推一个 `v` 开头的 tag（如 `v0.1.0`），GitHub Actions（`.github/workflows/build.yml`）会跑测试、
在 macOS 机器上构建并打包，再用这个 tag 建一个 Release，附上上面那几个文件。
Release 的说明文字取自 `.github/release-notes.md`。平时的推送和 PR 也会跑同样的测试和构建，
打好的文件作为 Actions 的产物保留，但不发布。

```sh
git tag v0.1.0
git push origin v0.1.0
```

不连真服务器也能看部署器的每一步界面：下面的命令在本机起一台假的服务器和部署器页面，
按它打印的地址打开页面，再用它打印的 IP、端口、用户名和密码连接。

```sh
MINTYX_DEPLOY_DEMO=1 go test -v -run TestDemo -timeout 0 ./internal/deploy/localui
```

页面的外观跟面板一致（Flover Diary），配色抄自 `web/src/theme/themes.ts`，改面板配色时一起改；
手写字体就是面板那两个子集文件，加了部署器页面的文字后要重新运行 `node web/scripts/subset-fonts.mjs`。

升级 Xray 版本：改 `internal/deploy/scripts.go` 里的 `XrayVersion` 和两个资源文件的 SHA-256。
