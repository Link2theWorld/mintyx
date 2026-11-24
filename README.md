# Mintyx

一个人用的 Xray 面板，带一键部署器：在自己的电脑上点几下，就能把面板装到海外服务器上，拿到第一条线路。

A self-hosted Xray panel for one person, with a desktop deployer that installs it on your server over SSH.

## 教学视频

3 分钟看完：一键部署、基础功能、只有 Mintyx 才有的功能。

https://github.com/user-attachments/assets/86d28c96-c89a-4ff3-a594-acabcf82d8ec

## 开始用

**1. 下载部署器**

| 你的电脑 | 下载 |
|---|---|
| Windows 10 / 11 | [mintyx-deploy-windows.exe](https://github.com/Link2theWorld/mintyx/releases/latest/download/mintyx-deploy-windows.exe) |
| macOS（Apple 芯片和 Intel 都能用） | [mintyx-deploy-macos.zip](https://github.com/Link2theWorld/mintyx/releases/latest/download/mintyx-deploy-macos.zip) |
| Linux（x86_64） | [mintyx-deploy-linux.tar.gz](https://github.com/Link2theWorld/mintyx/releases/latest/download/mintyx-deploy-linux.tar.gz) |

所有版本和 SHA-256 校验值在 [Releases 页面](https://github.com/Link2theWorld/mintyx/releases)。

**2. 打开部署器**

Windows 上双击 exe；macOS 上双击解压 zip，再双击 `mintyx-deploy`。
先出现一个命令行窗口，接着浏览器自动打开部署页面。用完之前别关这个窗口。

第一次打开时系统会拦一下：

- **Windows**：出现“Windows 已保护你的电脑”时，点“更多信息”，再点“仍要运行”。
- **macOS 15 及以后**：先点“完成”，到“系统设置 → 隐私与安全性”最下面点“仍要打开”，再确认一次。
- **macOS 14 及更早**：按住 Control 点 `mintyx-deploy`，选“打开”。

浏览器拦截下载、杀毒软件误报、怎么核对文件，见[部署器说明](docs/deployer.md#第一次打开被系统拦住)。

**3. 部署**

1. 填上服务商给你的服务器 IP、SSH 端口、用户名和密码（或私钥），点“连接”。
2. 选服务器所在的地区，点“开始部署”。部署器会检查系统、上传面板、安装 Xray、注册开机自启的服务，几分钟就好。
3. 部署完，用手机客户端扫二维码，或者复制链接导入。页面下方会写每种系统该装哪个 App。
4. 管理员密码只显示这一次，先存好。
5. 点“打开面板”进管理后台。

服务器要求：使用 systemd 的 64 位 Linux（x86_64 或 arm64），用 root 或能 sudo 的用户登录。

## 面板里有什么

- **概览**：线路和访客数量、总流量、Xray 的运行状态。
- **线路**：VLESS + REALITY、VLESS + XHTTP、Hysteria2 三种入站，端口和密钥自动生成。REALITY 走 443/tcp，Hysteria2 走 443/udp，可以放在同一台服务器上。
- **伪装网站**：REALITY 的伪装网站按服务器所在地区自动挑选，每 6 小时复查一次，不合格就自动换一个。开了连通性检测，还会从国内探测点核对候选站点。
- **访客**：每台设备或每位亲友一个，可以设流量上限和到期时间，用完自动停用，也可以每月自动清零。
- **分享**：订阅地址和单条链接，按对方的手机系统推荐 App。可以把别的服务器上的线路并进同一个订阅。
- **连通性检测**：定时从国内探测点测线路，分清是被墙还是服务器本身出了问题，有变化就发邮件。
- **线路图**：访客、线路、出口和互联网画在一张图上，拖一条线就能换出口。
- **攻击记录**：谁在扫端口、谁在猜密码，按类型和来源汇总，可以生成英文举报信。
- **应用**：Nginx、Docker 等常用软件，点一下安装。
- 日间、夜间、午夜三套主题，手机上也能用。

## 文档

- [部署器说明](docs/deployer.md)：部署器在服务器和你的电脑上改了什么、忘了密码怎么办、怎么卸载
- [SPEC.md](SPEC.md)：功能范围
- [API.md](API.md)：面板的 HTTP 接口

## 从源码构建

需要 Go 1.27 和 Node 26：

```sh
scripts/build-deployer.sh
```

生成的部署器在 `dist/` 下，里面已经带着两种 CPU 的面板程序。详见[部署器说明](docs/deployer.md#构建)。

## 许可证

[GPLv3](LICENSE)。界面里的两款手写字体（Long Cang、Caveat）按 SIL Open Font License 1.1 随附，
许可证在 `web/src/assets/fonts/` 下。
