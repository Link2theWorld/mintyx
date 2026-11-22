在自己的电脑上运行部署器，填上服务器的 IP、端口、用户名和密码，选好地区，点“开始部署”，
几分钟后就能拿到一条 VLESS + REALITY 线路的二维码和链接。

## 下载哪个

| 你的电脑 | 下载这个文件 | 怎么打开 |
|---|---|---|
| Windows 10 / 11 | `mintyx-deploy-windows.exe` | 双击 |
| macOS（Apple 芯片和 Intel 都能用） | `mintyx-deploy-macos.zip` | 双击解压，再双击 `mintyx-deploy` |
| Linux（x86_64） | `mintyx-deploy-linux.tar.gz` | `tar xzf mintyx-deploy-linux.tar.gz && ./mintyx-deploy` |

服务器要求：使用 systemd 的 64 位 Linux（x86_64 或 arm64），用 root 或能 sudo 的用户登录。

## 第一次打开被系统拦住

- **Windows**：出现“Windows 已保护你的电脑”时，点“更多信息”，再点“仍要运行”。
- **macOS 15 及以后**：先点“完成”，到“系统设置 → 隐私与安全性”最下面点“仍要打开”，再确认一次。
- **macOS 14 及更早**：按住 Control 点 `mintyx-deploy`，选“打开”。

浏览器下载时的拦截、杀毒软件误报和核对 SHA-256 的方法，见
[部署器说明](https://github.com/Link2theWorld/mintyx/blob/main/docs/deployer.md#第一次打开被系统拦住)。
