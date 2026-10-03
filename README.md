# x-scripts

## Ubuntu 24.04 一键安装 Xray VLESS

在 **Ubuntu 24.04、systemd、具有公网 IPv4 的服务器**上运行：

```bash
sudo bash cmd/xray/install-vless.sh --address 你的服务器公网IPv4
```

也可将 `--address` 设为解析到该服务器公网 IPv4 的域名。当前脚本监听 IPv4，
不支持 IPv6-only 服务器。未传入 `--sni` 时，脚本自动随机选择通过检测的 SNI，
无需交互输入。默认会执行系统软件升级；若希望跳过升级：

```bash
sudo bash cmd/xray/install-vless.sh --address 203.0.113.10 --skip-upgrade
```

`203.0.113.10` 仅为示例，必须换成真实服务器地址。可通过 `--port 8443`
修改监听端口，通过 `--sni www.microsoft.com` 固定 REALITY 目标域名。
显式指定的域名也会检测，失败时退出，不会偷偷替换为随机域名。目标端口为 443。

### 随机 SNI 候选（2026-10-03 检索整理）

内置 15 个候选，统一随机打乱，不按行业分配权重：

| 类别 | 域名 |
| --- | --- |
| 科技及开发者社区 | `www.apple.com`、`www.icloud.com`、`addons.mozilla.org`、`www.python.org`、`www.nvidia.com`、`www.samsung.com` |
| 零售及消费品牌 | `www.nike.com`、`www.adidas.com`、`www.ikea.com` |
| 在线旅游 | `www.booking.com`、`www.expedia.com`、`www.trip.com` |
| 商业软件及开发工具 | `www.jetbrains.com`、`www.atlassian.com`、`www.adobe.com` |

选择依据：

- [XTLS 官方 REALITY 说明](https://github.com/XTLS/REALITY)：目标站需支持
  TLS 1.3、HTTP/2，避免仅用于跳转的域名；IP 接近服务器、低延迟是加分项。
- [Reality-SNI-Check 项目的候选列表](https://github.com/chnnic/Reality-SNI-Check/blob/main/Reality-SNI-Check.sh)：
  原有六个科技及开发者域名来自该项目的候选池，并非 XTLS 官方认证推荐。
- 新增商业域名依据各公司官网核对：[Nike](https://www.nike.com/)、
  [adidas](https://www.adidas.com/)、[IKEA](https://www.ikea.com/)、
  [Booking.com](https://www.booking.com/)、[Expedia](https://www.expedia.com/)、
  [Trip.com](https://www.trip.com/)、[JetBrains](https://www.jetbrains.com/)、
  [Atlassian](https://www.atlassian.com/)、[Adobe](https://www.adobe.com/)。
  使用官网的 `www` 主机名作为候选，官网可访问不代表已验证 REALITY 兼容性。
  Nike、adidas 等可能跳转到同域名的地区路径；路径不写入 SNI。

脚本用系统随机源打乱候选顺序，每个域名最多检测一次，每次超时 15 秒。
在实际部署服务器上验证证书链及主机名、TLS 1.3、X25519 握手和 HTTP/2 ALPN，
失败则尝试下一个，首次成功后将同一域名写入 `target`、`serverNames` 和分享链接 `sni`。
全部失败时明确报错，允许使用 `--sni` 指定其他域名。

这是一份运行时筛选的候选池，不是“2026 年全球保证可用”名单。检测不包含
HTTP 跳转用途、客户端网络可达性或延迟排名，也不能代替客户端 REALITY 实际连接测试。
随机选择只发生在执行安装脚本时，不会在服务运行期间自动轮换。

### 自动执行的步骤

1. 检查 Ubuntu 版本、systemd、参数和端口占用，阻止并发安装。
2. 更新 apt 索引、默认升级系统并安装依赖，不自动重启服务器。
3. 写入 `/etc/sysctl.d/99-xray-bbr.conf`，加载并验证 BBR。
4. 通过 [XTLS 官方安装器](https://github.com/XTLS/Xray-install) 安装当前最新稳定版；
   已有 `/usr/local/bin/xray` 时复用，不自动升级 Xray。
5. 生成 UUID、X25519 密钥和随机 16 位十六进制 shortId；兼容 `Password`、
   `PublicKey` 和 `Public key` 输出。
6. 生成 VLESS + REALITY + Vision 配置，使用 `xray run -test` 验证后替换。
7. 已安装 UFW 时添加 TCP 放行规则，但不自动启用 UFW；启动 Xray，检查进程监听
   并设置开机自启。
8. 在 shell 中逐项输出本次配置使用的 UUID、对应私钥的 PublicKey（Password）、
   随机 shortId 和 SNI；同时输出 VLESS 导入链接，保存到
   `/root/xray-vless-link.txt`（权限 `600`）。

配置遵循 [REALITY 官方示例](https://github.com/XTLS/REALITY/blob/main/README.en.md)，
服务端采用 `network: raw` 和 `target`；链接使用客户端常见的 `type=tcp`。
私钥仅保存在服务端配置中，客户端使用 `pbk`（公钥/Password）、UUID 和 shortId。

### VLESS URI 分享链接与 subconverter

安装成功后自动在 shell 输出标准 `vless://UUID@服务器:端口?...#节点名称`
分享链接，同时保存到 `/root/xray-vless-link.txt`。原有 UUID、PublicKey、shortId
逐项输出保持不变。可指定节点名称：

```bash
sudo bash cmd/xray/install-vless.sh --address 你的服务器公网IPv4 --name '香港 REALITY'
```

链接包含 `encryption=none`、`type=tcp`、`headerType=none`、`security=reality`、
`flow=xtls-rprx-vision`、`sni`、`fp=chrome`、`pbk` 和 `sid`。
参数值和节点名称经过 URL 编码，支持中文、空格及特殊字符；链接不包含服务端私钥。
格式参考 [VLESS 分享链接提案](https://github.com/XTLS/Xray-core/discussions/716)，
参数已对照 [subconverter 的 VLESS 解析代码](https://github.com/asdlokj1qpi233/subconverter/blob/master/src/parser/subparser.cpp)。

将整行链接粘贴到订阅转换前端的输入框。后端必须支持 VLESS/REALITY，例如上述
subconverter 分支；不能保证所有旧版或原版后端均支持，输出目标客户端也需支持
VLESS + REALITY + Vision。调用 `/sub` API 时，应再将整个 URI 编码为 `url` 参数，
避免链接内部的 `&`、`#` 被当作转换 API 的分隔符。当前测试覆盖链接格式、编码及与
服务端配置的一致性，未运行实际 subconverter 转换测试。

### 已有配置、备份和故障处理

默认拒绝覆盖 `/usr/local/etc/xray/config.json`。如确实需要重新配置：

```bash
sudo bash cmd/xray/install-vless.sh --address 你的服务器公网IPv4 --force
```

`--force` 会重新生成所有连接凭据，旧客户端链接失效。原配置保存在
`/root/xray-backups/`，新配置启动失败时尝试恢复原配置及原服务运行状态。
非标准 systemd 启动命令会被拒绝；脚本面向官方安装器的单配置服务。
配置权限为 `640`，所属组取自服务的有效组，保证非 root 的 Xray 能读取私钥。
已有其他配置、自定义服务或旧版 Xray 时，建议先人工检查兼容性。

回滚仅覆盖配置替换阶段；系统升级、BBR、官方安装器操作、防火墙规则不会自动撤销。
BBR 在受限虚拟化环境中可能不可用，此时会报错退出。其他 sysctl 配置若设置相同键，
可能在重启时覆盖 BBR 设置，重启后可再次运行 `sysctl net.ipv4.tcp_congestion_control` 检查。

还需在云厂商控制台安全组放行所选 TCP 端口；脚本不能代为修改云端规则。
服务端检查通过不等于客户端端到端连接已验证，请导入链接后实测。

```bash
sudo systemctl status xray --no-pager
sudo journalctl -u xray -n 50 --no-pager
sudo /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
sudo cat /root/xray-vless-link.txt
```

### 本地验证（不会安装或修改系统）

需要 Bash、Python 3：

```bash
bash -n cmd/xray/install-vless.sh
python3 -m unittest discover -s tests -p 'test_xray_installer.py' -v
```
