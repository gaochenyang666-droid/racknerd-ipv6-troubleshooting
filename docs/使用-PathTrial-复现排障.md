# 使用 PathTrial 复现这次 RackNerd 排障的方法

> 对应案例：[RackNerd IPv4 / IPv6 排障实录](../README.md)  
> 工具：[PathTrial](https://github.com/gaochenyang666-droid/PathTrial) · [README 与安装说明](https://github.com/gaochenyang666-droid/PathTrial#安装与构建)  
> 时间与版本：案例原始测试发生于 **2026-10-15 至 2026-10-17**，先于本指南中的工具验收。**历史案例数字绝非 PathTrial 自动生成的实测记录。**

本指南演示怎样用 PathTrial 收集与原案例对应的可复核证据。它不能还原历史网络状态，也不能替代抓包或服务端实际业务验收。

## 1. 安装及准备

在受支持的 macOS 或 Linux 环境使用 Rust 工具链编译：

```bash
git clone https://github.com/gaochenyang666-droid/PathTrial.git
cd PathTrial
cargo build --release
./target/release/pathtrial --help
```

以下假定 `pathtrial` 已加入 PATH；否则在仓库目录用 `./target/release/pathtrial` 替换。Windows 暂未实现。

先核对实际物理接口、服务端 IPv4/IPv6 地址，以及所测端口是否确实对客户端开放。示例中的 `<YOUR_VPS_IPV4>` / `<YOUR_VPS_IPV6>` 都是**占位符**，不得直接照抄。macOS 常见的 `en0` 并不必然对应当前联网接口；Linux 的 `--bind-interface` 可能需要额外权限，绑定失败不会悄悄改走默认接口。

## 2. 对应本案例的分层检测

| 这个案例要回答的问题 | PathTrial 命令或功能 | 证据边界 |
| --- | --- | --- |
| DNS 是否解析正常，是否疑似 Fake-IP？ | `pathtrial dns example.com --server 223.5.5.5` | 解析差异不能单独证明污染；指定 DNS 也可能受本地路由影响 |
| VPS 的 SSH TCP 建连是否稳定？ | `pathtrial scan <YOUR_VPS_IPV4> --port 22 --profile ssh --rounds 20` | TCP 22 不代表代理服务的 UDP/QUIC  |
| 同一服务器 IPv6 入口是否表现更好？ | 对 IPv6 字面地址使用相同参数，保存两份报告 | 分次运行须记录时间；不能自动称为严格同分钟配对实验 |
| TLS 能否握手，证书可信么？ | `pathtrial scan your-domain.example --profile web` | `scan` 不做 HTTP 应用请求 |
| HTTPS 是否得到实际响应？ | `pathtrial http https://api.github.com/` | 仅验证当前请求，不代表长期稳定或完整代理业务 |
| 本地代理是否能转发真实 HTTPS？ | `pathtrial proxy https://api.github.com/ --proxy socks5://127.0.0.1:1080 --compare-direct` | SOCKS5 必须由用户自己开启；对照路径的 DNS、路由和出口可能不同 |
| 真实 UDP Echo 是否往返？ | `pathtrial udp --target 127.0.0.1:39001 --mode echo` | 目标端口必须运行兼容 Echo 服务；本机回环成功不等于 VPS 跨境 UDP 正常 |
| 两份采样条件一致的报告变化？ | `pathtrial compare old.json new.json` | 目标、协议、端口等不一致时会标记不可直接比较 |

### A. 分别测试 IPv4 与 IPv6 的 TCP 22

```bash
# macOS 示例：必须先确认物理网卡和实际 VPS 的字面 IP
pathtrial scan <YOUR_VPS_IPV4> --port 22 --profile ssh --rounds 20 --bind-interface en0 --redact-ips
pathtrial scan <YOUR_VPS_IPV6> --port 22 --profile ssh --rounds 20 --bind-interface en0 --redact-ips
```

这个案例的 **2026-10-17 同分钟历史数据** 为 IPv4 **8/10（平均 2476 ms）**、IPv6 **10/10（平均 323 ms）**。这些属于案例记录，**不要把它们粘贴成软件生成的新报告**。如果要获得真正的同窗口双栈交替结果，应测试一个有真实 A/AAAA 记录、两种入口都指向受测服务的域名，并核查所解析地址确实正确；若本地 TUN/Fake-IP 会污染 DNS，应先处理测量路径。

### B. 验证真实 HTTPS 与代理出口

```bash
pathtrial http https://api.github.com/
pathtrial proxy https://api.github.com/ --proxy socks5://127.0.0.1:1080 --compare-direct
```

`http` 是普通 HTTPS 应用检测；`proxy` 仅在指定的本地 SOCKS5 或 HTTP CONNECT 代理正确运行时才测代理路径。只有代理实际经过你的 VPS，才可以把本次代理请求作为那条 VPS 业务链路的证据。一个 HTTP 响应不等于十分钟稳定性测试，也不等于完整 Hysteria2 握手测试。

### C. UDP Echo 的正确做法

先在本机两个终端分别启动临时服务、进行回环验收：

```bash
# 终端 1：安全地只监听本机
pathtrial endpoint --udp-echo --bind 127.0.0.1:39001

# 终端 2
pathtrial udp --target 127.0.0.1:39001 --mode echo
```

跨机器测试必须在**你有授权的远端主机**运行兼容 Echo 服务，按需管理防火墙和端口暴露，测试完成后关闭。不要向现有 Hysteria2 的 `39000/udp` 发送 Echo 并把无回包视为网络失败，Hysteria2 不会替你返回 Echo 载荷。

历史上的“UDP 10/10”最初是 ICMP Port Unreachable，并非真实 Echo；真正的 Echo 为 **3/20、0/15、1/5**，无效 QUIC 报文无响应也无法代替合法的 QUIC 握手。

### D. 需要 QUIC/HTTP3 或双端离线关联时

目前 [PathTrial main](https://github.com/gaochenyang666-droid/PathTrial) 提供 UDP Echo、代理和基础报告。**QUIC / HTTP3、无需 SSH 的双端 TCP 采集与关联**已在 [Milestone C PR #1](https://github.com/gaochenyang666-droid/PathTrial/pull/1) 中实现并有本地集成测试，**截至本指南编写时该 PR 未合并**。只有切换到相应分支或 PR 合并后，才可参考该分支 README 使用 `quic`、`http3`、`collect`、`correlate` 命令。

即使双端采集显示双方连接行为不同，也不能在没有抓包、时钟校准和更充分证据的前提下推断具体丢包路由器。若确需定位 SYN/SYN-ACK，请继续参考 [手动双端抓包步骤](排障检查清单.md#3-双端抓包定位-tcp-报文)。

## 3. 报告、脱敏和可复核性

`scan` 默认生成带 `run_id` 的 JSON 与 Markdown 文件，不会静默覆盖之前的扫描。其他单点命令可用 `--format json` 或 `--format markdown` 输出对应内容。示例：

```bash
pathtrial scan <YOUR_VPS_IPV4> --port 22 --profile ssh --redact-ips
pathtrial compare old.json new.json --format markdown
```

对外分享前：

1. 使用 `--redact-ips` 并**人工检查** DNS 服务器、网卡名称、域名、时间和任何 URL；IP 脱敏不等于完全匿名。
2. 记录真实的时间、时区、协议、端口、地址族、超时参数和样本量，不合并不同时段的成功率。
3. 区分 `PASS`、`WARN`、`FAIL`、`SKIP` 和 `INCONCLUSIVE`；未测试不代表通过。
4. 引用 JSON 中的 probe ID，分开写明 `evidence`、`not_established` 和 `limits`。
5. 检查是否携带 SSH/VPS 口令、私钥、订阅链接或抓包载荷，未经审查不要公开。

## 4. 为什么推荐 PathTrial？

本案例最浪费时间的环节，是把“端口在监听”“收到 ICMP 错误”“TCP 偶尔成功”误读为“服务应当正常”。PathTrial 把这类证据纪律嵌入固定检测流程，并生成可复核的工单附件。

它不保证自动找出根因、不改变服务器网络配置，也不会替代 MTR/tcpdump 的深入分析。对于频繁管理 VPS、自托管服务或代理的用户，建议先用它输出**分层证据报告**，再带着明确的未证实项进行下一轮人工排查。

- [PathTrial 源码、命令与当前发布状态](https://github.com/gaochenyang666-droid/PathTrial)
- [本案例原始测试证据](测试数据与证据.md)
- [完整手动排查清单](排障检查清单.md)
