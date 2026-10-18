# netmon (source)

NetMonitor 的 Rust 源码。完整说明见仓库根的 `README.md` 与 `docs/MANUAL.md`。

## 模块职责

| 模块 | 职责 |
|---|---|
| `main.rs` | 入口；两种运行模式：无界面输出（默认，`--stream-json` 是其 JSON 形式）、`--doctor` |
| `cli.rs` | 命令行定义（clap） |
| `app.rs` | 会话编排：数据源生命周期、**先建监控后启动目标**的顺序约束、进程树监视线程、CPU 计量、hosts 与本地缓存的宿主、stdin 命令协议 |
| `pipeline.rs` | 归属判定、重复折叠、域名→进程关联、记录构造 |
| `store.rs` | 环形记录缓冲、统计、视图过滤、CSV/JSON 导出、IP↔域名缓存 |
| `model.rs` | `RawEvent` / `Record` / `Source` / `EventKind` |
| `util.rs` | UTF-16 读取、FILETIME 换算、域名类型名、格式化 |
| `domains.rs` | 每进程域名表与 AAAA 查询线程池 |
| `hosts.rs` | hosts 规划、追加式合并、原子写入、备份/恢复 |
| `persist.rs` | 本地缓存：域名表快照与 hosts 更改日志 |
| `win/etw.rs` | ETW 会话与实时消费者（安全的 RAII 封装） |
| `win/proctree.rs` | 目标进程树跟踪（快照 + 后代闭包 + 未知 PID 追溯） |
| `win/endpoint.rs` | UDP/TCP 端点表 → 端口属主 PID |
| `win/dnsq.rs` | `DnsQuery_W` 查 AAAA |
| `capture/etw_dns.rs` | 主数据源：`Microsoft-Windows-DNS-Client` 3006/3008 |
| `capture/pcap_capture.rs` | 辅助数据源：Npcap 抓包、BPF、链路层/传输层解析 |
| `capture/dns_msg.rs` | DNS 报文解析（含压缩指针） |
| `capture/tls.rs` | TLS ClientHello SNI 提取 |
| `bin/testapp.rs` | 验证用目标程序 |
| `bin/etwprobe.rs` | ETW 原始事件探针（用于推导/复核事件模板） |

## 构建

```powershell
..\scripts\build.ps1
```

或手工：

```powershell
$env:RUSTUP_HOME      = "..\.toolchain\rustup"
$env:CARGO_HOME       = "..\.toolchain\cargo"
$env:CARGO_TARGET_DIR = "..\.cache\target"
$env:NETMON_NPCAP_SDK = "..\.cache\deps\npcap-sdk"
cargo build --release
```

## 测试

```powershell
cargo test --bins
```

只跑解析与逻辑测试，不需要管理员权限（需要 ETW 会话的少数几项会在无权限时自动跳过）。
