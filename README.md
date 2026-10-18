# NetMonitor

[![CI](https://github.com/wangsawfer/NetMonitor/actions/workflows/ci.yml/badge.svg)](https://github.com/wangsawfer/NetMonitor/actions/workflows/ci.yml)

**Windows 11 上针对指定应用程序及其子进程的事件驱动 DNS 监控工具。**

给出一个可执行文件路径（可多个），NetMonitor 会**先建立监控、再启动该程序**，
从第一条 DNS 查询起实时显示它访问过的每个域名——时间戳、进程名、PID、域名，
并明确忽略其它进程产生的查询。

```
╭ NetMonitor | event-driven DNS monitor |──────────────────────────────────────╮
│* LIVE  Target D:\Apps\browser.exe  pid 42168                                │
│Uptime 00:01:12   Tree 9 proc   Sources ETW PCAP SNI                         │
╰──────────────────────────────────────────────────────────────────────────────╯
╭ Records  matching: 137  |  stored: 402  |  other processes filtered out: 91 ╮
│Time         Process       PID    Type  Src  Domain             Detail        │
│20:00:07.708 browser.exe   42168  A     ETW  www.example.com    104.20.23.154 │
│20:00:07.709 browser.exe   42168  AAAA  ETW  www.example.com    2606:4700::…  │
│20:00:08.291 browser.exe   42632  A     ETW  api.github.com     20.205.243.168│
╰──────────────────────────────────────────────────────────────────────────────╯
drops: none   DNS 137  domains 42  rate 8.6/s  cpu 0.4%  …            ▁▃█
```

## 特性

- **无真空期**：监控先于目标启动，目标的第一次查询就能被捕获
- **多目标**：可同时监控多个程序（`--app` 可重复），也可按多个映像名持续监视；
  每个目标都是同一棵进程树的一个根
- **PID 精确**：主数据源是 ETW `Microsoft-Windows-DNS-Client` 的 3006/3008 事件，
  由发起查询的进程写入，事件头 PID 就是应用本身——不是 `svchost.exe`
- **子进程全覆盖**：自动跟踪目标派生的全部后代进程
- **多源互补**：ETW + Npcap 明文抓包 + TLS SNI（应对自带解析器与 DoH）
- **纯事件驱动**：捕获路径阻塞等待内核事件，无任何定时轮询；界面按数据到达刷新
- **零依赖运行**：静态链接 MSVC 运行库，干净系统上可直接运行（Npcap 可选）
- **一个引擎、两种用法**：图形界面（`run-netmon-gui.cmd`，Python + tkinter）或
  无界面逐行输出（`--stream-json` / 纯文本），抓取能力完全相同
- **界面功能**：实时列表、暂停/恢复、清空、过滤、导出 CSV/JSON、统计、诊断日志
- **自愈**：自动清理被强杀后残留的 ETW 会话——否则它会让工具"看起来完全没有输出"
- **域名表 + AAAA 查询**：每个进程一张去重域名表，独立线程池批量查 AAAA 记录，
  不影响监控；结果可导出
- **写入 hosts**：把某个进程的域名表写入 hosts——有 IPv6 的写最优 IPv6 地址，
  没 IPv6 的默认指向 127.0.0.1 禁用；**按进程独立**，写入只追加、删除要用户点名；
  只动自己标记的区块，改前自动备份，可查看/编辑/恢复；域名表与改动记录**跨重启保留**，
  之前写的条目重启后仍可查、可按进程移除

## 下载

- **发布包**：[Releases](https://github.com/wangsawfer/NetMonitor/releases)
  （`NetMonitor-1.0.0-win64.zip`，解压即用；含 exe、图形界面、文档与源码）
- 单独的可执行文件：同一 Release 里的 `netmon.exe`（无界面 / `--stream-json` 引擎）

## 快速开始

```cmd
:: 1. 安装依赖（管理员；Rust 与所有缓存都装到非 C 盘）
powershell -ExecutionPolicy Bypass -File scripts\install.ps1

:: 2. 构建
powershell -ExecutionPolicy Bypass -File scripts\build.ps1

:: 3. 图形界面（需要 Python 3 + tkinter）
python gui\netmon_gui.py

:: 或：无界面监控一个程序，逐行输出
.\.cache\target\release\netmon.exe --app "C:\Path\To\App.exe"
```

发布包用户：

```cmd
install-npcap.cmd     :: 安装 Npcap 驱动（可选，会自动提权）
run-netmon-gui.cmd    :: 图形界面（需要 Python 3，会自动提权）
run-netmon.cmd --app "C:\Path\To\App.exe"   :: 无界面，逐行输出（会自动提权）
```

> 本版本已**移除终端界面（TUI）**。`netmon.exe` 是抓包引擎与可脚本化的前端，
> 交互操作请用 `run-netmon-gui.cmd`。

## 命令行

| 参数 | 说明 |
|---|---|
| `-a, --app <PATH>` | 目标程序路径（先建监控，再启动它）；**可重复**，同时监控多个程序 |
| `--arg <ARG>` | 传给目标的参数，可重复；所有 `--app` 共用同一组参数 |
| `--attach <IMAGE>` | 附加到已运行的进程（按映像名，收编该映像名的**全部**进程）；可重复 |
| `--keep-alive` | 目标退出后继续监控，直到手动停止 |
| `--watch <IMAGE>` | 持续按映像名监视进程并收编（含子进程），可重复 |
| `--aaaa-workers <N>` | AAAA 查询线程数，默认 4；0 关闭 |
| `--export-domains <PATH>` | 导出每个进程的域名表与 AAAA 结果 |
| `--hosts-file <PATH>` | 要管理的 hosts 文件（默认系统路径） |
| `--no-aaaa block\|skip` | 无 IPv6 的域名：指向 127.0.0.1（默认）或不写入 |
| `--no-etw` / `--no-npcap` | 关闭对应数据源 |
| `--headless` | 兼容保留；本版本没有终端界面，每次运行都是无界面模式 |
| `--duration <SECS>` | 无界面模式运行指定秒数 |
| `--export <PATH>` | 结束时导出（`.json` 走 JSON，否则 CSV） |
| `--doctor` | 打印环境自检结果 |
| `--clean-sessions` | 清理被强杀后残留的 ETW 会话（见手册 §10.5） |
| `--stream-json` | 输出 NDJSON，供图形界面/脚本消费 |

## 同时监控多个程序

`--app` 可以重复：每个程序都会作为**同一棵进程树**的一个根，它们派生的子进程
一起被监视；`--attach` 也可以重复，每个映像名会收编其全部进程。图形界面里
「浏览…」后点「添加」可以建立目标列表，按名称监视框里也能填多个映像名
（逗号或空格分隔）。

```cmd
netmon.exe --app "C:\App\main.exe" --app "C:\Tools\updater.exe"
netmon.exe --attach msedge.exe --attach chrome.exe --keep-alive
```

`--arg` 对所有 `--app` 共用同一组参数。域名表与 hosts 操作仍按进程分开。

## 只看某个进程

主程序派生的所有子进程（包括名字完全不同的下载子进程）都会自动被监控。
要看其中某一个，在界面里筛掉其它进程：

- 图形界面：「只看这些进程：」→「选择进程…」

列表列出的是**已经出现过**的进程，按记录数排序——不需要提前知道名字。
筛选同样作用于导出。详见手册 §6.4。

## 域名表与 AAAA 查询

每个进程一张去重域名表，表里每个域名都会被独立查询 AAAA 记录，结果是
「IPv6 地址 / 无 AAAA 记录 / 域名不存在 / 查询失败」四种之一。

查询跑在独立线程池里，捕获路径只做一次哈希插入和一次非阻塞入队——
DNS 服务器再慢也不会拖慢监控。

- 图形界面：工具栏「域名表 (Ctrl+W)」；表内可按**域名**或**解析地址**筛选

表格里每行显示域名、**当前解析地址**和 AAAA 查询结果。主界面过滤支持按**地址**筛
（完整 IP、`10.0.0.0/8` 网段、或 `104.16.` 片段）。
- 命令行：`--export-domains domains.csv`

详见手册 §6.5。

## 写入 hosts

把域名表写进 hosts 文件：有可用 IPv6 的域名写它的最优 IPv6 地址；
没有 IPv6 的默认指向 `127.0.0.1` 禁用（可切换为不写入）。
**可以一次选中多个进程一起写**（每个进程各写一次、各备份一次）。

**写入是按进程的，而且只增不删**：没写过的域名追加，已经写过的原样不动
（唯一例外是原来因查不到 IPv6 而写成 `127.0.0.1`、现在有 IPv6 了的，会更新成
IPv6 地址），也不会重复写第二行。删除是另外的、需要你点名的动作：
「移除该进程的条目」只删这个进程写的行，与别的进程共用的行保留。

每条记录末尾的 `# nm <进程名>` 记下这一行是谁写的，两个进程要同一个域名时
只写一行、名字并列。只修改本程序标记的区块，其它内容一个字节都不动——
写入再移除后文件哈希与原始完全一致。每次修改前自动备份，支持恢复。
程序内可以查看和编辑。

**写入范围可以是整张表，也可以是选中的几条**：在预览表里 `Ctrl` 多选、右键
「写入所选域名」即可；选中的行可以跨进程，写入时按进程分组，规则不变。

**「当前条目」支持右键**：`复制该行`（原样复制 hosts 里的那一行）和
`删除该行…`（只删这一行；若该行同时属于多个进程，会明确提示，删除前自动备份）。

**自动模式**：打开后所选进程的域名表一有变化就自动写入（一次只针对一个进程）。
会等 AAAA 查询全部落定、且计划稳定 1.5 秒后才写，避免把还没查到 IPv6 的域名先写成
127.0.0.1。只写入、不删除条目，也不清理备份。预览随域名表自动更新（没有「预览」按钮），
每条域名同时标注「文件里的现状」和「本次写入会做什么」。

**跨重启**：域名表和每一次 hosts 改动都缓存在程序旁的 `netmon-data\`
（`--data-dir` 可改，`--no-cache` 可关）。下次启动自动载入——上次写过条目的进程
即使没有在运行，也能在 hosts 窗口里选中、看它的域名表、按进程移除；
「当前条目」标签页按进程列出文件里现在由本程序写入的条目。自动模式只写本次真正
解析到的域名。

- 图形界面：工具栏「写入 hosts (Ctrl+H)」

详见手册 §6.6。

## 监控浏览器

浏览器是**单实例**程序：Edge/Chrome 已经打开时，再启动 `msedge.exe` 只会把请求
转交给已有实例然后立即退出，真正的浏览器进程跟它没有父子关系，因此什么都抓不到。
正确做法是附加到已经运行的浏览器：

```cmd
netmon.exe --attach msedge.exe --keep-alive
```

工具检测到这种转交行为时会直接把它说出来，并给出上面这条命令。详见手册 §6.3。

## 界面快捷键

| 键 | 功能 |
|---|---|
| `F5` | 开始监控 |
| `F6` | 停止 |
| `F7` | 暂停 / 恢复滚动（暂停时仍在捕获） |
| `F8` | 导出 |
| `Ctrl+S` | 统计信息 |
| `Ctrl+G` | 诊断日志 |
| `Ctrl+O` | 浏览目标程序 |
| `Ctrl+D` / `Ctrl+P` | 聚焦域名 / 进程过滤框 |
| `Ctrl+W` | 域名表 |
| `Ctrl+H` | 写入 hosts |
| `Ctrl+R` | 重查全部域名 |
| `Ctrl+T` | 选择进程 |
| `Ctrl+L` | 清空列表 |
| `Esc` | 清除过滤 |

工具栏按钮支持鼠标点击；完整说明见手册 §7。

## 文档

| 文档 | 内容 |
|---|---|
| [`docs/MANUAL.md`](docs/MANUAL.md) | 完整使用手册：安装、构建、运行、界面、输出格式、排查、性能与限制 |
| [`docs/TEST-REPORT.md`](docs/TEST-REPORT.md) | 测试报告：单元测试、端到端验证、界面验证、性能数据、开发中修复的缺陷 |

## 运行要求

| | |
|---|---|
| 操作系统 | Windows 11（Windows 10 1809+ 亦可） |
| 权限 | **管理员**（ETW 实时会话与 Npcap 驱动都需要） |
| 运行库 | 无（静态链接 MSVC 运行库） |
| Npcap | 可选。缺失时 ETW 主源仍可用，只是失去自带解析器应用的覆盖与 SNI 补充 |

## 工作原理（简版）

1. **先布监控、再启动目标**：ETW 会话与 Npcap 句柄先就绪，目标的第一条查询就能被捕获。
2. **三路采集**：ETW `Microsoft-Windows-DNS-Client` 3006/3008（PID 精确）、
   Npcap 明文抓包（自带解析器的应用）、TLS SNI（DoH/DoT 补主机名）。
3. **归属与去重**：捕获线程只解析域名并入队；单一管线线程做进程树归属、750 ms 去重、
   SNI 关联，然后写入环形缓冲。
4. **消费**：图形界面通过 `--stream-json` 读取；也可以用纯文本逐行输出或导出 CSV/JSON。
5. **hosts**：按进程生成计划 → 与现有文件追加式合并 → 备份 → 原子替换，只动本程序
   标记的区块。

线程模型、缓冲区大小与各项取舍见 [`docs/MANUAL.md`](docs/MANUAL.md) §9。

## 构建与测试

```powershell
# 依赖（管理员；Rust 与缓存装到项目盘）
powershell -ExecutionPolicy Bypass -File scripts\install.ps1

# 单元测试 + release 构建
powershell -ExecutionPolicy Bypass -File scripts\build.ps1

# 端到端验证（12 项断言，需要 ETW/Npcap 环境）
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1

# 打包到 dist\
powershell -ExecutionPolicy Bypass -File scripts\package.ps1
```

## 项目结构

```
ipv6/
├── netmon/                  Rust 源码
│   ├── src/
│   │   ├── main.rs          入口：无界面输出 / doctor 两种模式
│   │   ├── cli.rs           命令行参数
│   │   ├── app.rs           会话编排：数据源生命周期、目标启动、进程监视、hosts 与缓存
│   │   ├── pipeline.rs      归属、去重、关联、建记录
│   │   ├── store.rs         环形记录缓冲、统计、导出、IP 缓存
│   │   ├── model.rs         核心数据类型
│   │   ├── util.rs          UTF-16 / 时间 / 格式化
│   │   ├── domains.rs       每进程域名表与 AAAA 查询线程池
│   │   ├── hosts.rs         hosts 规划、合并、原子写入、备份
│   │   ├── persist.rs       域名表快照与 hosts 更改日志
│   │   ├── win/             ETW、进程树、端点表
│   │   ├── capture/         各数据源与协议解析
│   │   └── bin/             testapp.exe、etwprobe.exe
│   ├── build.rs             定位 Npcap SDK
│   └── .cargo/config.toml   静态 CRT、libpcap 版本声明
├── scripts/                 安装 / 构建 / 打包 / 验证 / 界面回归
├── docs/                    手册与测试报告
├── dist/                    打包产物
├── .toolchain/              Rust 工具链（非 C 盘）
└── .cache/                  下载缓存、构建产物、验证证据
```

## 许可证

本项目以 [MIT License](LICENSE) 开源。

开发中依赖 [Npcap](https://npcap.com/)（Nmap Project 的 Windows 抓包库与驱动）；
Npcap 的安装程序随发布包分发，其许可条款见安装器内 LICENSE，与本项目的 MIT
许可相互独立。
