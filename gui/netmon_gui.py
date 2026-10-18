#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NetMonitor 图形界面。

架构说明
========
真正做抓包的是 ``netmon.exe``（Rust 实现，ETW + Npcap，事件驱动）。
本程序是它的**前端**：以 ``--stream-json`` 模式启动引擎，逐行读取引擎输出的
NDJSON（每行一个 JSON 对象），把记录渲染到表格里，并把用户操作翻译成命令行。

这样分工的理由：域名捕获对延迟和丢包极其敏感，必须在内核事件回调里用原生代码
完成；而界面是"人机交互"问题，Python + tkinter 能以最少代码做出原生窗口、
原生文件对话框、可排序表格和实时过滤。把两者分开，任何一方卡住都不会影响另一方。

引擎 → 界面的事件类型
====================
``hello``    引擎已启动，携带是否管理员、目标路径
``log``      诊断信息（数据源状态、告警、错误）
``record``   一条 DNS 查询 / SNI 记录
``status``   周期性计数器（记录数、域名数、速率、CPU、丢包）
``summary``  会话结束时的汇总
``fatal``    启动失败，引擎即将退出

只依赖 Python 标准库（tkinter 随 CPython 一起安装），无需 pip。
"""

from __future__ import annotations

import ctypes
import json
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "NetMonitor — 目标应用 DNS 监控"
MAX_ROWS = 20000          # 表格中保留的最大行数，避免长时间运行后变慢
UI_TICK_MS = 80           # 界面刷新周期（与引擎的采集完全解耦）

# 来源配色。颜色之外同时显示文字标签，不依赖颜色单独传达信息。
SOURCE_COLORS = {
    "ETW": "#1f6f8b",
    "PCAP": "#8a6d1f",
    "SNI": "#6b3fa0",
}
KIND_LABELS = {
    "query": "查询",
    "response": "应答",
    "tls_sni": "SNI",
}

# 写入预览里「本次写入会做什么」这一列对应的颜色标签。
# 标签文字由引擎给出（Rust 侧的 RowAction::label），这里只负责配色；
# 出现没见过的操作时统一按最淡的灰色处理，不会因此漏掉一行。
ACTION_TAGS = {
    "追加": "add",
    "更新为 IPv6": "update",
    "登记本进程": "claim",
    "不动": "keep",
    "跳过": "skip",
}


# ---------------------------------------------------------------------------
# 引擎位置
# ---------------------------------------------------------------------------

def frozen_bundle_dir() -> Optional[Path]:
    """Where a one-file build unpacks its bundled files, if this is one."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return None


def app_dir() -> Path:
    """The folder the user sees: beside the exe when frozen, else the project."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def find_engine() -> Optional[Path]:
    """在常见位置寻找 netmon.exe。"""
    bundle = frozen_bundle_dir()
    if bundle is not None:
        c = bundle / "netmon.exe"
        if c.is_file():
            return c
    here = Path(__file__).resolve().parent
    candidates = [
        here / "netmon.exe",
        here.parent / "netmon.exe",
        here.parent / "tools" / "netmon.exe",
        here.parent / "target" / "release" / "netmon.exe",
        here.parent / ".cache" / "target" / "release" / "netmon.exe",
        here.parent.parent / ".cache" / "target" / "release" / "netmon.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """以管理员身份重新启动本程序。返回是否成功发起。"""
    try:
        if getattr(sys, "frozen", False):
            # A one-file build has no Python and no script to pass: the exe is
            # the program, and the rest of the command line is just arguments.
            exe = sys.executable
            params = " ".join(f'"{a}"' for a in sys.argv[1:])
        else:
            params = " ".join(f'"{a}"' for a in sys.argv)
            exe = sys.executable
            # pythonw 不存在时退回 python
            pythonw = Path(exe).with_name("pythonw.exe")
            if pythonw.is_file():
                exe = str(pythonw)
                params = f'"{Path(sys.argv[0]).resolve()}" ' + " ".join(
                    f'"{a}"' for a in sys.argv[1:]
                )
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, params, None, 1
        )
        return int(rc) > 32
    except Exception:
        return False


def split_args(text: str) -> list[str]:
    """按 Windows 习惯拆分参数串，支持双引号。"""
    out: list[str] = []
    cur: list[str] = []
    in_quotes = False
    for ch in text:
        if ch == '"':
            in_quotes = not in_quotes
        elif ch.isspace() and not in_quotes:
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def parse_process_names(text: str) -> list[str]:
    """把「msedge.exe, chrome.exe」这类输入拆成去重后的映像名列表。

    逗号、分号、空白都当分隔符；缺 ``.exe`` 时补上，因为用户经常只写进程名。
    """
    out: list[str] = []
    for raw in text.replace(";", ",").replace("，", ",").split():
        for part in raw.split(","):
            name = part.strip().strip('"')
            if not name:
                continue
            if "." not in Path(name).name:
                name += ".exe"
            if name.lower() not in (n.lower() for n in out):
                out.append(name)
    return out


# ---------------------------------------------------------------------------
# 引擎封装
# ---------------------------------------------------------------------------

@dataclass
class Status:
    """引擎上报的实时计数器。"""
    running: bool = False
    uptime_s: float = 0.0
    records: int = 0
    queries: int = 0
    sni: int = 0
    domains: int = 0
    processes: int = 0
    tree_members: int = 0
    filtered: int = 0
    rate: float = 0.0
    cpu: float = 0.0
    drops_kernel: int = 0
    drops_queue: int = 0
    domains_unique: int = 0
    aaaa_found: int = 0
    aaaa_none: int = 0
    aaaa_failed: int = 0
    aaaa_pending: int = 0
    etw: bool = False
    npcap: bool = False


class Engine:
    """管理 netmon.exe 子进程，把它的 NDJSON 输出搬到队列里。

    stdout 由后台线程逐行读取并解析成 dict 放进 ``events`` 队列；界面线程只从
    队列取数据。这是 tkinter 唯一安全的跨线程通信方式——绝不在后台线程里碰控件。
    """

    def __init__(self, exe: Path) -> None:
        self.exe = exe
        self.proc: Optional[subprocess.Popen] = None
        self.events: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self._reader: Optional[threading.Thread] = None
        self._stopping = False

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, apps: list[str], args: list[str], attaches: list[str],
              session_name: str) -> None:
        if self.running:
            raise RuntimeError("引擎已在运行")

        cmd: list[str] = [
            str(self.exe),
            "--stream-json",
            "--status-interval-ms", "400",
            "--session-name", session_name,
        ]
        # Always keep alive: the session should end when the user says so, not
        # when the launched process happens to exit. A browser launched while it
        # is already running exits within a second.
        cmd += ["--keep-alive"]
        # Honour an explicit hosts file and backup directory. Useful for a
        # non-standard layout, and it is how the test suite keeps itself away
        # from the real system file.
        for env, flag in (("NETMON_HOSTS_FILE", "--hosts-file"),
                          ("NETMON_HOSTS_BACKUP_DIR", "--hosts-backup-dir"),
                          # Domain-table snapshot and change log. Keeping this
                          # beside the program is what keeps it off C:, and it
                          # is what lets the next run manage entries this one
                          # wrote.
                          ("NETMON_DATA_DIR", "--data-dir")):
            v = os.environ.get(env)
            if v:
                cmd += [flag, v]
        # `--watch` rather than `--attach`: attaching adopts only what is running
        # at that instant, so typing a name before starting the program -- the
        # natural order -- would silently watch nothing. Watching adopts what is
        # already there *and* what appears later. Both flags are repeatable.
        for name in attaches:
            cmd += ["--watch", name]
        # Launching and watching are not exclusive: a session may start a few
        # programs and also adopt a few by name. `--arg` is shared by all of
        # them, which is why it is emitted once.
        if not apps and not attaches:
            raise ValueError("必须指定目标程序或要监视的进程名")
        for app in apps:
            cmd += ["--app", app]
        for a in args:
            cmd += ["--arg", a]

        # CREATE_NO_WINDOW: 引擎自带界面时不需要控制台窗口；这里它是被驱动的
        # 子进程，弹出的黑色窗口只会分散注意力。
        flags = 0x08000000 if os.name == "nt" else 0
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # 引擎的诊断信息也以 JSON 形式混在其中
            # PIPE, not DEVNULL: this is the command channel the GUI uses to
            # ask the engine to re-query or export. DEVNULL here silently
            # disabled every control in the domain window.
            stdin=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=flags,
        )
        self._stopping = False
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        proc = self.proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.events.put(json.loads(line))
            except json.JSONDecodeError:
                # 引擎只写 JSON；出现别的行说明是目标程序漏出来的输出，
                # 当成日志显示出来，不要丢掉。
                self.events.put({"type": "log", "level": "info", "text": line})
        rc = proc.wait()
        self.events.put({"type": "exited", "code": rc})

    def stop(self, timeout: float = 3.0) -> None:
        """结束引擎。

        注意：强制结束会留下一个 ETW 会话，但它不影响下次使用——引擎在启动时
        会清掉"属主进程已不存在"的残留会话，并在日志里说明。
        """
        proc = self.proc
        if proc is None:
            return
        self._stopping = True
        try:
            proc.terminate()
            proc.wait(timeout=timeout)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        self.proc = None


# ---------------------------------------------------------------------------
# 主界面
# ---------------------------------------------------------------------------

class App(ttk.Frame):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=6)
        self.master: tk.Tk = master
        self.grid(sticky="nsew")
        master.rowconfigure(0, weight=1)
        master.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        self.columnconfigure(0, weight=1)

        self.engine_path = find_engine()
        self.engine: Optional[Engine] = None
        self.status = Status()
        self.session_name = f"NetMonitorGUI-{os.getpid()}"
        self.records: list[dict[str, Any]] = []
        self.auto_scroll = tk.BooleanVar(value=True)
        self.show_etw = tk.BooleanVar(value=True)
        self.show_pcap = tk.BooleanVar(value=True)
        self.show_sni = tk.BooleanVar(value=True)
        self.show_unattributed = tk.BooleanVar(value=False)
        # 只看这些进程（小写镜像名）。空集合 = 全部显示。
        self.selected_procs: set[str] = set()
        self.log_lines: list[str] = []
        # process -> set of domains seen for it
        self.domains: dict[str, set[str]] = {}
        # domain -> {"status": str, "addresses": [str], "settled": bool}
        self.aaaa: dict[str, dict] = {}
        self._hosts_win: Optional[tk.Toplevel] = None
        # Preview rows from the engine, and the last read of the file.
        self._hosts_tree: Optional[ttk.Treeview] = None
        self._hosts_edit: Optional[tk.Text] = None
        self._hosts_status: Optional[ttk.Label] = None
        self._hosts_info: Optional[ttk.Label] = None
        # Several processes can be selected at once; the preview is the merge of
        # their plans, one block per process.
        self._hosts_proc_list: Optional[tk.Listbox] = None
        self._hosts_procs: list[str] = []
        # The processes whose plans are being written. Kept separate from the
        # listbox's highlight: right-click toggles membership, and the chosen
        # rows are drawn green.
        self._hosts_chosen: list[str] = []
        self._hosts_proc_hint: Optional[ttk.Label] = None
        # Reused by the process picker's right-click menu: posting a menu is
        # asynchronous, so the menu must outlive the event handler.
        self._hosts_proc_menu: Optional[tk.Menu] = None
        # Multi-line delete: how many replies are still outstanding, and how
        # many lines were asked for, so the status line can report the batch.
        self._hosts_delete_batch = 0
        self._hosts_delete_total = 0
        # Set once the user has chosen or cleared something, so a file reload
        # does not silently put the default process back.
        self._hosts_choice_made = False
        self._hosts_preview_by_process: dict[str, list[dict]] = {}
        self.hosts_preview: list[dict] = []
        self.hosts_meta: dict = {}
        self.hosts_text: str = ""
        # Processes named in the hosts block. Kept so a process that is not
        # running any more can still be selected and cleaned up after a restart.
        self._hosts_owners: set[str] = set()
        # The managed block as it stands in the file, with owners. Grouped by
        # process in the "当前条目" tab; a shared line is listed under each
        # process that asked for it.
        self.hosts_entries: list[dict] = []
        self._hosts_entries_tree: Optional[ttk.Treeview] = None
        self._hosts_entries_info: Optional[ttk.Label] = None
        # Entry row id -> the line it shows, so the context menu can act on the
        # exact line that was clicked.
        self._hosts_entries_by_iid: dict[str, dict] = {}
        self._hosts_entries_menu: Optional[tk.Menu] = None
        # Preview row id -> (process, domain), so a multi-selection can be
        # translated back into the per-process command the engine expects.
        self._hosts_row_keys: dict[str, tuple[str, str]] = {}
        self._hosts_menu: Optional[tk.Menu] = None
        self._hosts_policy = tk.StringVar(value="block")
        self._hosts_auto = tk.BooleanVar(value=False)
        # Set when the domain table moves; the preview catches up on the next
        # tick rather than on every single event.
        self._hosts_dirty = False
        self._hosts_last_refresh = 0.0
        self._domains_win: Optional[tk.Toplevel] = None
        self._domains_tree: Optional[ttk.Treeview] = None
        self._domains_proc: Optional[tk.Listbox] = None
        # Domain-table filters. Both are applied as case-insensitive substrings,
        # the same contract the main list's filter box has.
        self._domain_filter = tk.StringVar(master=self.master, value="")
        self._addr_filter = tk.StringVar(master=self.master, value="")
        self._domains_count: Optional[ttk.Label] = None
        self._filter_job: Optional[str] = None
        self._sort_col = "seq"
        self._sort_desc = True
        self._logs_win: Optional[tk.Toplevel] = None
        self._stats_win: Optional[tk.Toplevel] = None
        self._starting = False

        self._build_widgets()
        self._install_shortcuts()
        self._pump()
        self._update_controls()

        # 刻意不在启动时检查"是否管理员"：那只是"ETW 能否工作"的代理指标，
        # 实测出现过令牌未提升但 ETW 与 Npcap 都正常的情况，此时弹 UAC 纯属打扰。
        # 改为启动之后看引擎实际报告了哪些数据源起来了（status 事件里的
        # etw / npcap），真失败了再提示。
        if self.engine_path is None:
            self._log("找不到 netmon.exe，请把它放到本脚本同目录。", "error")

    # -- 界面搭建 ----------------------------------------------------------

    def _build_widgets(self) -> None:
        # 第 0 行：目标选择
        target = ttk.LabelFrame(self, text=" 目标程序 ", padding=4)
        target.grid(row=0, column=0, sticky="ew")
        target.columnconfigure(1, weight=1)

        ttk.Label(target, text="可执行文件：").grid(row=0, column=0, sticky="w")
        self.var_app = tk.StringVar()
        entry_app = ttk.Entry(target, textvariable=self.var_app)
        entry_app.grid(row=0, column=1, sticky="ew", padx=(0, 6))
        entry_app.bind("<Return>", lambda _e: self.on_add_target())
        ttk.Button(target, text="浏览…", command=self.on_browse,
                   width=10).grid(row=0, column=2)
        ttk.Button(target, text="添加", command=self.on_add_target,
                   width=8).grid(row=0, column=3, padx=(6, 0))

        # 可以同时监控多个程序：列表里每一项要么是可执行文件（启动它并监视
        # 整棵进程树），要么是进程映像名（监视已在运行的和之后出现的）。
        # 两种目标可以混在一起，右键管理这一份列表。
        self.targets: list[tuple[str, str]] = []
        box_frame = ttk.Frame(target)
        box_frame.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(4, 0))
        box_frame.columnconfigure(0, weight=1)
        self.targets_box = tk.Listbox(box_frame, height=3, exportselection=False,
                                      font=("Consolas", 10), activestyle="none",
                                      selectmode="extended")
        self.targets_box.grid(row=0, column=0, sticky="ew")
        sb_targets = ttk.Scrollbar(box_frame, orient="vertical",
                                   command=self.targets_box.yview)
        sb_targets.grid(row=0, column=1, sticky="ns")
        self.targets_box.configure(yscrollcommand=sb_targets.set)
        ttk.Label(target, text="要监控的程序（可多个，\n右键可移除 / 清空）：",
                  foreground="#666666").grid(
            row=1, column=0, sticky="nw", pady=(4, 0))
        self.targets_box.bind("<Button-3>", self._on_targets_right_click)
        self.targets_box.bind("<Delete>", lambda _e: self.on_remove_target())
        self._targets_menu = tk.Menu(self.targets_box, tearoff=0)
        self._targets_menu.add_command(label="移除选中", command=self.on_remove_target)
        self._targets_menu.add_command(label="清空列表", command=self.on_clear_targets)

        ttk.Label(target, text="启动参数：").grid(row=2, column=0, sticky="w", pady=(4, 0))
        self.var_args = tk.StringVar()
        ttk.Entry(target, textvariable=self.var_args).grid(
            row=2, column=1, columnspan=3, sticky="ew", pady=(4, 0))

        # 浏览器这类"单实例"程序，在已经打开的情况下再启动一个新进程，它会立刻
        # 把请求转交给已有实例并退出——真正的浏览器进程不是它的子进程，于是什么
        # 都抓不到。按映像名监视才是可行的做法。
        # 名字会加入上面的同一个列表，和可执行文件一起作为本次监控的目标。
        ttk.Label(target, text="按名称监视：").grid(row=3, column=0, sticky="w", pady=(4, 0))
        self.var_attach = tk.StringVar()
        entry_attach = ttk.Entry(target, textvariable=self.var_attach)
        entry_attach.grid(row=3, column=1, sticky="ew", pady=(4, 0))
        entry_attach.bind("<Return>", lambda _e: self.on_add_name())
        ttk.Button(target, text="添加名称", command=self.on_add_name,
                   width=10).grid(row=3, column=2, padx=(6, 0), pady=(4, 0))
        ttk.Label(target, text="进程映像名，如 msedge.exe（可填多个，加入上方列表）",
                  foreground="#666666").grid(row=3, column=3, sticky="w", padx=(6, 0),
                                             pady=(4, 0))

        # 第 1 行：操作按钮
        bar = ttk.Frame(self)
        bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        # 顺序即使用频率：先监控控制，再数据操作。全部支持快捷键（见 set_shortcuts）。
        self.btn_start = ttk.Button(bar, text="▶  开始监控 (F5)", command=self.on_start, width=18)
        self.btn_stop = ttk.Button(bar, text="■  停止 (F6)", command=self.on_stop, width=13)
        self.btn_pause = ttk.Button(bar, text="⏸  暂停滚动 (F7)", command=self.on_toggle_pause, width=17)
        self.btn_start.pack(side="left", padx=1)
        self.btn_stop.pack(side="left", padx=1)
        self.btn_pause.pack(side="left", padx=(1, 10))
        ttk.Button(bar, text="🗑  清空", command=self.on_clear, width=10).pack(side="left", padx=1)
        ttk.Button(bar, text="💾  导出… (F8)", command=self.on_export, width=14).pack(side="left", padx=1)
        ttk.Button(bar, text="📊  统计", command=self.on_stats, width=10).pack(side="left", padx=1)
        ttk.Button(bar, text="📋  日志", command=self.on_logs, width=10).pack(side="left", padx=1)
        ttk.Button(bar, text="🌐  域名表 (Ctrl+W)", command=self.on_domains,
                   width=18).pack(side="left", padx=1)
        ttk.Button(bar, text="📝  写入 hosts (Ctrl+H)", command=self.on_hosts,
                   width=20).pack(side="left", padx=1)

        # 第 2 行：过滤
        flt = ttk.LabelFrame(self, text=" 过滤 ", padding=4)
        flt.grid(row=2, column=0, sticky="ew", pady=(6, 0))
        flt.columnconfigure(1, weight=1)
        flt.columnconfigure(3, weight=1)

        ttk.Label(flt, text="域名包含：").grid(row=0, column=0, sticky="w")
        self.var_f_domain = tk.StringVar()
        self.var_f_domain.trace_add("write", lambda *_: self._schedule_filter())
        self.entry_domain = ttk.Entry(flt, textvariable=self.var_f_domain)
        self.entry_domain.grid(row=0, column=1, sticky="ew", padx=(0, 12))

        ttk.Label(flt, text="地址：").grid(row=0, column=2, sticky="w")
        self.var_f_ip = tk.StringVar()
        self.var_f_ip.trace_add("write", lambda *_: self._schedule_filter())
        self.entry_ip = ttk.Entry(flt, textvariable=self.var_f_ip, width=22)
        self.entry_ip.grid(row=0, column=3, sticky="w")
        ttk.Label(flt, text="IP / 网段(10.0.0.0/8) / 片段",
                  foreground="#888888").grid(row=0, column=4, sticky="w", padx=(6, 0))

        ttk.Label(flt, text="进程名包含：").grid(row=1, column=0, sticky="w", pady=(3, 0))
        self.var_f_proc = tk.StringVar()
        self.var_f_proc.trace_add("write", lambda *_: self._schedule_filter())
        self.entry_proc = ttk.Entry(flt, textvariable=self.var_f_proc)
        self.entry_proc.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(3, 0))

        # 进程白名单：主进程和它的子进程全都在抓，这里只决定"看哪些"。
        procs = ttk.Frame(flt)
        procs.grid(row=1, column=0, columnspan=5, sticky="ew", pady=(3, 0))
        ttk.Label(procs, text="只看这些进程：").pack(side="left")
        self.lbl_procs = ttk.Label(procs, text="全部", foreground="#666666")
        self.lbl_procs.pack(side="left", padx=(0, 8))
        ttk.Button(procs, text="选择进程…", command=self.on_pick_processes,
                   width=13).pack(side="left")
        ttk.Button(procs, text="全部", command=self.on_all_processes,
                   width=6).pack(side="left", padx=(6, 0))

        src = ttk.Frame(flt)
        src.grid(row=2, column=0, columnspan=5, sticky="w", pady=(3, 0))
        ttk.Label(src, text="数据源：").pack(side="left")
        for text, var in (("ETW（系统解析器）", self.show_etw),
                          ("PCAP（明文抓包）", self.show_pcap),
                          ("SNI（TLS 主机名）", self.show_sni),
                          ("无法归属", self.show_unattributed)):
            ttk.Checkbutton(src, text=text, variable=var,
                            command=self._schedule_filter).pack(side="left", padx=(0, 6))
        ttk.Button(src, text="清除过滤", command=self.on_clear_filter,
                   width=10).pack(side="left", padx=(6, 0))

        # 第 3 行：表格
        table_frame = ttk.Frame(self)
        table_frame.grid(row=3, column=0, sticky="nsew", pady=(6, 0))
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        columns = ("time", "process", "pid", "qtype", "source", "kind", "domain", "detail")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                 selectmode="extended")
        headings = {
            "time": ("时间", 105, "w"),
            "process": ("进程", 150, "w"),
            "pid": ("PID", 70, "e"),
            "qtype": ("类型", 60, "center"),
            "source": ("来源", 60, "center"),
            "kind": ("类别", 60, "center"),
            "domain": ("域名", 320, "w"),
            "detail": ("详情", 380, "w"),
        }
        for col, (text, width, anchor) in headings.items():
            self.tree.heading(col, text=text, command=lambda c=col: self.on_sort(c))
            self.tree.column(col, width=width, anchor=anchor, stretch=(col in ("domain", "detail")))

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        for name, colour in SOURCE_COLORS.items():
            self.tree.tag_configure(name, foreground=colour)
        self.tree.tag_configure("sni", foreground="#6b3fa0")
        self.tree.tag_configure("response", foreground="#888888")

        self.tree.bind("<Double-1>", self.on_row_double_click)
        self.tree.bind("<Button-3>", self.on_row_menu)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._update_selection_label())

        self.menu = tk.Menu(self.master, tearoff=0)
        self.menu.add_command(label="复制域名", command=lambda: self._copy_column("domain"))
        self.menu.add_command(label="复制整行", command=lambda: self._copy_column("row"))

        # 第 4 行：数据源告警条（正常情况下不占位）
        self.alert_bar = tk.Frame(self, bg="#ffe9e9")
        self.lbl_alert = tk.Label(
            self.alert_bar, text="", anchor="w", justify="left", wraplength=1080,
            bg="#ffe9e9", fg="#8a1010", padx=8, pady=6,
            font=("Microsoft YaHei UI", 10))
        self.lbl_alert.pack(side="left", fill="x", expand=True)
        self.btn_elevate = ttk.Button(
            self.alert_bar, text="以管理员身份重启", command=self._offer_elevation)
        self.alert_bar.grid(row=4, column=0, sticky="ew", pady=(6, 0))
        self.alert_bar.grid_remove()
        self._elevate_offered = False

        # 第 5 行：状态栏
        status = ttk.Frame(self)
        status.grid(row=5, column=0, sticky="ew", pady=(6, 0))
        status.columnconfigure(2, weight=1)

        self.lbl_state = tk.Label(status, text="● 未监控", fg="#777777",
                                  font=("Segoe UI", 10, "bold"))
        self.lbl_state.grid(row=0, column=0, sticky="w")
        self.lbl_stats = ttk.Label(status, text="", foreground="#333333")
        self.lbl_stats.grid(row=0, column=1, sticky="w", padx=12)
        self.lbl_hint = ttk.Label(status, text="", foreground="#0a6b3d")
        self.lbl_hint.grid(row=0, column=2, sticky="w")
        self.lbl_sel = ttk.Label(status, text="", foreground="#666666")
        self.lbl_sel.grid(row=0, column=3, sticky="e")

    def _install_shortcuts(self) -> None:
        m = self.master
        m.bind("<F5>", lambda _e: self.on_start())
        m.bind("<F6>", lambda _e: self.on_stop())
        m.bind("<F7>", lambda _e: self.on_toggle_pause())
        m.bind("<F8>", lambda _e: self.on_export())
        m.bind("<Control-s>", lambda _e: self.on_stats())
        m.bind("<Control-g>", lambda _e: self.on_logs())
        m.bind("<Control-o>", lambda _e: self.on_browse())
        m.bind("<Control-d>", lambda _e: self.entry_domain.focus_set())
        m.bind("<Control-p>", lambda _e: self.entry_proc.focus_set())
        m.bind("<Control-t>", lambda _e: self.on_pick_processes())
        m.bind("<Control-w>", lambda _e: self.on_domains())
        m.bind("<Control-h>", lambda _e: self.on_hosts())
        m.bind("<Control-r>", lambda _e: self.send_requery(False))
        m.bind("<Escape>", lambda _e: self._clear_filter_widgets())
        m.bind("<Control-l>", lambda _e: self.on_clear())
        m.protocol("WM_DELETE_WINDOW", self.on_close)

    # -- 引擎事件泵 --------------------------------------------------------

    def _pump(self) -> None:
        """周期性排空引擎事件队列。这是唯一的界面更新入口。

        这个函数**必须永远不抛异常**。它把自己排在最后一行重新调度，所以任何
        一处未捕获的异常都会让定时器彻底停摆——界面冻结、计数不动、域名表不再
        更新，而引擎其实还在跑。曾经就是这样：一个新会话的记录 ID 和旧行撞了，
        抛出的 TclError 直接把整个界面锁死。
        """
        try:
            drained = 0
            try:
                while drained < 4000:
                    ev = self.engine.events.get_nowait()
                    drained += 1
                    self._handle_event(ev)
            except (queue.Empty, AttributeError):
                pass

            if drained:
                self._render_new_records()
            self._refresh_status_bar()
            self._update_controls()
        except Exception as exc:  # noqa: BLE001 - 见上：这里绝不能中断
            self._log(f"界面刷新出错（已跳过这一帧）：{exc}", "error")
        finally:
            self._sync_hosts_window()
            self.master.after(UI_TICK_MS, self._pump)

    def _sync_hosts_window(self) -> None:
        """Keep the hosts window in step with the domain table.

        Rate limited: a page load can add dozens of names per second and each
        refresh is a round-trip to the engine.
        """
        win = self._hosts_win
        if win is None or not win.winfo_exists() or not self._hosts_dirty:
            return
        now = time.time()
        if now - self._hosts_last_refresh < 1.2:
            return
        self._hosts_dirty = False
        self._hosts_last_refresh = now
        # New processes can appear at any time, so the picker follows too.
        self._fill_hosts_processes()
        self._refresh_hosts_preview()

    def _handle_event(self, ev: dict[str, Any]) -> None:
        kind = ev.get("type")
        if kind == "hello":
            elevated = ev.get("elevated")
            self._log(f"引擎已启动（版本 {ev.get('version')}，"
                      f"令牌{'已提升' if elevated else '未提升'}，pid {ev.get('pid')}）")
            # 令牌未提升不等于抓不到：实测存在令牌未提升而 ETW 与 Npcap 都正常的
            # 情况。真正的判据是引擎随后上报的 status.etw / status.npcap，
            # 那由 _update_source_alert 处理。这里只记录事实，不报警。
        elif kind == "log":
            self._log(ev.get("text", ""), ev.get("level", "info"))
        elif kind == "record":
            self.records.append(ev)
        elif kind == "status":
            for key, value in ev.items():
                if key != "type" and hasattr(self.status, key):
                    setattr(self.status, key, value)
        elif kind == "domain":
            self.domains.setdefault(ev.get("process", ""), set()).add(ev.get("domain", ""))
            # Seen live in this session, so whatever the cache said about it is
            # now a current observation.
            info = self.aaaa.get(ev.get("domain", ""))
            if info is not None:
                info["archived"] = False
            self._hosts_dirty = True
        elif kind == "aaaa":
            self._hosts_dirty = True
            self.aaaa[ev.get("domain", "")] = {
                "status": ev.get("status", ""),
                # `addresses` is the AAAA lookup result; `resolved_ips` is
                # everything the domain is known to resolve to, which is what
                # the address filter and the table's first column show.
                "addresses": ev.get("addresses", []),
                "resolved_ips": ev.get("resolved_ips", []),
                "settled": ev.get("settled", False),
                "resolved_by_us": bool(ev.get("resolved_by_us", False)),
                # Restored from the previous session's cache: the row is
                # history, and the UI says so.
                "archived": bool(ev.get("archived", False)),
            }
        elif kind == "hosts_preview":
            proc = ev.get("process") or ""
            # A reply for a process the user has already switched away from
            # must not repaint the table: switching is a single click, and the
            # round trip is not instantaneous.
            selected = self._selected_hosts_processes()
            if proc not in selected:
                return
            self._hosts_preview_by_process[proc] = list(ev.get("entries") or [])
            self._rebuild_hosts_preview(selected)
            self._render_hosts_preview()
        elif kind == "hosts_content":
            self.hosts_text = ev.get("text", "")
            self.hosts_meta = ev
            # The block as it stands in the file: address, domain and who asked
            # for it. This is what the "当前条目" tab groups by process.
            self.hosts_entries = list(ev.get("entries") or [])
            # The processes named in the file. Their tables may be long gone;
            # the file still knows they wrote something.
            self._hosts_owners = {
                str(o.get("process"))
                for o in (ev.get("by_owner") or [])
                if o.get("process")
            }
            self._fill_hosts_processes()
            self._render_hosts_content()
            self._render_hosts_entries()
        elif kind == "hosts_auto":
            self._hosts_auto.set(bool(ev.get("enabled")))
            note = ev.get("note", "")
            if note:
                self._log(note)
                self._set_hosts_status(note, ok=True)
        elif kind == "hosts_auto_written":
            self._log(ev.get("note", "自动写入"))
            self._set_hosts_status(
                f"{ev.get('note', '')}（本次会话自动写入 {ev.get('writes', 0)} 次；"
                "自动模式只写入，从不删除条目或备份）", ok=True)
            self._hosts_dirty = True
            # The file changed, so the "current entries" tab and the editor are
            # now stale; one read repaints both.
            self.send_command({"cmd": "hosts_read"})
        elif kind in ("hosts_written", "hosts_removed", "hosts_edited", "hosts_restored"):
            self._log(ev.get("note", kind))
            batch_note: Optional[str] = None
            if kind == "hosts_removed" and self._hosts_delete_batch > 0:
                # One reply per line in a multi-line delete. Report the batch,
                # not whichever single line happened to finish last.
                self._hosts_delete_batch -= 1
                if self._hosts_delete_batch == 0:
                    batch_note = (
                        f"已删除 {self._hosts_delete_total} 行（删除前已备份）")
                else:
                    batch_note = f"正在删除… 还剩 {self._hosts_delete_batch} 行"
            else:
                self._set_hosts_status(ev.get("note", ""), ok=ev.get("ok", True))
            # Anything that changed the file invalidates what we were showing:
            # reload the editor, and mark the preview so its "already written"
            # column catches up too.
            self._hosts_dirty = True
            self._hosts_last_refresh = 0.0
            # One read repaints the editor, the "current entries" tab and the
            # preview's "already written" column -- they are all views of the
            # same file.
            self.send_command({"cmd": "hosts_read"})
            self._refresh_hosts_preview()
            if batch_note is not None:
                # After the preview refresh, which sets its own status line.
                self._set_hosts_status(batch_note, ok=True)
        elif kind == "hosts_result":
            self._log(ev.get("note", ""), "error" if not ev.get("ok") else "info")
            if not ev.get("ok", True) and self._hosts_delete_batch > 0:
                self._hosts_delete_batch = 0
                self._set_hosts_status(
                    f"批量删除中断：{ev.get('note', '')}", ok=False)
            else:
                self._set_hosts_status(ev.get("note", ""), ok=ev.get("ok", True))
        elif kind == "domain_tables":
            # Sent at startup (the previous session's tables) and again at the
            # end of a run, so a UI opened later still fills in.
            for t in ev.get("tables", []):
                for row in t.get("domains", []):
                    self.aaaa[row.get("domain", "")] = {
                        "status": row.get("status", ""),
                        "addresses": row.get("addresses", []),
                        "resolved_ips": row.get("resolved_ips", []),
                        "settled": row.get("settled", False),
                        "resolved_by_us": bool(row.get("resolved_by_us", False)),
                        "archived": bool(row.get("archived", False)),
                    }
                    self.domains.setdefault(t.get("process", ""), set()).add(
                        row.get("domain", ""))
        elif kind == "summary":
            self._log(
                "会话结束：{queries} 次 DNS 查询，{domains} 个域名，"
                "过滤掉其它进程 {filtered} 条，丢包 {dropped}".format(
                    queries=ev.get("queries", 0),
                    domains=ev.get("domains", 0),
                    filtered=ev.get("filtered_out_of_tree", 0),
                    dropped=ev.get("drops_kernel", 0) + ev.get("drops_queue", 0),
                )
            )
        elif kind == "fatal":
            self._log(ev.get("text", "引擎启动失败"), "error")
            self._show_hint("引擎启动失败，详见「日志」", error=True)
        elif kind == "exited":
            self._log(f"引擎已退出（代码 {ev.get('code')}）")

    def _log(self, text: str, level: str = "info") -> None:
        stamp = time.strftime("%H:%M:%S")
        prefix = {"info": "·", "warn": "!", "error": "×"}.get(level, "·")
        line = f"[{stamp}] {prefix} {text}"
        self.log_lines.append(line)
        if len(self.log_lines) > 5000:
            del self.log_lines[:1000]
        if level in ("warn", "error"):
            self._show_hint(text, error=(level == "error"))
            # Warnings go to the alert bar as well: they are usually the reason
            # the table is staying empty, and the log window is not open.
            self._set_alert(text, error=(level == "error"))
        if self._logs_win is not None:
            try:
                self._logs_win.deiconify()
                self._logs_win.lift()
            except Exception:
                self._logs_win = None

    def _show_hint(self, text: str, error: bool = False) -> None:
        self.lbl_hint.configure(text=text[:160],
                                foreground="#a11" if error else "#0a6b3d")

    # -- 表格渲染 ----------------------------------------------------------

    def _passes_filter(self, r: dict[str, Any]) -> bool:
        src = r.get("source")
        if src == "ETW" and not self.show_etw.get():
            return False
        if src == "PCAP" and not self.show_pcap.get():
            return False
        if src == "SNI" and not self.show_sni.get():
            return False
        if r.get("pid", 0) == 0 and not self.show_unattributed.get():
            return False
        d = self.var_f_domain.get().strip().lower()
        if d and d not in str(r.get("domain", "")).lower():
            return False
        p = self.var_f_proc.get().strip().lower()
        if p and p not in str(r.get("process", "")).lower():
            return False
        ip = self.var_f_ip.get().strip()
        if ip and not self._ip_passes(ip, r):
            return False
        if self.selected_procs:
            if str(r.get("process", "")).lower() not in self.selected_procs:
                return False
        return True

    def _ip_passes(self, text: str, r: dict) -> bool:
        """Match the address box against a record's resolved addresses.

        A bare address matches exactly, `a.b.c.d/n` matches a network, and
        anything else is a substring match on the rendered addresses -- so the
        list still narrows while a prefix is being typed.
        """
        addrs = [str(a) for a in r.get("resolved_ips", [])]
        if not addrs:
            # A row is created when the query is seen; its answer may not have
            # arrived yet. The domain table knows the addresses by now, so ask
            # it rather than missing the row.
            info = self.aaaa.get(str(r.get("domain", "")))
            if info:
                addrs = [str(a) for a in info.get("resolved_ips", [])]
        if not addrs:
            # Nothing structured anywhere: fall back to the detail column,
            # which renders the same addresses.
            addrs = [str(r.get("detail", ""))]
        if "/" in text:
            head, _, bits = text.partition("/")
            try:
                import ipaddress
                net = ipaddress.ip_network(text, strict=False)
            except Exception:
                net = None
            if net is not None:
                for a in addrs:
                    try:
                        if ipaddress.ip_address(a) in net:
                            return True
                    except Exception:
                        continue
                return False
            text = head
        try:
            import ipaddress
            want = ipaddress.ip_address(text)
            return any(a == str(want) for a in addrs)
        except Exception:
            pass
        low = text.lower()
        return any(low in a.lower() for a in addrs)

    def _schedule_filter(self) -> None:
        if self._filter_job is not None:
            self.master.after_cancel(self._filter_job)
        # 输入时不要每个字符都重建表格；停顿 220 ms 后再重建。
        self._filter_job = self.master.after(220, self._rebuild_table)

    def _rebuild_table(self) -> None:
        """重新按当前过滤条件构建整个表格。

        必须同时把"已渲染到第几条"推进到末尾：否则紧随其后的增量渲染会再把
        这些记录插一遍，而 Treeview 的 iid 是序号，重复即报 "Item N already
        exists"。这是排序功能上线后暴露出来的真实缺陷。
        """
        self._filter_job = None
        self.tree.delete(*self.tree.get_children())
        for r in self.records:
            if self._passes_filter(r):
                self._insert_row(r)
        self._rendered = len(self.records)
        if self.auto_scroll.get():
            self._scroll_to_end()

    def _render_new_records(self) -> None:
        """只追加新记录，不重建表格——高刷新率下的关键。"""
        start = getattr(self, "_rendered", 0)
        if start > len(self.records):
            # 记录被清空过，整体重建
            start = 0
            self.tree.delete(*self.tree.get_children())
        new = self.records[start:]
        self._rendered = len(self.records)
        if not new:
            return

        if len(self.records) > MAX_ROWS:
            # 超出上限时从头部丢弃，并重建一次，避免表格无限增长。
            del self.records[: len(self.records) - MAX_ROWS]
            self._rendered = len(self.records)
            self._rebuild_table()
            return

        for r in new:
            if self._passes_filter(r):
                self._insert_row(r)
        if self.auto_scroll.get():
            self._scroll_to_end()

    def _insert_row(self, r: dict[str, Any]) -> None:
        kind = r.get("kind", "query")
        tags = []
        if kind == "tls_sni":
            tags.append("sni")
        elif kind == "response":
            tags.append("response")
        elif r.get("source") in SOURCE_COLORS:
            tags.append(r["source"])
        self.tree.insert(
            "", "end",
            iid=str(r.get("seq")),
            values=(
                r.get("time", ""),
                r.get("process", ""),
                r.get("pid", 0) or "",
                r.get("qtype", ""),
                r.get("source", ""),
                KIND_LABELS.get(kind, kind),
                r.get("domain", ""),
                r.get("detail", ""),
            ),
            tags=tuple(tags),
        )

    def _scroll_to_end(self) -> None:
        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])

    def _refresh_status_bar(self) -> None:
        s = self.status
        if self.engine is not None and self.engine.running:
            self.lbl_state.configure(text="● 监控中", fg="#0a8f4d")
        elif self.engine is not None:
            self.lbl_state.configure(text="● 已停止", fg="#a11")
        else:
            self.lbl_state.configure(text="● 未监控", fg="#777777")

        drops = s.drops_kernel + s.drops_queue
        text = (f"记录 {s.records}   域名 {s.domains}   进程 {s.processes}   "
                f"速率 {s.rate:.1f}/s   CPU {s.cpu:.1f}%   "
                f"进程树 {s.tree_members}   过滤 {s.filtered}   "
                f"AAAA {s.aaaa_found}/{s.aaaa_found + s.aaaa_none}   "
                f"丢包 {drops}")
        self.lbl_stats.configure(text=text)

        visible = len(self.tree.get_children())
        if visible != len(self.records):
            self.lbl_sel.configure(text=f"显示 {visible} / {len(self.records)} 条")

        self._update_source_alert()

    def _update_source_alert(self) -> None:
        """数据源出问题时必须显眼——这正是"什么都看不到却不知道为什么"的来源。

        ETW 是主数据源：它一旦起不来，目标应用走系统解析器的查询就完全看不见，
        而抓包源只会看到 svchost 发的包（会被抑制），结果就是列表全空。
        """
        if self.engine is None or not self.engine.running:
            self.alert_bar.grid_remove()
            return
        if self.status.etw and self.status.npcap:
            self.alert_bar.grid_remove()
            return
        if not self.status.etw and not self.status.npcap:
            msg = ("两个数据源都没能启动，无法监控。"
                   "若「日志」里 ETW 报的是「资源不足」，先用 netmon.exe --clean-sessions 清理残留会话。")
        elif not self.status.etw:
            msg = ("ETW 主数据源未启动：目标应用通过系统解析器发出的查询看不到。"
                   "常见原因是权限不足，或系统 ETW 资源被残留会话占满（见「日志」）。")
        else:
            msg = "抓包数据源未启动：自带 DNS 解析器的应用与 TLS SNI 可能捕捉不到。"
        self._set_alert(msg, error=True)

    def _set_alert(self, text: str, error: bool = True) -> None:
        self.lbl_alert.configure(
            text="⚠ " + text,
            bg="#ffe9e9" if error else "#fff6e0",
            fg="#8a1010" if error else "#7a5000")
        self.alert_bar.configure(bg="#ffe9e9" if error else "#fff6e0")
        # 只有在提权确实可能解决问题（且还没试过）时才显示按钮。
        if not self._elevate_offered and not is_admin():
            self.btn_elevate.pack(side="right", padx=8)
        else:
            self.btn_elevate.pack_forget()
        self.alert_bar.grid()

    def _update_controls(self) -> None:
        running = self.engine is not None and self.engine.running
        self.btn_start.configure(state="disabled" if running else "normal")
        self.btn_stop.configure(state="normal" if running else "disabled")
        self.btn_pause.configure(
            text="▶  恢复滚动" if not self.auto_scroll.get() else "⏸  暂停滚动")
        if not is_admin():
            self.btn_start.configure(state="normal")  # 允许尝试，引擎会解释原因

    def _update_selection_label(self) -> None:
        n = len(self.tree.selection())
        if n:
            self.lbl_sel.configure(text=f"选中 {n} 行")

    # -- 用户操作 ----------------------------------------------------------

    def on_browse(self) -> None:
        path = filedialog.askopenfilename(
            title="选择要监控的应用程序",
            filetypes=[("可执行文件", "*.exe"), ("批处理/脚本", "*.bat;*.cmd;*.ps1"),
                       ("所有文件", "*.*")],
        )
        if path:
            self._add_target(path)

    # -- 目标列表 ----------------------------------------------------------

    def _target_label(self, kind: str, value: str) -> str:
        return f"[文件] {value}" if kind == "app" else f"[名称] {value}"

    def _refresh_target_box(self) -> None:
        self.targets_box.delete(0, "end")
        for kind, value in self.targets:
            self.targets_box.insert("end", self._target_label(kind, value))

    def _add_target(self, path: str) -> None:
        """Add one executable to the list, ignoring duplicates."""
        path = path.strip().strip('"')
        if not path:
            return
        key = os.path.normcase(os.path.abspath(path))
        if any(k == "app" and os.path.normcase(os.path.abspath(v)) == key
               for k, v in self.targets):
            self._show_hint("这个程序已经在列表里了")
        else:
            self.targets.append(("app", path))
            self._refresh_target_box()
            self._show_hint(f"已添加 {Path(path).name}（共 {len(self.targets)} 个目标）")
        self.var_app.set("")

    def _add_watch_names(self, text: str) -> int:
        """Add image names to the same target list. Returns how many were new."""
        if "\\" in text or "/" in text:
            self._show_hint(
                "“按名称监视”只接受进程映像名；可执行文件请用上方的“浏览…”添加",
                error=True)
            return 0
        added = 0
        for name in parse_process_names(text):
            if any(k == "name" and v.lower() == name.lower() for k, v in self.targets):
                continue
            self.targets.append(("name", name))
            added += 1
        if added:
            self._refresh_target_box()
            self._show_hint(f"已按名称添加 {added} 个（共 {len(self.targets)} 个目标）")
        elif text.strip():
            self._show_hint("这些名称已经在列表里了")
        return added

    def on_add_name(self) -> None:
        text = self.var_attach.get().strip()
        if not text:
            self._show_hint("先填写进程映像名，如 msedge.exe", error=True)
            return
        if self._add_watch_names(text):
            self.var_attach.set("")

    def _on_targets_right_click(self, event: "tk.Event") -> None:
        menu = getattr(self, "_targets_menu", None)
        if menu is None:
            return
        row = self.targets_box.nearest(event.y)
        if row >= 0 and self.targets_box.size():
            if row not in self.targets_box.curselection():
                self.targets_box.selection_clear(0, "end")
                self.targets_box.selection_set(row)
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

    def on_add_target(self) -> None:
        path = self.var_app.get().strip().strip('"')
        if not path:
            self.on_browse()
            return
        if not Path(path).is_file():
            messagebox.showerror(APP_TITLE, f"找不到文件：\n{path}")
            return
        self._add_target(path)

    def on_remove_target(self) -> None:
        selection = sorted(self.targets_box.curselection(), reverse=True)
        if not selection:
            self._show_hint("先在列表里选中要移除的目标（右键可打开菜单）", error=True)
            return
        for index in selection:
            if 0 <= index < len(self.targets):
                del self.targets[index]
        self._refresh_target_box()
        self._show_hint(f"已移除 {len(selection)} 个，还剩 {len(self.targets)} 个目标")

    def on_clear_targets(self) -> None:
        if not self.targets:
            return
        self.targets.clear()
        self._refresh_target_box()
        self._show_hint("目标列表已清空")

    def on_start(self) -> None:
        if self._starting:
            return
        # 路径可能是从命令行或资源管理器拖进来的，带引号也一并接受。
        pending = self.var_app.get().strip().strip('"')
        if pending:
            if not Path(pending).is_file():
                messagebox.showerror(APP_TITLE, f"找不到文件：\n{pending}")
                return
            self._add_target(pending)
        # 名称栏里还没点“添加名称”的，开始监控时也一并采用，省一次点击。
        if self.var_attach.get().strip():
            self._add_watch_names(self.var_attach.get())
            self.var_attach.set("")
        apps = [value for kind, value in self.targets if kind == "app"]
        attaches = [value for kind, value in self.targets if kind == "name"]
        if not apps and not attaches:
            self._show_hint("请先添加要监控的程序，或添加要监视的进程名", error=True)
            self.on_browse()
            return
        for app_path in apps:
            if not Path(app_path).is_file():
                messagebox.showerror(APP_TITLE, f"找不到文件：\n{app_path}")
                return
        if self.engine_path is None:
            messagebox.showerror(
                APP_TITLE,
                "找不到 netmon.exe。\n\n请把它放在本脚本同目录，"
                "或从发布包中一并解压。")
            return

        self._starting = True
        try:
            if self.engine is not None:
                self.engine.stop()

            # A new engine numbers its records from 1 again, so anything the
            # previous session left behind has to go: the table's row ids are
            # those sequence numbers, and a stale row id is a hard error rather
            # than a cosmetic one.
            had_previous = bool(self.records)
            self._reset_session()

            self.engine = Engine(self.engine_path)
            self.engine.start(
                apps=apps,
                args=split_args(self.var_args.get()),
                attaches=attaches,
                session_name=self.session_name,
            )
            # A new engine starts with automatic writing off and nothing
            # adopted. Leaving the checkbox ticked would have the window claim
            # something the engine is not doing.
            if self._hosts_auto.get():
                self._hosts_auto.set(False)
                self._log("新的会话：自动写入已回到关闭状态，需要时请重新勾选")
            self._rendered = len(self.records)
            if had_previous:
                self._log("已清空上一个会话的记录与域名表（新引擎的记录编号从头开始）")
            if attaches:
                self._show_hint(f"正在按名称监视 {', '.join(attaches)}")
                self._log(f"按名称监视：{', '.join(attaches)}"
                          "（已运行的与之后启动的都会被收编）")
            if apps:
                names = ", ".join(Path(p).name for p in apps)
                self._show_hint(f"已开始监控 {names}（先启动监控，再启动目标）")
                self._log(f"目标（{len(apps)} 个）：{'; '.join(apps)}")
            self._log(f"引擎：{self.engine_path}")
        except Exception as exc:
            self._log(f"启动失败：{exc}", "error")
            messagebox.showerror(APP_TITLE, f"启动失败：\n{exc}")
        finally:
            self._starting = False

    def _reset_session(self) -> None:
        """Drop everything that belongs to the previous engine.

        Called when starting a new session, and only then -- so the log, which
        is a record of what happened rather than of what is being watched,
        survives.
        """
        self.records.clear()
        self._rendered = 0
        self.tree.delete(*self.tree.get_children())
        self.selected_procs.clear()
        self.domains.clear()
        self.aaaa.clear()
        self.status = Status()
        if self._domains_tree is not None and self._domains_tree.winfo_exists():
            self._domains_tree.delete(*self._domains_tree.get_children())
            self._refresh_domains_window()

    def on_stop(self) -> None:
        if self.engine is not None:
            self.engine.stop()
            self._log("已停止监控")
        self._show_hint("已停止")

    def on_toggle_pause(self) -> None:
        self.auto_scroll.set(not self.auto_scroll.get())
        if self.auto_scroll.get():
            self._scroll_to_end()
            self._show_hint("已恢复自动滚动")
        else:
            self._show_hint("已暂停自动滚动（监控仍在继续）")

    def on_clear(self) -> None:
        self.records.clear()
        self._rendered = 0
        self.tree.delete(*self.tree.get_children())
        # 进程列表来自已观察到的记录，清空后旧的选择会把新记录全部藏起来。
        self.selected_procs.clear()
        self._update_proc_label()
        self._show_hint("列表已清空（统计计数由引擎继续累计）")

    def on_pick_processes(self) -> None:
        """列出已经出现过的所有进程，勾选想看的。

        用"已经出现过的"而不是让用户提前输入：下载子进程在跑起来之前根本不存在，
        名字也无从得知。列表按记录数排序，最活跃的在最上面。
        """
        counts: dict[str, int] = {}
        for r in self.records:
            if r.get("pid", 0) == 0:
                continue
            name = str(r.get("process", ""))
            counts[name] = counts.get(name, 0) + 1
        if not counts:
            messagebox.showinfo(
                APP_TITLE,
                "还没有看到任何进程。先开始监控，目标产生查询后这里就会列出来。")
            return

        win = tk.Toplevel(self.master)
        win.title("选择要显示的进程")
        win.geometry("460x520")
        win.transient(self.master)
        win.grab_set()

        ttk.Label(win, text="勾选要显示的进程（可多选，Ctrl/Shift 连选）：",
                  padding=8).pack(anchor="w")

        body = ttk.Frame(win, padding=(8, 0))
        body.pack(fill="both", expand=True)
        lb = tk.Listbox(body, selectmode="extended", font=("Consolas", 10),
                        activestyle="none", exportselection=False)
        sb = ttk.Scrollbar(body, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        lb.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        ordered = sorted(counts.items(), key=lambda kv: -kv[1])
        for i, (name, n) in enumerate(ordered):
            lb.insert("end", f"{n:>7}  {name}")
            if name.lower() in self.selected_procs:
                lb.selection_set(i)
        if not self.selected_procs:
            # 默认全不选 = 显示全部；这里不预选任何项，避免误解为"只能看这些"
            pass

        btns = ttk.Frame(win, padding=8)
        btns.pack(fill="x")

        def apply() -> None:
            picked = {ordered[i][0].lower() for i in lb.curselection()}
            self.selected_procs = picked
            self._update_proc_label()
            self._rebuild_table()
            win.destroy()

        def select_all() -> None:
            lb.selection_set(0, "end")

        def select_none() -> None:
            lb.selection_clear(0, "end")

        ttk.Button(btns, text="全选", command=select_all, width=8).pack(side="left")
        ttk.Button(btns, text="清空选择", command=select_none, width=10).pack(side="left", padx=6)
        ttk.Button(btns, text="取消", command=win.destroy, width=8).pack(side="right")
        ttk.Button(btns, text="确定", command=apply, width=8).pack(side="right", padx=6)
        lb.bind("<Double-1>", lambda _e: apply())

    def on_all_processes(self) -> None:
        self.selected_procs.clear()
        self._update_proc_label()
        self._rebuild_table()

    def _update_proc_label(self) -> None:
        if not self.selected_procs:
            self.lbl_procs.configure(text="全部", foreground="#666666")
            return
        names = sorted(self.selected_procs)
        shown = "、".join(names[:4])
        if len(names) > 4:
            shown += f" 等 {len(names)} 个"
        self.lbl_procs.configure(text=shown, foreground="#1f6f8b")

    def on_clear_filter(self) -> None:
        self._clear_filter_widgets()

    def _clear_filter_widgets(self) -> None:
        self.var_f_domain.set("")
        self.var_f_proc.set("")
        self.var_f_ip.set("")
        self.show_etw.set(True)
        self.show_pcap.set(True)
        self.show_sni.set(True)
        self.selected_procs.clear()
        self._update_proc_label()
        self._rebuild_table()
        self._show_hint("过滤已清除")

    def on_sort(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_col = col
            self._sort_desc = col in ("seq", "time", "pid")

        keymap = {
            "time": lambda r: r.get("unix_ms", 0),
            "process": lambda r: str(r.get("process", "")).lower(),
            "pid": lambda r: r.get("pid", 0),
            "qtype": lambda r: str(r.get("qtype", "")),
            "source": lambda r: str(r.get("source", "")),
            "kind": lambda r: str(r.get("kind", "")),
            "domain": lambda r: str(r.get("domain", "")).lower(),
            "detail": lambda r: str(r.get("detail", "")),
        }
        key = keymap.get(col)
        if key is None:
            return
        self.records.sort(key=key, reverse=self._sort_desc)
        self._rendered = 0
        self._rebuild_table()
        arrow = " ▼" if self._sort_desc else " ▲"
        for c in self.tree["columns"]:
            text = self.tree.heading(c)["text"].rstrip(" ▲▼")
            self.tree.heading(c, text=text + (arrow if c == col else ""))
        self._show_hint("已按「%s」排序" % self.tree.heading(col)["text"])

    def on_export(self) -> None:
        if not self.records:
            messagebox.showinfo(APP_TITLE, "还没有记录可以导出。")
            return
        path = filedialog.asksaveasfilename(
            title="导出记录",
            defaultextension=".csv",
            initialfile=time.strftime("netmon-%Y%m%d-%H%M%S.csv"),
            filetypes=[("CSV 文件", "*.csv"), ("JSON 文件", "*.json")],
        )
        if not path:
            return
        try:
            n = self._export_to(Path(path))
            self._show_hint(f"已导出 {n} 条到 {Path(path).name}")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"导出失败：\n{exc}")

    def _export_to(self, path: Path) -> int:
        """把当前过滤条件下的记录写入文件，返回写入条数。

        与文件对话框分开，既让导出逻辑可以单独测试，也方便以后加"自动导出"。
        """
        rows = [r for r in self.records if self._passes_filter(r)]
        fields = ("seq", "unix_ms", "time", "process", "pid",
                  "qtype", "source", "kind", "domain", "detail")
        if str(path).lower().endswith(".json"):
            with open(path, "w", encoding="utf-8") as f:
                json.dump([{k: r.get(k) for k in fields} for r in rows],
                          f, ensure_ascii=False, indent=2)
        else:
            import csv
            # utf-8-sig: Excel 在中文区域设置下会把没有 BOM 的 UTF-8 当 GBK 读，
            # 非 ASCII 内容会变成乱码。
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(fields)
                for r in rows:
                    w.writerow([r.get(k, "") for k in fields])
        return len(rows)

    def on_row_double_click(self, _event: tk.Event) -> None:
        self._copy_column("domain")

    def on_row_menu(self, event: tk.Event) -> None:
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _copy_column(self, which: str) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        if which == "row":
            lines = ["\t".join(str(v) for v in self.tree.item(i, "values")) for i in sel]
        else:
            lines = [str(self.tree.item(i, "values")[6]) for i in sel]
        text = "\n".join(lines)
        self.master.clipboard_clear()
        self.master.clipboard_append(text)
        self._show_hint(f"已复制 {len(lines)} 条到剪贴板")

    # -- 弹出窗口 ----------------------------------------------------------

    def send_command(self, payload: dict) -> bool:
        """Send one command to the engine over its stdin channel."""
        proc = self.engine.proc if self.engine is not None else None
        if proc is None or proc.stdin is None or proc.poll() is not None:
            self._show_hint("引擎没有在运行", error=True)
            return False
        try:
            proc.stdin.write(json.dumps(payload) + "\n")
            proc.stdin.flush()
            return True
        except Exception as exc:
            self._log(f"发送命令失败：{exc}", "error")
            return False

    def send_requery(self, failed_only: bool) -> None:
        if self.send_command({"cmd": "requery", "failed_only": failed_only}):
            self._show_hint("已请求重新查询"
                            + ("（仅失败项）" if failed_only else "（全部）"))

    def on_export_domains(self) -> None:
        path = filedialog.asksaveasfilename(
            title="导出域名表",
            defaultextension=".csv",
            initialfile=time.strftime("netmon-domains-%Y%m%d-%H%M%S.csv"),
            filetypes=[("CSV 文件", "*.csv"), ("JSON 文件", "*.json")],
        )
        if path and self.send_command({"cmd": "export_domains", "path": path}):
            self._show_hint(f"引擎正在导出到 {Path(path).name}")

    def on_domains(self) -> None:
        """Per-process domain tables, with the AAAA result for each name.

        One row per (process, domain). A name two processes both asked for
        appears once under each, because that is what "this process's domains"
        means -- but it is resolved only once, since an AAAA record belongs to
        the name and not to the asker.
        """
        if self._domains_win is not None and self._domains_win.winfo_exists():
            self._domains_win.lift()
            self._refresh_domains_window()
            return

        win = tk.Toplevel(self.master)
        win.title("NetMonitor — 域名表与 AAAA 记录")
        win.geometry("1120x620")
        win.transient(self.master)
        self._domains_win = win

        top = ttk.Frame(win, padding=(8, 8, 8, 0))
        top.pack(fill="x")
        self.lbl_domain_stats = ttk.Label(top, text="", foreground="#333333")
        self.lbl_domain_stats.pack(side="left")
        ttk.Button(top, text="导出…", command=self.on_export_domains,
                   width=10).pack(side="right", padx=(6, 0))
        ttk.Button(top, text="全部重查", command=lambda: self.send_requery(False),
                   width=10).pack(side="right", padx=(6, 0))
        ttk.Button(top, text="重查失败项", command=lambda: self.send_requery(True),
                   width=12).pack(side="right", padx=(6, 0))

        body = ttk.Frame(win, padding=8)
        body.pack(fill="both", expand=True)
        body.rowconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)

        left = ttk.LabelFrame(body, text=" 进程 ", padding=4)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 8))
        self._domains_proc = tk.Listbox(left, width=26, exportselection=False,
                                        font=("Consolas", 10), activestyle="none")
        self._domains_proc.pack(fill="both", expand=True)
        # Only the *rows* are redrawn when the selection changes. Rebuilding
        # the listbox itself here would re-enter this handler through the very
        # event that triggered it, and undo the click that caused it.
        self._domains_proc.bind("<<ListboxSelect>>", lambda _e: self._refresh_domain_rows())

        right = ttk.LabelFrame(body, text=" 域名与 AAAA 记录 ", padding=4)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        # Filters narrow the rows of the selected process. Both are plain
        # case-insensitive substrings, applied as they are typed: a domain
        # fragment, or an address fragment such as "2606:" when looking for
        # whatever resolved over IPv6.
        bar = ttk.Frame(right)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        ttk.Label(bar, text="域名：").pack(side="left")
        entry_domain = ttk.Entry(bar, textvariable=self._domain_filter, width=26)
        entry_domain.pack(side="left", padx=(0, 12))
        ttk.Label(bar, text="解析地址：").pack(side="left")
        ttk.Entry(bar, textvariable=self._addr_filter, width=26).pack(side="left")
        ttk.Button(bar, text="清除",
                   command=self._clear_domain_filters, width=6).pack(side="left", padx=8)
        self._domains_count = ttk.Label(bar, text="", foreground="#333333")
        self._domains_count.pack(side="left", padx=8)
        self._domain_filter.trace_add("write", lambda *_a: self._refresh_domain_rows())
        self._addr_filter.trace_add("write", lambda *_a: self._refresh_domain_rows())

        cols = ("domain", "resolved", "status", "ipv6")
        tree = ttk.Treeview(right, columns=cols, show="headings")
        tree.heading("domain", text="域名")
        tree.heading("resolved", text="当前解析地址")
        tree.heading("status", text="AAAA 状态")
        tree.heading("ipv6", text="AAAA 查询结果")
        tree.column("domain", width=230, anchor="w")
        tree.column("resolved", width=330, anchor="w")
        tree.column("status", width=150, anchor="w")
        tree.column("ipv6", width=330, anchor="w")
        sb = ttk.Scrollbar(right, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.grid(row=1, column=0, sticky="nsew")
        sb.grid(row=1, column=1, sticky="ns")
        tree.tag_configure("found", foreground="#0a7d3d")
        tree.tag_configure("none", foreground="#777777")
        tree.tag_configure("failed", foreground="#a11")
        tree.tag_configure("pending", foreground="#8a6d1f")
        # Previous session's answer: present, but visibly not current.
        tree.tag_configure("archived", foreground="#5a5a7a")
        self._domains_tree = tree

        self._domains_proc.bind("<Double-1>", lambda _e: None)
        win.protocol("WM_DELETE_WINDOW", self.on_close_domains)
        self._refresh_domains_window()
        win.after(1200, self._domains_tick)

    def on_close_domains(self) -> None:
        if self._domains_win is not None:
            self._domains_win.destroy()
        self._domains_win = None
        self._domains_tree = None
        self._domains_proc = None
        self._domains_count = None

    def _domains_tick(self) -> None:
        """Redraw while the window is open, then reschedule."""
        if self._domains_win is None or not self._domains_win.winfo_exists():
            self._domains_win = None
            return
        self._refresh_domains_window()
        self._domains_win.after(1200, self._domains_tick)

    def _selected_process(self) -> Optional[str]:
        lb = self._domains_proc
        if lb is None or not lb.winfo_exists():
            return None
        sel = lb.curselection()
        if not sel:
            return None
        # The entry reads "name  (count)"; the name may itself contain spaces,
        # so split on the last " (" rather than on whitespace.
        text = lb.get(sel[0])
        return text.rsplit("  (", 1)[0]

    def _refresh_domains_window(self) -> None:
        """Rebuild the process list, keeping the current selection."""
        lb = self._domains_proc
        if lb is None or not lb.winfo_exists():
            return

        s = self.status
        total = sum(len(v) for v in self.domains.values())
        self.lbl_domain_stats.configure(
            text=(f"  进程 {len(self.domains)}   域名行 {total}   "
                  f"唯一域名 {s.domains_unique}   待查 {s.aaaa_pending}   "
                  f"有 AAAA {s.aaaa_found}   无 AAAA {s.aaaa_none}   "
                  f"查询失败 {s.aaaa_failed}"))

        keep = self._selected_process()
        ordered = sorted(self.domains.items(), key=lambda kv: (-len(kv[1]), kv[0]))

        lb.delete(0, "end")
        for name, doms in ordered:
            lb.insert("end", f"{name}  ({len(doms)})")
        if ordered:
            idx = 0
            if keep is not None:
                for i, (name, _) in enumerate(ordered):
                    if name == keep:
                        idx = i
                        break
            lb.selection_clear(0, "end")
            lb.selection_set(idx)
            lb.see(idx)

        self._refresh_domain_rows()

    def _refresh_domain_rows(self) -> None:
        """Redraw the right-hand table for whatever is selected.

        Both filter boxes apply to the selected process's rows only: they narrow
        what is shown, they do not change the table the engine keeps.
        """
        tree = self._domains_tree
        if tree is None or not tree.winfo_exists():
            return
        tree.delete(*tree.get_children())
        name = self._selected_process()
        if name is None:
            if self._domains_count is not None and self._domains_count.winfo_exists():
                self._domains_count.configure(text="")
            return
        needle_domain = self._domain_filter.get().strip().lower()
        needle_addr = self._addr_filter.get().strip().lower()
        rows = sorted(self.domains.get(name, ()))
        shown = 0
        for d in rows:
            info = self.aaaa.get(d, {})
            status = info.get("status", "待查询")
            addrs = ", ".join(info.get("addresses", []))
            resolved = ", ".join(info.get("resolved_ips", []))
            # The filter matches the address column as displayed, not the
            # decorated text below it, so typing an IP fragment behaves the way
            # the column reads.
            if needle_domain and needle_domain not in d.lower():
                continue
            if needle_addr and needle_addr not in resolved.lower():
                continue
            shown += 1
            if resolved and info.get("resolved_by_us"):
                # Say where it came from: this one was resolved by the program
                # itself rather than seen on the wire.
                resolved += "（本程序解析）"
            # Restored from the previous session's cache: the answer is the one
            # that session last saw, so it is labelled rather than passed off as
            # current.
            archived = bool(info.get("archived"))
            if archived:
                status += "（上次会话）"
            if archived:
                tag = "archived"
            elif addrs:
                tag = "found"
            elif "失败" in status:
                tag = "failed"
            elif "待查询" in status or "查询中" in status:
                tag = "pending"
            else:
                tag = "none"
            tree.insert("", "end", values=(d, resolved, status, addrs), tags=(tag,))
        if self._domains_count is not None and self._domains_count.winfo_exists():
            if needle_domain or needle_addr:
                self._domains_count.configure(text=f"显示 {shown} / 共 {len(rows)}")
            else:
                self._domains_count.configure(text=f"共 {len(rows)}")

    def _clear_domain_filters(self) -> None:
        self._domain_filter.set("")
        self._addr_filter.set("")

    # -- hosts ---------------------------------------------------------------

    def on_hosts(self) -> None:
        """Write the selected processes' domain tables into the hosts file.

        Several processes can be chosen at once; their plans are merged, so a
        domain both resolved becomes one line with both owners. Writing is
        never automatic until the user ticks the box: what goes into a hosts
        file changes how the whole machine resolves names, so it should show
        what it is about to do first.
        """
        if self._hosts_win is not None and self._hosts_win.winfo_exists():
            self._hosts_win.lift()
            self._reload_hosts()
            return

        win = tk.Toplevel(self.master)
        win.title("NetMonitor — 写入 hosts")
        win.geometry("1000x640")
        win.transient(self.master)
        self._hosts_win = win
        win.protocol("WM_DELETE_WINDOW", self.on_close_hosts)

        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=6, pady=6)

        # ---------------- tab 1: write ----------------
        tab1 = ttk.Frame(nb, padding=6)
        nb.add(tab1, text=" 写入 ")

        head = ttk.LabelFrame(tab1, text=" 要写入哪些进程的域名表（右键选择，可多选） ", padding=6)
        head.pack(fill="x")
        head.columnconfigure(1, weight=1)
        ttk.Label(head, text="进程：").grid(row=0, column=0, sticky="nw")
        proc_frame = ttk.Frame(head)
        proc_frame.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        proc_frame.columnconfigure(0, weight=1)
        self._hosts_proc_list = tk.Listbox(
            proc_frame, height=4, width=30, exportselection=False,
            selectmode="browse", font=("Consolas", 10), activestyle="none",
            selectbackground="#e6f4ec", selectforeground="#0a6b3d",
        )
        self._hosts_proc_list.grid(row=0, column=0, sticky="ew")
        sb_proc = ttk.Scrollbar(proc_frame, orient="vertical",
                                command=self._hosts_proc_list.yview)
        sb_proc.grid(row=0, column=1, sticky="ns")
        self._hosts_proc_list.configure(yscrollcommand=sb_proc.set)
        # The set of processes that will be written is the set of green rows,
        # not the highlight bar: right-click adds or removes one, and the
        # preview follows immediately. Left-click only moves the cursor.
        self._hosts_proc_list.bind("<Button-3>", self._on_hosts_proc_right_click)
        self._hosts_proc_list.bind("<Double-Button-1>",
                                   lambda _e: self._toggle_hosts_process_at_cursor())
        self._hosts_proc_menu = tk.Menu(self._hosts_proc_list, tearoff=0)
        self._hosts_proc_hint = ttk.Label(head, text="", foreground="#666666")
        self._hosts_proc_hint.grid(row=1, column=1, sticky="w", pady=(2, 0))
        ttk.Button(head, text="刷新进程列表", command=self._fill_hosts_processes,
                   width=14).grid(row=0, column=2, sticky="n")

        ttk.Label(head, text="无 IPv6 的域名：").grid(row=2, column=0, sticky="w", pady=(6, 0))
        pol = ttk.Frame(head)
        pol.grid(row=2, column=1, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Radiobutton(pol, text="指向 127.0.0.1（禁用该域名）",
                        variable=self._hosts_policy,
                        value="block", command=self._on_policy_change
                        ).pack(side="left")
        ttk.Radiobutton(pol, text="不写入（保持原解析）",
                        variable=self._hosts_policy,
                        value="skip", command=self._on_policy_change
                        ).pack(side="left", padx=(10, 0))

        auto = ttk.LabelFrame(tab1, text=" 自动模式（可多进程，同名域名合并为一行） ", padding=6)
        auto.pack(fill="x", pady=(6, 0))
        ttk.Checkbutton(
            auto,
            text="开启后，上方已选进程的域名表一有变化就自动写入 hosts",
            variable=self._hosts_auto, command=self.on_hosts_auto_toggle,
        ).pack(anchor="w")
        ttk.Label(
            auto,
            text=("会在所有进程的 AAAA 查询全部落定、且计划稳定 1.5 秒后才写入，避免把还没查到"
                  "IPv6 的域名先写成 127.0.0.1。两个进程写入同一条域名时合并为一行，"
                  "并记录两个归属；自动模式只写入、不删除条目。"),
            foreground="#666666", wraplength=900,
        ).pack(anchor="w", pady=(2, 0))

        actions = ttk.Frame(tab1, padding=(0, 6))
        actions.pack(fill="x")
        ttk.Button(actions, text="写入 hosts", command=self.on_hosts_write,
                   width=12).pack(side="left")
        ttk.Button(actions, text="移除该进程的条目", command=self.on_hosts_remove_process,
                   width=18).pack(side="left", padx=6)
        ttk.Button(actions, text="移除全部条目…", command=self.on_hosts_remove_all,
                   width=15).pack(side="left", padx=6)
        ttk.Button(actions, text="立即备份", command=self.on_hosts_backup,
                   width=10).pack(side="left", padx=(16, 0))
        ttk.Button(actions, text="恢复备份…", command=self.on_hosts_restore,
                   width=11).pack(side="left", padx=6)
        ttk.Button(actions, text="清理旧备份…", command=self.on_hosts_prune,
                   width=12).pack(side="left", padx=6)
        ttk.Label(actions, text="Ctrl 多选后可右键只写入所选域名",
                  foreground="#666666").pack(side="left", padx=(16, 0))

        # The status line is packed before the table and anchored to the
        # bottom, so it stays visible however many rows the preview has.
        self._hosts_status = ttk.Label(tab1, text="", foreground="#333333")
        self._hosts_status.pack(side="bottom", fill="x", pady=(6, 0))

        table_area = ttk.Frame(tab1)
        table_area.pack(side="top", fill="both", expand=True)

        cols = ("process", "domain", "address", "written", "action", "reason")
        tree = ttk.Treeview(table_area, columns=cols, show="headings",
                            selectmode="extended")
        tree.heading("process", text="进程")
        tree.heading("domain", text="域名")
        tree.heading("address", text="将写入的地址")
        tree.heading("written", text="hosts 里的现状")
        tree.heading("action", text="本次写入")
        tree.heading("reason", text="说明")
        tree.column("process", width=150, anchor="w")
        tree.column("domain", width=210, anchor="w")
        tree.column("address", width=210, anchor="w")
        tree.column("written", width=140, anchor="w")
        tree.column("action", width=95, anchor="w")
        tree.column("reason", width=130, anchor="w")
        sb = ttk.Scrollbar(table_area, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        tree.tag_configure("add", foreground="#0a7d3d")
        tree.tag_configure("update", foreground="#8a6d1f")
        tree.tag_configure("claim", foreground="#3d5a80")
        tree.tag_configure("keep", foreground="#555555")
        tree.tag_configure("skip", foreground="#999999")
        # A subset write is something the user asks for by selecting rows, so
        # the right-click menu is where it lives; Ctrl/Shift multi-select works
        # because the tree is in "extended" mode.
        tree.bind("<Button-3>", self._on_hosts_preview_right_click)
        self._hosts_menu = tk.Menu(tree, tearoff=0)
        self._hosts_menu.add_command(
            label="写入所选域名", command=self.on_hosts_write_selected)
        self._hosts_menu.add_command(
            label="写入全部域名", command=self.on_hosts_write)
        self._hosts_menu.add_separator()
        self._hosts_menu.add_command(
            label="复制所选域名", command=self.on_hosts_copy_selected)
        self._hosts_tree = tree

        # ---------------- tab 2: current entries, grouped by process ----------
        tab_entries = ttk.Frame(nb, padding=6)
        nb.add(tab_entries, text=" 当前条目 ")
        bar3 = ttk.Frame(tab_entries)
        bar3.pack(fill="x")
        ttk.Button(bar3, text="刷新", command=self._reload_hosts,
                   width=8).pack(side="left")
        self._hosts_entries_info = ttk.Label(bar3, text="", foreground="#333333")
        self._hosts_entries_info.pack(side="left", padx=12)
        ttk.Label(
            bar3,
            text="Ctrl/Shift 多选，右键复制 / 删除",
            foreground="#666666",
        ).pack(side="right")
        # The tree column carries the process; the two data columns are the
        # entry itself. Parent rows are processes, children are their lines.
        entries = ttk.Treeview(
            tab_entries, columns=("address", "domain"),
            show="tree headings", selectmode="extended",
        )
        entries.heading("#0", text="进程")
        entries.heading("address", text="地址")
        entries.heading("domain", text="域名")
        entries.column("#0", width=220, anchor="w")
        entries.column("address", width=300, anchor="w")
        entries.column("domain", width=320, anchor="w")
        sb3 = ttk.Scrollbar(tab_entries, orient="vertical", command=entries.yview)
        entries.configure(yscrollcommand=sb3.set)
        entries.pack(side="left", fill="both", expand=True, pady=(6, 0))
        sb3.pack(side="right", fill="y", pady=(6, 0))
        entries.tag_configure("process", foreground="#1f3b57")
        entries.tag_configure("ipv6", foreground="#0a7d3d")
        entries.tag_configure("block", foreground="#a11")
        entries.tag_configure("unrecorded", foreground="#777777")
        entries.bind("<Button-3>", self._on_hosts_entries_right_click)
        self._hosts_entries_menu = tk.Menu(entries, tearoff=0)
        self._hosts_entries_menu.add_command(
            label="复制该行", command=self.on_hosts_entry_copy)
        self._hosts_entries_menu.add_command(
            label="删除该行…", command=self.on_hosts_entry_delete)
        self._hosts_entries_tree = entries
        nb.bind("<<NotebookTabChanged>>",
                lambda _e: self._reload_hosts_if_visible())

        # ---------------- tab 3: view / edit ----------------
        tab2 = ttk.Frame(nb, padding=6)
        nb.add(tab2, text=" 查看 / 编辑 ")
        bar2 = ttk.Frame(tab2)
        bar2.pack(fill="x")
        ttk.Button(bar2, text="重新载入", command=self._reload_hosts,
                   width=10).pack(side="left")
        ttk.Button(bar2, text="保存", command=self.on_hosts_save,
                   width=10).pack(side="left", padx=6)
        self._hosts_info = ttk.Label(bar2, text="", foreground="#333333")
        self._hosts_info.pack(side="left", padx=12)
        edit = tk.Text(tab2, wrap="none", font=("Consolas", 10), undo=True)
        sb2 = ttk.Scrollbar(tab2, orient="vertical", command=edit.yview)
        edit.configure(yscrollcommand=sb2.set)
        edit.pack(side="left", fill="both", expand=True, pady=(6, 0))
        sb2.pack(side="right", fill="y", pady=(6, 0))
        self._hosts_edit = edit

        self._fill_hosts_processes()
        # Needed even when the process did not change: the window may have been
        # closed and reopened, and the preview rows are not kept across that.
        self._refresh_hosts_preview()
        self._reload_hosts()

    def on_close_hosts(self) -> None:
        if self._hosts_win is not None:
            self._hosts_win.destroy()
        self._hosts_win = None
        self._hosts_tree = None
        self._hosts_edit = None
        self._hosts_status = None
        self._hosts_info = None
        self._hosts_proc_list = None
        self._hosts_proc_hint = None
        self._hosts_proc_menu = None
        self._hosts_entries_tree = None
        self._hosts_entries_info = None
        self._hosts_menu = None
        self._hosts_entries_menu = None
        self._hosts_delete_batch = 0
        self._hosts_delete_total = 0
        self._hosts_entries_by_iid.clear()
        self._hosts_row_keys.clear()
        self._hosts_preview_by_process.clear()

    def _selected_hosts_processes(self) -> list[str]:
        """The processes currently chosen, in list order."""
        known = set(self._hosts_procs)
        return [name for name in self._hosts_chosen if name in known]

    def _sync_hosts_processes(self) -> None:
        """Paint chosen rows green and say how many there are."""
        lb = getattr(self, "_hosts_proc_list", None)
        if lb is None or not lb.winfo_exists():
            return
        chosen = set(self._hosts_chosen)
        for index, name in enumerate(self._hosts_procs):
            on = name in chosen
            # The cursor highlight uses a light green background, so a chosen
            # row stays readable whether or not it is the focused one.
            lb.itemconfig(
                index,
                foreground="#0a7d3d" if on else "#333333",
                selectforeground="#0a6b3d" if on else "#000000",
            )
        hint = getattr(self, "_hosts_proc_hint", None)
        if hint is not None and hint.winfo_exists():
            if chosen:
                shown = "、".join(self._hosts_chosen[:4])
                more = f" 等 {len(self._hosts_chosen)} 个" if len(self._hosts_chosen) > 4 else ""
                hint.configure(
                    text=f"已选 {len(self._hosts_chosen)} 个（绿色）：{shown}{more}",
                    foreground="#0a6b3d")
            else:
                hint.configure(text="右键点进程名选择要写入的进程（可多选）",
                               foreground="#666666")

    def _fill_hosts_processes(self) -> None:
        # Everything with a domain table -- including the previous session's,
        # which the engine restores from its cache -- plus everything named in
        # the hosts file, so old entries stay manageable.
        names = sorted(set(self.domains) | set(self._hosts_owners))
        lb = getattr(self, "_hosts_proc_list", None)
        if lb is None or not lb.winfo_exists():
            return
        keep = [name for name in self._hosts_chosen if name in names]
        self._hosts_procs = names
        lb.delete(0, "end")
        for name in names:
            lb.insert("end", name)
        if not keep and names and not self._hosts_choice_made:
            # Nothing chosen yet (first open): default to the first process so
            # the table is not empty. A deliberate "选择全不选" is respected.
            keep = [names[0]]
        self._hosts_chosen = keep
        if self._hosts_chosen:
            index = names.index(self._hosts_chosen[0])
            lb.selection_clear(0, "end")
            lb.selection_set(index)
        self._sync_hosts_processes()
        # A process that vanished from the list can no longer be written to;
        # drop its cached plan instead of showing rows whose commands would
        # name a process the engine does not know.
        self._hosts_preview_by_process = {
            name: rows for name, rows in self._hosts_preview_by_process.items()
            if name in names
        }
        self._rebuild_hosts_preview(self._selected_hosts_processes())
        self._render_hosts_preview()

    def _toggle_hosts_process(self, name: str) -> None:
        self._hosts_choice_made = True
        if name in self._hosts_chosen:
            self._hosts_chosen.remove(name)
            note = f"已取消选择 {name}"
        else:
            self._hosts_chosen.append(name)
            # Keep the chosen list in the order the picker shows, so the
            # preview rows do not jump around as processes are added.
            order = {n: i for i, n in enumerate(self._hosts_procs)}
            self._hosts_chosen.sort(key=lambda n: order.get(n, 0))
            note = f"已选择 {name}"
        self._sync_hosts_processes()
        self._refresh_hosts_preview()
        self._set_hosts_status(note, ok=True)
        # Automatic mode follows the set, otherwise it would keep writing the
        # processes that were chosen when it was switched on.
        if self._hosts_auto.get():
            self.on_hosts_auto_toggle()

    def _toggle_hosts_process_at_cursor(self) -> None:
        lb = getattr(self, "_hosts_proc_list", None)
        if lb is None or not lb.winfo_exists():
            return
        selection = lb.curselection()
        if selection and selection[0] < len(self._hosts_procs):
            self._toggle_hosts_process(self._hosts_procs[selection[0]])

    def _on_hosts_proc_right_click(self, event: "tk.Event") -> None:
        lb = getattr(self, "_hosts_proc_list", None)
        menu = getattr(self, "_hosts_proc_menu", None)
        if lb is None or menu is None or not lb.winfo_exists():
            return
        index = lb.nearest(event.y)
        if index < 0 or index >= len(self._hosts_procs):
            return
        lb.selection_clear(0, "end")
        lb.selection_set(index)
        lb.activate(index)
        name = self._hosts_procs[index]
        # The menu is created once and rebuilt here. `tk_popup` returns as soon
        # as it is posted, so a menu destroyed in a `finally` block would be
        # gone before the user could click it -- which is exactly why this
        # looked like a dead right-click.
        menu.delete(0, "end")
        chosen = name in self._hosts_chosen
        menu.add_command(
            label=("取消选择该进程" if chosen else "选择该进程"),
            command=lambda n=name: self._toggle_hosts_process(n))
        menu.add_separator()
        menu.add_command(label=f"全选（{len(self._hosts_procs)} 个）",
                         command=self._select_all_hosts_processes)
        menu.add_command(label="全不选", command=self._clear_hosts_processes)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _select_all_hosts_processes(self) -> None:
        self._hosts_choice_made = True
        self._hosts_chosen = list(self._hosts_procs)
        self._sync_hosts_processes()
        self._refresh_hosts_preview()
        if self._hosts_auto.get():
            self.on_hosts_auto_toggle()

    def _clear_hosts_processes(self) -> None:
        self._hosts_choice_made = True
        self._hosts_chosen.clear()
        self._sync_hosts_processes()
        self._set_hosts_status(
            "已清空选择。右键点进程名重新选择要写入的进程。", ok=False)
        if self._hosts_auto.get():
            self.on_hosts_auto_toggle()

    def _on_policy_change(self) -> None:
        """Refresh the preview, and keep automatic mode on the same policy."""
        if self._hosts_auto.get():
            self.on_hosts_auto_toggle()
        self._refresh_hosts_preview()

    def _rebuild_hosts_preview(self, processes: list[str]) -> None:
        """Merge the per-process plans into the flat list the table renders."""
        merged: list[dict] = []
        for name in processes:
            for row in self._hosts_preview_by_process.get(name, ()):
                item = dict(row)
                item["process"] = name
                merged.append(item)
        self.hosts_preview = merged

    def _refresh_hosts_preview(self) -> None:
        processes = self._selected_hosts_processes()
        if not processes:
            self._set_hosts_status(
                "还没有可写入的进程（先监控并让它解析几个域名）", ok=False)
            return
        self._hosts_last_refresh = time.time()
        policy = self._hosts_policy.get()
        # Forget plans of processes that are no longer selected, so selecting
        # one again asks the engine instead of showing a stale plan.
        for name in list(self._hosts_preview_by_process):
            if name not in processes:
                del self._hosts_preview_by_process[name]
        for proc in processes:
            self.send_command({
                "cmd": "hosts_preview",
                "process": proc,
                "policy": policy,
            })
        self._rebuild_hosts_preview(processes)
        self._render_hosts_preview()

    def _render_hosts_preview(self) -> None:
        tree = getattr(self, "_hosts_tree", None)
        if tree is None or not tree.winfo_exists():
            return
        # A refresh must not throw away a selection the user just made: the
        # preview updates on its own whenever the domain table moves, which can
        # happen while rows are selected.
        selected = {
            self._hosts_row_keys.get(iid) for iid in tree.selection()
        }
        selected.discard(None)
        tree.delete(*tree.get_children())
        self._hosts_row_keys.clear()
        for index, e in enumerate(self.hosts_preview):
            action = e.get("action", "")
            reason = e.get("reason", "")
            if e.get("previous"):
                # The address came from the previous session's cache, not from
                # a lookup made now.
                reason = f"{reason}（上次会话）"
            domain = e.get("domain", "")
            process = e.get("process", "")
            iid = f"row{index}"
            tree.insert("", "end", iid=iid, values=(
                process,
                domain,
                e.get("address", "") or "（不写入）",
                e.get("written", ""),
                action,
                reason,
            ), tags=(ACTION_TAGS.get(action, "skip"),))
            self._hosts_row_keys[iid] = (process, domain)
        keep = [iid for iid, key in self._hosts_row_keys.items() if key in selected]
        if keep:
            tree.selection_set(keep)
        counts: dict = {}
        for e in self.hosts_preview:
            k = e.get("action", "")
            counts[k] = counts.get(k, 0) + 1
        parts = [f"{k} {n}" for k, n in counts.items() if n]
        processes = self._selected_hosts_processes()
        who = f"{len(processes)} 个进程" if len(processes) > 1 else (
            processes[0] if processes else "（无）")
        self._set_hosts_status(
            f"（{who}）{len(self.hosts_preview)} 条："
            + "、".join(parts)
            + " ｜ 写入只增不改：已写入的域名不动，也不会重复写入", ok=True)

    def _render_hosts_content(self) -> None:
        edit = getattr(self, "_hosts_edit", None)
        info = getattr(self, "_hosts_info", None)
        if edit is None or not edit.winfo_exists():
            return
        edit.delete("1.0", "end")
        edit.insert("1.0", self.hosts_text)
        if info is not None and info.winfo_exists():
            m = self.hosts_meta
            owners = m.get("by_owner") or []
            who = "，".join(
                f"{o.get('process') or '(未记录进程)'} {o.get('entries')} 条"
                for o in owners) or "无"
            info.configure(text=(
                f"{m.get('path', '')}   本程序条目 {m.get('managed_entries', 0)}"
                f"   按进程：{who}   总条目 {m.get('total_entries', 0)}"
                f"   备份 {len(m.get('backups', []))} 个"))

    def _render_hosts_entries(self) -> None:
        """Show the managed block grouped by the process that asked for it.

        The grouping comes from the per-line owner marker, not from the domain
        tables: a process that is no longer running still owns the lines it
        wrote, and that is exactly what has to stay visible to remove them.
        Shared lines are listed under every owner, so the counts can add up to
        more than the number of lines.
        """
        tree = getattr(self, "_hosts_entries_tree", None)
        if tree is None or not tree.winfo_exists():
            return
        tree.delete(*tree.get_children())
        self._hosts_entries_by_iid.clear()
        grouped: dict[str, list[dict]] = {}
        for entry in self.hosts_entries:
            owners = entry.get("owners") or []
            if not owners:
                owners = [""]
            for owner in owners:
                grouped.setdefault(owner, []).append(entry)

        for owner in sorted(grouped, key=lambda n: (-len(grouped[n]), n.lower())):
            rows = sorted(grouped[owner], key=lambda e: e.get("domain", "").lower())
            label = owner or "(未记录进程)"
            parent = tree.insert(
                "", "end", text=f"{label}（{len(rows)} 条）",
                values=("", ""), open=True, tags=("process",),
            )
            for index, entry in enumerate(rows):
                address = entry.get("address", "")
                if address == "127.0.0.1":
                    tag = "block"
                elif ":" in address:
                    tag = "ipv6"
                else:
                    tag = "unrecorded"
                # A shared line appears under each owner; the ids stay unique
                # per owner/row so the context menu can tell them apart.
                iid = f"entry-{owner}-{index}"
                tree.insert(parent, "end", iid=iid,
                            values=(address, entry.get("domain", "")),
                            tags=(tag,))
                self._hosts_entries_by_iid[iid] = entry

        info = getattr(self, "_hosts_entries_info", None)
        if info is not None and info.winfo_exists():
            m = self.hosts_meta
            info.configure(text=(
                f"本程序条目 {m.get('managed_entries', 0)}"
                f"   涉及进程 {len(grouped)}"
                f"   文件总条目 {m.get('total_entries', 0)}"
                f"   {m.get('path', '')}"))

    def _selected_hosts_entries(self) -> list[dict]:
        """All selected lines, deduplicated.

        A shared line is shown once under each owner; selecting both copies
        must not delete it twice. The identity is the line itself.
        """
        tree = getattr(self, "_hosts_entries_tree", None)
        if tree is None or not tree.winfo_exists():
            return []
        out: list[dict] = []
        seen: set[tuple[str, str, str]] = set()
        for iid in tree.selection():
            entry = self._hosts_entries_by_iid.get(iid)
            if entry is None:
                continue
            key = (
                entry.get("address", ""),
                entry.get("domain", ""),
                entry.get("line", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(entry)
        return out

    def _on_hosts_entries_right_click(self, event: "tk.Event") -> None:
        """Right-click a line for copy / delete; process headings have neither.

        Clicking inside an existing multi-selection keeps it, so the menu acts
        on every selected line; clicking another line selects just that one.
        """
        tree = getattr(self, "_hosts_entries_tree", None)
        menu = getattr(self, "_hosts_entries_menu", None)
        if tree is None or menu is None:
            return
        row = tree.identify_row(event.y)
        if not row or not tree.parent(row):
            # A process heading is a grouping, not a line in the file.
            return
        if row not in tree.selection():
            tree.selection_set(row)
        tree.focus(row)
        count = len(self._selected_hosts_entries())
        if count:
            menu.entryconfigure(
                0, label=f"复制所选行（{count} 行）" if count > 1 else "复制该行")
            menu.entryconfigure(
                1, label=f"删除所选 {count} 行…" if count > 1 else "删除该行…")
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def on_hosts_entry_copy(self) -> None:
        entries = self._selected_hosts_entries()
        if not entries:
            self._set_hosts_status("先选中至少一行", ok=False)
            return
        lines = [
            e.get("line") or "{} {}".format(e.get("address", ""), e.get("domain", ""))
            for e in entries
        ]
        self.master.clipboard_clear()
        self.master.clipboard_append("\n".join(lines))
        self._set_hosts_status(
            f"已复制 {len(lines)} 行" if len(lines) > 1 else "已复制该行", ok=True)

    def on_hosts_entry_delete(self) -> None:
        """Delete the selected lines outright, even if another process owns them."""
        entries = self._selected_hosts_entries()
        if not entries:
            self._set_hosts_status("先选中至少一行", ok=False)
            return
        shared: list[str] = []
        for entry in entries:
            owners = [o for o in (entry.get("owners") or []) if o]
            if len(owners) > 1:
                shared.append(
                    f"{entry.get('domain', '')}（{'、'.join(owners)}）")
        listing = "\n".join(
            "{}    {}".format(e.get("address", ""), e.get("domain", ""))
            for e in entries[:10])
        if len(entries) > 10:
            listing += f"\n… 共 {len(entries)} 行"
        shared_note = ""
        if shared:
            shared_note = (
                "\n\n注意：以下行同时属于多个进程，删除后所有进程都不再拥有它：\n"
                + "\n".join(shared[:6])
                + ("\n…" if len(shared) > 6 else ""))
        if not messagebox.askyesno(
            APP_TITLE,
            f"从 hosts 文件里删除选中的 {len(entries)} 行？\n\n"
            f"{listing}"
            f"{shared_note}\n\n"
            "只删除这些行，文件其它内容不动；每一行删除前都会自动备份。",
        ):
            return
        self._hosts_delete_batch = len(entries)
        self._hosts_delete_total = len(entries)
        self._set_hosts_status(f"正在删除 {len(entries)} 行…", ok=True)
        for entry in entries:
            owners = [o for o in (entry.get("owners") or []) if o]
            self.send_command({
                "cmd": "hosts_remove_entry",
                "domain": entry.get("domain", ""),
                "address": entry.get("address", ""),
                "process": owners[0] if owners else "",
            })

    def _reload_hosts(self) -> None:
        self.send_command({"cmd": "hosts_read"})

    def _reload_hosts_if_visible(self) -> None:
        """Re-read the file when the "current entries" tab is opened.

        The tab is a view of a file that anything could have changed since the
        window was built, so showing it is a reason to read it again.
        """
        tree = getattr(self, "_hosts_entries_tree", None)
        if tree is None or not tree.winfo_exists():
            return
        if self.engine is None or self.engine.proc is None:
            return
        if self.engine.proc.poll() is not None:
            return
        self._reload_hosts()

    def _set_hosts_status(self, text: str, ok: bool = True) -> None:
        lbl = getattr(self, "_hosts_status", None)
        if lbl is not None and lbl.winfo_exists():
            lbl.configure(text=text, foreground="#0a6b3d" if ok else "#a11")

    def on_hosts_auto_toggle(self) -> None:
        on = self._hosts_auto.get()
        processes = self._selected_hosts_processes()
        if on and not processes:
            self._hosts_auto.set(False)
            self.send_command({"cmd": "hosts_auto", "on": False})
            self._set_hosts_status(
                "请先右键选择至少一个进程，再开启自动模式", ok=False)
            return
        self.send_command({
            "cmd": "hosts_auto",
            "on": on,
            "processes": processes,
            "policy": self._hosts_policy.get(),
        })

    def on_hosts_write(self) -> None:
        processes = self._selected_hosts_processes()
        if not processes:
            self._set_hosts_status("请先右键选择进程", ok=False)
            return
        policy = self._hosts_policy.get()
        what = ("指向 127.0.0.1" if policy == "block" else "不写入")
        names = "、".join(processes)
        if not messagebox.askyesno(
            APP_TITLE,
            f"把以下 {len(processes)} 个进程的域名表写入 hosts 文件？\n\n"
            f"{names}\n\n"
            "· 已经写过的域名不动，也不会重复写入；\n"
            "· 没有写过的域名追加到本程序标记的区块里；\n"
            "· 两个进程写入同一条域名时合并为一行，记录两个归属；\n"
            "· 之前因查不到 IPv6 而指向 127.0.0.1 的域名，现在有 IPv6 了会更新为 IPv6 地址；\n"
            "· 其它进程写入的条目、以及文件里的其它内容，一律不动；\n"
            "· 所有进程合并成一次写入，写入前自动备份一次。\n\n"
            f"无 IPv6 的域名：{what}。",
        ):
            return
        self.send_command({
            "cmd": "hosts_write", "processes": processes, "policy": policy})

    def _on_hosts_preview_right_click(self, event: "tk.Event") -> None:
        """Right-click: keep the selection if the click lands inside it.

        Tk's default right-click behaviour would collapse a multi-selection to
        the row under the cursor before the menu opens, which would make the
        "write the selected domains" item act on one row instead of the ones
        the user picked.
        """
        tree = self._hosts_tree
        menu = self._hosts_menu
        if tree is None or menu is None:
            return
        row = tree.identify_row(event.y)
        if row:
            if row not in tree.selection():
                tree.selection_set(row)
            tree.focus(row)
        elif not tree.selection():
            return
        count = len(tree.selection())
        label = f"写入所选域名（{count} 条）" if count else "写入所选域名"
        try:
            menu.entryconfigure(0, label=label)
        except tk.TclError:
            pass
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _selected_hosts_keys(self) -> list[tuple[str, str]]:
        """Selected preview rows as (process, domain) pairs."""
        tree = self._hosts_tree
        if tree is None:
            return []
        out: list[tuple[str, str]] = []
        for iid in tree.selection():
            key = self._hosts_row_keys.get(iid)
            if key and key not in out:
                out.append(key)
        return out

    def on_hosts_write_selected(self) -> None:
        """Write only the rows selected in the preview.

        The selection decides which domains are planned, and may span several
        processes: the engine folds them into one write, so a name both
        processes resolved becomes one shared line with one backup. The policy
        and every write rule are unchanged.
        """
        keys = self._selected_hosts_keys()
        if not keys:
            self._set_hosts_status("先在预览表里选中要写入的域名（Ctrl/Shift 多选）",
                                   ok=False)
            return
        groups: dict[str, list[str]] = {}
        for proc, domain in keys:
            groups.setdefault(proc, []).append(domain)
        policy = self._hosts_policy.get()
        what = ("指向 127.0.0.1" if policy == "block" else "不写入")
        summary = "\n".join(
            f"· {proc}：{len(domains)} 条" for proc, domains in groups.items())
        if not messagebox.askyesno(
            APP_TITLE,
            f"只把选中的 {len(keys)} 行写入 hosts？\n\n{summary}\n\n"
            "· 已写入的域名不动，没有写过的追加到本程序标记的区块里；\n"
            "· 同名域名由多个进程选中时合并为一行，记录所有归属；\n"
            "· 其它域名保持原样，不会因为这次写入而发生变化；\n"
            f"· 选中的域名若没有可用 IPv6：{what}。\n"
            "写入前会自动备份一次。",
        ):
            return
        self.send_command({
            "cmd": "hosts_write",
            "processes": list(groups),
            "policy": policy,
            "domains": [domain for _proc, domain in keys],
        })

    def on_hosts_copy_selected(self) -> None:
        keys = self._selected_hosts_keys()
        if not keys:
            self._set_hosts_status("没有选中的域名", ok=False)
            return
        domains = [domain for _proc, domain in keys]
        self.master.clipboard_clear()
        self.master.clipboard_append("\n".join(domains))
        self._set_hosts_status(f"已复制 {len(domains)} 个域名", ok=True)

    def on_hosts_remove_process(self) -> None:
        """Remove the selected processes' entries, leaving every other one alone."""
        processes = self._selected_hosts_processes()
        if not processes:
            self._set_hosts_status("请先选择进程", ok=False)
            return
        names = "、".join(processes)
        if messagebox.askyesno(
            APP_TITLE,
            f"移除 hosts 文件里由以下 {len(processes)} 个进程写入的条目？\n\n"
            f"{names}\n\n"
            "只删除记录了这些进程的行；与其它进程共用的行会保留下来，"
            "只去掉它们的名字。\n"
            "文件里的其它内容不动，每个进程移除前都会自动备份。",
        ):
            for proc in processes:
                self.send_command({"cmd": "hosts_remove", "process": proc})

    def on_hosts_remove_all(self) -> None:
        if messagebox.askyesno(
            APP_TITLE,
            "移除 hosts 文件里本程序写入的全部条目？\n\n"
            "所有进程的条目都会被删除，只删除位于 NetMonitor 标记之间的行，"
            "文件其它内容不动。\n"
            "移除前会自动备份。",
        ):
            self.send_command({"cmd": "hosts_remove"})

    def on_hosts_backup(self) -> None:
        self.send_command({"cmd": "hosts_backup"})

    def on_hosts_restore(self) -> None:
        meta = self.hosts_meta or {}
        backups = meta.get("backups", [])
        if not backups:
            messagebox.showinfo(APP_TITLE, "还没有备份。")
            return
        win = tk.Toplevel(self.master)
        win.title("选择要恢复的备份")
        win.geometry("620x360")
        win.transient(self._hosts_win or self.master)
        win.grab_set()
        ttk.Label(win, text=f"备份目录：{meta.get('backup_dir', '')}",
                  padding=8).pack(anchor="w")
        lb = tk.Listbox(win, font=("Consolas", 9), exportselection=False)
        lb.pack(fill="both", expand=True, padx=8)
        for b in backups:
            lb.insert("end", b)
        lb.selection_set(0)

        def do_restore() -> None:
            sel = lb.curselection()
            if not sel:
                return
            path = lb.get(sel[0])
            if messagebox.askyesno(
                APP_TITLE,
                f"用这个备份覆盖当前的 hosts 文件？\n\n{path}\n\n"
                "当前文件会先被备份，所以这一步本身也可以撤销。",
            ):
                self.send_command({"cmd": "hosts_restore", "path": path})
                win.destroy()

        btns = ttk.Frame(win, padding=8)
        btns.pack(fill="x")
        ttk.Button(btns, text="恢复", command=do_restore, width=10).pack(side="right")
        ttk.Button(btns, text="取消", command=win.destroy, width=10).pack(side="right", padx=6)
        lb.bind("<Double-1>", lambda _e: do_restore())

    def on_hosts_prune(self) -> None:
        """Delete old backups. Never happens on its own."""
        backups = (self.hosts_meta or {}).get("backups", [])
        keep = 50
        if len(backups) <= keep:
            messagebox.showinfo(
                APP_TITLE, f"当前有 {len(backups)} 个备份，未超过 {keep} 个，无需清理。")
            return
        if messagebox.askyesno(
            APP_TITLE,
            f"删除较旧的备份，只保留最新 {keep} 个？\n\n"
            f"当前共 {len(backups)} 个，将删除 {len(backups) - keep} 个。\n\n"
            "这一步会真正删除文件，且无法撤销。",
        ):
            self.send_command({"cmd": "hosts_prune_backups", "keep": keep})

    def on_hosts_save(self) -> None:
        edit = getattr(self, "_hosts_edit", None)
        if edit is None or not edit.winfo_exists():
            return
        text = edit.get("1.0", "end-1c")
        if not messagebox.askyesno(
            APP_TITLE,
            "保存对 hosts 文件的修改？\n\n"
            "整个文件会被替换为你编辑后的内容，保存前会自动备份。",
        ):
            return
        self.send_command({"cmd": "hosts_edit", "text": text})

    def on_logs(self) -> None:
        if self._logs_win is not None and self._logs_win.winfo_exists():
            self._logs_win.lift()
            return
        win = tk.Toplevel(self.master)
        win.title("NetMonitor — 诊断日志")
        win.geometry("900x420")
        win.transient(self.master)
        txt = tk.Text(win, wrap="word", font=("Consolas", 10))
        sb = ttk.Scrollbar(win, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        txt.insert("1.0", "\n".join(self.log_lines))
        txt.see("end")
        txt.configure(state="disabled")
        self._logs_win = win

        def _refresh() -> None:
            if not win.winfo_exists():
                return
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            txt.insert("1.0", "\n".join(self.log_lines))
            txt.see("end")
            txt.configure(state="disabled")
            win.after(1000, _refresh)

        win.after(1000, _refresh)

    def on_stats(self) -> None:
        if self._stats_win is not None and self._stats_win.winfo_exists():
            self._stats_win.lift()
            return
        win = tk.Toplevel(self.master)
        win.title("NetMonitor — 统计")
        win.geometry("720x560")
        win.transient(self.master)
        tree = ttk.Treeview(win, columns=("k", "v"), show="headings")
        tree.heading("k", text="项目")
        tree.heading("v", text="数值")
        tree.column("k", width=260, anchor="w")
        tree.column("v", width=420, anchor="w")
        sb = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._stats_win = win

        def _refresh() -> None:
            if not win.winfo_exists():
                return
            for item in tree.get_children():
                tree.delete(item)
            s = self.status
            rows = [
                ("监控状态", "运行中" if s.running else "已停止"),
                ("运行时长", f"{s.uptime_s:.1f} 秒"),
                ("记录总数", s.records),
                ("DNS 查询数", s.queries),
                ("SNI 观测数", s.sni),
                ("唯一域名数", s.domains),
                ("涉及进程数", s.processes),
                ("进程树成员数", s.tree_members),
                ("被过滤的其它进程事件", s.filtered),
                ("平均速率", f"{s.rate:.2f} 条/秒"),
                ("本程序 CPU", f"{s.cpu:.2f} %"),
                ("内核丢包", s.drops_kernel),
                ("队列丢包", s.drops_queue),
            ]
            for k, v in rows:
                tree.insert("", "end", values=(k, v))

            counts: dict[str, int] = {}
            for r in self.records:
                counts[r.get("domain", "")] = counts.get(r.get("domain", ""), 0) + 1
            top = sorted(counts.items(), key=lambda kv: -kv[1])[:20]
            tree.insert("", "end", values=("—— 出现最多的域名 ——", ""))
            for d, c in top:
                tree.insert("", "end", values=(f"{c:>6}   {d}", ""))

            procs: dict[str, int] = {}
            for r in self.records:
                key = f"{r.get('process')} ({r.get('pid')})"
                procs[key] = procs.get(key, 0) + 1
            tree.insert("", "end", values=("—— 记录最多的进程 ——", ""))
            for p, c in sorted(procs.items(), key=lambda kv: -kv[1])[:15]:
                tree.insert("", "end", values=(f"{c:>6}   {p}", ""))

            win.after(1000, _refresh)

        _refresh()

    def _offer_elevation(self) -> None:
        """Relaunch with an elevated token. Only reached when the user asks.

        注意：提权重启会结束当前会话（引擎会一并停掉，它的残留 ETW 会话会在
        下次启动时自动清理）。
        """
        self._elevate_offered = True
        if messagebox.askyesno(
            APP_TITLE,
            "以管理员身份重新启动 NetMonitor？\n\n"
            "当前会话会被结束，重启后需要重新开始监控。",
        ):
            if relaunch_as_admin():
                self.on_close()
            else:
                messagebox.showwarning(APP_TITLE, "提权被取消，程序继续以当前权限运行。")
                self.btn_elevate.pack_forget()

    def on_close(self) -> None:
        try:
            self.on_close_domains()
            self.on_close_hosts()
            if self.engine is not None:
                self.engine.stop()
        finally:
            self.master.destroy()


def parse_cli(argv: list[str]) -> dict[str, Any]:
    """极简参数解析：--app / --args / --attach / --auto。

    有这个是因为从快捷方式或命令行直接带目标启动比"先开界面再点浏览"方便得多。
    `--args` 会取走其后**全部**参数，所以要放在最后。
    """
    out: dict[str, Any] = {"app": None, "args": "", "attach": None, "auto": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--app" and i + 1 < len(argv):
            out["app"] = argv[i + 1]; i += 2
        elif a == "--args":
            # 吞掉后面所有内容：用户很自然地会写
            #   --args --fork 3 example.com github.com
            # 只取一个 token 会把后面的目标域名全丢掉。
            out["args"] = " ".join(argv[i + 1:])
            break
        elif a == "--attach" and i + 1 < len(argv):
            out["attach"] = argv[i + 1]; i += 2
        elif a == "--auto":
            out["auto"] = True; i += 1
        else:
            i += 1
    return out


def wpcap_available() -> bool:
    """Whether Npcap's wpcap.dll can be loaded.

    netmon.exe links against it at load time, so without it the engine cannot
    start at all -- this is a prerequisite, not an optional feature.
    """
    try:
        ctypes.WinDLL("wpcap.dll")
        return True
    except OSError:
        return False


def bundled_npcap_installer() -> Optional[Path]:
    """The Npcap installer shipped inside a one-file build, if there is one."""
    roots = [frozen_bundle_dir(), app_dir() / "deps", app_dir() / "tools"]
    for root in roots:
        if root is None:
            continue
        found = sorted(root.glob("npcap-*.exe"))
        if found:
            return found[0]
    return None


def install_npcap(installer: Path) -> bool:
    """Run the bundled installer elevated and wait for it. Returns success."""
    script = (
        f"$p = Start-Process -FilePath '{installer}' "
        "-ArgumentList '/S','/winpcap_mode=yes','/loopback_support=yes' "
        "-Verb RunAs -Wait -PassThru; exit $p.ExitCode"
    )
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script],
            timeout=300, check=False,
        )
    except Exception:
        return False
    return wpcap_available()


def ensure_npcap(root: tk.Tk) -> bool:
    """Explain and, when possible, install the missing driver."""
    if wpcap_available():
        return True
    installer = bundled_npcap_installer()
    if installer is not None and messagebox.askyesno(
        APP_TITLE,
        "NetMonitor 的抓包引擎需要 Npcap 驱动，但这台机器上还没有安装。\n\n"
        "发布包里已经带了安装程序，现在安装吗？（需要管理员权限，"
        "安装的是 Npcap 官方的网络驱动）\n\n"
        "选择「否」仍然可以打开界面，但开始监控会失败。",
    ):
        root.withdraw()
        ok = install_npcap(installer)
        root.deiconify()
        if ok:
            messagebox.showinfo(APP_TITLE, "Npcap 已安装，可以开始监控了。")
            return True
        messagebox.showwarning(
            APP_TITLE,
            "Npcap 没有安装成功。\n\n"
            "可以手动运行发布包里的 install-npcap.cmd，或从 https://npcap.com 下载安装。")
        return False
    if installer is None:
        messagebox.showwarning(
            APP_TITLE,
            "找不到 Npcap（wpcap.dll），抓包引擎无法启动。\n\n"
            "请先安装 Npcap：https://npcap.com\n"
            "图形界面仍会打开，但开始监控会失败。")
    return False


def run_selftest(out: Path) -> int:
    """Headless check used by the packaging script to verify a one-file build."""
    engine = find_engine()
    info = {
        "frozen": bool(getattr(sys, "frozen", False)),
        "executable": sys.executable,
        "bundle": str(frozen_bundle_dir() or ""),
        "engine": str(engine) if engine else None,
        "engine_exists": bool(engine and engine.is_file()),
        "wpcap": wpcap_available(),
        "npcap_installer": (lambda p: str(p) if p else None)(bundled_npcap_installer()),
        "tk": tk.TkVersion,
        "python": sys.version,
    }
    out.write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if info["engine_exists"] else 2


def prepare_frozen_dirs() -> None:
    """One-file builds: keep runtime data next to the exe, not in the temp dir.

    The engine's defaults are relative to its own executable, and in a one-file
    build that is a temporary extraction folder that disappears on exit. Setting
    these explicitly is what makes the records and hosts backups survive a
    restart. If the exe sits somewhere read-only, fall back to LocalAppData.
    """
    if not getattr(sys, "frozen", False):
        return
    root = app_dir()
    try:
        (root / "netmon-data").mkdir(exist_ok=True)
        probe = root / ".netmon-write-test"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except OSError:
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "NetMonitor"
        root.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("NETMON_DATA_DIR", str(root / "netmon-data"))
    os.environ.setdefault("NETMON_HOSTS_BACKUP_DIR", str(root / "hosts-backups"))


def main() -> int:
    argv = sys.argv[1:]
    if "--selftest" in argv:
        i = argv.index("--selftest")
        out = Path(argv[i + 1]) if i + 1 < len(argv) else Path("netmon-selftest.json")
        return run_selftest(out)
    prepare_frozen_dirs()
    opts = parse_cli(argv)
    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("1280x760")
    root.minsize(900, 520)
    try:
        # 高 DPI 下文字不糊
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    # Npcap is a hard prerequisite for the engine, so say so before the window
    # is shown -- and install the copy the one-file build carries, if the user
    # agrees.
    ensure_npcap(root)
    app = App(root)
    if opts["app"]:
        app._add_target(opts["app"])
    if opts["attach"]:
        app._add_watch_names(opts["attach"])
    if opts["args"]:
        app.var_args.set(opts["args"])
    if opts["auto"]:
        # 稍等窗口画完再自动开始，否则提权对话框会挡在前面
        root.after(600, app.on_start)
    root.mainloop()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        # A windowed build has no console: without this, a startup failure is
        # a window that never appears and nothing to read. Leave the traceback
        # somewhere findable and say where it is.
        import traceback

        text = traceback.format_exc()
        log = None
        for candidate in (Path(os.environ.get("TEMP", ".")), app_dir()):
            try:
                log = candidate / "NetMonitor-crash.log"
                log.write_text(text, encoding="utf-8")
                break
            except OSError:
                continue
        try:
            ctypes.windll.user32.MessageBoxW(
                None,
                f"NetMonitor 启动失败：\n\n{text[-1200:]}\n\n日志：{log}",
                APP_TITLE, 0x10)
        except Exception:
            pass
        raise
