"""
CodeAlpha Internship — Task 4: Network Intrusion Detection System
Name       : Saad Ali
Student-ID : CA/DF1/41152
Tool    : Snort (log reader) + Tkinter
Purpose : Monitor Snort alert logs, visualize intrusions, and respond to threats
"""

import os
import re
import time
import threading
import datetime
import subprocess
import platform
from collections import defaultdict, deque
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import math

# ══════════════════════════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════════════════════════

BG        = "#090C10"
PANEL     = "#0D1117"
PANEL2    = "#161B22"
BORDER    = "#21262D"
ACCENT    = "#FF4C4C"       # Red — threat color
ACCENT2   = "#00BFFF"       # Blue — info
ACCENT3   = "#00FF9C"       # Green — OK
WARNING   = "#FFB700"
TEXT      = "#E6EDF3"
SUBTEXT   = "#7D8590"
FONT_MONO = ("Consolas", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_H1   = ("Segoe UI Semibold", 14)
FONT_H2   = ("Segoe UI Semibold", 10)
FONT_STAT = ("Segoe UI Semibold", 24)

SEV_COLORS = {
    "HIGH":   "#FF4C4C",
    "MEDIUM": "#FFB700",
    "LOW":    "#00BFFF",
    "INFO":   "#7D8590",
}

# Map common Snort SID ranges / keywords → severity
SEVERITY_MAP = [
    (r"EXPLOIT|ATTACK|BACKDOOR|SHELLCODE|OVERFLOW|INJECTION|RCE",  "HIGH"),
    (r"SCAN|PROBE|RECON|BRUTE|FLOOD|DOS|DDOS|SPOOF",               "MEDIUM"),
    (r"POLICY|BLACKLIST|MALWARE|VIRUS|TROJAN|WORM",                "HIGH"),
    (r"INFO|SNMP|FTP|TELNET|CHAT|P2P|GAME",                       "LOW"),
]

# ══════════════════════════════════════════════════════════════════════════════
#  SNORT LOG PARSER
# ══════════════════════════════════════════════════════════════════════════════

# Snort fast-alert format:
#   MM/DD-HH:MM:SS.uuuuuu  [**] [<gid>:<sid>:<rev>] Message [**] [Priority: N] {PROTO} src -> dst
FAST_RE = re.compile(
    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s*(.+?)\]\s+)?"
    r"\[Priority:\s*(\d+)\]\s+"
    r"\{(\w+)\}\s+"
    r"([\d\.\:a-fA-F]+)\s+->\s+([\d\.\:a-fA-F]+)"
)

# Snort full (unified) alert — simplified pattern for alternate log styles
FULL_RE = re.compile(
    r"\[Priority:\s*(\d)\].*?\{(\w+)\}\s+([\d\.]+)(?::(\d+))?\s+->\s+([\d\.]+)(?::(\d+))?"
)

SAMPLE_ALERTS = [
    '01/15-14:23:01.000001 [**] [1:1000001:1] ET SCAN Nmap TCP Scan [**] [Classification: Attempted Recon] [Priority: 2] {TCP} 192.168.1.50:54321 -> 10.0.0.1:80',
    '01/15-14:23:02.000002 [**] [1:2001219:20] ET EXPLOIT Buffer Overflow Attempt [**] [Classification: Attempted Admin] [Priority: 1] {TCP} 203.0.113.5:1337 -> 10.0.0.5:445',
    '01/15-14:23:03.000003 [**] [1:2002910:6] ET MALWARE Trojan Detected [**] [Classification: Malware] [Priority: 1] {TCP} 198.51.100.22:80 -> 10.0.0.12:49152',
    '01/15-14:23:04.000004 [**] [1:2100366:8] ET POLICY FTP Login Attempt [**] [Classification: Policy Violation] [Priority: 3] {TCP} 10.0.0.15:21 -> 192.168.5.10:51234',
    '01/15-14:23:05.000005 [**] [1:2001569:13] ET SCAN SSH Brute Force [**] [Classification: Attempted Recon] [Priority: 2] {TCP} 185.220.101.10:44444 -> 10.0.0.1:22',
    '01/15-14:23:06.000006 [**] [1:2009358:4] ET DOS ICMP Flood [**] [Classification: Denial of Service Attack] [Priority: 2] {ICMP} 203.0.113.99:0 -> 10.0.0.1:0',
    '01/15-14:23:07.000007 [**] [1:2014726:6] ET EXPLOIT SQL Injection Attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 91.108.4.11:54100 -> 10.0.0.8:80',
    '01/15-14:23:08.000008 [**] [1:2101411:15] ET SHELLCODE x86 NOP Sled Detected [**] [Classification: Shellcode Detect] [Priority: 1] {UDP} 185.220.101.5:53 -> 10.0.0.3:53',
]


def classify_severity(msg: str, priority: str) -> str:
    msg_up = msg.upper()
    for pattern, sev in SEVERITY_MAP:
        if re.search(pattern, msg_up):
            return sev
    p = int(priority) if priority.isdigit() else 3
    return "HIGH" if p == 1 else "MEDIUM" if p == 2 else "LOW"


def parse_alert_line(line: str) -> dict | None:
    m = FAST_RE.search(line)
    if not m:
        return None
    ts, sid_str, msg, classification, priority, proto, src, dst = m.groups()
    sev = classify_severity(msg, priority)
    return {
        "time":           ts,
        "sid":            sid_str,
        "message":        msg.strip(),
        "classification": classification or "—",
        "priority":       priority,
        "severity":       sev,
        "proto":          proto,
        "src":            src,
        "dst":            dst,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  LOG TAIL MONITOR
# ══════════════════════════════════════════════════════════════════════════════

class LogMonitor:
    """Tails a Snort alert file in a background thread."""

    def __init__(self, path: str, callback):
        self._path     = path
        self._callback = callback
        self._stop     = threading.Event()
        self._thread   = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        try:
            with open(self._path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)   # go to EOF
                while not self._stop.is_set():
                    line = f.readline()
                    if line:
                        parsed = parse_alert_line(line)
                        if parsed:
                            self._callback(parsed)
                    else:
                        time.sleep(0.2)
        except FileNotFoundError:
            self._callback({"_error": f"Log file not found: {self._path}"})
        except Exception as e:
            self._callback({"_error": str(e)})


# ══════════════════════════════════════════════════════════════════════════════
#  MINI CANVAS CHARTS
# ══════════════════════════════════════════════════════════════════════════════

class SparklineCanvas(tk.Canvas):
    """Simple live sparkline for event rate over time."""

    HISTORY = 60  # data points

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=PANEL2, highlightthickness=0,
                         height=60, **kw)
        self._data = deque([0] * self.HISTORY, maxlen=self.HISTORY)
        self.bind("<Configure>", lambda _: self._draw())

    def push(self, value: float):
        self._data.append(value)
        self._draw()

    def _draw(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 2 or h < 2:
            return
        self.delete("all")
        self.create_rectangle(0, 0, w, h, fill=PANEL2, outline="")

        mx = max(self._data) or 1
        pts = []
        step = w / max(len(self._data) - 1, 1)
        for i, v in enumerate(self._data):
            x = i * step
            y = h - (v / mx) * (h - 6) - 3
            pts.append((x, y))

        if len(pts) >= 2:
            flat = [c for pt in pts for c in pt]
            self.create_line(*flat, fill=ACCENT, width=2, smooth=True)
            # fill under
            poly = [0, h] + flat + [w, h]
            self.create_polygon(*poly, fill=ACCENT, stipple="gray25", outline="")

        self.create_text(4, 4, text=f"max {int(mx)}/min",
                         fill=SUBTEXT, font=("Segoe UI", 7), anchor="nw")


class PieCanvas(tk.Canvas):
    """Mini donut chart for severity breakdown."""

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=PANEL2, highlightthickness=0,
                         width=160, height=160, **kw)
        self._counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    def update_counts(self, counts: dict):
        self._counts.update(counts)
        self._draw()

    def _draw(self):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 10 or h < 10:
            self.after(100, self._draw)
            return
        self.delete("all")
        self.create_rectangle(0, 0, w, h, fill=PANEL2, outline="")

        total = sum(self._counts.values()) or 1
        colors = [SEV_COLORS[k] for k in ("HIGH", "MEDIUM", "LOW", "INFO")]
        keys   = list(self._counts.keys())
        cx, cy = w / 2, h / 2
        r_outer, r_inner = min(cx, cy) - 8, min(cx, cy) - 28
        angle = -90.0

        for k, color in zip(keys, colors):
            sweep = (self._counts[k] / total) * 360
            if sweep > 0.5:
                self.create_arc(
                    cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer,
                    start=angle, extent=sweep,
                    fill=color, outline=PANEL2, width=2, style="pieslice"
                )
            angle += sweep

        # inner circle (donut hole)
        self.create_oval(cx - r_inner, cy - r_inner,
                         cx + r_inner, cy + r_inner,
                         fill=PANEL2, outline="")
        self.create_text(cx, cy - 8, text=str(sum(self._counts.values())),
                         fill=TEXT, font=("Segoe UI Semibold", 14))
        self.create_text(cx, cy + 8, text="Alerts",
                         fill=SUBTEXT, font=("Segoe UI", 8))


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class NIDSApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("SentinelWatch — Snort NIDS Dashboard  |  CodeAlpha Task 4")
        self.geometry("1380x860")
        self.minsize(1100, 700)
        self.configure(bg=BG)

        # State
        self._alerts        = []
        self._running       = False
        self._monitor       = None
        self._queue         = []
        self._queue_lock    = threading.Lock()
        self._stats         = defaultdict(int)
        self._rate_window   = deque(maxlen=60)
        self._top_src       = defaultdict(int)
        self._top_sig       = defaultdict(int)
        self._sample_idx    = 0

        self._build_ui()
        self._poll_queue()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_titlebar()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()

    def _build_titlebar(self):
        bar = tk.Frame(self, bg=PANEL, height=58)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        # Blinking threat indicator
        self._threat_light = tk.Label(bar, text="■", font=("Segoe UI", 18),
                                      bg=PANEL, fg=ACCENT3)
        self._threat_light.pack(side="left", padx=(16, 8), pady=12)

        tk.Label(bar, text="SentinelWatch",
                 font=("Segoe UI Semibold", 17), bg=PANEL, fg=ACCENT
                 ).pack(side="left", pady=14)
        tk.Label(bar, text="  —  Snort Intrusion Detection Monitor",
                 font=("Segoe UI", 10), bg=PANEL, fg=SUBTEXT
                 ).pack(side="left", pady=18)

        badge = tk.Label(bar, text="  CodeAlpha — Task 4  ",
                         font=("Segoe UI", 9), bg=ACCENT, fg=TEXT, padx=6)
        badge.pack(side="right", padx=16, pady=16)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _build_toolbar(self):
        tb = tk.Frame(self, bg=PANEL, pady=10)
        tb.pack(fill="x")

        # Log file path
        tk.Label(tb, text="Alert Log:", bg=PANEL, fg=SUBTEXT,
                 font=FONT_UI).pack(side="left", padx=(16, 4))
        self._log_var = tk.StringVar(value="/var/log/snort/alert")
        log_entry = tk.Entry(
            tb, textvariable=self._log_var, width=38,
            bg=BG, fg=TEXT, insertbackground=TEXT,
            relief="flat", font=FONT_MONO,
            highlightthickness=1, highlightcolor=ACCENT,
            highlightbackground=BORDER
        )
        log_entry.pack(side="left", padx=(0, 4))

        tk.Button(tb, text="Browse", command=self._browse,
                  bg=BORDER, fg=TEXT, activebackground=PANEL2,
                  relief="flat", font=FONT_UI, padx=8, cursor="hand2"
                  ).pack(side="left", padx=(0, 16))

        # Severity filter
        tk.Label(tb, text="Show:", bg=PANEL, fg=SUBTEXT,
                 font=FONT_UI).pack(side="left", padx=(0, 4))
        self._sev_var = tk.StringVar(value="ALL")
        sev_combo = ttk.Combobox(
            tb, textvariable=self._sev_var, state="readonly", width=10,
            values=["ALL", "HIGH", "MEDIUM", "LOW", "INFO"]
        )
        sev_combo.pack(side="left", padx=(0, 16))
        sev_combo.bind("<<ComboboxSelected>>", lambda _: self._apply_filter())

        # Search
        tk.Label(tb, text="Search:", bg=PANEL, fg=SUBTEXT,
                 font=FONT_UI).pack(side="left", padx=(0, 4))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._apply_filter())
        tk.Entry(
            tb, textvariable=self._search_var, width=20,
            bg=BG, fg=TEXT, insertbackground=TEXT,
            relief="flat", font=FONT_MONO,
            highlightthickness=1, highlightcolor=ACCENT2,
            highlightbackground=BORDER
        ).pack(side="left", padx=(0, 24))

        # Buttons
        self._btn_start  = self._btn(tb, "▶  Monitor Log",    ACCENT,   BG,   self._start)
        self._btn_stop   = self._btn(tb, "■  Stop",            "#444",   TEXT, self._stop, "disabled")
        self._btn_demo   = self._btn(tb, "⚡ Inject Demo",     WARNING,  BG,   self._demo_tick)
        self._btn_clear  = self._btn(tb, "✕  Clear",           BORDER,   TEXT, self._clear)
        self._btn_export = self._btn(tb, "⬇  Export",          ACCENT2,  BG,   self._export)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _btn(self, parent, text, bg, fg, cmd, state="normal"):
        b = tk.Button(
            parent, text=text, command=cmd, state=state,
            bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
            relief="flat", font=("Segoe UI Semibold", 9),
            padx=14, pady=5, cursor="hand2", bd=0
        )
        b.pack(side="left", padx=4)
        return b

    def _build_body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=12, pady=(8, 0))

        # Left: stats + charts
        left = tk.Frame(body, bg=BG, width=230)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.pack_propagate(False)
        self._build_left_panel(left)

        # Right: table + detail
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        self._build_right_panel(right)

    def _build_left_panel(self, parent):
        # Stat cards
        cards = [
            ("Total Alerts",  "_s_total",  TEXT),
            ("HIGH",          "_s_high",   SEV_COLORS["HIGH"]),
            ("MEDIUM",        "_s_medium", SEV_COLORS["MEDIUM"]),
            ("LOW",           "_s_low",    SEV_COLORS["LOW"]),
        ]
        for label, attr, color in cards:
            card = tk.Frame(parent, bg=PANEL2, pady=8)
            card.pack(fill="x", pady=3)
            var = tk.StringVar(value="0")
            setattr(self, attr, var)
            tk.Label(card, textvariable=var, font=FONT_STAT,
                     bg=PANEL2, fg=color).pack()
            tk.Label(card, text=label, font=("Segoe UI", 8),
                     bg=PANEL2, fg=SUBTEXT).pack()

        # Donut chart
        tk.Label(parent, text="SEVERITY BREAKDOWN", bg=BG, fg=SUBTEXT,
                 font=FONT_H2).pack(anchor="w", pady=(12, 4))
        self._pie = PieCanvas(parent)
        self._pie.pack(fill="x")

        # Sparkline
        tk.Label(parent, text="ALERT RATE / MIN", bg=BG, fg=SUBTEXT,
                 font=FONT_H2).pack(anchor="w", pady=(12, 4))
        self._spark = SparklineCanvas(parent)
        self._spark.pack(fill="x")

        # Top sources
        tk.Label(parent, text="TOP SOURCES", bg=BG, fg=SUBTEXT,
                 font=FONT_H2).pack(anchor="w", pady=(12, 4))
        self._top_src_text = tk.Text(
            parent, bg=PANEL2, fg=ACCENT2, font=("Consolas", 9),
            relief="flat", height=6, state="disabled", wrap="none"
        )
        self._top_src_text.pack(fill="x")

        # Response actions
        tk.Label(parent, text="RESPONSE", bg=BG, fg=SUBTEXT,
                 font=FONT_H2).pack(anchor="w", pady=(12, 4))

        for label, cmd in [
            ("Block Source IP",  self._block_ip),
            ("Generate Report",  self._gen_report),
        ]:
            tk.Button(
                parent, text=label, command=cmd,
                bg=PANEL2, fg=WARNING, activebackground=BORDER,
                relief="flat", font=("Segoe UI", 9), pady=6,
                cursor="hand2", anchor="w", padx=10
            ).pack(fill="x", pady=2)

    def _build_right_panel(self, parent):
        paned = tk.PanedWindow(parent, orient="vertical", bg=BG,
                               sashwidth=4, sashrelief="flat")
        paned.pack(fill="both", expand=True)

        # ── Alert Table ───────────────────────────────────────────────────
        top = tk.Frame(paned, bg=BG)
        paned.add(top, height=430)

        hdr = tk.Frame(top, bg=BG)
        hdr.pack(fill="x", pady=(4, 4))
        tk.Label(hdr, text="INTRUSION ALERTS", font=FONT_H2,
                 bg=BG, fg=SUBTEXT).pack(side="left")
        self._alert_count_var = tk.StringVar(value="0 events")
        tk.Label(hdr, textvariable=self._alert_count_var,
                 bg=BG, fg=ACCENT, font=FONT_H2).pack(side="right")

        cols = ("#", "Time", "Severity", "Protocol",
                "Source", "Destination", "SID", "Message", "Classification")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("NIDS.Treeview",
            background=PANEL, foreground=TEXT, fieldbackground=PANEL,
            borderwidth=0, rowheight=28, font=FONT_MONO)
        style.configure("NIDS.Treeview.Heading",
            background=BORDER, foreground=SUBTEXT,
            borderwidth=0, relief="flat", font=("Segoe UI Semibold", 9))
        style.map("NIDS.Treeview",
            background=[("selected", BORDER)],
            foreground=[("selected", ACCENT)])

        frame_tv = tk.Frame(top, bg=PANEL)
        frame_tv.pack(fill="both", expand=True)

        vsb = tk.Scrollbar(frame_tv, orient="vertical",   bg=BORDER, troughcolor=BG, bd=0, width=10)
        hsb = tk.Scrollbar(frame_tv, orient="horizontal", bg=BORDER, troughcolor=BG, bd=0, width=10)

        self._tree = ttk.Treeview(
            frame_tv, columns=cols, show="headings",
            style="NIDS.Treeview",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set
        )

        col_w = [45, 100, 75, 70, 145, 145, 100, 320, 180]
        for col, w in zip(cols, col_w):
            self._tree.heading(col, text=col, command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=w, minwidth=40, anchor="w")

        vsb.config(command=self._tree.yview)
        hsb.config(command=self._tree.xview)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Tags per severity
        for sev, color in SEV_COLORS.items():
            self._tree.tag_configure(sev, foreground=color)
        self._tree.tag_configure("HIGH_BG", background="#1A0808")

        # ── Detail & Log Panel ─────────────────────────────────────────────
        bot = tk.Frame(paned, bg=BG)
        paned.add(bot, height=200)

        nb = ttk.Notebook(bot)
        nb.pack(fill="both", expand=True, pady=(6, 0))

        detail_frame = tk.Frame(nb, bg=PANEL)
        nb.add(detail_frame, text="  Alert Detail  ")
        self._detail = scrolledtext.ScrolledText(
            detail_frame, bg=PANEL, fg=ACCENT, insertbackground=ACCENT,
            font=FONT_MONO, relief="flat", wrap="word", state="disabled"
        )
        self._detail.pack(fill="both", expand=True)

        log_frame = tk.Frame(nb, bg=PANEL)
        nb.add(log_frame, text="  Event Log  ")
        self._event_log = scrolledtext.ScrolledText(
            log_frame, bg=PANEL, fg=TEXT,
            font=FONT_MONO, relief="flat", wrap="word", state="disabled"
        )
        self._event_log.pack(fill="both", expand=True)

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=PANEL, height=28)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._status_var = tk.StringVar(value="Ready — load a Snort alert log or inject demo events")
        self._status_lbl = tk.Label(
            bar, textvariable=self._status_var,
            bg=PANEL, fg=SUBTEXT, font=("Segoe UI", 9), anchor="w"
        )
        self._status_lbl.pack(side="left", padx=12, fill="y")

        self._run_dot = tk.Label(bar, text="●", bg=PANEL, fg=SUBTEXT, font=("Segoe UI", 10))
        self._run_dot.pack(side="right", padx=12)

        tk.Label(bar, text="Snort  |  CodeAlpha Cybersecurity Internship",
                 bg=PANEL, fg=SUBTEXT, font=("Segoe UI", 9)
                 ).pack(side="right", padx=16)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select Snort Alert Log",
            filetypes=[("Alert files", "alert*"), ("All", "*.*")]
        )
        if path:
            self._log_var.set(path)

    def _start(self):
        path = self._log_var.get().strip()
        self._running = True
        self._btn_start.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._status(f"Monitoring: {path}", ACCENT3)
        self._blink()

        self._monitor = LogMonitor(path, self._enqueue)
        self._monitor.start()
        self._log_event("system", f"Started monitoring: {path}")

    def _stop(self):
        if self._monitor:
            self._monitor.stop()
        self._running = False
        self._btn_start.config(state="normal")
        self._btn_stop.config(state="disabled")
        self._run_dot.config(fg=SUBTEXT)
        self._status("Monitoring stopped.", SUBTEXT)
        self._log_event("system", "Monitoring stopped.")

    def _demo_tick(self):
        """Inject the next demo alert (cycle through samples)."""
        line = SAMPLE_ALERTS[self._sample_idx % len(SAMPLE_ALERTS)]
        self._sample_idx += 1
        parsed = parse_alert_line(line)
        if parsed:
            self._enqueue(parsed)
            self._status(f"Demo alert injected: {parsed['message'][:60]}", WARNING)

    def _clear(self):
        self._stop()
        self._alerts.clear()
        self._stats.clear()
        self._top_src.clear()
        self._top_sig.clear()
        self._tree.delete(*self._tree.get_children())
        self._detail_write("")
        self._update_stats()
        self._top_src_refresh()
        self._status("Cleared.", SUBTEXT)

    def _export(self):
        if not self._alerts:
            messagebox.showinfo("Export", "No alerts to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Text", "*.txt"), ("All", "*.*")],
            title="Export Alerts"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            headers = ["#","Time","Severity","Protocol","Source","Destination",
                       "SID","Message","Classification","Priority"]
            f.write(",".join(headers) + "\n")
            for i, a in enumerate(self._alerts, 1):
                row = [str(i), a["time"], a["severity"], a["proto"],
                       a["src"], a["dst"], a["sid"], a["message"],
                       a["classification"], a["priority"]]
                f.write(",".join(f'"{v}"' for v in row) + "\n")
        self._status(f"Exported → {path}", ACCENT3)

    def _block_ip(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Block IP", "Select an alert first.")
            return
        iid = sel[0]
        idx = int(self._tree.item(iid, "values")[0]) - 1
        if idx < 0 or idx >= len(self._alerts):
            return
        src = self._alerts[idx]["src"].split(":")[0]
        system = platform.system()
        if system == "Windows":
            cmd = f'netsh advfirewall firewall add rule name="NIDS_BLOCK_{src}" dir=in action=block remoteip={src}'
        else:
            cmd = f"sudo iptables -I INPUT -s {src} -j DROP"
        confirm = messagebox.askyesno(
            "Block IP",
            f"Block source IP: {src}?\n\nCommand:\n{cmd}\n\nProceed?"
        )
        if confirm:
            try:
                subprocess.run(cmd, shell=True, check=True)
                self._log_event("BLOCK", f"Blocked IP: {src}")
                self._status(f"Blocked: {src}", ACCENT)
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _gen_report(self):
        if not self._alerts:
            messagebox.showinfo("Report", "No alerts to report.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt")],
            title="Save Report"
        )
        if not path:
            return
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        high   = sum(1 for a in self._alerts if a["severity"] == "HIGH")
        medium = sum(1 for a in self._alerts if a["severity"] == "MEDIUM")
        low    = sum(1 for a in self._alerts if a["severity"] == "LOW")
        top_src = sorted(self._top_src.items(), key=lambda x: -x[1])[:5]
        top_sig = sorted(self._top_sig.items(), key=lambda x: -x[1])[:5]

        lines = [
            "=" * 70,
            "     SentinelWatch — Snort NIDS Incident Report",
            f"     Generated: {now}",
            "=" * 70,
            "",
            "SUMMARY",
            f"  Total Alerts : {len(self._alerts)}",
            f"  HIGH         : {high}",
            f"  MEDIUM       : {medium}",
            f"  LOW          : {low}",
            "",
            "TOP SOURCE IPs",
        ] + [f"  {ip:<20} {count} alerts" for ip, count in top_src] + [
            "",
            "TOP SIGNATURES",
        ] + [f"  {sig[:50]:<50} {count}x" for sig, count in top_sig] + [
            "",
            "ALL ALERTS",
            "-" * 70,
        ] + [
            f"[{a['severity']:<6}] {a['time']}  {a['proto']:<5} "
            f"{a['src']:<22} -> {a['dst']:<22}  {a['message']}"
            for a in self._alerts
        ] + ["", "=" * 70, "  End of Report", "=" * 70]

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self._status(f"Report saved → {path}", ACCENT3)

    # ── Queue & Rendering ─────────────────────────────────────────────────────

    def _enqueue(self, alert):
        with self._queue_lock:
            self._queue.append(alert)

    def _poll_queue(self):
        with self._queue_lock:
            batch, self._queue = self._queue, []

        for item in batch:
            if "_error" in item:
                self._status(item["_error"], ACCENT)
                self._log_event("ERROR", item["_error"])
            else:
                self._add_alert(item)

        self.after(100, self._poll_queue)

    def _add_alert(self, a):
        self._alerts.append(a)
        idx = len(self._alerts)

        sev = a["severity"]
        self._stats[sev]    += 1
        self._stats["total"] += 1
        self._top_src[a["src"].split(":")[0]] += 1
        self._top_sig[a["message"]] += 1

        tags = (sev,) + (("HIGH_BG",) if sev == "HIGH" else ())
        values = (
            idx, a["time"], sev, a["proto"],
            a["src"], a["dst"], a["sid"],
            a["message"], a["classification"]
        )
        self._tree.insert("", "end", values=values, tags=tags)
        self._tree.yview_moveto(1.0)

        self._update_stats()
        self._top_src_refresh()

        # Sparkline: count per minute bucket (approx)
        self._rate_window.append(1)
        self._spark.push(len([x for x in self._rate_window]))

        # Blink threat light on HIGH
        if sev == "HIGH":
            self._flash_threat()

        self._log_event(sev, f"{a['proto']} {a['src']} → {a['dst']} | {a['message']}")

    def _update_stats(self):
        self._s_total.set(str(self._stats.get("total", 0)))
        self._s_high.set(str(self._stats.get("HIGH", 0)))
        self._s_medium.set(str(self._stats.get("MEDIUM", 0)))
        self._s_low.set(str(self._stats.get("LOW", 0)))
        self._alert_count_var.set(f"{self._stats.get('total', 0)} events")
        self._pie.update_counts({
            "HIGH":   self._stats.get("HIGH", 0),
            "MEDIUM": self._stats.get("MEDIUM", 0),
            "LOW":    self._stats.get("LOW", 0),
            "INFO":   self._stats.get("INFO", 0),
        })

    def _top_src_refresh(self):
        top = sorted(self._top_src.items(), key=lambda x: -x[1])[:5]
        self._top_src_text.config(state="normal")
        self._top_src_text.delete("1.0", "end")
        for ip, cnt in top:
            bar_len = int((cnt / max(v for _, v in top)) * 12)
            bar = "█" * bar_len
            self._top_src_text.insert(
                "end", f"  {ip:<18} {cnt:>4}  {bar}\n"
            )
        self._top_src_text.config(state="disabled")

    def _on_select(self, _event):
        sel = self._tree.selection()
        if not sel:
            return
        idx = int(self._tree.item(sel[0], "values")[0]) - 1
        if idx < 0 or idx >= len(self._alerts):
            return
        a = self._alerts[idx]
        detail = (
            f"{'═'*62}\n"
            f"  INTRUSION ALERT #{idx+1}\n"
            f"{'═'*62}\n"
            f"  Severity       : {a['severity']}\n"
            f"  Time           : {a['time']}\n"
            f"  SID            : {a['sid']}\n"
            f"  Protocol       : {a['proto']}\n"
            f"  Source         : {a['src']}\n"
            f"  Destination    : {a['dst']}\n"
            f"  Priority       : {a['priority']}\n"
            f"  Classification : {a['classification']}\n"
            f"{'─'*62}\n"
            f"  Signature:\n    {a['message']}\n"
            f"{'─'*62}\n"
            f"  Recommended Action:\n"
            f"    {'🚨 Immediate investigation required — block source IP' if a['severity']=='HIGH' else '⚠ Review and monitor source activity' if a['severity']=='MEDIUM' else '  Log and monitor'}\n"
            f"{'═'*62}\n"
        )
        self._detail_write(detail)

    def _apply_filter(self):
        sev    = self._sev_var.get()
        term   = self._search_var.get().lower()
        for iid in self._tree.get_children():
            vals_list = self._tree.item(iid, "values")
            row_sev = vals_list[2] if len(vals_list) > 2 else ""
            row_txt = " ".join(str(v) for v in vals_list).lower()
            show = (sev == "ALL" or row_sev == sev) and (not term or term in row_txt)
            if show:
                try:
                    self._tree.reattach(iid, "", "end")
                except Exception:
                    pass
            else:
                self._tree.detach(iid)

    def _sort_by(self, col):
        pass  # sorting stub (extend as needed)

    def _detail_write(self, text):
        self._detail.config(state="normal")
        self._detail.delete("1.0", "end")
        self._detail.insert("end", text)
        self._detail.config(state="disabled")

    def _log_event(self, level: str, msg: str):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] [{level}] {msg}\n"
        self._event_log.config(state="normal")
        self._event_log.insert("end", entry)
        self._event_log.yview_moveto(1.0)
        self._event_log.config(state="disabled")

    def _status(self, msg, color=TEXT):
        self._status_var.set(msg)
        self._status_lbl.config(fg=color)

    def _blink(self):
        if not self._running:
            return
        cur = self._run_dot.cget("fg")
        self._run_dot.config(fg=ACCENT3 if cur != ACCENT3 else BG)
        self.after(700, self._blink)

    def _flash_threat(self):
        self._threat_light.config(fg=ACCENT)
        self.after(400, lambda: self._threat_light.config(fg=ACCENT3))


# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = NIDSApp()
    app.mainloop()