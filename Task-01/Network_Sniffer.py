"""
CodeAlpha Internship — Task 1: Basic Network Sniffer
Name       : Saad Ali
Student-ID : CA/DF1/41152
Tool       : Scapy + Tkinter
Purpose    : Capture & analyze live network packets with a professional GUI

"""

import threading
import time
import datetime
from collections import defaultdict

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

# ── Scapy ─────────────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether,
        get_if_list, conf, wrpcap
    )
    try:
        from scapy.arch.windows import get_windows_if_list
        _WIN_IFACES = {str(i["win_index"]): i["name"] for i in get_windows_if_list()}
    except Exception:
        _WIN_IFACES = {}
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    _WIN_IFACES = {}


# ══════════════════════════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════════════════════════
BG        = "#0D1117"
PANEL     = "#161B22"
BORDER    = "#21262D"
ACCENT    = "#00FF9C"
ACCENT2   = "#00BFFF"
WARNING   = "#FFB700"
DANGER    = "#FF4C4C"
TEXT      = "#E6EDF3"
SUBTEXT   = "#7D8590"
FONT_MONO = ("Consolas", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_H2   = ("Segoe UI Semibold", 11)
FONT_STAT = ("Segoe UI Semibold", 22)

PROTO_COLORS = {
    "TCP":   "#00BFFF",
    "UDP":   "#00FF9C",
    "ICMP":  "#FFB700",
    "ARP":   "#C678DD",
    "DNS":   "#E5C07B",
    "OTHER": "#7D8590",
}


# ══════════════════════════════════════════════════════════════════════════════
#  INTERFACE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _get_default_iface() -> str:
    if not SCAPY_AVAILABLE:
        return ""
    try:
        return str(conf.iface)
    except Exception:
        return ""


def _build_iface_map() -> dict:
    """Return {raw_scapy_name: display_label} for every interface."""
    if not SCAPY_AVAILABLE:
        return {}
    result = {}
    for iface in get_if_list():
        label = iface
        if _WIN_IFACES:
            for win_idx, friendly in _WIN_IFACES.items():
                if win_idx in iface or friendly.lower() in iface.lower():
                    label = f"{friendly}  [{iface[-8:]}]"
                    break
        result[iface] = label
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  PACKET ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class PacketEngine:
    """
    Wraps Scapy sniff() in a background daemon thread.

    Stop reliability fix:
        sniff() is called with timeout=1 inside a while-loop that checks
        _stop_event. The thread exits within ~1 second of stop() being called.
        Only ONE engine is created per capture session (previous code
        accidentally created two, leaving the first untracked and unstoppable).
    """

    def __init__(self, on_packet):
        self.on_packet   = on_packet
        self._stop_event = threading.Event()
        self._thread     = None
        self._raw_pkts   = []          # kept for .pcap export

    def start(self, iface, bpf_filter):
        self._stop_event.clear()
        self._raw_pkts.clear()
        self._thread = threading.Thread(
            target=self._run,
            args=(iface, bpf_filter),
            daemon=True,
            name="PacketCapture",
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def get_raw_packets(self):
        return list(self._raw_pkts)

    def _run(self, iface, bpf_filter):
        try:
            while not self._stop_event.is_set():
                sniff(
                    iface=iface,
                    filter=bpf_filter,
                    prn=self._process,
                    store=False,
                    timeout=1,
                )
        except Exception as exc:
            self.on_packet({"error": str(exc)})

    def _process(self, pkt):
        self._raw_pkts.append(pkt)

        info = {
            "time":    datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "proto":   "OTHER",
            "src":     "—",
            "dst":     "—",
            "sport":   "—",
            "dport":   "—",
            "length":  len(pkt),
            "payload": "",
            "flags":   "",
            "ttl":     "",
            "raw":     pkt.summary(),
        }

        if pkt.haslayer(IP):
            info["src"] = pkt[IP].src
            info["dst"] = pkt[IP].dst
            info["ttl"] = str(pkt[IP].ttl)

        if pkt.haslayer(ARP):
            info["proto"] = "ARP"
            info["src"]   = pkt[ARP].psrc
            info["dst"]   = pkt[ARP].pdst
        elif pkt.haslayer(TCP):
            info["proto"]  = "TCP"
            info["sport"]  = str(pkt[TCP].sport)
            info["dport"]  = str(pkt[TCP].dport)
            info["flags"]  = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            info["proto"] = "DNS" if pkt.haslayer(DNS) else "UDP"
            info["sport"] = str(pkt[UDP].sport)
            info["dport"] = str(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            info["proto"] = "ICMP"

        if pkt.haslayer(Raw):
            raw_bytes = pkt[Raw].load
            try:
                decoded   = raw_bytes.decode("utf-8", errors="strict")
                printable = sum(32 <= ord(c) < 127 for c in decoded)
                info["payload"] = (
                    decoded[:200]
                    if printable / max(len(decoded), 1) > 0.6
                    else raw_bytes[:100].hex()
                )
            except UnicodeDecodeError:
                info["payload"] = raw_bytes[:100].hex()

        self.on_packet(info)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class NetworkSnifferApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("NetScope — Network Packet Analyzer  |  CodeAlpha Task 1")
        self.geometry("1280x820")
        self.minsize(1000, 680)
        self.configure(bg=BG)

        self._packets    = []
        self._running    = False
        self._stats      = defaultdict(int)
        self._engine     = None
        self._queue      = []
        self._queue_lock = threading.Lock()
        self._start_time = 0.0

        self._iface_map  = _build_iface_map()           # raw → label
        self._label_map  = {v: k for k, v in self._iface_map.items()}  # label → raw

        self._apply_style()
        self._build_ui()
        self._poll_queue()

    # ── Style (applied before any widget is created) ──────────────────────────

    def _apply_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Dark Combobox
        style.configure("Dark.TCombobox",
            fieldbackground=BG, background=BORDER,
            foreground=TEXT, selectbackground=BORDER,
            selectforeground=ACCENT, arrowcolor=ACCENT,
            bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
            relief="flat", padding=(6, 4),
        )
        style.map("Dark.TCombobox",
            fieldbackground=[("readonly", BG), ("focus", BG)],
            background=[("active", BORDER), ("pressed", PANEL)],
            foreground=[("readonly", TEXT), ("focus", TEXT)],
            bordercolor=[("focus", ACCENT), ("!focus", BORDER)],
            arrowcolor=[("disabled", SUBTEXT), ("!disabled", ACCENT)],
        )
        # Dropdown listbox (plain tk widget inside ttk.Combobox)
        self.option_add("*TCombobox*Listbox.background",       PANEL)
        self.option_add("*TCombobox*Listbox.foreground",       TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", BORDER)
        self.option_add("*TCombobox*Listbox.selectForeground", ACCENT)
        self.option_add("*TCombobox*Listbox.font",             FONT_MONO)
        self.option_add("*TCombobox*Listbox.relief",           "flat")

        # Dark Treeview
        style.configure("Dark.Treeview",
            background=PANEL, foreground=TEXT, fieldbackground=PANEL,
            borderwidth=0, rowheight=26, font=FONT_MONO,
        )
        style.configure("Dark.Treeview.Heading",
            background=BORDER, foreground=SUBTEXT,
            borderwidth=0, relief="flat",
            font=("Segoe UI Semibold", 9),
        )
        style.map("Dark.Treeview",
            background=[("selected", BORDER)],
            foreground=[("selected", ACCENT)],
        )

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_titlebar()
        self._build_toolbar()
        self._build_stats_row()
        self._build_main_area()
        self._build_statusbar()

    def _build_titlebar(self):
        bar = tk.Frame(self, bg=PANEL, height=56)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        tk.Label(bar, text="NetScope",
                 font=("Segoe UI Semibold", 16), bg=PANEL, fg=ACCENT
                 ).pack(side="left", padx=20, pady=12)
        tk.Label(bar, text="Basic Network Packet Analyzer",
                 font=FONT_UI, bg=PANEL, fg=SUBTEXT
                 ).pack(side="left", pady=16)
        tk.Label(bar, text="  CodeAlpha — Task 1  ",
                 font=("Segoe UI", 9), bg=ACCENT, fg=BG, padx=6
                 ).pack(side="right", padx=16, pady=14)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _build_toolbar(self):
        tb = tk.Frame(self, bg=PANEL, pady=10)
        tb.pack(fill="x")

        # Interface
        tk.Label(tb, text="Interface:", bg=PANEL, fg=SUBTEXT,
                 font=FONT_UI).pack(side="left", padx=(16, 4))

        labels        = list(self._iface_map.values())
        default_raw   = _get_default_iface()
        default_label = self._iface_map.get(default_raw, labels[0] if labels else "")

        self._iface_var = tk.StringVar(value=default_label)
        self._iface_cb  = ttk.Combobox(
            tb, textvariable=self._iface_var, values=labels,
            width=30, state="readonly", style="Dark.TCombobox",
        )
        self._iface_cb.pack(side="left", padx=(0, 4))

        # "← active" hint next to the dropdown
        self._hint_lbl = tk.Label(tb, text="← active", bg=PANEL, fg=ACCENT,
                                  font=("Segoe UI", 8))
        self._hint_lbl.pack(side="left", padx=(0, 16))
        self._iface_var.trace_add("write", self._on_iface_change)

        # BPF filter
        tk.Label(tb, text="Filter (BPF):", bg=PANEL, fg=SUBTEXT,
                 font=FONT_UI).pack(side="left", padx=(0, 4))
        self._filter_var = tk.StringVar()
        tk.Entry(tb, textvariable=self._filter_var, width=18,
                 bg=BG, fg=TEXT, insertbackground=TEXT, relief="flat",
                 font=FONT_MONO, highlightthickness=1,
                 highlightcolor=ACCENT, highlightbackground=BORDER,
                 ).pack(side="left", padx=(0, 16))

        # Protocol filter
        tk.Label(tb, text="Protocol:", bg=PANEL, fg=SUBTEXT,
                 font=FONT_UI).pack(side="left", padx=(0, 4))
        self._proto_filter = tk.StringVar(value="ALL")
        ttk.Combobox(
            tb, textvariable=self._proto_filter,
            values=["ALL", "TCP", "UDP", "ICMP", "DNS", "ARP"],
            width=8, state="readonly", style="Dark.TCombobox",
        ).pack(side="left", padx=(0, 8))
        self._proto_filter.trace_add("write", lambda *_: self._apply_filters())

        # Search
        tk.Label(tb, text="Search:", bg=PANEL, fg=SUBTEXT,
                 font=FONT_UI).pack(side="left", padx=(0, 4))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._apply_filters())
        tk.Entry(tb, textvariable=self._search_var, width=16,
                 bg=BG, fg=TEXT, insertbackground=TEXT, relief="flat",
                 font=FONT_MONO, highlightthickness=1,
                 highlightcolor=ACCENT2, highlightbackground=BORDER,
                 ).pack(side="left", padx=(0, 24))

        # Buttons
        self._btn_start = self._mk_btn(tb, "▶  Start Capture", ACCENT,  BG,   self._start)
        self._btn_stop  = self._mk_btn(tb, "■  Stop",          DANGER,  TEXT, self._stop,  "disabled")
        self._mk_btn(tb, "⬇  Export", ACCENT2, BG,   self._export)
        self._mk_btn(tb, "✕  Clear",  WARNING, BG,   self._clear)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _mk_btn(self, parent, text, bg, fg, cmd, state="normal"):
        b = tk.Button(
            parent, text=text, command=cmd, state=state,
            bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
            relief="flat", font=("Segoe UI Semibold", 9),
            padx=14, pady=5, cursor="hand2", bd=0,
        )
        b.pack(side="left", padx=4)
        return b

    def _on_iface_change(self, *_):
        default_raw   = _get_default_iface()
        default_label = self._iface_map.get(default_raw, "")
        is_default    = self._iface_var.get() == default_label
        self._hint_lbl.config(text="← active" if is_default else "")

    def _build_stats_row(self):
        row = tk.Frame(self, bg=BG, pady=10)
        row.pack(fill="x", padx=16)
        for label, attr, color in [
            ("Total Packets", "_stat_total", TEXT),
            ("TCP",           "_stat_tcp",   ACCENT2),
            ("UDP",           "_stat_udp",   ACCENT),
            ("ICMP",          "_stat_icmp",  WARNING),
            ("DNS",           "_stat_dns",   "#E5C07B"),
            ("ARP",           "_stat_arp",   "#C678DD"),
            ("Data (KB)",     "_stat_kb",    SUBTEXT),
            ("PPS",           "_stat_pps",   ACCENT),
        ]:
            card = tk.Frame(row, bg=PANEL, padx=16, pady=10)
            card.pack(side="left", padx=6)
            var = tk.StringVar(value="0")
            setattr(self, attr, var)
            tk.Label(card, textvariable=var, font=FONT_STAT, bg=PANEL, fg=color).pack()
            tk.Label(card, text=label, font=("Segoe UI", 8), bg=PANEL, fg=SUBTEXT).pack()

    def _build_main_area(self):
        paned = tk.PanedWindow(self, orient="vertical", bg=BG, sashwidth=4, sashrelief="flat")
        paned.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        top = tk.Frame(paned, bg=BG)
        paned.add(top, height=400)
        tk.Label(top, text="CAPTURED PACKETS", font=FONT_H2,
                 bg=BG, fg=SUBTEXT).pack(anchor="w", pady=(8, 4))

        cols = ("#", "Time", "Protocol", "Source IP", "Dst IP",
                "Src Port", "Dst Port", "Flags", "TTL", "Length", "Payload")
        frame_tv = tk.Frame(top, bg=PANEL)
        frame_tv.pack(fill="both", expand=True)

        vsb = tk.Scrollbar(frame_tv, orient="vertical",   bg=BORDER, troughcolor=BG, bd=0, width=10)
        hsb = tk.Scrollbar(frame_tv, orient="horizontal", bg=BORDER, troughcolor=BG, bd=0, width=10)

        self._tree = ttk.Treeview(
            frame_tv, columns=cols, show="headings",
            style="Dark.Treeview",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        for col, w in zip(cols, [50, 100, 70, 130, 130, 80, 80, 70, 50, 70, 250]):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, minwidth=40, anchor="w")

        vsb.config(command=self._tree.yview)
        hsb.config(command=self._tree.xview)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._tree.pack(fill="both", expand=True)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        bot = tk.Frame(paned, bg=BG)
        paned.add(bot, height=180)
        tk.Label(bot, text="PACKET DETAIL", font=FONT_H2,
                 bg=BG, fg=SUBTEXT).pack(anchor="w", pady=(8, 4))
        self._detail = scrolledtext.ScrolledText(
            bot, bg=PANEL, fg=ACCENT, insertbackground=ACCENT,
            font=FONT_MONO, relief="flat", wrap="word", state="disabled",
        )
        self._detail.pack(fill="both", expand=True)

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=PANEL, height=28)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        tk.Frame(bar, bg=BORDER, width=1).pack(side="left", fill="y")
        self._status_var = tk.StringVar(value="Ready — press ▶ Start Capture")
        self._status_lbl = tk.Label(
            bar, textvariable=self._status_var,
            bg=PANEL, fg=SUBTEXT, font=("Segoe UI", 9), anchor="w",
        )
        self._status_lbl.pack(side="left", padx=12, fill="y")
        self._capture_dot = tk.Label(bar, text="●", bg=PANEL, fg=SUBTEXT,
                                     font=("Segoe UI", 10))
        self._capture_dot.pack(side="right", padx=12)
        tk.Label(bar, text="Scapy  |  CodeAlpha Cybersecurity Internship",
                 bg=PANEL, fg=SUBTEXT, font=("Segoe UI", 9)
                 ).pack(side="right", padx=16)

    # ══════════════════════════════════════════════════════════════════════════
    #  ACTIONS
    # ══════════════════════════════════════════════════════════════════════════

    def _start(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror(
                "Scapy Not Found",
                "Install Scapy:  pip install scapy\n\n"
                "Windows: also install Npcap from https://npcap.com\n"
                "Linux/macOS: run with sudo/root",
            )
            return

        selected_label = self._iface_var.get().strip()
        iface = self._label_map.get(selected_label) or selected_label or None
        bpf   = self._filter_var.get().strip() or None

        self._running    = True
        self._start_time = time.time()

        # ── FIX: exactly ONE engine created here ──────────────────────────
        self._engine = PacketEngine(self._enqueue_packet)
        self._engine.start(iface=iface, bpf_filter=bpf)
        # ─────────────────────────────────────────────────────────────────

        self._btn_start.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._status(f"Capturing on: {selected_label}", ACCENT)
        self._blink()

    def _stop(self):
        if self._engine:
            self._engine.stop()
        self._running = False
        self._btn_start.config(state="normal")
        self._btn_stop.config(state="disabled")
        self._capture_dot.config(fg=SUBTEXT)
        self._status(f"Stopped — {len(self._packets)} packets captured", SUBTEXT)

    def _clear(self):
        self._stop()
        self._packets.clear()
        self._stats.clear()
        self._tree.delete(*self._tree.get_children())
        self._detail_write("")
        self._update_stats()
        self._status("Cleared.", SUBTEXT)

    def _export(self):
        if not self._packets:
            messagebox.showinfo("Export", "No packets to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[
                ("Wireshark Capture (.pcap)", "*.pcap"),
                ("CSV",                       "*.csv"),
                ("Text File",                 "*.txt"),
                ("All",                       "*.*"),
            ],
            title="Export Packets",
        )
        if not path:
            return

        # .pcap — Wireshark compatible
        if path.lower().endswith(".pcap"):
            if not SCAPY_AVAILABLE or not self._engine:
                messagebox.showerror("Error", "Scapy not available for pcap export.")
                return
            raw = self._engine.get_raw_packets()
            if not raw:
                messagebox.showinfo("Export", "No raw packets collected.")
                return
            try:
                wrpcap(path, raw)
                self._status(f"Saved {len(raw)} packets → {path}", ACCENT)
            except Exception as exc:
                messagebox.showerror("pcap Error", str(exc))
            return

        # CSV / TXT
        with open(path, "w", encoding="utf-8") as f:
            headers = ["#","Time","Protocol","Src IP","Dst IP",
                       "Src Port","Dst Port","Flags","TTL","Length","Payload"]
            f.write(",".join(headers) + "\n")
            for i, p in enumerate(self._packets, 1):
                row = [str(i), p["time"], p["proto"], p["src"], p["dst"],
                       p["sport"], p["dport"], p["flags"], p["ttl"],
                       str(p["length"]), p["payload"].replace("\n", " ")]
                f.write(",".join(f'"{v}"' for v in row) + "\n")
        self._status(f"Exported → {path}", ACCENT)

    # ══════════════════════════════════════════════════════════════════════════
    #  QUEUE / DISPLAY
    # ══════════════════════════════════════════════════════════════════════════

    def _enqueue_packet(self, info):
        with self._queue_lock:
            self._queue.append(info)

    def _poll_queue(self):
        with self._queue_lock:
            batch, self._queue = self._queue, []
        for info in batch:
            if "error" in info:
                self._status(f"Error: {info['error']}", DANGER)
            else:
                self._add_packet(info)
        self.after(50, self._poll_queue)

    def _add_packet(self, info):
        self._packets.append(info)
        idx   = len(self._packets)
        proto = info["proto"]

        self._stats[proto]   += 1
        self._stats["total"] += 1
        self._stats["bytes"] += info["length"]

        tag = f"proto_{proto}"
        self._tree.insert(
            "", "end",
            values=(idx, info["time"], proto, info["src"], info["dst"],
                    info["sport"], info["dport"], info["flags"],
                    info["ttl"], info["length"],
                    info["payload"][:60].replace("\n", " ")),
            tags=(tag,),
        )
        self._tree.tag_configure(tag, foreground=PROTO_COLORS.get(proto, PROTO_COLORS["OTHER"]))
        self._tree.yview_moveto(1.0)
        self._update_stats()

    def _update_stats(self):
        self._stat_total.set(str(self._stats.get("total", 0)))
        self._stat_tcp.set(str(self._stats.get("TCP",   0)))
        self._stat_udp.set(str(self._stats.get("UDP",   0)))
        self._stat_icmp.set(str(self._stats.get("ICMP", 0)))
        self._stat_dns.set(str(self._stats.get("DNS",   0)))
        self._stat_arp.set(str(self._stats.get("ARP",   0)))
        self._stat_kb.set(str(round(self._stats.get("bytes", 0) / 1024, 1)))
        if self._start_time > 0:
            elapsed = time.time() - self._start_time
            pps = int(len(self._packets) / elapsed) if elapsed >= 1.0 else 0
            self._stat_pps.set(str(pps))

    def _on_select(self, _event):
        sel = self._tree.selection()
        if not sel:
            return
        idx = int(self._tree.item(sel[0], "values")[0]) - 1
        if not (0 <= idx < len(self._packets)):
            return
        p = self._packets[idx]
        self._detail_write(
            f"{'═'*60}\n"
            f"  Packet #{idx+1}   |   {p['time']}\n"
            f"{'═'*60}\n"
            f"  Protocol  : {p['proto']}\n"
            f"  Source    : {p['src']}:{p['sport']}\n"
            f"  Dest      : {p['dst']}:{p['dport']}\n"
            f"  Length    : {p['length']} bytes\n"
            f"  TTL       : {p['ttl']}\n"
            f"  TCP Flags : {p['flags']}\n"
            f"{'─'*60}\n"
            f"  Summary   : {p['raw']}\n"
            f"{'─'*60}\n"
            f"  Payload   :\n{p['payload'] or '  (empty)'}\n"
            f"{'═'*60}\n"
        )

    def _apply_filters(self):
        """
        FIX: iterate all children first, classify into visible/hidden lists,
        then detach hidden and reattach visible — preserving row order and
        preventing the 'ghost reappearance' bug from the previous implementation.
        """
        search  = self._search_var.get().lower()
        proto_f = self._proto_filter.get()

        visible, hidden = [], []
        for iid in self._tree.get_children():
            vals      = self._tree.item(iid, "values")
            row_proto = vals[2] if len(vals) > 2 else ""
            row_text  = " ".join(str(v) for v in vals).lower()
            show = (
                (proto_f == "ALL" or row_proto == proto_f)
                and (not search or search in row_text)
            )
            (visible if show else hidden).append(iid)

        for iid in hidden:
            self._tree.detach(iid)
        for iid in visible:
            try:
                self._tree.reattach(iid, "", "end")
            except tk.TclError:
                pass

    def _detail_write(self, text):
        self._detail.config(state="normal")
        self._detail.delete("1.0", "end")
        self._detail.insert("end", text)
        self._detail.config(state="disabled")

    def _status(self, msg, color=TEXT):
        self._status_var.set(msg)
        self._status_lbl.config(fg=color)

    def _blink(self):
        if not self._running:
            return
        cur = self._capture_dot.cget("fg")
        self._capture_dot.config(fg=ACCENT if cur != ACCENT else BG)
        self.after(600, self._blink)


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = NetworkSnifferApp()
    app.mainloop()