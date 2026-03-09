#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║  NEON GRID - Network Threat Intelligence Dashboard       ║
║  Desktop Edition  |  Powered by Suricata + Zeek          ║
╚══════════════════════════════════════════════════════════╝
Retrowave/Synthwave themed IDS/NSM log analyzer
Usage: python3 neon_dashboard_desktop.py [log_dir]
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import os
import sys
import re
import glob
from datetime import datetime
from collections import Counter, defaultdict
import threading
import math

# ─── RETROWAVE COLOR PALETTE ────────────────────────────
BG_DARK      = "#0a0010"
BG_PANEL     = "#0e0018"
BG_CARD      = "#130020"
NEON_PINK    = "#ff2d78"
NEON_CYAN    = "#00f5ff"
NEON_PURPLE  = "#bf00ff"
NEON_YELLOW  = "#ffe600"
NEON_GREEN   = "#00ff9f"
NEON_ORANGE  = "#ff6b00"
GRID_COLOR   = "#1a003a"
TEXT_BRIGHT  = "#ffffff"
TEXT_DIM     = "#8855aa"
TEXT_MID     = "#cc88ff"
ALERT_RED    = "#ff0044"
ALERT_ORANGE = "#ff6b00"
ALERT_YELLOW = "#ffe600"

FONT_TITLE   = ("Courier", 22, "bold")
FONT_HEADER  = ("Courier", 13, "bold")
FONT_LABEL   = ("Courier", 10)
FONT_VALUE   = ("Courier", 16, "bold")
FONT_SMALL   = ("Courier", 9)
FONT_MONO    = ("Courier", 9)

# ─── LOG PARSER ─────────────────────────────────────────

class LogParser:
    """
    Robust log parser that works on Windows, Linux and macOS.
    Auto-discovers log files in:
      - The given directory (flat layout)
      - Any immediate subdirectory (zeek/, suricata/, etc.)
    Supports both Zeek JSON logs and Suricata eve.json / text logs.
    """

    ZEEK_FILES     = ["conn.log", "dns.log", "http.log", "ssl.log",
                      "dhcp.log", "weird.log", "x509.log", "notice.log",
                      "files.log", "known_services.log"]
    SURICATA_FILES = ["eve.json", "fast.log", "suricata.log", "stats.log"]
    ALL_FILES      = ZEEK_FILES + SURICATA_FILES

    def __init__(self, log_dir=".", extra_dirs=None):
        """
        log_dir    : root directory to search (flat or with subfolders)
        extra_dirs : list of (label, path) tuples for explicitly added dirs
                     e.g. [("suricata", "C:/logs/suricata"), ("zeek", "C:/logs/zeek")]
        """
        self.log_dir    = os.path.normpath(os.path.abspath(log_dir))
        self.extra_dirs = [(lbl, os.path.normpath(os.path.abspath(p)))
                           for lbl, p in (extra_dirs or [])]
        self.data = {
            "connections": [],
            "dns": [],
            "http": [],
            "ssl": [],
            "dhcp": [],
            "weird": [],
            "eve_alerts": [],
            "eve_stats": None,
            "fast_alerts": [],
            "suricata_log": [],
            "suricata_stats_text": {},
        }
        self._file_map = self._build_file_map()

    def _build_file_map(self):
        """
        Build filename -> path map.
        Search order:
          1. Explicitly added extra_dirs (highest priority)
          2. Root log_dir
          3. Immediate subdirs of log_dir
        First match for each filename wins.
        """
        fmap = {}

        # Collect search dirs in priority order
        search_dirs = []

        # 1. Explicit extra dirs first
        for _lbl, d in self.extra_dirs:
            if os.path.isdir(d) and d not in search_dirs:
                search_dirs.append(d)

        # 2. Root dir
        if self.log_dir not in search_dirs:
            search_dirs.append(self.log_dir)

        # 3. Immediate subdirs of root
        try:
            for entry in sorted(os.listdir(self.log_dir)):
                full = os.path.normpath(os.path.join(self.log_dir, entry))
                if os.path.isdir(full) and full not in search_dirs:
                    search_dirs.append(full)
        except (PermissionError, OSError):
            pass

        for fname in self.ALL_FILES:
            for d in search_dirs:
                candidate = os.path.normpath(os.path.join(d, fname))
                if os.path.isfile(candidate):
                    fmap[fname] = candidate
                    break

        return fmap

    def _resolved(self, filename):
        return self._file_map.get(filename)

    def found_files(self):
        return sorted(self._file_map.items())

    def _read_jsonl(self, filename):
        path = self._resolved(filename)
        records = []
        if not path:
            return records
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except Exception:
                            pass
        except OSError:
            pass
        return records

    def parse_all(self):
        # Zeek logs
        self.data["connections"] = self._read_jsonl("conn.log")
        self.data["dns"]         = self._read_jsonl("dns.log")
        self.data["http"]        = self._read_jsonl("http.log")
        self.data["ssl"]         = self._read_jsonl("ssl.log")
        self.data["dhcp"]        = self._read_jsonl("dhcp.log")
        self.data["weird"]       = self._read_jsonl("weird.log")
        # Suricata logs
        self._parse_eve_json()
        self._parse_fast_log()
        self._parse_suricata_log()
        self._parse_stats_log()
        return self.data

    def _parse_eve_json(self):
        path = self._resolved("eve.json")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        et = rec.get("event_type")
                        if et == "alert":
                            self.data["eve_alerts"].append(rec)
                        elif et == "stats":
                            # Keep the last stats record (most complete)
                            self.data["eve_stats"] = rec.get("stats", {})
                    except Exception:
                        pass
        except OSError:
            pass

    def _parse_fast_log(self):
        path = self._resolved("fast.log")
        if not path:
            return
        pattern = re.compile(
            r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)'
            r'\s+\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]'
        )
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = pattern.search(line)
                    if m:
                        self.data["fast_alerts"].append({
                            "ts":  m.group(1),
                            "sid": m.group(2),
                            "msg": m.group(3),
                            "raw": line.strip(),
                        })
        except OSError:
            pass

    def _parse_suricata_log(self):
        path = self._resolved("suricata.log")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.data["suricata_log"].append(line)
        except OSError:
            pass

    def _parse_stats_log(self):
        """
        Parse Suricata's text-format stats.log.
        Lines look like:
          decoder.pkts  | Total  | 292039
        """
        path = self._resolved("stats.log")
        if not path:
            return
        stats = {}
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if "|" not in line:
                        continue
                    if line.startswith("-") or line.startswith("Counter"):
                        continue
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) == 3:
                        key, thread, val = parts
                        if thread == "Total":
                            try:
                                stats[key] = int(val)
                            except ValueError:
                                pass
            self.data["suricata_stats_text"] = stats
        except OSError:
            pass


# ─── ANALYTICS ENGINE ────────────────────────────────────

class Analytics:
    def __init__(self, data):
        self.d = data

    def total_connections(self):
        return len(self.d["connections"])

    def total_alerts(self):
        return len(self.d["eve_alerts"]) + len(self.d["fast_alerts"])

    def total_dns(self):
        return len(self.d["dns"])

    def total_http(self):
        return len(self.d["http"])

    def total_ssl(self):
        return len(self.d["ssl"])

    def unique_src_ips(self):
        ips = set()
        for c in self.d["connections"]:
            h = c.get("id.orig_h")
            if h:
                ips.add(h)
        return len(ips)

    def unique_dst_ips(self):
        ips = set()
        for c in self.d["connections"]:
            h = c.get("id.resp_h")
            if h:
                ips.add(h)
        return len(ips)

    def top_src_ips(self, n=10):
        c = Counter()
        for conn in self.d["connections"]:
            h = conn.get("id.orig_h")
            if h:
                c[h] += 1
        return c.most_common(n)

    def top_dst_ips(self, n=10):
        c = Counter()
        for conn in self.d["connections"]:
            h = conn.get("id.resp_h")
            if h:
                c[h] += 1
        return c.most_common(n)

    def top_dst_ports(self, n=10):
        c = Counter()
        for conn in self.d["connections"]:
            p = conn.get("id.resp_p")
            if p:
                c[str(p)] += 1
        return c.most_common(n)

    def proto_distribution(self):
        c = Counter()
        for conn in self.d["connections"]:
            p = conn.get("proto", "unknown")
            c[p] += 1
        return dict(c)

    def conn_states(self, n=10):
        c = Counter()
        for conn in self.d["connections"]:
            s = conn.get("conn_state", "?")
            c[s] += 1
        return c.most_common(n)

    def alert_categories(self, n=10):
        c = Counter()
        for a in self.d["eve_alerts"]:
            cat = a.get("alert", {}).get("category", "Unknown")
            c[cat] += 1
        return c.most_common(n)

    def alert_severity_dist(self, n=10):
        c = Counter()
        for a in self.d["eve_alerts"]:
            sev = a.get("alert", {}).get("severity", 0)
            c[sev] += 1
        return dict(c)

    def top_dns_queries(self, n=10):
        c = Counter()
        for r in self.d["dns"]:
            q = r.get("query")
            if q:
                c[q] += 1
        return c.most_common(n)

    def dns_rcode_dist(self, n=10):
        c = Counter()
        for r in self.d["dns"]:
            rc = r.get("rcode_name", r.get("rcode", "?"))
            if rc:
                c[str(rc)] += 1
        return c.most_common(n)

    def ssl_versions(self, n=10):
        c = Counter()
        for r in self.d["ssl"]:
            v = r.get("version", "?")
            c[v] += 1
        return c.most_common(n)

    def weird_names(self, n=10):
        c = Counter()
        for r in self.d["weird"]:
            n2 = r.get("name", "?")
            c[n2] += 1
        return c.most_common(n)

    def total_bytes(self):
        total = 0
        for c in self.d["connections"]:
            total += c.get("orig_ip_bytes", 0) + c.get("resp_ip_bytes", 0)
        return total

    def suricata_stats(self):
        # Primary source: eve.json stats event
        s = self.d.get("eve_stats") or {}
        dec    = s.get("decoder", {})
        flow   = s.get("flow", {})
        detect = s.get("detect", {})
        al     = s.get("app_layer", {}).get("flow", {})

        # Fallback source: stats.log text file
        t = self.d.get("suricata_stats_text") or {}

        def ev(json_val, text_key):
            # Pick eve_stats value if non-zero, else fall back to stats.log text
            return json_val if json_val else t.get(text_key, 0)

        return {
            "pkts":         ev(dec.get("pkts", 0),      "decoder.pkts"),
            "bytes":        ev(dec.get("bytes", 0),     "decoder.bytes"),
            "tcp":          ev(dec.get("tcp", 0),       "decoder.tcp"),
            "udp":          ev(dec.get("udp", 0),       "decoder.udp"),
            "icmpv4":       ev(dec.get("icmpv4", 0),    "decoder.icmpv4"),
            "tls_flows":    ev(al.get("tls", 0),        "app_layer.flow.tls"),
            "http_flows":   ev(al.get("http", 0),       "app_layer.flow.http"),
            "dns_flows":    ev(al.get("dns_udp", 0),    "app_layer.flow.dns_udp"),
            "total_flows":  ev(flow.get("total", 0),    "flow.total"),
            "alerts":       ev(detect.get("alert", 0),  "detect.alert"),
            "rules_loaded": (detect.get("engines") or [{}])[0].get("rules_loaded", 0)
                             if detect.get("engines") else t.get("detect.rule_ids_loaded", 0),
        }

    def recent_alerts(self, n=15):
        alerts = []
        for a in self.d["eve_alerts"][-n:]:
            alerts.append({
                "ts": a.get("timestamp", ""),
                "src": f"{a.get('src_ip','')}:{a.get('src_port','')}",
                "dst": f"{a.get('dest_ip','')}:{a.get('dest_port','')}",
                "msg": a.get("alert", {}).get("signature", ""),
                "sev": a.get("alert", {}).get("severity", 0),
                "proto": a.get("proto", ""),
            })
        for fa in self.d["fast_alerts"][-5:]:
            alerts.append({
                "ts": fa.get("ts", ""),
                "src": "",
                "dst": "",
                "msg": fa.get("msg", ""),
                "sev": 3,
                "proto": "",
            })
        return alerts[-n:]


# ─── RETRO CANVAS WIDGETS ────────────────────────────────

class NeonBarChart(tk.Canvas):
    def __init__(self, parent, data, title="", color=NEON_CYAN, max_bars=8, **kwargs):
        kwargs.setdefault("bg", BG_CARD)
        kwargs.setdefault("highlightthickness", 0)
        super().__init__(parent, **kwargs)
        self.data = data[:max_bars]
        self.title = title
        self.color = color
        self.bind("<Configure>", self._draw)
        self.after(50, self._draw)

    def _draw(self, event=None):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 10 or h < 10:
            return
        self._draw_grid(w, h)
        if self.title:
            self.create_text(w // 2, 12, text=self.title, fill=TEXT_MID,
                             font=("Courier", 9, "bold"))
        if not self.data:
            self.create_text(w // 2, h // 2, text="NO DATA", fill=TEXT_DIM, font=FONT_SMALL)
            return

        n = len(self.data)
        # Reserve bottom space for diagonal labels: ~60px for 8-char, more for longer
        max_lbl_len = max(len(str(label)) for label, _ in self.data)
        # Diagonal label area height (approx chars * sin45 * font_px)
        lbl_area = min(80, max(45, int(max_lbl_len * 5.5)))
        pad_l, pad_r, pad_t = 36, 10, 24
        pad_b = lbl_area + 6

        chart_w = w - pad_l - pad_r
        chart_h = h - pad_t - pad_b
        if chart_h < 20:
            return
        max_val = max(v for _, v in self.data) or 1

        # Draw horizontal reference lines with value labels on Y axis
        for frac, lc in [(1.0, "#1a0040"), (0.75, "#1a0040"), (0.5, "#1a0040"), (0.25, "#1a0040")]:
            y = pad_t + chart_h - int(chart_h * frac)
            self.create_line(pad_l, y, w - pad_r, y, fill=lc, width=1, dash=(3, 6))
            ref_val = int(max_val * frac)
            self.create_text(pad_l - 4, y, text=str(ref_val),
                             fill="#442266", font=("Courier", 7), anchor="e")

        slot_w = chart_w / n
        bar_w  = max(8, slot_w * 0.55)

        for i, (label, val) in enumerate(self.data):
            bar_h = max(2, int((val / max_val) * chart_h * 0.92))
            cx    = pad_l + i * slot_w + slot_w / 2
            x     = cx - bar_w / 2
            y_bot = pad_t + chart_h
            y_top = y_bot - bar_h

            # Glow rings
            for glow in [4, 2]:
                self.create_rectangle(x - glow, y_top - glow,
                                      x + bar_w + glow, y_bot,
                                      fill="", outline=self._lighten(self.color, glow * 0.06), width=1)
            # Bar fill
            self.create_rectangle(x, y_top, x + bar_w, y_bot,
                                  fill=self._darken(self.color), outline=self.color, width=1)

            # Value above bar — bright, readable
            val_str = f"{val:,}" if val >= 1000 else str(val)
            self.create_text(cx, y_top - 8, text=val_str,
                             fill=self.color, font=("Courier", 8, "bold"), anchor="s")

            # Diagonal label below bar
            lbl_full = str(label)
            # Limit length but keep more chars since we rotate
            lbl = lbl_full if len(lbl_full) <= 18 else lbl_full[:16] + ".."
            self.create_text(cx + 2, y_bot + 6,
                             text=lbl,
                             fill=TEXT_MID,            # brighter than TEXT_DIM
                             font=("Courier", 8),
                             angle=40,                 # 40° diagonal
                             anchor="ne")

    def _draw_grid(self, w, h):
        for x in range(0, w, 20):
            self.create_line(x, 0, x, h, fill=GRID_COLOR, width=1)
        for y in range(0, h, 20):
            self.create_line(0, y, w, y, fill=GRID_COLOR, width=1)

    def _darken(self, color):
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        return f"#{r//4:02x}{g//4:02x}{b//4:02x}"

    def _lighten(self, color, factor):
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        r2 = min(255, int(r + (255 - r) * factor))
        g2 = min(255, int(g + (255 - g) * factor))
        b2 = min(255, int(b + (255 - b) * factor))
        return f"#{r2:02x}{g2:02x}{b2:02x}"


class NeonPieChart(tk.Canvas):
    def __init__(self, parent, data, title="", colors=None, **kwargs):
        kwargs.setdefault("bg", BG_CARD)
        kwargs.setdefault("highlightthickness", 0)
        super().__init__(parent, **kwargs)
        self.data = data
        self.title = title
        self.colors = colors or [NEON_PINK, NEON_CYAN, NEON_PURPLE, NEON_YELLOW,
                                  NEON_GREEN, NEON_ORANGE, "#ff88ff", "#88ffff"]
        self.bind("<Configure>", self._draw)
        self.after(50, self._draw)

    def _draw(self, event=None):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 10 or h < 10:
            return
        # Grid
        for x in range(0, w, 20):
            self.create_line(x, 0, x, h, fill=GRID_COLOR)
        for y in range(0, h, 20):
            self.create_line(0, y, w, y, fill=GRID_COLOR)
        if self.title:
            self.create_text(w // 2, 14, text=self.title, fill=TEXT_MID,
                             font=("Courier", 9, "bold"))
        if not self.data:
            return
        total = sum(v for _, v in self.data)
        if total == 0:
            return
        cx, cy = w // 2, h // 2 + 6
        r = min(w, h) // 2 - 30
        if r < 10:
            return
        start = -90
        for i, (label, val) in enumerate(self.data):
            if val == 0:
                continue
            angle = (val / total) * 360
            color = self.colors[i % len(self.colors)]
            # Glow
            for g in range(3, 0, -1):
                self.create_arc(cx - r - g, cy - r - g, cx + r + g, cy + r + g,
                                start=start, extent=angle,
                                fill="", outline=color, width=1, style="arc")
            self.create_arc(cx - r, cy - r, cx + r, cy + r,
                            start=start, extent=angle,
                            fill=self._darken(color), outline=color, width=2)
            # Label at midpoint
            mid_angle = math.radians(start + angle / 2)
            lx = cx + (r + 12) * math.cos(mid_angle)
            ly = cy - (r + 12) * math.sin(mid_angle)
            pct = int(val / total * 100)
            if pct >= 5:
                self.create_text(lx, ly, text=f"{pct}%", fill=color,
                                 font=("Courier", 7, "bold"))
            start += angle
        # Legend
        leg_y = 18
        for i, (label, val) in enumerate(self.data[:6]):
            color = self.colors[i % len(self.colors)]
            lx = 8
            self.create_rectangle(lx, leg_y + i * 14, lx + 8, leg_y + i * 14 + 8,
                                   fill=color, outline=color)
            self.create_text(lx + 12, leg_y + i * 14 + 4,
                             text=f"{str(label)[:14]}: {val}",
                             fill=TEXT_DIM, font=("Courier", 7), anchor="w")

    def _darken(self, color):
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        return f"#{r//5:02x}{g//5:02x}{b//5:02x}"


class StatCard(tk.Frame):
    def __init__(self, parent, label, value, color=NEON_CYAN, icon="▶", **kwargs):
        super().__init__(parent, bg=BG_CARD,
                         highlightbackground=color, highlightthickness=1, **kwargs)
        self.color = color
        # Glow top border
        tk.Frame(self, bg=color, height=2).pack(fill="x")
        inner = tk.Frame(self, bg=BG_CARD)
        inner.pack(fill="both", expand=True, padx=8, pady=6)
        tk.Label(inner, text=icon, fg=color, bg=BG_CARD,
                 font=("Courier", 18)).pack(side="left", padx=(0, 6))
        right = tk.Frame(inner, bg=BG_CARD)
        right.pack(side="left", fill="both", expand=True)
        self.val_label = tk.Label(right, text=str(value), fg=color, bg=BG_CARD,
                                   font=FONT_VALUE)
        self.val_label.pack(anchor="w")
        tk.Label(right, text=label, fg=TEXT_DIM, bg=BG_CARD,
                 font=FONT_SMALL).pack(anchor="w")

    def update_value(self, v):
        self.val_label.config(text=str(v))


class AlertTable(tk.Frame):
    def __init__(self, parent, alerts, **kwargs):
        super().__init__(parent, bg=BG_CARD, **kwargs)
        self._build(alerts)

    def _build(self, alerts):
        for w in self.winfo_children():
            w.destroy()
        # Header
        hdr = tk.Frame(self, bg=BG_PANEL)
        hdr.pack(fill="x")
        cols = [("TIME", 16), ("SRC", 22), ("DST", 22), ("SEV", 4), ("MESSAGE", 45)]
        for col, width in cols:
            tk.Label(hdr, text=col, fg=NEON_PURPLE, bg=BG_PANEL,
                     font=("Courier", 8, "bold"), width=width, anchor="w").pack(side="left")
        tk.Frame(self, bg=NEON_PURPLE, height=1).pack(fill="x")
        # Scrollable area
        canvas = tk.Canvas(self, bg=BG_CARD, highlightthickness=0)
        vsb = tk.Scrollbar(self, orient="vertical", command=canvas.yview,
                           bg=BG_DARK, troughcolor=BG_PANEL)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        frame = tk.Frame(canvas, bg=BG_CARD)
        frame.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=frame, anchor="nw")
        SEV_COLORS = {1: ALERT_RED, 2: NEON_ORANGE, 3: ALERT_YELLOW, 0: TEXT_DIM}
        for i, a in enumerate(reversed(alerts)):
            bg = BG_CARD if i % 2 == 0 else "#110020"
            row = tk.Frame(frame, bg=bg)
            row.pack(fill="x")
            sev = a.get("sev", 0)
            color = SEV_COLORS.get(sev, TEXT_DIM)
            ts = a.get("ts", "")[:19]
            src = a.get("src", "")[:21]
            dst = a.get("dst", "")[:21]
            msg = a.get("msg", "")[:44]
            for txt, width in [(ts, 16), (src, 22), (dst, 22), (str(sev), 4), (msg, 45)]:
                tk.Label(row, text=txt, fg=color, bg=bg,
                         font=FONT_MONO, width=width, anchor="w").pack(side="left")


# ─── MAIN DASHBOARD APP ──────────────────────────────────

class NeonDashboard(tk.Tk):
    def __init__(self, log_dir="."):
        super().__init__()
        self.log_dir = log_dir
        self.title("◈ NEON GRID ◈  Network Threat Intelligence Dashboard")
        self.configure(bg=BG_DARK)
        self.geometry("1400x900")
        self.minsize(1100, 700)

        self.parser = LogParser(log_dir)
        self._last_parser = None
        self.data = {}
        self.analytics = None

        self._build_ui()
        self._load_data()

    def _build_ui(self):
        # ── TOP HEADER ──
        header = tk.Frame(self, bg=BG_DARK)
        header.pack(fill="x", padx=0, pady=0)
        tk.Frame(header, bg=NEON_PINK, height=2).pack(fill="x")
        title_row = tk.Frame(header, bg=BG_DARK)
        title_row.pack(fill="x", padx=16, pady=6)
        tk.Label(title_row, text="◈ NEON GRID", fg=NEON_PINK, bg=BG_DARK,
                 font=("Courier", 20, "bold")).pack(side="left")
        tk.Label(title_row, text=" NETWORK THREAT INTELLIGENCE DASHBOARD",
                 fg=NEON_PURPLE, bg=BG_DARK,
                 font=("Courier", 12, "bold")).pack(side="left", pady=4)
        # Controls
        ctrl = tk.Frame(title_row, bg=BG_DARK)
        ctrl.pack(side="right")
        self.dir_label = tk.Label(ctrl, text=f"DIR: {os.path.abspath(self.log_dir)}",
                                   fg=TEXT_DIM, bg=BG_DARK, font=FONT_SMALL)
        self.dir_label.pack(side="left", padx=6)
        tk.Button(ctrl, text="[ OPEN DIR ]", fg=NEON_CYAN, bg=BG_PANEL,
                  font=("Courier", 9, "bold"), relief="flat", bd=0,
                  activeforeground=NEON_CYAN, activebackground=BG_DARK,
                  command=self._open_dir).pack(side="left", padx=4)
        tk.Button(ctrl, text="[ + SURICATA DIR ]", fg=NEON_PINK, bg=BG_PANEL,
                  font=("Courier", 9, "bold"), relief="flat", bd=0,
                  activeforeground=NEON_PINK, activebackground=BG_DARK,
                  command=self._open_suricata_dir).pack(side="left", padx=4)
        tk.Button(ctrl, text="[ + ZEEK DIR ]", fg=NEON_YELLOW, bg=BG_PANEL,
                  font=("Courier", 9, "bold"), relief="flat", bd=0,
                  activeforeground=NEON_YELLOW, activebackground=BG_DARK,
                  command=self._open_zeek_dir).pack(side="left", padx=4)
        tk.Button(ctrl, text="[ RELOAD ]", fg=NEON_GREEN, bg=BG_PANEL,
                  font=("Courier", 9, "bold"), relief="flat", bd=0,
                  activeforeground=NEON_GREEN, activebackground=BG_DARK,
                  command=self._load_data).pack(side="left", padx=4)
        tk.Frame(header, bg=NEON_PURPLE, height=1).pack(fill="x")

        # ── NOTEBOOK TABS ──
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Neon.TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("Neon.TNotebook.Tab",
                        background=BG_PANEL, foreground=TEXT_DIM,
                        font=("Courier", 10, "bold"),
                        padding=[14, 6], borderwidth=0)
        style.map("Neon.TNotebook.Tab",
                  background=[("selected", BG_CARD)],
                  foreground=[("selected", NEON_PINK)])

        self.nb = ttk.Notebook(self, style="Neon.TNotebook")
        self.nb.pack(fill="both", expand=True, padx=0, pady=0)

        self.tab_overview  = tk.Frame(self.nb, bg=BG_DARK)
        self.tab_alerts    = tk.Frame(self.nb, bg=BG_DARK)
        self.tab_network   = tk.Frame(self.nb, bg=BG_DARK)
        self.tab_dns       = tk.Frame(self.nb, bg=BG_DARK)
        self.tab_suricata  = tk.Frame(self.nb, bg=BG_DARK)

        self.nb.add(self.tab_overview,  text="  ◉ OVERVIEW  ")
        self.nb.add(self.tab_alerts,    text="  ⚡ ALERTS   ")
        self.nb.add(self.tab_network,   text="  ◈ NETWORK   ")
        self.nb.add(self.tab_dns,       text="  ◆ DNS/TLS   ")
        self.nb.add(self.tab_suricata,  text="  ▶ SURICATA  ")

        # Status bar
        self.status_var = tk.StringVar(value="Loading...")
        status = tk.Frame(self, bg=BG_PANEL, height=22)
        status.pack(fill="x", side="bottom")
        tk.Frame(status, bg=NEON_CYAN, width=2).pack(side="left", fill="y")
        tk.Label(status, textvariable=self.status_var, fg=NEON_CYAN, bg=BG_PANEL,
                 font=FONT_SMALL).pack(side="left", padx=8)
        self.time_label = tk.Label(status, text="", fg=TEXT_DIM, bg=BG_PANEL, font=FONT_SMALL)
        self.time_label.pack(side="right", padx=8)
        self._tick()

    def _tick(self):
        self.time_label.config(text=datetime.now().strftime("⏱ %Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick)

    def _open_dir(self):
        d = filedialog.askdirectory(initialdir=self.log_dir,
                                    title="Select Log Directory (Flat or with zeek/suricata subfolders)")
        if d:
            self.log_dir = os.path.normpath(d)
            self.extra_dirs = []
            self.dir_label.config(text=f"DIR: {self.log_dir}")
            self._load_data()

    def _open_suricata_dir(self):
        d = filedialog.askdirectory(initialdir=self.log_dir,
                                    title="Select Suricata log folder (with eve.json, fast.log ...)")
        if d:
            if not hasattr(self, "extra_dirs"):
                self.extra_dirs = []
            self.extra_dirs = [x for x in self.extra_dirs if x != "__suricata__"]
            self.extra_dirs.append(("suricata", os.path.normpath(d)))
            self.dir_label.config(text=f"SURI: {os.path.normpath(d)}")
            self._load_data()

    def _open_zeek_dir(self):
        d = filedialog.askdirectory(initialdir=self.log_dir,
                                    title="Select Zeek log folder (with conn.log, dns.log ...)")
        if d:
            if not hasattr(self, "extra_dirs"):
                self.extra_dirs = []
            self.extra_dirs = [x for x in self.extra_dirs if x != "__zeek__"]
            self.extra_dirs.append(("zeek", os.path.normpath(d)))
            self.dir_label.config(text=f"ZEEK: {os.path.normpath(d)}")
            self._load_data()

    def _load_data(self):
        self.status_var.set("⏳ Parsing logs...")
        self.update()
        def _parse():
            extra = getattr(self, "extra_dirs", [])
            p = LogParser(self.log_dir, extra_dirs=extra)
            data = p.parse_all()
            self.data = data
            self._last_parser = p
            self.analytics = Analytics(data)
            self.after(0, self._refresh_ui)
        threading.Thread(target=_parse, daemon=True).start()

    def _refresh_ui(self):
        a = self.analytics
        self._build_overview(a)
        self._build_alerts(a)
        self._build_network(a)
        self._build_dns(a)
        self._build_suricata(a)
        totals = (f"CONN:{a.total_connections()}  ALERTS:{a.total_alerts()}  "
                  f"DNS:{a.total_dns()}  HTTP:{a.total_http()}  SSL:{a.total_ssl()}")
        found = len(self._last_parser.found_files()) if self._last_parser else 0
        self.status_var.set(f"✓ Loaded  |  FILES:{found}  |  {totals}")
        # Update dir label to show resolved search path
        if self._last_parser and self._last_parser.found_files():
            paths = set(os.path.dirname(p) for _, p in self._last_parser.found_files())
            dirs_str = "  +  ".join(sorted(paths))
            self.dir_label.config(text=f"LOGS: {dirs_str}")

    # ── OVERVIEW TAB ──────────────────────────────────────
    def _build_overview(self, a):
        for w in self.tab_overview.winfo_children():
            w.destroy()
        pad = dict(padx=8, pady=4)

        # Stat cards row
        cards_frame = tk.Frame(self.tab_overview, bg=BG_DARK)
        cards_frame.pack(fill="x", padx=12, pady=10)
        stats_data = [
            ("CONNECTIONS", a.total_connections(), NEON_CYAN, "⇄"),
            ("ALERTS", a.total_alerts(), NEON_PINK, "⚡"),
            ("DNS QUERIES", a.total_dns(), NEON_YELLOW, "◆"),
            ("SSL/TLS", a.total_ssl(), NEON_PURPLE, "🔒"),
            ("HTTP REQs", a.total_http(), NEON_GREEN, "⬡"),
            ("UNIQ SRC IPs", a.unique_src_ips(), NEON_ORANGE, "◎"),
            ("UNIQ DST IPs", a.unique_dst_ips(), TEXT_MID, "◉"),
            ("WEIRD EVENTS", len(self.data.get("weird", [])), ALERT_RED, "⚠"),
        ]
        for i, (label, val, color, icon) in enumerate(stats_data):
            card = StatCard(cards_frame, label, f"{val:,}", color=color, icon=icon)
            card.grid(row=0, column=i, sticky="ew", padx=5, pady=2)
            cards_frame.columnconfigure(i, weight=1)

        # Charts row
        charts = tk.Frame(self.tab_overview, bg=BG_DARK)
        charts.pack(fill="both", expand=True, padx=12, pady=4)
        charts.columnconfigure(0, weight=2)
        charts.columnconfigure(1, weight=2)
        charts.columnconfigure(2, weight=1)
        charts.rowconfigure(0, weight=1)

        # Top Src IPs bar
        src_frame = tk.LabelFrame(charts, text=" TOP SOURCE IPs ", fg=NEON_CYAN,
                                   bg=BG_DARK, font=("Courier", 9, "bold"),
                                   bd=1, relief="flat",
                                   highlightbackground=NEON_CYAN, highlightthickness=1)
        src_frame.grid(row=0, column=0, sticky="nsew", padx=6)
        NeonBarChart(src_frame, a.top_src_ips(8), color=NEON_CYAN,
                     height=220).pack(fill="both", expand=True)

        # Top Dst IPs bar
        dst_frame = tk.LabelFrame(charts, text=" TOP DEST IPs ", fg=NEON_PINK,
                                   bg=BG_DARK, font=("Courier", 9, "bold"),
                                   bd=1, relief="flat",
                                   highlightbackground=NEON_PINK, highlightthickness=1)
        dst_frame.grid(row=0, column=1, sticky="nsew", padx=6)
        NeonBarChart(dst_frame, a.top_dst_ips(8), color=NEON_PINK,
                     height=220).pack(fill="both", expand=True)

        # Protocol pie
        proto_frame = tk.LabelFrame(charts, text=" PROTOCOLS ", fg=NEON_PURPLE,
                                     bg=BG_DARK, font=("Courier", 9, "bold"),
                                     bd=1, relief="flat",
                                     highlightbackground=NEON_PURPLE, highlightthickness=1)
        proto_frame.grid(row=0, column=2, sticky="nsew", padx=6)
        proto = [(k, v) for k, v in sorted(a.proto_distribution().items(),
                                            key=lambda x: -x[1])]
        NeonPieChart(proto_frame, proto[:6],
                     height=220).pack(fill="both", expand=True)

        # Bytes info
        info_frame = tk.Frame(self.tab_overview, bg=BG_PANEL)
        info_frame.pack(fill="x", padx=12, pady=4)
        total_bytes = a.total_bytes()
        tb_str = f"{total_bytes / 1e9:.2f} GB" if total_bytes > 1e9 else \
                 f"{total_bytes / 1e6:.2f} MB" if total_bytes > 1e6 else \
                 f"{total_bytes / 1e3:.1f} KB"
        tk.Label(info_frame, text=f" TOTAL TRAFFIC: {tb_str}  |  "
                                   f"DHCP EVENTS: {len(self.data.get('dhcp',[]))}  |  "
                                   f"ZEEK WEIRD: {len(self.data.get('weird',[]))}  |  "
                                   f"X.509 CERTS: {len(self._read_x509())}",
                 fg=NEON_CYAN, bg=BG_PANEL, font=FONT_SMALL).pack(side="left", padx=8, pady=3)

    def _read_x509(self):
        # Use the parser's file map if available, else fallback to log_dir
        path = None
        if hasattr(self, '_last_parser') and self._last_parser:
            path = self._last_parser._resolved("x509.log")
        if not path:
            path = os.path.join(self.log_dir, "x509.log")
        records = []
        if os.path.exists(path):
            with open(path, errors="replace") as f:
                for line in f:
                    try:
                        records.append(json.loads(line.strip()))
                    except:
                        pass
        return records

    # ── ALERTS TAB ────────────────────────────────────────
    def _build_alerts(self, a):
        for w in self.tab_alerts.winfo_children():
            w.destroy()
        top = tk.Frame(self.tab_alerts, bg=BG_DARK)
        top.pack(fill="x", padx=12, pady=8)

        # Alert severity cards
        sev_dist = a.alert_severity_dist()
        for sev, label, color in [(1, "CRITICAL", ALERT_RED),
                                   (2, "HIGH", NEON_ORANGE),
                                   (3, "MEDIUM", ALERT_YELLOW),
                                   (0, "INFO", TEXT_DIM)]:
            StatCard(top, label, sev_dist.get(sev, 0),
                     color=color, icon="⚡").pack(side="left", fill="x",
                                                   expand=True, padx=6)

        mid = tk.Frame(self.tab_alerts, bg=BG_DARK)
        mid.pack(fill="x", padx=12, pady=4)
        mid.columnconfigure(0, weight=2)
        mid.columnconfigure(1, weight=1)
        mid.rowconfigure(0, weight=1)

        # Alert categories bar
        cat_frame = tk.LabelFrame(mid, text=" ALERT CATEGORIES ", fg=NEON_PINK,
                                   bg=BG_DARK, font=("Courier", 9, "bold"),
                                   highlightbackground=NEON_PINK, highlightthickness=1)
        cat_frame.grid(row=0, column=0, sticky="nsew", padx=4)
        NeonBarChart(cat_frame, a.alert_categories(8), color=NEON_PINK,
                     height=160).pack(fill="both", expand=True)

        # Severity pie
        sev_frame = tk.LabelFrame(mid, text=" SEVERITY DIST ", fg=NEON_ORANGE,
                                   bg=BG_DARK, font=("Courier", 9, "bold"),
                                   highlightbackground=NEON_ORANGE, highlightthickness=1)
        sev_frame.grid(row=0, column=1, sticky="nsew", padx=4)
        sev_data = [(f"Sev{k}", v) for k, v in sorted(sev_dist.items())]
        NeonPieChart(sev_frame, sev_data,
                     colors=[ALERT_RED, NEON_ORANGE, ALERT_YELLOW, TEXT_DIM],
                     height=160).pack(fill="both", expand=True)

        # Alert table
        tbl_frame = tk.LabelFrame(self.tab_alerts, text=" ⚡ RECENT ALERTS ", fg=NEON_PINK,
                                   bg=BG_DARK, font=("Courier", 9, "bold"),
                                   highlightbackground=NEON_PINK, highlightthickness=1)
        tbl_frame.pack(fill="both", expand=True, padx=12, pady=4)
        AlertTable(tbl_frame, a.recent_alerts(30)).pack(fill="both", expand=True)

    # ── NETWORK TAB ──────────────────────────────────────
    def _build_network(self, a):
        for w in self.tab_network.winfo_children():
            w.destroy()
        top = tk.Frame(self.tab_network, bg=BG_DARK)
        top.pack(fill="both", expand=True, padx=12, pady=8)
        top.columnconfigure(0, weight=1)
        top.columnconfigure(1, weight=1)
        top.columnconfigure(2, weight=1)
        top.rowconfigure(0, weight=1)
        top.rowconfigure(1, weight=1)

        # Top dst ports
        port_frame = tk.LabelFrame(top, text=" TOP DEST PORTS ", fg=NEON_CYAN,
                                    bg=BG_DARK, font=("Courier", 9, "bold"),
                                    highlightbackground=NEON_CYAN, highlightthickness=1)
        port_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        NeonBarChart(port_frame, a.top_dst_ports(8), color=NEON_CYAN).pack(fill="both", expand=True)

        # Connection states
        state_frame = tk.LabelFrame(top, text=" CONN STATES ", fg=NEON_YELLOW,
                                     bg=BG_DARK, font=("Courier", 9, "bold"),
                                     highlightbackground=NEON_YELLOW, highlightthickness=1)
        state_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        NeonBarChart(state_frame, a.conn_states(8), color=NEON_YELLOW).pack(fill="both", expand=True)

        # Weird events
        weird_frame = tk.LabelFrame(top, text=" ZEEK WEIRD EVENTS ", fg=ALERT_RED,
                                     bg=BG_DARK, font=("Courier", 9, "bold"),
                                     highlightbackground=ALERT_RED, highlightthickness=1)
        weird_frame.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        NeonBarChart(weird_frame, a.weird_names(8), color=ALERT_RED).pack(fill="both", expand=True)

        # Connection log table
        conn_frame = tk.LabelFrame(top, text=" ◈ CONNECTION LOG (recent) ", fg=NEON_CYAN,
                                    bg=BG_DARK, font=("Courier", 9, "bold"),
                                    highlightbackground=NEON_CYAN, highlightthickness=1)
        conn_frame.grid(row=1, column=0, columnspan=3, sticky="nsew", padx=5, pady=5)
        self._build_conn_table(conn_frame)

    def _build_conn_table(self, parent):
        cols = [("TS", 18), ("SRC", 18), ("DST", 18), ("PROTO", 6),
                ("STATE", 8), ("ORIG_B", 10), ("RESP_B", 10)]
        hdr = tk.Frame(parent, bg=BG_PANEL)
        hdr.pack(fill="x")
        for col, w in cols:
            tk.Label(hdr, text=col, fg=NEON_CYAN, bg=BG_PANEL,
                     font=("Courier", 8, "bold"), width=w, anchor="w").pack(side="left")
        tk.Frame(parent, bg=NEON_CYAN, height=1).pack(fill="x")
        canvas = tk.Canvas(parent, bg=BG_CARD, highlightthickness=0)
        vsb = tk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        frame = tk.Frame(canvas, bg=BG_CARD)
        frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=frame, anchor="nw")
        conns = self.data.get("connections", [])[-60:]
        for i, c in enumerate(reversed(conns)):
            bg = BG_CARD if i % 2 == 0 else "#110020"
            row = tk.Frame(frame, bg=bg)
            row.pack(fill="x")
            ts = datetime.fromtimestamp(c.get("ts", 0)).strftime("%m-%d %H:%M:%S")
            src = f"{c.get('id.orig_h','')}:{c.get('id.orig_p','')}"[:17]
            dst = f"{c.get('id.resp_h','')}:{c.get('id.resp_p','')}"[:17]
            proto = c.get("proto", "")[:5]
            state = c.get("conn_state", "")[:7]
            ob = str(c.get("orig_ip_bytes", 0))
            rb = str(c.get("resp_ip_bytes", 0))
            for txt, width in [(ts, 18), (src, 18), (dst, 18), (proto, 6),
                                (state, 8), (ob, 10), (rb, 10)]:
                tk.Label(row, text=txt, fg=TEXT_MID, bg=bg,
                         font=FONT_MONO, width=width, anchor="w").pack(side="left")

    # ── DNS/TLS TAB ──────────────────────────────────────
    def _build_dns(self, a):
        for w in self.tab_dns.winfo_children():
            w.destroy()
        top = tk.Frame(self.tab_dns, bg=BG_DARK)
        top.pack(fill="both", expand=True, padx=12, pady=8)
        top.columnconfigure(0, weight=1)
        top.columnconfigure(1, weight=1)
        top.columnconfigure(2, weight=1)
        top.rowconfigure(0, weight=1)
        top.rowconfigure(1, weight=1)

        # Top DNS queries
        dns_frame = tk.LabelFrame(top, text=" TOP DNS QUERIES ", fg=NEON_YELLOW,
                                   bg=BG_DARK, font=("Courier", 9, "bold"),
                                   highlightbackground=NEON_YELLOW, highlightthickness=1)
        dns_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        NeonBarChart(dns_frame, a.top_dns_queries(8), color=NEON_YELLOW).pack(fill="both", expand=True)

        # DNS rcodes
        rcode_frame = tk.LabelFrame(top, text=" DNS RESPONSE CODES ", fg=NEON_GREEN,
                                     bg=BG_DARK, font=("Courier", 9, "bold"),
                                     highlightbackground=NEON_GREEN, highlightthickness=1)
        rcode_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        NeonBarChart(rcode_frame, a.dns_rcode_dist(), color=NEON_GREEN).pack(fill="both", expand=True)

        # SSL versions
        ssl_frame = tk.LabelFrame(top, text=" TLS VERSIONS ", fg=NEON_PURPLE,
                                   bg=BG_DARK, font=("Courier", 9, "bold"),
                                   highlightbackground=NEON_PURPLE, highlightthickness=1)
        ssl_frame.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        NeonPieChart(ssl_frame, a.ssl_versions()).pack(fill="both", expand=True)

        # X.509 cert table
        cert_frame = tk.LabelFrame(top, text=" X.509 CERTIFICATES ", fg=NEON_CYAN,
                                    bg=BG_DARK, font=("Courier", 9, "bold"),
                                    highlightbackground=NEON_CYAN, highlightthickness=1)
        cert_frame.grid(row=1, column=0, columnspan=3, sticky="nsew", padx=5, pady=5)
        self._build_cert_table(cert_frame)

    def _build_cert_table(self, parent):
        certs = self._read_x509()
        cols = [("FINGERPRINT", 20), ("SUBJECT", 40), ("ISSUER", 30),
                ("NOT_BEFORE", 20), ("NOT_AFTER", 20)]
        hdr = tk.Frame(parent, bg=BG_PANEL)
        hdr.pack(fill="x")
        for col, w in cols:
            tk.Label(hdr, text=col, fg=NEON_CYAN, bg=BG_PANEL,
                     font=("Courier", 8, "bold"), width=w, anchor="w").pack(side="left")
        tk.Frame(parent, bg=NEON_CYAN, height=1).pack(fill="x")
        for i, c in enumerate(certs):
            bg = BG_CARD if i % 2 == 0 else "#110020"
            row = tk.Frame(parent, bg=bg)
            row.pack(fill="x")
            fp = c.get("fingerprint", "")[:18]
            subj = c.get("certificate.subject", "")[:38]
            issuer = c.get("certificate.issuer", "")[:28]
            nb = datetime.fromtimestamp(c.get("certificate.not_valid_before", 0)).strftime("%Y-%m-%d")
            na = datetime.fromtimestamp(c.get("certificate.not_valid_after", 0)).strftime("%Y-%m-%d")
            for txt, w2 in [(fp, 20), (subj, 40), (issuer, 30), (nb, 20), (na, 20)]:
                tk.Label(row, text=txt, fg=TEXT_MID, bg=bg,
                         font=FONT_MONO, width=w2, anchor="w").pack(side="left")

    # ── SURICATA TAB ─────────────────────────────────────
    def _build_suricata(self, a):
        for w in self.tab_suricata.winfo_children():
            w.destroy()
        stats = a.suricata_stats()
        fast_alerts = self.data.get("fast_alerts", [])
        eve_alerts  = self.data.get("eve_alerts", [])

        # ── Row 1: stat cards ──────────────────────────
        top = tk.Frame(self.tab_suricata, bg=BG_DARK)
        top.pack(fill="x", padx=12, pady=8)

        bytes_val = stats.get('bytes', 0)
        if bytes_val > 1e9:
            bytes_str = f"{bytes_val/1e9:.1f}GB"
        elif bytes_val > 1e6:
            bytes_str = f"{bytes_val/1e6:.1f}MB"
        else:
            bytes_str = f"{bytes_val/1e3:.1f}KB"

        items = [
            ("PACKETS",      f"{stats.get('pkts', 0):,}",         NEON_CYAN,   "▶"),
            ("BYTES RX",     bytes_str,                             NEON_PINK,   "⇩"),
            ("TCP DECODED",  f"{stats.get('tcp', 0):,}",           NEON_PURPLE, "⇄"),
            ("UDP DECODED",  f"{stats.get('udp', 0):,}",           NEON_YELLOW, "◆"),
            ("TLS FLOWS",    f"{stats.get('tls_flows', 0):,}",     NEON_GREEN,  "🔒"),
            ("HTTP FLOWS",   f"{stats.get('http_flows', 0):,}",    NEON_CYAN,   "⬡"),
            ("ALERTS FIRED", f"{stats.get('alerts', 0):,}",        NEON_PINK,   "⚡"),
            ("RULES LOADED", f"{stats.get('rules_loaded', 0):,}",  TEXT_MID,    "◉"),
        ]
        for label, val, color, icon in items:
            StatCard(top, label, val, color=color, icon=icon).pack(
                side="left", fill="x", expand=True, padx=4)

        # ── Row 2: charts + alert table ───────────────
        mid = tk.Frame(self.tab_suricata, bg=BG_DARK)
        mid.pack(fill="both", expand=True, padx=12, pady=4)
        mid.columnconfigure(0, weight=1)
        mid.columnconfigure(1, weight=1)
        mid.columnconfigure(2, weight=2)
        mid.rowconfigure(0, weight=1)

        # App layer pie
        app_frame = tk.LabelFrame(mid, text=" APP LAYER FLOWS ", fg=NEON_CYAN,
                                   bg=BG_DARK, font=("Courier", 9, "bold"),
                                   highlightbackground=NEON_CYAN, highlightthickness=1)
        app_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        app_data = [
            ("TLS",  stats.get("tls_flows", 0)),
            ("DNS",  stats.get("dns_flows", 0)),
            ("HTTP", stats.get("http_flows", 0)),
        ]
        NeonPieChart(app_frame, app_data,
                     colors=[NEON_PURPLE, NEON_YELLOW, NEON_GREEN]).pack(fill="both", expand=True)

        # Top alert signatures bar chart (from eve_alerts)
        sig_counter = Counter()
        for ea in eve_alerts:
            sig = ea.get("alert", {}).get("signature", "unknown")
            # Shorten for display
            sig_counter[sig[:25]] += 1
        top_sigs = sig_counter.most_common(6)

        sig_frame = tk.LabelFrame(mid, text=" TOP SIGNATURES (eve.json) ", fg=NEON_PINK,
                                   bg=BG_DARK, font=("Courier", 9, "bold"),
                                   highlightbackground=NEON_PINK, highlightthickness=1)
        sig_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        NeonBarChart(sig_frame, top_sigs, color=NEON_PINK).pack(fill="both", expand=True)

        # Fast.log + eve alerts combined table
        fast_frame = tk.LabelFrame(mid, text=f" ⚡ ALERTS  (eve:{len(eve_alerts)}  fast:{len(fast_alerts)}) ",
                                    fg=NEON_PINK, bg=BG_DARK, font=("Courier", 9, "bold"),
                                    highlightbackground=NEON_PINK, highlightthickness=1)
        fast_frame.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)

        # Header
        hdr = tk.Frame(fast_frame, bg=BG_PANEL)
        hdr.pack(fill="x")
        for col, w in [("SOURCE", 8), ("TIME", 20), ("SID/SIG", 60)]:
            tk.Label(hdr, text=col, fg=NEON_PURPLE, bg=BG_PANEL,
                     font=("Courier", 8, "bold"), width=w, anchor="w").pack(side="left")
        tk.Frame(fast_frame, bg=NEON_PINK, height=1).pack(fill="x")

        canvas2 = tk.Canvas(fast_frame, bg=BG_CARD, highlightthickness=0)
        vsb2 = tk.Scrollbar(fast_frame, orient="vertical", command=canvas2.yview,
                             bg=BG_DARK, troughcolor=BG_PANEL)
        canvas2.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side="right", fill="y")
        canvas2.pack(fill="both", expand=True)
        inner = tk.Frame(canvas2, bg=BG_CARD)
        inner.bind("<Configure>", lambda e: canvas2.configure(scrollregion=canvas2.bbox("all")))
        canvas2.create_window((0, 0), window=inner, anchor="nw")

        # Combine eve_alerts + fast_alerts into one list, newest first
        combined = []
        SEV_COLORS = {1: ALERT_RED, 2: NEON_ORANGE, 3: ALERT_YELLOW}
        for ea in reversed(eve_alerts[-60:]):
            combined.append({
                "source": "EVE",
                "ts": ea.get("timestamp", "")[:19],
                "msg": ea.get("alert", {}).get("signature", "")[:58],
                "sev": ea.get("alert", {}).get("severity", 3),
            })
        for fa in reversed(fast_alerts[-60:]):
            combined.append({
                "source": "FAST",
                "ts": fa.get("ts", "")[:19],
                "msg": f"[{fa.get('sid','')}] {fa.get('msg','')}",
                "sev": 3,
            })
        # Sort by ts descending
        combined.sort(key=lambda x: x["ts"], reverse=True)

        for i, item in enumerate(combined[:80]):
            bg = BG_CARD if i % 2 == 0 else "#110020"
            color = SEV_COLORS.get(item["sev"], TEXT_DIM)
            row2 = tk.Frame(inner, bg=bg)
            row2.pack(fill="x")
            tk.Label(row2, text=item["source"], fg=NEON_PURPLE, bg=bg,
                     font=FONT_MONO, width=8, anchor="w").pack(side="left")
            tk.Label(row2, text=item["ts"], fg=TEXT_DIM, bg=bg,
                     font=FONT_MONO, width=20, anchor="w").pack(side="left")
            tk.Label(row2, text=item["msg"][:60], fg=color, bg=bg,
                     font=FONT_MONO, anchor="w").pack(side="left", fill="x", expand=True)

        # ── Row 3: files found debug panel ───────────
        files_frame = tk.LabelFrame(self.tab_suricata,
                                     text=" ◉ FILES FOUND (click [ + SURICATA DIR ] to add folder) ",
                                     fg=NEON_CYAN, bg=BG_DARK, font=("Courier", 9, "bold"),
                                     highlightbackground=NEON_CYAN, highlightthickness=1)
        files_frame.pack(fill="x", padx=12, pady=(0, 4))
        files_row = tk.Frame(files_frame, bg=BG_DARK)
        files_row.pack(fill="x", padx=6, pady=4)

        found = self._last_parser.found_files() if self._last_parser else []
        suricata_found = {f: p for f, p in found if f in LogParser.SURICATA_FILES}
        zeek_found     = {f: p for f, p in found if f in LogParser.ZEEK_FILES}

        # Suricata files column
        sc = tk.Frame(files_row, bg=BG_DARK)
        sc.pack(side="left", fill="x", expand=True)
        tk.Label(sc, text="SURICATA FILES:", fg=NEON_PINK, bg=BG_DARK,
                 font=("Courier", 8, "bold")).pack(anchor="w")
        for fname in LogParser.SURICATA_FILES:
            if fname in suricata_found:
                fc = NEON_GREEN
                txt_lbl = f"  ✓ {fname}  ->  {suricata_found[fname]}"
            else:
                fc = ALERT_RED
                txt_lbl = f"  ✗ {fname}  (not found)"
            tk.Label(sc, text=txt_lbl, fg=fc, bg=BG_DARK,
                     font=("Courier", 8), anchor="w").pack(anchor="w")

        # Zeek files column
        zc = tk.Frame(files_row, bg=BG_DARK)
        zc.pack(side="left", fill="x", expand=True)
        tk.Label(zc, text="ZEEK FILES:", fg=NEON_YELLOW, bg=BG_DARK,
                 font=("Courier", 8, "bold")).pack(anchor="w")
        for fname in LogParser.ZEEK_FILES[:6]:
            if fname in zeek_found:
                fc = NEON_GREEN
                txt_lbl = f"  ✓ {fname}  ->  {zeek_found[fname]}"
            else:
                fc = TEXT_DIM
                txt_lbl = f"  - {fname}  (not found)"
            tk.Label(zc, text=txt_lbl, fg=fc, bg=BG_DARK,
                     font=("Courier", 8), anchor="w").pack(anchor="w")

        # ── Row 3: suricata.log viewer ─────────────────
        log_frame = tk.LabelFrame(self.tab_suricata,
                                   text=" ▶ SURICATA.LOG ", fg=NEON_CYAN,
                                   bg=BG_DARK, font=("Courier", 9, "bold"),
                                   highlightbackground=NEON_CYAN, highlightthickness=1)
        log_frame.pack(fill="x", padx=12, pady=(0, 8))

        log_canvas = tk.Canvas(log_frame, bg=BG_CARD, highlightthickness=0, height=90)
        log_vsb = tk.Scrollbar(log_frame, orient="vertical", command=log_canvas.yview,
                                bg=BG_DARK, troughcolor=BG_PANEL)
        log_canvas.configure(yscrollcommand=log_vsb.set)
        log_vsb.pack(side="right", fill="y")
        log_canvas.pack(fill="both", expand=True)
        log_inner = tk.Frame(log_canvas, bg=BG_CARD)
        log_inner.bind("<Configure>", lambda e: log_canvas.configure(scrollregion=log_canvas.bbox("all")))
        log_canvas.create_window((0, 0), window=log_inner, anchor="nw")

        suri_log = self.data.get("suricata_log", [])
        if not suri_log:
            tk.Label(log_inner, text="  (suricata.log not found or empty)",
                     fg=TEXT_DIM, bg=BG_CARD, font=FONT_MONO).pack(anchor="w", padx=6)
        else:
            for i, line in enumerate(suri_log[-50:]):
                bg = BG_CARD if i % 2 == 0 else "#110020"
                # Color by log level
                if "Error" in line or "error" in line:
                    fc = ALERT_RED
                elif "Warning" in line or "Warn" in line:
                    fc = NEON_ORANGE
                elif "Notice" in line:
                    fc = NEON_CYAN
                else:
                    fc = TEXT_DIM
                tk.Label(log_inner, text=line[:120], fg=fc, bg=bg,
                         font=("Courier", 8), anchor="w").pack(fill="x", padx=4)


# ─── ENTRY POINT ─────────────────────────────────────────

def main():
    log_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    if not os.path.isdir(log_dir):
        print(f"Error: '{log_dir}' is not a valid directory.")
        sys.exit(1)

    # Auto-check: if no known logs found in log_dir, ask user to pick
    test_parser = LogParser(log_dir)
    if not test_parser.found_files():
        # Show a minimal Tk root to ask for directory
        import tkinter as tk
        from tkinter import filedialog, messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(
            "NEON GRID - Select Log Directory",
            "No log files found in the current directory.\n\n"
            "Please select the folder containing your Suricata/Zeek logs.\n"
            "(Supports flat layout or zeek/ + suricata/ subfolders)"
        )
        chosen = filedialog.askdirectory(title="Select Log Directory")
        root.destroy()
        if chosen:
            log_dir = chosen
        else:
            sys.exit(0)

    app = NeonDashboard(log_dir=log_dir)
    app.mainloop()


if __name__ == "__main__":
    main()
