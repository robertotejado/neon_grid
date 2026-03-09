#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║  NEON GRID - Network Threat Intelligence Dashboard       ║
║  Web Edition  |  Powered by Suricata + Zeek              ║
╚══════════════════════════════════════════════════════════╝
Usage:
  python3 neon_dashboard_web.py [log_dir] [--port 5000]
  python3 neon_dashboard_web.py --suricata /logs/suricata --zeek /logs/zeek
"""

import os, sys, re, json, argparse, threading, time
from datetime import datetime
from collections import Counter
from flask import Flask, render_template_string, jsonify, request

# ─── LOG PARSER ──────────────────────────────────────────────────────────────

class LogParser:
    ZEEK_FILES     = ["conn.log","dns.log","http.log","ssl.log","dhcp.log",
                      "weird.log","x509.log","notice.log","files.log","known_services.log"]
    SURICATA_FILES = ["eve.json","fast.log","suricata.log","stats.log"]
    ALL_FILES      = ZEEK_FILES + SURICATA_FILES

    def __init__(self, log_dir=".", extra_dirs=None):
        self.log_dir    = os.path.normpath(os.path.abspath(log_dir))
        self.extra_dirs = [(lbl, os.path.normpath(os.path.abspath(p)))
                           for lbl, p in (extra_dirs or [])]
        self._file_map  = self._build_file_map()

    def _build_file_map(self):
        fmap, search_dirs = {}, []
        for _lbl, d in self.extra_dirs:
            if os.path.isdir(d) and d not in search_dirs:
                search_dirs.append(d)
        if self.log_dir not in search_dirs:
            search_dirs.append(self.log_dir)
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
        data = {
            "connections": self._read_jsonl("conn.log"),
            "dns":         self._read_jsonl("dns.log"),
            "http":        self._read_jsonl("http.log"),
            "ssl":         self._read_jsonl("ssl.log"),
            "dhcp":        self._read_jsonl("dhcp.log"),
            "weird":       self._read_jsonl("weird.log"),
            "x509":        self._read_jsonl("x509.log"),
            "notice":      self._read_jsonl("notice.log"),
            "eve_alerts":  [],
            "eve_stats":   None,
            "fast_alerts": [],
            "suricata_log": [],
            "suricata_stats_text": {},
        }
        self._parse_eve(data)
        self._parse_fast(data)
        self._parse_suricata_log(data)
        self._parse_stats_log(data)
        return data

    def _parse_eve(self, data):
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
                            data["eve_alerts"].append(rec)
                        elif et == "stats":
                            data["eve_stats"] = rec.get("stats", {})
                    except Exception:
                        pass
        except OSError:
            pass

    def _parse_fast(self, data):
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
                        data["fast_alerts"].append({
                            "ts": m.group(1), "sid": m.group(2),
                            "msg": m.group(3), "raw": line.strip()
                        })
        except OSError:
            pass

    def _parse_suricata_log(self, data):
        path = self._resolved("suricata.log")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        data["suricata_log"].append(line)
        except OSError:
            pass

    def _parse_stats_log(self, data):
        path = self._resolved("stats.log")
        if not path:
            return
        stats = {}
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if "|" not in line or line.startswith("-") or line.startswith("Counter"):
                        continue
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) == 3 and parts[1] == "Total":
                        try:
                            stats[parts[0]] = int(parts[2])
                        except ValueError:
                            pass
            data["suricata_stats_text"] = stats
        except OSError:
            pass


# ─── DATA CACHE ──────────────────────────────────────────────────────────────

class DataCache:
    def __init__(self, log_dir=".", extra_dirs=None, ttl=30):
        self.log_dir    = log_dir
        self.extra_dirs = extra_dirs or []
        self.ttl        = ttl
        self._data      = None
        self._analytics = None
        self._parser    = None
        self._ts        = 0
        self._lock      = threading.Lock()

    def update_dirs(self, log_dir=None, extra_dirs=None):
        with self._lock:
            if log_dir is not None:
                self.log_dir = log_dir
            if extra_dirs is not None:
                self.extra_dirs = extra_dirs
            self._ts = 0

    def get(self):
        with self._lock:
            if self._data is None or (time.time() - self._ts) > self.ttl:
                self._parser    = LogParser(self.log_dir, self.extra_dirs)
                self._data      = self._parser.parse_all()
                self._analytics = Analytics(self._data)
                self._ts        = time.time()
            return self._analytics, self._data, self._parser


# ─── ANALYTICS ───────────────────────────────────────────────────────────────

class Analytics:
    def __init__(self, data):
        self.d = data

    def _ev(self, jv, tk):
        t = self.d.get("suricata_stats_text") or {}
        return jv if jv else t.get(tk, 0)

    def summary(self):
        sev = Counter(a.get("alert",{}).get("severity",0) for a in self.d["eve_alerts"])
        s   = self.d.get("eve_stats") or {}
        dec = s.get("decoder", {})
        return {
            "total_conn":   len(self.d["connections"]),
            "total_alerts": len(self.d["eve_alerts"]) + len(self.d["fast_alerts"]),
            "total_dns":    len(self.d["dns"]),
            "total_ssl":    len(self.d["ssl"]),
            "total_http":   len(self.d["http"]),
            "total_weird":  len(self.d["weird"]),
            "unique_src":   len({c.get("id.orig_h") for c in self.d["connections"] if c.get("id.orig_h")}),
            "unique_dst":   len({c.get("id.resp_h") for c in self.d["connections"] if c.get("id.resp_h")}),
            "total_bytes":  sum(c.get("orig_ip_bytes",0)+c.get("resp_ip_bytes",0) for c in self.d["connections"]),
            "sev_crit":     sev.get(1, 0),
            "sev_high":     sev.get(2, 0),
            "sev_med":      sev.get(3, 0),
            "pkts":         self._ev(dec.get("pkts",0), "decoder.pkts"),
            "rules_loaded": (s.get("detect",{}).get("engines") or [{}])[0].get("rules_loaded",0),
        }

    def top_src_ips(self, n=10):
        c = Counter(x.get("id.orig_h") for x in self.d["connections"] if x.get("id.orig_h"))
        return [{"ip": k, "count": v} for k, v in c.most_common(n)]

    def top_dst_ips(self, n=10):
        c = Counter(x.get("id.resp_h") for x in self.d["connections"] if x.get("id.resp_h"))
        return [{"ip": k, "count": v} for k, v in c.most_common(n)]

    def top_dst_ports(self, n=10):
        c = Counter(str(x.get("id.resp_p")) for x in self.d["connections"] if x.get("id.resp_p"))
        return [{"port": k, "count": v} for k, v in c.most_common(n)]

    def proto_dist(self):
        c = Counter(x.get("proto","?") for x in self.d["connections"])
        return [{"proto": k, "count": v} for k, v in c.most_common()]

    def conn_states(self, n=10):
        c = Counter(x.get("conn_state","?") for x in self.d["connections"])
        return [{"state": k, "count": v} for k, v in c.most_common(n)]

    def alert_categories(self, n=10):
        c = Counter(a.get("alert",{}).get("category","Unknown") for a in self.d["eve_alerts"])
        return [{"cat": k, "count": v} for k, v in c.most_common(n)]

    def alert_sev_dist(self):
        c = Counter(a.get("alert",{}).get("severity",0) for a in self.d["eve_alerts"])
        return [{"sev": k, "count": v} for k, v in sorted(c.items())]

    def top_dns(self, n=10):
        c = Counter(r.get("query") for r in self.d["dns"] if r.get("query"))
        return [{"query": k, "count": v} for k, v in c.most_common(n)]

    def dns_rcodes(self, n=10):
        c = Counter(str(r.get("rcode_name", r.get("rcode","?")))
                    for r in self.d["dns"]
                    if r.get("rcode_name") or r.get("rcode") is not None)
        return [{"rcode": k, "count": v} for k, v in c.most_common(n)]

    def ssl_versions(self, n=10):
        c = Counter(r.get("version","?") for r in self.d["ssl"])
        return [{"version": k, "count": v} for k, v in c.most_common(n)]

    def weird_names(self, n=10):
        c = Counter(r.get("name","?") for r in self.d["weird"])
        return [{"name": k, "count": v} for k, v in c.most_common(n)]

    def recent_alerts(self, n=25):
        alerts = []
        for a in self.d["eve_alerts"][-n:]:
            alerts.append({
                "ts":    a.get("timestamp","")[:19],
                "src":   f"{a.get('src_ip','')}:{a.get('src_port','')}",
                "dst":   f"{a.get('dest_ip','')}:{a.get('dest_port','')}",
                "msg":   a.get("alert",{}).get("signature","")[:80],
                "sev":   a.get("alert",{}).get("severity",0),
                "cat":   a.get("alert",{}).get("category",""),
                "proto": a.get("proto",""),
            })
        for fa in self.d["fast_alerts"][-5:]:
            alerts.append({"ts":fa.get("ts","")[:19],"src":"","dst":"",
                           "msg":fa.get("msg","")[:80],"sev":3,"cat":"","proto":""})
        return list(reversed(alerts[-n:]))

    def recent_conns(self, n=30):
        rows = []
        for c in reversed(self.d["connections"][-n:]):
            try:
                ts = datetime.fromtimestamp(c.get("ts",0)).strftime("%m-%d %H:%M:%S")
            except Exception:
                ts = ""
            rows.append({
                "ts": ts,
                "src": f"{c.get('id.orig_h','')}:{c.get('id.orig_p','')}",
                "dst": f"{c.get('id.resp_h','')}:{c.get('id.resp_p','')}",
                "proto": c.get("proto",""), "state": c.get("conn_state",""),
                "ob": c.get("orig_ip_bytes",0), "rb": c.get("resp_ip_bytes",0),
            })
        return rows

    def certs(self):
        rows = []
        for c in self.d.get("x509",[]):
            try:
                nb = datetime.fromtimestamp(c.get("certificate.not_valid_before",0)).strftime("%Y-%m-%d")
                na = datetime.fromtimestamp(c.get("certificate.not_valid_after",0)).strftime("%Y-%m-%d")
            except Exception:
                nb = na = ""
            rows.append({
                "fp":      c.get("fingerprint","")[:16],
                "subject": c.get("certificate.subject","")[:50],
                "issuer":  c.get("certificate.issuer","")[:40],
                "nb": nb, "na": na,
            })
        return rows

    def fast_alerts_list(self, n=30):
        return list(reversed(self.d.get("fast_alerts",[])[-n:]))

    def app_layer(self):
        s  = self.d.get("eve_stats") or {}
        fl = s.get("app_layer",{}).get("flow",{})
        return [
            {"proto":"TLS",  "count": self._ev(fl.get("tls",0),     "app_layer.flow.tls")},
            {"proto":"DNS",  "count": self._ev(fl.get("dns_udp",0), "app_layer.flow.dns_udp")},
            {"proto":"HTTP", "count": self._ev(fl.get("http",0),    "app_layer.flow.http")},
            {"proto":"DHCP", "count": self._ev(fl.get("dhcp",0),    "app_layer.flow.dhcp")},
        ]

    def suricata_summary(self):
        s   = self.d.get("eve_stats") or {}
        dec = s.get("decoder",{})
        det = s.get("detect",{})
        return {
            "pkts":   self._ev(dec.get("pkts",0),   "decoder.pkts"),
            "bytes":  self._ev(dec.get("bytes",0),  "decoder.bytes"),
            "tcp":    self._ev(dec.get("tcp",0),    "decoder.tcp"),
            "udp":    self._ev(dec.get("udp",0),    "decoder.udp"),
            "alerts": self._ev(det.get("alert",0),  "detect.alert"),
            "rules":  (det.get("engines") or [{}])[0].get("rules_loaded",0),
        }

    def alert_signatures(self, n=8):
        c = Counter(
            a.get("alert",{}).get("signature","unknown")[:35]
            for a in self.d["eve_alerts"]
        )
        return [{"sig": k, "count": v} for k, v in c.most_common(n)]

    def files_status(self, parser):
        found = dict(parser.found_files())
        result = []
        for fname in LogParser.SURICATA_FILES + LogParser.ZEEK_FILES:
            if fname in found:
                result.append({"file": fname, "path": found[fname], "found": True})
            else:
                result.append({"file": fname, "path": "", "found": False})
        return result


# ─── HTML TEMPLATE ───────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>◈ NEON GRID — Network Threat Intelligence</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
:root{--bg:#050008;--bg2:#0a0012;--bg3:#0f001a;--pink:#ff2d78;--cyan:#00f5ff;--purple:#bf00ff;--yellow:#ffe600;--green:#00ff9f;--orange:#ff6b00;--red:#ff0044;--dim:#663388;--mid:#cc88ff;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:#fff;font-family:'Share Tech Mono',monospace;min-height:100vh;overflow-x:hidden;}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.07) 2px,rgba(0,0,0,.07) 4px);pointer-events:none;z-index:9999;}
body::after{content:'';position:fixed;inset:0;background-image:linear-gradient(#150028 1px,transparent 1px),linear-gradient(90deg,#150028 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0;}

/* HEADER */
header{position:relative;z-index:10;background:linear-gradient(180deg,#0a001a,var(--bg));border-bottom:1px solid var(--purple);padding:10px 20px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 0 30px rgba(191,0,255,.3);}
.logo{font-family:'Orbitron',sans-serif;font-weight:900;font-size:1.6rem;letter-spacing:.15em;background:linear-gradient(90deg,var(--pink),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;filter:drop-shadow(0 0 10px var(--pink));}
.logo-sub{font-size:.6rem;color:var(--purple);letter-spacing:.3em;margin-top:2px;}
.hdr-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
#clock{font-size:.75rem;color:var(--cyan);}

/* DIR BAR */
.dir-bar{position:relative;z-index:10;background:var(--bg2);border-bottom:1px solid #1a0030;padding:6px 20px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.dir-lbl{font-size:.65rem;color:var(--dim);white-space:nowrap;}
.dir-val{font-size:.65rem;color:var(--mid);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}

/* BUTTONS */
.neon-btn{background:transparent;border:1px solid;font-family:'Share Tech Mono',monospace;font-size:.7rem;padding:5px 12px;cursor:pointer;letter-spacing:.08em;transition:all .2s;}
.neon-btn:hover{filter:brightness(1.5);box-shadow:0 0 10px currentColor;}
.btn-cyan{border-color:var(--cyan);color:var(--cyan);}
.btn-pink{border-color:var(--pink);color:var(--pink);}
.btn-green{border-color:var(--green);color:var(--green);}
.btn-orange{border-color:var(--orange);color:var(--orange);}

/* MODAL */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:1000;align-items:center;justify-content:center;}
.modal-overlay.open{display:flex;}
.modal{background:var(--bg3);border:1px solid var(--cyan);box-shadow:0 0 40px rgba(0,245,255,.2);padding:26px;min-width:440px;max-width:620px;width:92%;}
.modal h3{font-family:'Orbitron',sans-serif;color:var(--cyan);margin-bottom:14px;font-size:.85rem;letter-spacing:.2em;text-shadow:0 0 10px var(--cyan);}
.modal p{font-size:.68rem;color:var(--dim);margin-bottom:14px;line-height:1.6;}
.modal label{display:block;font-size:.65rem;color:var(--dim);margin-bottom:3px;letter-spacing:.1em;text-transform:uppercase;}
.modal input[type=text]{width:100%;background:#0a0018;border:1px solid var(--purple);color:var(--mid);font-family:'Share Tech Mono',monospace;font-size:.72rem;padding:7px 10px;margin-bottom:10px;outline:none;}
.modal input[type=text]:focus{border-color:var(--cyan);}
.modal-btns{display:flex;gap:8px;justify-content:flex-end;margin-top:6px;}

/* TABS */
.tabs{position:relative;z-index:10;display:flex;gap:1px;background:var(--bg2);padding:0 16px;border-bottom:1px solid #1a0030;}
.tab-btn{background:transparent;border:none;border-bottom:2px solid transparent;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:.76rem;padding:9px 14px;cursor:pointer;letter-spacing:.1em;transition:all .2s;text-transform:uppercase;}
.tab-btn:hover{color:var(--mid);}
.tab-btn.active{color:var(--pink);border-bottom-color:var(--pink);text-shadow:0 0 10px var(--pink);}

/* MAIN */
main{position:relative;z-index:5;padding:13px 17px;padding-bottom:38px;}
.tab-pane{display:none;}
.tab-pane.active{display:block;}

/* STAT CARDS */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:13px;}
.stat-card{background:var(--bg3);border:1px solid;padding:10px 12px;position:relative;overflow:hidden;transition:transform .2s;}
.stat-card:hover{transform:translateY(-2px);}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:currentColor;box-shadow:0 0 10px currentColor;}
.stat-icon{font-size:1.1rem;margin-bottom:2px;display:block;}
.stat-value{font-family:'Orbitron',sans-serif;font-size:1.25rem;font-weight:700;}
.stat-label{font-size:.58rem;color:var(--dim);letter-spacing:.12em;text-transform:uppercase;margin-top:2px;}

/* CHARTS */
.chart-row{display:grid;gap:10px;margin-bottom:11px;}
.cr3{grid-template-columns:repeat(3,1fr);}
.cr2{grid-template-columns:2fr 1fr;}
.cr21{grid-template-columns:2fr 1fr;}
.cr1{grid-template-columns:1fr;}
.chart-card{background:var(--bg3);border:1px solid #1a0030;padding:10px;}
.chart-title{font-size:.63rem;letter-spacing:.18em;text-transform:uppercase;margin-bottom:7px;padding-bottom:4px;border-bottom:1px solid #1a0030;}
canvas{display:block;width:100%!important;}

/* TABLES */
.data-table{width:100%;border-collapse:collapse;font-size:.66rem;}
.data-table th{background:var(--bg2);color:var(--purple);font-size:.6rem;letter-spacing:.1em;text-transform:uppercase;padding:5px 6px;text-align:left;border-bottom:1px solid var(--purple);}
.data-table td{padding:3px 6px;color:var(--mid);border-bottom:1px solid #150028;font-family:'Share Tech Mono',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px;}
.data-table tr:nth-child(even) td{background:rgba(255,255,255,.012);}
.data-table tr:hover td{background:rgba(191,0,255,.08);color:#fff;}
.tbl-wrap{max-height:270px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--purple) var(--bg2);}
.sev-1{color:var(--red)!important;} .sev-2{color:var(--orange)!important;} .sev-3{color:var(--yellow)!important;} .sev-0{color:var(--dim)!important;}

/* FILES */
.files-2col{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.file-row{display:flex;align-items:center;gap:6px;padding:3px 0;border-bottom:1px solid #150028;}
.fdot{width:7px;height:7px;border-radius:50%;flex-shrink:0;}
.fdot-ok{background:var(--green);box-shadow:0 0 5px var(--green);}
.fdot-miss{background:#2a0040;}
.fname{color:var(--mid);min-width:128px;font-size:.65rem;}
.fpath{color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.6rem;}

/* STATUS */
#statusbar{position:fixed;bottom:0;left:0;right:0;z-index:100;background:var(--bg2);border-top:1px solid var(--purple);padding:3px 14px;font-size:.62rem;color:var(--cyan);display:flex;justify-content:space-between;}

/* HORIZON */
.horizon{position:fixed;bottom:22px;left:0;right:0;height:90px;pointer-events:none;z-index:1;overflow:hidden;opacity:.1;}
.h-sun{width:140px;height:70px;border-radius:70px 70px 0 0;background:linear-gradient(180deg,#ffe600,#ff6b00 40%,#ff2d78);position:absolute;bottom:0;left:50%;transform:translateX(-50%);box-shadow:0 0 50px 16px #ff2d78;}
.h-line{position:absolute;bottom:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,#ff2d78 30%,#ffe600 50%,#ff2d78 70%,transparent);}

@media(max-width:900px){.cr3{grid-template-columns:1fr 1fr;}.cr2,.cr21{grid-template-columns:1fr;}}
@media(max-width:580px){.cr3,.cr2,.cr21{grid-template-columns:1fr;}.stat-grid{grid-template-columns:repeat(2,1fr);}.files-2col{grid-template-columns:1fr;}}
</style>
</head>
<body>
<div class="horizon"><div class="h-sun"></div><div class="h-line"></div></div>

<header>
  <div>
    <div class="logo">◈ NEON GRID</div>
    <div class="logo-sub">Network Threat Intelligence — Suricata + Zeek</div>
  </div>
  <div class="hdr-right">
    <span id="clock"></span>
    <button class="neon-btn btn-cyan" onclick="openModal()">⊕ FOLDERS</button>
    <button class="neon-btn btn-green" onclick="loadAll()">⟳ RELOAD</button>
  </div>
</header>

<div class="dir-bar">
  <span class="dir-lbl">ROOT:</span><span class="dir-val" id="lbl-root">—</span>
  <span class="dir-lbl" style="margin-left:10px">SURICATA:</span><span class="dir-val" id="lbl-suri">—</span>
  <span class="dir-lbl" style="margin-left:10px">ZEEK:</span><span class="dir-val" id="lbl-zeek">—</span>
</div>

<!-- MODAL -->
<div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <h3>⊕ CONFIGURE LOG DIRECTORIES</h3>
    <p>Set the path(s) where your logs live. Supports flat layout or separate suricata/ and zeek/ folders. Leave blank to skip that source. Changes apply immediately (no server restart needed).</p>
    <label>ROOT DIRECTORY (auto-searches subdirs)</label>
    <input type="text" id="inp-root" placeholder="e.g.  C:\Users\...\logs   or   /var/log">
    <label>SURICATA FOLDER (eve.json, fast.log, stats.log, suricata.log)</label>
    <input type="text" id="inp-suri" placeholder="e.g.  C:\Users\...\logs\suricata">
    <label>ZEEK FOLDER (conn.log, dns.log, ssl.log ...)</label>
    <input type="text" id="inp-zeek" placeholder="e.g.  C:\Users\...\logs\zeek">
    <div class="modal-btns">
      <button class="neon-btn btn-orange" onclick="closeModal()">CANCEL</button>
      <button class="neon-btn btn-green" onclick="applyDirs()">✓ APPLY &amp; RELOAD</button>
    </div>
  </div>
</div>

<div class="tabs">
  <button class="tab-btn active" onclick="showTab('overview',this)">◉ OVERVIEW</button>
  <button class="tab-btn" onclick="showTab('alerts',this)">⚡ ALERTS</button>
  <button class="tab-btn" onclick="showTab('network',this)">◈ NETWORK</button>
  <button class="tab-btn" onclick="showTab('dns',this)">◆ DNS/TLS</button>
  <button class="tab-btn" onclick="showTab('suricata',this)">▶ SURICATA</button>
  <button class="tab-btn" onclick="showTab('files',this)">◌ FILES</button>
</div>

<main>

<div id="tab-overview" class="tab-pane active">
  <div id="ov-cards" class="stat-grid"></div>
  <div class="chart-row cr3">
    <div class="chart-card" style="border-color:var(--cyan)"><div class="chart-title" style="color:var(--cyan)">TOP SOURCE IPs</div><canvas id="c-src" height="185"></canvas></div>
    <div class="chart-card" style="border-color:var(--pink)"><div class="chart-title" style="color:var(--pink)">TOP DEST IPs</div><canvas id="c-dst" height="185"></canvas></div>
    <div class="chart-card" style="border-color:var(--purple)"><div class="chart-title" style="color:var(--purple)">PROTOCOLS</div><canvas id="c-proto" height="185"></canvas></div>
  </div>
</div>

<div id="tab-alerts" class="tab-pane">
  <div id="al-cards" class="stat-grid"></div>
  <div class="chart-row cr2">
    <div class="chart-card" style="border-color:var(--pink)"><div class="chart-title" style="color:var(--pink)">ALERT CATEGORIES</div><canvas id="c-alcat" height="165"></canvas></div>
    <div class="chart-card" style="border-color:var(--orange)"><div class="chart-title" style="color:var(--orange)">SEVERITY DIST</div><canvas id="c-alsev" height="165"></canvas></div>
  </div>
  <div class="chart-card" style="border-color:var(--pink);margin-bottom:11px">
    <div class="chart-title" style="color:var(--pink)">⚡ RECENT ALERTS</div>
    <div class="tbl-wrap"><table class="data-table" id="tbl-al"><thead><tr><th>TIME</th><th>SRC</th><th>DST</th><th>S</th><th>CATEGORY</th><th>SIGNATURE</th></tr></thead><tbody></tbody></table></div>
  </div>
</div>

<div id="tab-network" class="tab-pane">
  <div class="chart-row cr3">
    <div class="chart-card" style="border-color:var(--cyan)"><div class="chart-title" style="color:var(--cyan)">TOP DEST PORTS</div><canvas id="c-ports" height="185"></canvas></div>
    <div class="chart-card" style="border-color:var(--yellow)"><div class="chart-title" style="color:var(--yellow)">CONN STATES</div><canvas id="c-states" height="185"></canvas></div>
    <div class="chart-card" style="border-color:var(--red)"><div class="chart-title" style="color:var(--red)">ZEEK WEIRD</div><canvas id="c-weird" height="185"></canvas></div>
  </div>
  <div class="chart-card" style="border-color:var(--cyan)">
    <div class="chart-title" style="color:var(--cyan)">◈ RECENT CONNECTIONS</div>
    <div class="tbl-wrap"><table class="data-table" id="tbl-conn"><thead><tr><th>TIME</th><th>SRC</th><th>DST</th><th>PROTO</th><th>STATE</th><th>ORIG B</th><th>RESP B</th></tr></thead><tbody></tbody></table></div>
  </div>
</div>

<div id="tab-dns" class="tab-pane">
  <div class="chart-row cr3">
    <div class="chart-card" style="border-color:var(--yellow)"><div class="chart-title" style="color:var(--yellow)">TOP DNS QUERIES</div><canvas id="c-dnsq" height="185"></canvas></div>
    <div class="chart-card" style="border-color:var(--green)"><div class="chart-title" style="color:var(--green)">DNS RCODES</div><canvas id="c-dnsr" height="185"></canvas></div>
    <div class="chart-card" style="border-color:var(--purple)"><div class="chart-title" style="color:var(--purple)">TLS VERSIONS</div><canvas id="c-tls" height="185"></canvas></div>
  </div>
  <div class="chart-card" style="border-color:var(--cyan)">
    <div class="chart-title" style="color:var(--cyan)">X.509 CERTIFICATES</div>
    <div class="tbl-wrap"><table class="data-table" id="tbl-cert"><thead><tr><th>FINGERPRINT</th><th>SUBJECT</th><th>ISSUER</th><th>FROM</th><th>TO</th></tr></thead><tbody></tbody></table></div>
  </div>
</div>

<div id="tab-suricata" class="tab-pane">
  <div id="su-cards" class="stat-grid"></div>
  <div class="chart-row cr21">
    <div class="chart-card" style="border-color:var(--pink)"><div class="chart-title" style="color:var(--pink)">⚡ TOP ALERT SIGNATURES</div><canvas id="c-sigs" height="185"></canvas></div>
    <div class="chart-card" style="border-color:var(--cyan)"><div class="chart-title" style="color:var(--cyan)">APP LAYER FLOWS</div><canvas id="c-app" height="185"></canvas></div>
  </div>
  <div class="chart-row cr2">
    <div class="chart-card" style="border-color:var(--pink)">
      <div class="chart-title" style="color:var(--pink)">FAST.LOG ALERTS</div>
      <div class="tbl-wrap"><table class="data-table" id="tbl-fast"><thead><tr><th>TIME</th><th>SID</th><th>MESSAGE</th></tr></thead><tbody></tbody></table></div>
    </div>
    <div class="chart-card" style="border-color:var(--dim)">
      <div class="chart-title" style="color:var(--mid)">▶ SURICATA.LOG</div>
      <div class="tbl-wrap" id="suri-log" style="max-height:220px"></div>
    </div>
  </div>
</div>

<div id="tab-files" class="tab-pane">
  <div class="chart-card" style="border-color:var(--cyan);margin-bottom:12px">
    <div class="chart-title" style="color:var(--cyan)">◉ LOG FILES DISCOVERY  <span style="color:var(--dim);font-size:.6rem">(green = found | grey = missing)</span></div>
    <div class="files-2col" id="files-list"></div>
  </div>
  <div class="chart-card" style="border-color:var(--purple)">
    <div class="chart-title" style="color:var(--purple)">SEARCH PATHS</div>
    <div id="search-paths" style="font-size:.68rem;color:var(--mid);line-height:2"></div>
  </div>
</div>

</main>

<div id="statusbar"><span id="status-msg">Initializing...</span><span id="status-time"></span></div>

<script>
const C={pink:'#ff2d78',cyan:'#00f5ff',purple:'#bf00ff',yellow:'#ffe600',green:'#00ff9f',orange:'#ff6b00',red:'#ff0044',dim:'#663388',mid:'#cc88ff'};
const PAL=[C.cyan,C.pink,C.purple,C.yellow,C.green,C.orange,C.red,C.mid];

// Clock
function tick(){const n=new Date();document.getElementById('clock').textContent=n.toISOString().replace('T',' ').substring(0,19)+' UTC';document.getElementById('status-time').textContent='⏱ '+n.toLocaleTimeString();}
setInterval(tick,1000);tick();

// Tabs
function showTab(name,btn){
  document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  if(btn)btn.classList.add('active');
}

// Modal
function openModal(){
  fetch('/api/dirs').then(r=>r.json()).then(d=>{
    document.getElementById('inp-root').value=d.root||'';
    document.getElementById('inp-suri').value=d.suricata||'';
    document.getElementById('inp-zeek').value=d.zeek||'';
  }).catch(()=>{});
  document.getElementById('modal').classList.add('open');
}
function closeModal(){document.getElementById('modal').classList.remove('open');}
function applyDirs(){
  const body={root:document.getElementById('inp-root').value.trim(),suricata:document.getElementById('inp-suri').value.trim(),zeek:document.getElementById('inp-zeek').value.trim()};
  fetch('/api/set_dirs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(r=>r.json()).then(()=>{closeModal();loadAll();})
    .catch(e=>{document.getElementById('status-msg').textContent='Error: '+e.message;});
}

// Canvas helpers
function prep(id){
  const el=document.getElementById(id);if(!el)return null;
  const ctx=el.getContext('2d');
  el.width=el.parentElement.clientWidth-20;
  ctx.clearRect(0,0,el.width,el.height);
  ctx.strokeStyle='#150028';ctx.lineWidth=1;
  for(let x=0;x<el.width;x+=30){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,el.height);ctx.stroke();}
  for(let y=0;y<el.height;y+=30){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(el.width,y);ctx.stroke();}
  return{ctx,w:el.width,h:el.height};
}
function bar(id,labels,vals,col){
  const r=prep(id);if(!r||!vals.length)return;
  const{ctx,w,h}=r;
  // Dynamic bottom padding based on longest label
  const maxLen=Math.max(...labels.map(l=>String(l).length));
  const pL=38,pR=10,pT=22,pB=Math.min(85,Math.max(48,maxLen*5));
  const cw=w-pL-pR,ch=h-pT-pB;
  if(ch<10)return;
  const max=Math.max(...vals)||1,n=labels.length;
  const slot=cw/n,bw=Math.max(6,slot*0.55);

  // Y-axis reference lines + labels
  ctx.setLineDash([3,6]);
  [1,.75,.5,.25].forEach(frac=>{
    const y=pT+ch-ch*frac;
    ctx.strokeStyle='#1a0040';ctx.lineWidth=1;
    ctx.beginPath();ctx.moveTo(pL,y);ctx.lineTo(w-pR,y);ctx.stroke();
    const rv=Math.round(max*frac);
    ctx.fillStyle='#553377';ctx.font='7px Share Tech Mono';ctx.textAlign='right';
    ctx.fillText(rv>=1000?(rv/1000).toFixed(1)+'k':rv,pL-3,y+3);
  });
  ctx.setLineDash([]);

  labels.forEach((lbl,i)=>{
    const v=vals[i],bh=Math.max(2,(v/max)*ch*0.92);
    const cx=pL+i*slot+slot/2,x=cx-bw/2,y=pT+ch-bh;

    // Glow
    ctx.shadowColor=col;ctx.shadowBlur=12;
    // Gradient fill
    const g=ctx.createLinearGradient(x,y,x,pT+ch);
    g.addColorStop(0,col+'ee');g.addColorStop(1,col+'22');
    ctx.fillStyle=g;ctx.fillRect(x,y,bw,bh);
    ctx.strokeStyle=col;ctx.lineWidth=1.5;ctx.strokeRect(x,y,bw,bh);
    ctx.shadowBlur=0;

    // Value above bar — large, bright
    const vs=v>=1000?(v/1000).toFixed(1)+'k':String(v);
    ctx.fillStyle='#ffffff';ctx.font='bold 9px Share Tech Mono';ctx.textAlign='center';
    ctx.fillText(vs,cx,y-5);

    // Diagonal label — rotated 40deg, full text, brighter color
    const full=String(lbl);
    const disp=full.length>20?full.substring(0,18)+'…':full;
    ctx.save();
    ctx.translate(cx+2, pT+ch+7);
    ctx.rotate(-0.7);  // ~40 degrees
    ctx.fillStyle='#cc88ff';
    ctx.font='9px Share Tech Mono';
    ctx.textAlign='right';
    ctx.fillText(disp,0,0);
    ctx.restore();
  });
}
function pie(id,labels,vals,colors){
  const r=prep(id);if(!r)return;
  const{ctx,w,h}=r,total=vals.reduce((a,b)=>a+b,0);if(!total)return;
  const cx=w/2+18,cy=h/2+8,rad=Math.min(w,h)/2-30;if(rad<10)return;
  let start=-Math.PI/2;
  labels.forEach((lbl,i)=>{
    const v=vals[i];if(!v)return;
    const sweep=(v/total)*2*Math.PI,col=(colors||PAL)[i%PAL.length];
    ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,rad,start,start+sweep);ctx.closePath();
    ctx.fillStyle=col+'33';ctx.fill();
    ctx.shadowColor=col;ctx.shadowBlur=9;ctx.strokeStyle=col;ctx.lineWidth=2;ctx.stroke();ctx.shadowBlur=0;
    const pct=Math.round(v/total*100),mid2=start+sweep/2;
    if(pct>=5){ctx.fillStyle=col;ctx.font='bold 8px Share Tech Mono';ctx.textAlign='center';ctx.fillText(pct+'%',cx+(rad+13)*Math.cos(mid2),cy+(rad+13)*Math.sin(mid2));}
    start+=sweep;
  });
  labels.forEach((lbl,i)=>{
    const col=(colors||PAL)[i%PAL.length],ly=13+i*14;
    ctx.fillStyle=col;ctx.fillRect(6,ly,8,8);
    ctx.fillStyle='#aa88cc';ctx.font='7px Share Tech Mono';ctx.textAlign='left';
    ctx.fillText(String(lbl).substring(0,16)+': '+vals[i],17,ly+7);
  });
}

// Helpers
function card(icon,val,lbl,col){return`<div class="stat-card" style="border-color:${col};color:${col}"><span class="stat-icon">${icon}</span><div class="stat-value" style="color:${col};text-shadow:0 0 10px ${col}">${val}</div><div class="stat-label">${lbl}</div></div>`;}
function fmtB(b){return b>1e9?(b/1e9).toFixed(2)+' GB':b>1e6?(b/1e6).toFixed(2)+' MB':b>1e3?(b/1e3).toFixed(1)+' KB':b+' B';}
async function get(url,fb=[]){try{const r=await fetch(url);if(!r.ok)return fb;return await r.json();}catch(e){console.warn(url,e);return fb;}}

// Main load - sequential fetches so one failure never blocks the rest
async function loadAll(){
  document.getElementById('status-msg').textContent='⏳ Parsing logs...';

  const[sum,srcI,dstI,proto,ports,states,alCat,alSev,dnsQ,dnsR,sslV,weird,
        alerts,conns,certs,fast,app,suri,dirs,files,suriLog,sigs]=
    await Promise.all([
      get('/api/summary',{}),get('/api/top_src_ips',[]),get('/api/top_dst_ips',[]),
      get('/api/proto_dist',[]),get('/api/top_ports',[]),get('/api/conn_states',[]),
      get('/api/alert_categories',[]),get('/api/alert_sev',[]),
      get('/api/top_dns',[]),get('/api/dns_rcodes',[]),get('/api/ssl_versions',[]),
      get('/api/weird',[]),get('/api/recent_alerts',[]),get('/api/recent_conns',[]),
      get('/api/certs',[]),get('/api/fast_alerts',[]),get('/api/app_layer',[]),
      get('/api/suricata_summary',{}),get('/api/dirs',{}),
      get('/api/files_status',[]),get('/api/suricata_log',[]),get('/api/alert_signatures',[]),
    ]);

  // Dir labels
  document.getElementById('lbl-root').textContent=dirs.root||'(not set)';
  document.getElementById('lbl-suri').textContent=dirs.suricata||'(auto)';
  document.getElementById('lbl-zeek').textContent=dirs.zeek||'(auto)';

  // Overview
  document.getElementById('ov-cards').innerHTML=[
    card('⇄',(sum.total_conn||0).toLocaleString(),'CONNECTIONS',C.cyan),
    card('⚡',(sum.total_alerts||0).toLocaleString(),'ALERTS',C.pink),
    card('◆',(sum.total_dns||0).toLocaleString(),'DNS QUERIES',C.yellow),
    card('🔒',(sum.total_ssl||0).toLocaleString(),'SSL/TLS',C.purple),
    card('⬡',(sum.total_http||0).toLocaleString(),'HTTP',C.green),
    card('◎',(sum.unique_src||0).toLocaleString(),'UNIQ SRC IPs',C.orange),
    card('◉',(sum.unique_dst||0).toLocaleString(),'UNIQ DST IPs',C.mid),
    card('⚠',(sum.total_weird||0).toLocaleString(),'WEIRD',C.red),
  ].join('');
  bar('c-src',srcI.map(x=>x.ip),srcI.map(x=>x.count),C.cyan);
  bar('c-dst',dstI.map(x=>x.ip),dstI.map(x=>x.count),C.pink);
  pie('c-proto',proto.map(x=>x.proto),proto.map(x=>x.count));

  // Alerts
  document.getElementById('al-cards').innerHTML=[
    card('⚡',sum.sev_crit||0,'CRITICAL (SEV1)',C.red),
    card('⚡',sum.sev_high||0,'HIGH (SEV2)',C.orange),
    card('⚡',sum.sev_med||0,'MEDIUM (SEV3)',C.yellow),
    card('◉',(sum.total_alerts||0).toLocaleString(),'TOTAL ALERTS',C.pink),
  ].join('');
  bar('c-alcat',alCat.map(x=>x.cat),alCat.map(x=>x.count),C.pink);
  const sc={1:C.red,2:C.orange,3:C.yellow,0:C.dim};
  pie('c-alsev',alSev.map(x=>'Sev'+x.sev),alSev.map(x=>x.count),alSev.map(x=>sc[x.sev]||C.mid));
  document.querySelector('#tbl-al tbody').innerHTML=alerts.map(a=>`<tr class="sev-${a.sev}"><td>${a.ts}</td><td>${a.src}</td><td>${a.dst}</td><td class="sev-${a.sev}">${a.sev}</td><td>${a.cat}</td><td title="${a.msg}">${a.msg.substring(0,60)}</td></tr>`).join('');

  // Network
  bar('c-ports',ports.map(x=>x.port),ports.map(x=>x.count),C.cyan);
  bar('c-states',states.map(x=>x.state),states.map(x=>x.count),C.yellow);
  bar('c-weird',weird.map(x=>x.name),weird.map(x=>x.count),C.red);
  document.querySelector('#tbl-conn tbody').innerHTML=conns.map(c=>`<tr><td>${c.ts}</td><td>${c.src}</td><td>${c.dst}</td><td>${c.proto}</td><td>${c.state}</td><td>${c.ob.toLocaleString()}</td><td>${c.rb.toLocaleString()}</td></tr>`).join('');

  // DNS/TLS
  bar('c-dnsq',dnsQ.map(x=>x.query),dnsQ.map(x=>x.count),C.yellow);
  bar('c-dnsr',dnsR.map(x=>x.rcode),dnsR.map(x=>x.count),C.green);
  pie('c-tls',sslV.map(x=>x.version),sslV.map(x=>x.count));
  document.querySelector('#tbl-cert tbody').innerHTML=certs.map(c=>`<tr><td>${c.fp}</td><td title="${c.subject}">${c.subject.substring(0,38)}</td><td title="${c.issuer}">${c.issuer.substring(0,30)}</td><td>${c.nb}</td><td>${c.na}</td></tr>`).join('');

  // Suricata
  document.getElementById('su-cards').innerHTML=[
    card('▶',(suri.pkts||0).toLocaleString(),'PACKETS',C.cyan),
    card('⇩',fmtB(suri.bytes||0),'BYTES RX',C.pink),
    card('⇄',(suri.tcp||0).toLocaleString(),'TCP',C.purple),
    card('◆',(suri.udp||0).toLocaleString(),'UDP',C.yellow),
    card('⚡',(suri.alerts||0).toLocaleString(),'ALERTS FIRED',C.red),
    card('◉',(suri.rules||0).toLocaleString(),'RULES LOADED',C.mid),
  ].join('');
  bar('c-sigs',sigs.map(x=>x.sig),sigs.map(x=>x.count),C.pink);
  pie('c-app',app.map(x=>x.proto),app.map(x=>x.count));
  document.querySelector('#tbl-fast tbody').innerHTML=fast.map(f=>`<tr class="sev-3"><td>${f.ts}</td><td>${f.sid}</td><td title="${f.msg}">${f.msg.substring(0,70)}</td></tr>`).join('');
  const lw=document.getElementById('suri-log');
  lw.innerHTML=suriLog.length
    ?suriLog.map((ln,i)=>{const col=ln.includes('Error')||ln.includes('error')?C.red:ln.includes('Warning')?C.orange:ln.includes('Notice')?C.cyan:C.dim;return`<div style="padding:1px 6px;font-size:.62rem;color:${col};background:${i%2?'rgba(255,255,255,.01)':'transparent'}">${ln.substring(0,115)}</div>`;}).join('')
    :'<div style="color:var(--dim);padding:8px;font-size:.68rem">(suricata.log not found)</div>';

  // Files tab
  const fm=Object.fromEntries((files||[]).map(x=>[x.file,x]));
  const mkRows=fnames=>fnames.map(fn=>{const x=fm[fn]||{found:false,path:''};return`<div class="file-row"><span class="fdot ${x.found?'fdot-ok':'fdot-miss'}"></span><span class="fname">${fn}</span><span class="fpath">${x.found?x.path:'not found'}</span></div>`;}).join('');
  document.getElementById('files-list').innerHTML=
    `<div><div style="font-size:.65rem;color:var(--pink);font-family:Orbitron,sans-serif;letter-spacing:.15em;margin-bottom:6px">SURICATA</div>${mkRows(['eve.json','fast.log','suricata.log','stats.log'])}</div>`+
    `<div><div style="font-size:.65rem;color:var(--yellow);font-family:Orbitron,sans-serif;letter-spacing:.15em;margin-bottom:6px">ZEEK</div>${mkRows(['conn.log','dns.log','http.log','ssl.log','dhcp.log','weird.log','x509.log','notice.log'])}</div>`;
  document.getElementById('search-paths').innerHTML=
    (dirs.search_paths||[]).map(p=>`<div>◈ ${p}</div>`).join('')||'<span style="color:var(--dim)">none</span>';

  // Status bar
  const nFound=(files||[]).filter(x=>x.found).length;
  document.getElementById('status-msg').textContent=
    `✓  FILES:${nFound}/${(files||[]).length}  |  CONN:${(sum.total_conn||0).toLocaleString()}  ALERTS:${(sum.total_alerts||0).toLocaleString()}  DNS:${(sum.total_dns||0).toLocaleString()}  BYTES:${fmtB(sum.total_bytes||0)}`;
}

window.addEventListener('load',loadAll);
window.addEventListener('resize',loadAll);
</script>
</body>
</html>
"""

# ─── FLASK APP ───────────────────────────────────────────────────────────────

def create_app(log_dir=".", extra_dirs=None):
    app   = Flask(__name__)
    cache = DataCache(log_dir, extra_dirs or [], ttl=30)

    cfg = {
        "root":     os.path.normpath(os.path.abspath(log_dir)),
        "suricata": next((p for lbl,p in (extra_dirs or []) if lbl=="suricata"), ""),
        "zeek":     next((p for lbl,p in (extra_dirs or []) if lbl=="zeek"),     ""),
    }

    def _get():
        return cache.get()

    @app.route("/")
    def index():
        return render_template_string(HTML_TEMPLATE)

    @app.route("/api/dirs")
    def api_dirs():
        a, data, parser = _get()
        seen, paths = set(), []
        for _, path in parser.found_files():
            d = os.path.dirname(path)
            if d not in seen:
                seen.add(d); paths.append(d)
        return jsonify({"root": cfg["root"], "suricata": cfg["suricata"],
                        "zeek": cfg["zeek"], "search_paths": paths})

    @app.route("/api/set_dirs", methods=["POST"])
    def api_set_dirs():
        body = request.get_json(force=True)
        root = body.get("root","").strip()
        suri = body.get("suricata","").strip()
        zeek = body.get("zeek","").strip()
        if root: cfg["root"] = os.path.normpath(os.path.abspath(root))
        if suri: cfg["suricata"] = os.path.normpath(os.path.abspath(suri))
        if zeek: cfg["zeek"] = os.path.normpath(os.path.abspath(zeek))
        extra = []
        if cfg["suricata"]: extra.append(("suricata", cfg["suricata"]))
        if cfg["zeek"]:     extra.append(("zeek",     cfg["zeek"]))
        cache.update_dirs(log_dir=cfg["root"], extra_dirs=extra)
        return jsonify({"ok": True})

    @app.route("/api/summary")
    def api_summary():
        a,*_ = _get(); return jsonify(a.summary())

    @app.route("/api/top_src_ips")
    def api_src():
        a,*_ = _get(); return jsonify(a.top_src_ips())

    @app.route("/api/top_dst_ips")
    def api_dst():
        a,*_ = _get(); return jsonify(a.top_dst_ips())

    @app.route("/api/proto_dist")
    def api_proto():
        a,*_ = _get(); return jsonify(a.proto_dist())

    @app.route("/api/top_ports")
    def api_ports():
        a,*_ = _get(); return jsonify(a.top_dst_ports())

    @app.route("/api/conn_states")
    def api_states():
        a,*_ = _get(); return jsonify(a.conn_states())

    @app.route("/api/alert_categories")
    def api_alcat():
        a,*_ = _get(); return jsonify(a.alert_categories())

    @app.route("/api/alert_sev")
    def api_alsev():
        a,*_ = _get(); return jsonify(a.alert_sev_dist())

    @app.route("/api/top_dns")
    def api_dns():
        a,*_ = _get(); return jsonify(a.top_dns())

    @app.route("/api/dns_rcodes")
    def api_dnsr():
        a,*_ = _get(); return jsonify(a.dns_rcodes())

    @app.route("/api/ssl_versions")
    def api_ssl():
        a,*_ = _get(); return jsonify(a.ssl_versions())

    @app.route("/api/weird")
    def api_weird():
        a,*_ = _get(); return jsonify(a.weird_names())

    @app.route("/api/recent_alerts")
    def api_alerts():
        a,*_ = _get(); return jsonify(a.recent_alerts())

    @app.route("/api/recent_conns")
    def api_conns():
        a,*_ = _get(); return jsonify(a.recent_conns())

    @app.route("/api/certs")
    def api_certs():
        a,*_ = _get(); return jsonify(a.certs())

    @app.route("/api/fast_alerts")
    def api_fast():
        a,*_ = _get(); return jsonify(a.fast_alerts_list())

    @app.route("/api/app_layer")
    def api_app():
        a,*_ = _get(); return jsonify(a.app_layer())

    @app.route("/api/suricata_summary")
    def api_suri():
        a,*_ = _get(); return jsonify(a.suricata_summary())

    @app.route("/api/suricata_log")
    def api_surilog():
        _,data,_ = _get(); return jsonify(data.get("suricata_log",[])[-100:])

    @app.route("/api/alert_signatures")
    def api_sigs():
        a,*_ = _get(); return jsonify(a.alert_signatures())

    @app.route("/api/files_status")
    def api_files():
        a,data,parser = _get(); return jsonify(a.files_status(parser))

    return app


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="NEON GRID Web Dashboard")
    p.add_argument("log_dir",    nargs="?", default=".",  help="Root log directory")
    p.add_argument("--suricata", default="", metavar="DIR")
    p.add_argument("--zeek",     default="", metavar="DIR")
    p.add_argument("--port",     type=int,  default=5000)
    p.add_argument("--host",     default="0.0.0.0")
    p.add_argument("--ttl",      type=int,  default=30,   help="Cache TTL seconds")
    args = p.parse_args()

    extra = []
    if args.suricata: extra.append(("suricata", args.suricata))
    if args.zeek:     extra.append(("zeek",     args.zeek))

    print(f"""
╔══════════════════════════════════════════════════════╗
║  ◈ NEON GRID — Network Threat Intelligence Web       ║
╠══════════════════════════════════════════════════════╣
║  Root      : {args.log_dir:<40}║
║  Suricata  : {(args.suricata or '(auto)'):<40}║
║  Zeek      : {(args.zeek or '(auto)'):<40}║
║  URL       : http://localhost:{args.port:<25}║
╚══════════════════════════════════════════════════════╝
""")
    app = create_app(args.log_dir, extra)
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
