#!/usr/bin/env python3
"""Local, read-only web UI for this project's logs and split-tunnel state.

Single-file HTTP server (HTML/CSS/JS are inlined in PAGE_HTML below --
there is no sibling .html file) that binds to 127.0.0.1 ONLY, never
0.0.0.0 -- see the "Safety" note below. Serves two things:

  GET /            one static HTML page (poll loop lives in its own
                   inline <script>, no external requests, no CDN assets).
  GET /api/state   JSON snapshot the page polls every 10s.

Everything this script does is read-only: it never writes a route, DNS
setting, VPN state, or any file under local/. It shells out only to
ifconfig, netstat and launchctl (all read-only queries) and reads a
small, fixed set of paths:
  - local/tunnels.txt and local/split-mode.txt (same KEY=VALUE parsing
    convention as bin/lib-routes.sh's get_tunnel_prefix() and
    bin/split-health.sh's MODE parsing -- grep/cut-equivalent, never
    sourced/eval'd)
  - ~/Library/Application Support/comrades-tunnel/split-health-state/*.state
    (format: STATUS=/EVIDENCE=/LAST_FAIL_NOTIFY=/LAST_TS=, written by
    bin/split-health.sh's state_write())
  - the three log files in LOG_PANES below
No other file is ever opened, so there is nothing else that could leak
into /api/state.

Utun detection mirrors bin/lib-routes.sh's detect_utun_by_prefix(): read
CORP_TUNNEL_PREFIX/PERSONAL_TUNNEL_PREFIX from local/tunnels.txt, then
scan `ifconfig -l`'s utun* interfaces for the first inet address starting
with that prefix. The utun number is never hardcoded.

launchd status:
  - dev.comrades-tunnel.split-health lives in the GUI domain
    (gui/$(id -u)/...) -- any process running as that user can query it
    reliably, so `launchctl print` there gives a trustworthy "loaded" /
    "not loaded" answer.
  - dev.comrades-tunnel.dns-guard and dev.comrades-tunnel.route-lift are
    LaunchDaemons in the SYSTEM domain. Empirically (verified on this
    machine against com.apple.mDNSResponder, a system daemon that is
    definitely loaded): a non-root `launchctl print system/<label>` fails
    with the exact same "Bad request. Could not find service ... in
    domain for system" (exit 113) whether the service is genuinely absent
    or merely hidden from a non-root caller. There is no way to tell
    those two cases apart from a non-root process, so this script never
    reports "not loaded" for a system-domain job unless it is itself
    running as root (os.getuid() == 0) -- otherwise it reports
    "unknown (needs root to query)", which is the honest answer.

Safety: BIND_HOST below is a literal "127.0.0.1", not a flag -- there is
no way to make this listen on 0.0.0.0 short of editing this constant.
Only --port is configurable. Bind failure (port already in use) prints a
clear message to stderr and exits 1. Ctrl-C stops the server cleanly.

Usage: logs-ui.py [--port PORT]   (default port 8765)
"""
import argparse
import collections
import json
import os
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

BIND_HOST = "127.0.0.1"  # never 0.0.0.0 -- see module docstring
DEFAULT_PORT = 8765
SUBPROCESS_TIMEOUT = 5  # seconds, per ifconfig/netstat/launchctl call
TAIL_LINES = 200

STATE_DIR = Path.home() / "Library/Application Support/comrades-tunnel/split-health-state"

# id -> Russian label, copied verbatim from check_label() in
# bin/split-health.sh so this page reads the same as `make health-status`.
CHECK_IDS = ["CORP_LEAK", "SPLIT_ABSENT", "IPV6", "STALE", "DNS_CLOBBER"]
CHECK_LABELS = {
    "CORP_LEAK": "корпоративный хост через личный VPN",
    "SPLIT_ABSENT": "личный VPN поднят, но сплит не применён",
    "IPV6": "глобальный IPv6 обходит исключения",
    "STALE": "список сайтов устарел",
    "DNS_CLOBBER": "DNS основного сервиса подменён",
}

# (json key, display name, domain, launchd label)
LAUNCHD_JOBS = [
    ("split_health", "split-health", "gui", "dev.comrades-tunnel.split-health"),
    ("dns_guard", "dns-guard", "system", "dev.comrades-tunnel.dns-guard"),
    ("route_lift", "route-lift", "system", "dev.comrades-tunnel.route-lift"),
]

# (json key, display name, path)
LOG_PANES = [
    ("dns_guard", "dns-guard", Path("/var/log/comrades-tunnel-dns-guard.log")),
    ("route_lift", "route-lift", Path("/var/log/comrades-tunnel-route-lift.log")),
    ("split_health", "split-health", Path.home() / "Library/Logs/comrades-tunnel-split-health.log"),
]


def run(cmd):
    """subprocess.run wrapper: never raises, always returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
        return p.returncode, p.stdout, p.stderr
    except Exception as exc:  # pragma: no cover -- defensive, keeps a request alive
        return -1, "", str(exc)


def get_tunnel_prefix(key):
    """Last 'KEY=VALUE' line in local/tunnels.txt, or None. Mirrors
    bin/lib-routes.sh's get_tunnel_prefix() (grep/cut, never sourced)."""
    path = REPO_ROOT / "local" / "tunnels.txt"
    value = None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith(key + "="):
                    value = line[len(key) + 1:]
    except OSError:
        return None
    return value


def routes_on_iface(iface):
    """Number of live IPv4 routes whose Netif column is iface. Mirrors
    bin/lib-routes.sh's routes_on_iface()."""
    rc, out, _ = run(["netstat", "-rn", "-f", "inet"])
    if rc != 0:
        return 0
    count = 0
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[-1] == iface:
            count += 1
    return count


def total_route_count():
    """Total line count of `netstat -rn -f inet`, matching
    bin/lib-routes.sh's route_count() (includes the routing-table header
    lines -- kept identical to that function so this number is directly
    comparable to what the shell tools already report)."""
    rc, out, _ = run(["netstat", "-rn", "-f", "inet"])
    if rc != 0:
        return None
    return len(out.splitlines())


def utun_info(prefix):
    """First utunN whose inet address starts with prefix -- {name, inet,
    routes}, or None if prefix is unset or no match is found. Mirrors
    bin/lib-routes.sh's detect_utun_by_prefix(), plus the inet address and
    route count the summary strip needs."""
    if not prefix:
        return None
    rc, out, _ = run(["ifconfig", "-l"])
    if rc != 0:
        return None
    for iface in out.split():
        if not iface.startswith("utun"):
            continue
        rc2, out2, _ = run(["ifconfig", iface])
        if rc2 != 0:
            continue
        inet = None
        for line in out2.splitlines():
            line = line.strip()
            if line.startswith("inet "):  # excludes "inet6 ..." lines
                fields = line.split()
                if len(fields) >= 2:
                    inet = fields[1]
                break
        if inet and inet.startswith(prefix):
            return {"name": iface, "inet": inet, "routes": routes_on_iface(iface)}
    return None


def read_split_mode():
    """(mode, note) from local/split-mode.txt -- same default-to-forward
    behaviour as bin/split-health.sh when the file or MODE= is missing."""
    path = REPO_ROOT / "local" / "split-mode.txt"
    mode = None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("MODE="):
                    mode = line[len("MODE="):].strip()
    except OSError:
        pass
    if mode not in ("forward", "exclude"):
        return "forward", f"{path} не найден или MODE не задан -- по умолчанию forward"
    return mode, None


def launchd_status(domain, label):
    """See the module docstring's "launchd status" section for why the
    system domain branch refuses to report "not loaded" for a non-root
    caller."""
    if domain == "gui":
        target = f"gui/{os.getuid()}/{label}"
        rc, _, _ = run(["launchctl", "print", target])
        return "loaded" if rc == 0 else "not loaded"
    # domain == "system"
    if os.getuid() != 0:
        return "unknown (needs root to query)"
    rc, _, _ = run(["launchctl", "print", f"system/{label}"])
    return "loaded" if rc == 0 else "not loaded"


def read_state_file(check_id):
    """Parse one STATE_DIR/<id>.state file (KEY=VALUE lines) into a dict,
    or None if it does not exist / cannot be read. Same format as
    bin/split-health.sh's state_write()/state_read()."""
    path = STATE_DIR / f"{check_id}.state"
    if not path.exists():
        return None
    data = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k] = v
    except OSError:
        return None
    return data


def split_health_checks():
    now = time.time()
    rows = []
    for cid in CHECK_IDS:
        data = read_state_file(cid)
        if data is None:
            rows.append({"id": cid, "label": CHECK_LABELS[cid], "status": None, "evidence": None, "age_min": None})
            continue
        age_min = None
        last_ts = data.get("LAST_TS")
        if last_ts:
            try:
                age_min = int((now - float(last_ts)) / 60)
            except ValueError:
                pass
        rows.append({
            "id": cid,
            "label": CHECK_LABELS[cid],
            "status": data.get("STATUS"),
            "evidence": data.get("EVIDENCE"),
            "age_min": age_min,
        })
    return rows


def tail_lines(path, n=TAIL_LINES):
    dq = collections.deque(maxlen=n)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            dq.append(line.rstrip("\n"))
    return list(dq)


def read_log_pane(path):
    if not path.exists():
        return {"exists": False, "readable": None, "lines": [], "message": "no log yet", "fix_cmd": None}
    if not os.access(path, os.R_OK):
        return {
            "exists": True,
            "readable": False,
            "lines": [],
            "message": "exists but not readable by the current user",
            "fix_cmd": f"sudo chmod 644 {path}",
        }
    try:
        return {"exists": True, "readable": True, "lines": tail_lines(path), "message": None, "fix_cmd": None}
    except OSError as exc:
        return {
            "exists": True,
            "readable": False,
            "lines": [],
            "message": f"exists but could not be read: {exc}",
            "fix_cmd": f"sudo chmod 644 {path}",
        }


def build_state():
    corp_prefix = get_tunnel_prefix("CORP_TUNNEL_PREFIX")
    personal_prefix = get_tunnel_prefix("PERSONAL_TUNNEL_PREFIX")
    split_mode, split_mode_note = read_split_mode()

    launchd = {}
    for key, name, domain, label in LAUNCHD_JOBS:
        launchd[key] = {"name": name, "label": label, "status": launchd_status(domain, label)}

    logs = {}
    for key, name, path in LOG_PANES:
        pane = read_log_pane(path)
        pane["name"] = name
        pane["path"] = str(path)
        logs[key] = pane

    return {
        "generated_at": time.time(),
        "summary": {
            "corp_utun": utun_info(corp_prefix),
            "personal_utun": utun_info(personal_prefix),
            "total_routes": total_route_count(),
            "split_mode": split_mode,
            "split_mode_note": split_mode_note,
            "launchd": launchd,
        },
        "split_health_checks": split_health_checks(),
        "logs": logs,
    }


PAGE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>comrades-tunnel logs</title>
<style>
:root {
  --bg: #f5f5f7;
  --fg: #1a1a1c;
  --muted: #6b6b70;
  --panel-bg: #ffffff;
  --border: #d9d9de;
  --ok: #1a7f37;
  --warn: #9a6700;
  --fail: #c62828;
  --unknown: #6b6b70;
  --mono-bg: #101114;
  --mono-fg: #d8d8dc;
  --accent: #2b6cb0;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #17181b;
    --fg: #e7e7ea;
    --muted: #9a9aa2;
    --panel-bg: #1f2024;
    --border: #35363b;
    --ok: #57d38c;
    --warn: #e0b039;
    --fail: #ff6b6b;
    --unknown: #9a9aa2;
    --mono-bg: #0a0b0d;
    --mono-fg: #d8d8dc;
    --accent: #7db7ff;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 16px;
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  font-size: 14px;
}
h1 { font-size: 18px; margin: 0 0 12px; }
h2 { font-size: 14px; margin: 0 0 8px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; }
.panel {
  background: var(--panel-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 14px;
  margin-bottom: 14px;
}
.summary-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 24px;
}
.summary-item { min-width: 220px; }
.summary-item .k { color: var(--muted); font-size: 12px; }
.summary-item .v { font-weight: 600; }
.badge {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 10px;
  font-size: 12px;
  font-weight: 600;
  color: #fff;
}
.badge-ok { background: var(--ok); }
.badge-fail { background: var(--fail); }
.badge-unknown { background: var(--unknown); }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }
.st-ok { color: var(--ok); font-weight: 700; }
.st-warn { color: var(--warn); font-weight: 700; }
.st-fail { color: var(--fail); font-weight: 700; }
.st-unknown { color: var(--unknown); font-weight: 700; }
.log-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 14px;
}
@media (max-width: 900px) {
  .log-grid { grid-template-columns: 1fr; }
}
.log-pane { display: flex; flex-direction: column; min-width: 0; }
.log-pane-header { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin-bottom: 6px; }
.log-pane-header .path { color: var(--muted); font-size: 11px; word-break: break-all; }
.log-filter {
  width: 100%;
  margin-bottom: 6px;
  padding: 4px 6px;
  border-radius: 4px;
  border: 1px solid var(--border);
  background: var(--panel-bg);
  color: var(--fg);
  font-family: inherit;
  font-size: 12px;
}
.log-box {
  background: var(--mono-bg);
  color: var(--mono-fg);
  border-radius: 6px;
  padding: 8px;
  height: 320px;
  overflow-y: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11.5px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
}
.logline.lvl-err { color: var(--fail); }
.logline.lvl-warn { color: var(--warn); }
.log-empty { color: var(--muted); font-style: italic; }
.log-empty code { display: block; margin-top: 4px; color: var(--mono-fg); background: var(--mono-bg); padding: 4px 6px; border-radius: 4px; }
footer { color: var(--muted); font-size: 12px; margin-top: 4px; }
footer code { background: var(--panel-bg); border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; }
</style>
</head>
<body>
<h1>comrades-tunnel &mdash; logs &amp; state</h1>

<div class="panel">
  <h2>Summary</h2>
  <div class="summary-grid">
    <div class="summary-item"><div class="k">Corporate utun</div><div class="v" id="sum-corp">&mdash;</div></div>
    <div class="summary-item"><div class="k">Personal utun</div><div class="v" id="sum-personal">&mdash;</div></div>
    <div class="summary-item"><div class="k">Total IPv4 routes</div><div class="v" id="sum-total-routes">&mdash;</div></div>
    <div class="summary-item"><div class="k">Split mode</div><div class="v" id="sum-mode">&mdash;</div></div>
    <div class="summary-item"><div class="k">launchd jobs</div><div class="v" id="sum-launchd">&mdash;</div></div>
  </div>
</div>

<div class="panel">
  <h2>split-health state</h2>
  <table>
    <thead><tr><th>Check</th><th>Status</th><th>Evidence</th><th>Age</th></tr></thead>
    <tbody id="checks-body"><tr><td colspan="4">loading&hellip;</td></tr></tbody>
  </table>
</div>

<div class="panel">
  <h2>Logs (last 200 lines, newest at the bottom)</h2>
  <div class="log-grid">
    <div class="log-pane">
      <div class="log-pane-header"><strong>dns-guard</strong><span class="path" id="path-dns_guard"></span></div>
      <input type="text" class="log-filter" id="filter-dns_guard" placeholder="filter&hellip;">
      <div class="log-box" id="log-dns_guard"></div>
    </div>
    <div class="log-pane">
      <div class="log-pane-header"><strong>route-lift</strong><span class="path" id="path-route_lift"></span></div>
      <input type="text" class="log-filter" id="filter-route_lift" placeholder="filter&hellip;">
      <div class="log-box" id="log-route_lift"></div>
    </div>
    <div class="log-pane">
      <div class="log-pane-header"><strong>split-health</strong><span class="path" id="path-split_health"></span></div>
      <input type="text" class="log-filter" id="filter-split_health" placeholder="filter&hellip;">
      <div class="log-box" id="log-split_health"></div>
    </div>
  </div>
</div>

<footer>
  <span id="footer-refresh">not yet refreshed</span> &middot;
  Stop: <code>Ctrl-C</code> in the terminal running <code>python3 bin/logs-ui.py</code>, or
  <code>make logs-ui-uninstall</code> if it is installed as a LaunchAgent.
</footer>

<script>
"use strict";
var REFRESH_MS = 10000;
var PANE_KEYS = ["dns_guard", "route_lift", "split_health"];
var lastState = null;

function esc(s) {
  var d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function lineClass(line) {
  if (line.indexOf("ERROR") !== -1 || line.indexOf("FAIL") !== -1) return "lvl-err";
  if (line.indexOf("WARNING") !== -1 || line.indexOf("WARN") !== -1) return "lvl-warn";
  return "";
}

function launchdBadge(status) {
  var cls = "badge-unknown";
  if (status === "loaded") cls = "badge-ok";
  else if (status === "not loaded") cls = "badge-fail";
  return '<span class="badge ' + cls + '">' + esc(status) + "</span>";
}

function utunText(u) {
  if (!u) return "not present";
  return u.name + " (" + u.inet + ", " + u.routes + " routes)";
}

function checkStatusClass(status) {
  if (status === "OK") return "st-ok";
  if (status === "WARN") return "st-warn";
  if (status === "FAIL") return "st-fail";
  return "st-unknown";
}

function renderSummary(s) {
  document.getElementById("sum-corp").textContent = utunText(s.corp_utun);
  document.getElementById("sum-personal").textContent = utunText(s.personal_utun);
  document.getElementById("sum-total-routes").textContent = (s.total_routes === null || s.total_routes === undefined) ? "unknown" : s.total_routes;
  document.getElementById("sum-mode").textContent = s.split_mode + (s.split_mode_note ? " (" + s.split_mode_note + ")" : "");
  var l = s.launchd;
  document.getElementById("sum-launchd").innerHTML =
    "split-health " + launchdBadge(l.split_health.status) + "<br>" +
    "dns-guard " + launchdBadge(l.dns_guard.status) + "<br>" +
    "route-lift " + launchdBadge(l.route_lift.status);
}

function renderChecks(checks) {
  var tbody = document.getElementById("checks-body");
  var rows = checks.map(function (c) {
    var status = c.status || "no state yet";
    var evidence = c.evidence || "—";
    var age = (c.age_min === null || c.age_min === undefined) ? "—" : (c.age_min + " min ago");
    return "<tr><td>" + esc(c.label) + "</td><td class=\"" + checkStatusClass(c.status) + "\">" + esc(status) +
      "</td><td>" + esc(evidence) + "</td><td>" + esc(age) + "</td></tr>";
  });
  tbody.innerHTML = rows.join("");
}

function renderLogPane(key, pane) {
  document.getElementById("path-" + key).textContent = pane.path;
  var box = document.getElementById("log-" + key);
  var nearBottom = (box.scrollTop + box.clientHeight) >= (box.scrollHeight - 24);

  if (!pane.exists) {
    box.innerHTML = '<div class="log-empty">' + esc(pane.message) + "</div>";
    return;
  }
  if (!pane.readable) {
    box.innerHTML = '<div class="log-empty">' + esc(pane.message) + "<code>" + esc(pane.fix_cmd) + "</code></div>";
    return;
  }

  var filterInput = document.getElementById("filter-" + key);
  var filterVal = (filterInput.value || "").toLowerCase();
  var lines = pane.lines.filter(function (l) {
    return !filterVal || l.toLowerCase().indexOf(filterVal) !== -1;
  });

  if (lines.length === 0) {
    box.innerHTML = '<div class="log-empty">(no lines match the filter)</div>';
    return;
  }
  box.innerHTML = lines.map(function (l) {
    return '<div class="logline ' + lineClass(l) + '">' + esc(l) + "</div>";
  }).join("");
  if (nearBottom) {
    box.scrollTop = box.scrollHeight;
  }
}

function renderAll(data) {
  renderSummary(data.summary);
  renderChecks(data.split_health_checks);
  PANE_KEYS.forEach(function (key) {
    renderLogPane(key, data.logs[key]);
  });
}

function refresh() {
  fetch("/api/state", { cache: "no-store" })
    .then(function (res) { return res.json(); })
    .then(function (data) {
      lastState = data;
      renderAll(data);
      document.getElementById("footer-refresh").textContent =
        "Last refresh: " + new Date().toLocaleTimeString();
    })
    .catch(function (err) {
      document.getElementById("footer-refresh").textContent = "Refresh failed: " + err;
    });
}

document.addEventListener("DOMContentLoaded", function () {
  refresh();
  setInterval(refresh, REFRESH_MS);
  PANE_KEYS.forEach(function (key) {
    document.getElementById("filter-" + key).addEventListener("input", function () {
      if (lastState) renderLogPane(key, lastState.logs[key]);
    });
  });
});
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "logs-ui/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # quiet: a local, read-only polling tool has nothing worth spamming stderr for

    def _send(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            try:
                body = json.dumps(build_state()).encode("utf-8")
                self._send(200, body, "application/json")
            except Exception as exc:  # never let a request crash the server
                body = json.dumps({"error": str(exc)}).encode("utf-8")
                self._send(500, body, "application/json")
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"TCP port to listen on (default {DEFAULT_PORT})")
    args = parser.parse_args()

    try:
        httpd = ThreadingHTTPServer((BIND_HOST, args.port), Handler)
    except OSError as exc:
        print(f"ERROR: could not bind to {BIND_HOST}:{args.port}: {exc}", file=sys.stderr)
        return 1

    url = f"http://{BIND_HOST}:{args.port}/"
    print(f"comrades-tunnel logs UI listening on {url}")
    print("Read-only, localhost-only. Press Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping (Ctrl-C)...")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
