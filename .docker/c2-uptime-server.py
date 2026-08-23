#!/usr/bin/env python3
"""
sdc-noise — C2 sink + fleet uptime monitor (Counterattack range infra)
======================================================================
Opaque range infrastructure. Cadets never read this. Two jobs:

1. C2 sink (`GET /checkin?node=X`)
   The baked-in beacon implant on each fleet node curls this every ~10s. We
   latch the last check-in time per node. Eradication is then behaviourally
   verifiable: after the implant is purged and the C2 blocked, the callbacks
   must cease.

2. Uptime monitor (`POST /arm`, `GET /status`)
   A background sampler probes every node's nginx /healthz at 10 Hz and latches
   the WORST availability seen during an armed segment:
     - min_available : fewest nodes answering /healthz at once
     - blackout_ms   : longest contiguous span below quorum (>=2 of 3)
   A 3-sample (~300 ms) debounce means a spurious single-sample blip cannot
   trip the latch, while the deterministic ~3s nginx preflight window that a
   NAIVE parallel restart opens is impossible to miss.

The harness arms a segment, runs the cadet's eradicate.yml, then reads the
segment: a rolling (serial:1 + health-gated) restart holds min_available>=2 /
blackout_ms==0; a naive parallel restart drops to 0 for ~3s.
"""
import http.client
import json
import os
import subprocess
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TARGETS = ["172.30.0.11", "172.30.0.12", "172.30.0.13"]
QUORUM = 2                       # >=2 of 3 nodes answering = fleet available
SAMPLE_INTERVAL = 0.1            # 10 Hz
PROBE_TIMEOUT = 0.3             # per-node /healthz timeout
DEBOUNCE_WINDOW = 3             # samples a drop must persist to count (~300ms)
LAB_DIR = "/lab"

# The C2 sink lives on .20 (the IP the cadet blocks). The uptime prober sources
# its /healthz probes from a SEPARATE address (.30) so that blocking the C2
# never blinds the monitor — you sever the adversary without losing your eyes.
C2_IP = "172.30.0.20"
MONITOR_IP = "172.30.0.30"

_lock = threading.Lock()
_state = {
    "segment": 0,
    "armed_ts": None,
    "min_available": len(TARGETS),
    "blackout_ms": 0,
    "quorum": QUORUM,
    "targets": TARGETS,
    "callbacks": {},            # node -> last check-in epoch
    "callback_count_total": 0,
}
# sampler-private latch state (reset on arm)
_window = deque(maxlen=DEBOUNCE_WINDOW)
_cur_blackout_ms = 0.0


def _add_monitor_ip():
    """Bring up the .30 monitor source IP (idempotent). Requires NET_ADMIN."""
    subprocess.run(
        ["ip", "addr", "add", f"{MONITOR_IP}/24", "dev", "eth0"],
        capture_output=True,
    )


def _probe(ip):
    try:
        conn = http.client.HTTPConnection(
            ip, 80, timeout=PROBE_TIMEOUT, source_address=(MONITOR_IP, 0)
        )
        conn.request("GET", "/healthz")
        r = conn.getresponse()
        ok = r.status == 200
        r.read()
        conn.close()
        return ok
    except Exception:
        return False


def _write_lab():
    try:
        with _lock:
            snap = dict(_state)
        tmp = os.path.join(LAB_DIR, ".uptime.tmp")
        with open(tmp, "w") as f:
            json.dump(snap, f)
        os.replace(tmp, os.path.join(LAB_DIR, "uptime.json"))
    except Exception:
        pass


def sampler():
    """Probe the fleet at 10 Hz; latch worst debounced availability."""
    global _cur_blackout_ms
    _add_monitor_ip()
    pool = ThreadPoolExecutor(max_workers=len(TARGETS))
    last = time.time()
    tick = 0
    while True:
        results = list(pool.map(_probe, TARGETS))
        available = sum(1 for ok in results if ok)

        now = time.time()
        dt_ms = (now - last) * 1000.0
        last = now

        with _lock:
            armed = _state["armed_ts"] is not None
            if armed:
                _window.append(available)
                # Rolling-max debounce: availability only "drops" once the low
                # reading has persisted across the whole window, so a single
                # spurious blip cannot trip the latch.
                debounced = max(_window)
                if debounced < _state["min_available"]:
                    _state["min_available"] = debounced
                if debounced < QUORUM:
                    _cur_blackout_ms += dt_ms
                    if _cur_blackout_ms > _state["blackout_ms"]:
                        _state["blackout_ms"] = int(_cur_blackout_ms)
                else:
                    _cur_blackout_ms = 0.0

        tick += 1
        if tick % 10 == 0:
            _write_lab()
        time.sleep(SAMPLE_INTERVAL)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/checkin":
            qs = parse_qs(u.query)
            node = (qs.get("node") or ["unknown"])[0]
            with _lock:
                _state["callbacks"][node] = time.time()
                _state["callback_count_total"] += 1
            self._send(200, b"ok\n")
        elif u.path == "/status":
            with _lock:
                snap = dict(_state)
                snap["now"] = time.time()
            self._json(200, snap)
        elif u.path == "/healthz":
            self._send(200, b"ok\n")
        else:
            self._send(404, b"not found\n")

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/arm":
            global _cur_blackout_ms
            with _lock:
                _state["segment"] += 1
                _state["armed_ts"] = time.time()
                _state["min_available"] = len(TARGETS)
                _state["blackout_ms"] = 0
                _window.clear()
                _cur_blackout_ms = 0.0
                seg = _state["segment"]
                ts = _state["armed_ts"]
            self._json(200, {"segment": seg, "armed_ts": ts})
        else:
            self._send(404, b"not found\n")


def main():
    os.makedirs(LAB_DIR, exist_ok=True)
    threading.Thread(target=sampler, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", 80), Handler)
    srv.serve_forever()


if __name__ == "__main__":
    main()
