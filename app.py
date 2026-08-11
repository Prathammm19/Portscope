#!/usr/bin/env python3
"""
Web Deployment: Port Scanner + Service Detector
================================================
Wraps port_scanner.py in a small Flask app so the tool can run from a
browser instead of a terminal. Demonstrates:

  - Turning a CLI tool into an HTTP service
  - Running blocking/slow work (the scan) off the request thread
  - Basic input validation & rate/scope limiting for a public-facing tool

SAFETY GUARDRAILS built in for a public deployment:
  - Ports are capped to a max range per request (prevents someone using your
    server as an open scanning proxy against arbitrary huge ranges)
  - A simple in-memory rate limiter per IP
  - Banner grabbing is optional per scan, off by default

Run locally:
    pip install -r requirements.txt
    python3 app.py
    -> open http://127.0.0.1:5000
"""

import time
import socket
import threading
from flask import Flask, render_template, request, jsonify

from port_scanner import parse_ports, run_scan

app = Flask(__name__)

MAX_PORTS_PER_SCAN = 500          # hard cap so one request can't scan 65535 ports
MIN_SECONDS_BETWEEN_SCANS = 10    # naive per-process rate limit
_last_scan_time = {"t": 0}
_lock = threading.Lock()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    target = (data.get("target") or "").strip()
    port_spec = (data.get("ports") or "1-1024").strip()
    do_banner = bool(data.get("banner", False))

    if not target:
        return jsonify({"error": "Target host is required."}), 400

    # --- basic rate limiting ---
    with _lock:
        now = time.time()
        if now - _last_scan_time["t"] < MIN_SECONDS_BETWEEN_SCANS:
            wait = MIN_SECONDS_BETWEEN_SCANS - (now - _last_scan_time["t"])
            return jsonify({"error": f"Please wait {wait:.0f}s before scanning again."}), 429
        _last_scan_time["t"] = now

    # --- validate + cap the port list ---
    try:
        ports = parse_ports(port_spec)
    except ValueError:
        return jsonify({"error": "Invalid port specification."}), 400

    if len(ports) > MAX_PORTS_PER_SCAN:
        return jsonify({"error": f"Too many ports requested (max {MAX_PORTS_PER_SCAN})."}), 400

    # --- resolve target early so we can give a clean error ---
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        return jsonify({"error": f"Could not resolve host: {target}"}), 400

    try:
        results = run_scan(target, ports, timeout=0.8, max_workers=100,
                            do_banner=do_banner, progress=False)
    except SystemExit:
        return jsonify({"error": "Scan failed."}), 400

    return jsonify({
        "target": target,
        "ports_scanned": len(ports),
        "open_ports": [
            {"port": p, "state": s, "service": svc, "banner": b}
            for p, s, svc, b in results
        ],
    })


if __name__ == "__main__":
    # debug=False in anything resembling production; a scanning tool with
    # the Werkzeug debugger exposed is a remote-code-execution risk.
    app.run(host="0.0.0.0", port=5000, debug=False)
