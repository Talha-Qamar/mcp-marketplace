"""MCP Secure analyzer kit: the HTTP side of the analyzer contract (spec section 6).

An analyzer implements two functions and calls ``serve``:

    def health() -> dict        # GET  /v1/health   (contracts/analyzer-health.schema.json)
    def analyze(bundle, context) -> dict   # POST /v1/analyze (contracts/analyzer-result.schema.json)

The kit handles HTTP, body limits, JSON errors, serialisation of analyze calls
(one at a time, so CPU models stay deterministic and memory stays flat), and
helpers every analyzer needs: stable finding ids, contract-ordered findings,
and tool/function span lookup. Standard library only.
"""

import hashlib
import json
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTRACT_VERSION = "1"
MAX_BODY = 32 * 1024 * 1024


def sha256_prefixed(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def finding_id(analyzer_id, *parts):
    """Stable across runs: a hash of the analyzer id and what/where was found."""
    return sha256_prefixed(canonical([analyzer_id] + [p for p in parts]))


def sort_findings(findings):
    def key(f):
        loc = f.get("location") or {}
        return (loc.get("file") or "", loc.get("line") or 0, f.get("threat") or "", f.get("finding_id") or "")
    return sorted(findings, key=key)


def tool_for_span(bundle, file_path, start_line, end_line):
    """tool_id of the bundle tool whose handler span overlaps [start_line, end_line] in file_path."""
    best = None
    for tool in bundle.get("tools", []):
        if tool.get("file") != file_path:
            continue
        h = tool.get("handler") or {}
        if h.get("start_line", 0) <= end_line and start_line <= h.get("end_line", 0):
            # Prefer the tightest enclosing handler when spans nest.
            width = h["end_line"] - h["start_line"]
            if best is None or width < best[0]:
                best = (width, tool["tool_id"])
    return best[1] if best else None


def result(analyzer, status, findings=(), units_total=0, units_analyzed=0, languages=(), notes=(), error=None):
    out = {
        "analyzer": analyzer,
        "status": status,
        "coverage": {
            "units_total": int(units_total),
            "units_analyzed": int(units_analyzed),
            "languages": sorted(set(languages)),
            "notes": list(notes),
        },
        "findings": sort_findings(list(findings)),
    }
    if error:
        out["error"] = error
    return out


def log(line):
    """Best-effort logging. A service started by `npm start` outlives a crashed
    parent, and then stderr is a closed pipe: a failed log write must never
    drop the response being sent (BaseHTTPRequestHandler logs mid-response)."""
    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def serve(health, analyze, port, host="127.0.0.1", aliases=(), name="analyzer"):
    """Run the contract server. ``aliases`` are extra POST paths served by analyze (spec D8)."""
    lock = threading.Lock()
    analyze_paths = {"/v1/analyze", *aliases}

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            body = json.dumps(obj, sort_keys=True).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            log("[%s] %s" % (name, fmt % args))

        def do_GET(self):
            if self.path in ("/v1/health", "/health"):
                return self._send(200, health())
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path not in analyze_paths:
                return self._send(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_BODY:
                return self._send(413 if n > MAX_BODY else 400, {"error": "JSON body required (max 32 MB)"})
            try:
                req = json.loads(self.rfile.read(n))
                bundle = req["bundle"]
            except Exception:
                return self._send(400, {"error": "body must be {\"bundle\": AnalysisBundle, \"context\"?: {...}}"})
            try:
                with lock:
                    res = analyze(bundle, req.get("context") or {})
            except Exception as exc:  # contract: an analyzer failure is a status, not a crash
                log(traceback.format_exc().rstrip())
                h = health()
                res = result({"id": h["id"], "version": h["version"], "artifact_hash": h["artifact_hash"],
                              "engine": h["engine"]}, "error", error="%s: %s" % (type(exc).__name__, exc))
            return self._send(200, res)

    server = ThreadingHTTPServer((host, port), Handler)
    log("[%s] contract v%s listening on http://%s:%d" % (name, CONTRACT_VERSION, host, port))
    server.serve_forever()
