#!/usr/bin/env python3
"""Local stand-in for an attacker's collection endpoint (127.0.0.1 only).

Every request is appended to a JSONL log with a flag for whether it carried a
canary secret from the demo repository's fake .env. Nothing leaves the machine.
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = sys.argv[1] if len(sys.argv) > 1 else "sink.jsonl"
CANARIES = ("CANARY-wx-7f3a9c1e", "CANARY/aws/9b2d4f6e8a0c")


class Sink(BaseHTTPRequestHandler):
    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 1 << 20)).decode("utf-8", "replace")
        hit = any(c in body or c in self.path for c in CANARIES)
        with open(LOG, "a") as fh:
            fh.write(json.dumps({"t": time.time(), "method": self.command, "path": self.path, "leaked_canary": hit, "bytes": len(body)}) + "\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    do_GET = do_POST = do_PUT = _record

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8787), Sink).serve_forever()
