#!/usr/bin/env python3
"""Throwaway webhook receiver — prints every POST body and timestamps it."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import sys

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] POST {self.path} <- {self.client_address[0]} | {body}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *_):  # silence default access log
        pass

HTTPServer(("0.0.0.0", 8888), Handler).serve_forever()
