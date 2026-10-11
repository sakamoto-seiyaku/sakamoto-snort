#!/usr/bin/env python3
"""Serve this isolated, in-memory design prototype. No Product API is exposed."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--port", type=int, default=4173)
parser.add_argument("--bind", default="127.0.0.1")
args = parser.parse_args()
root = Path(__file__).resolve().parent
server = ThreadingHTTPServer((args.bind, args.port), partial(SimpleHTTPRequestHandler, directory=str(root)))
print(f"Sakamoto HTML prototype: http://{args.bind}:{args.port}/", flush=True)
print(f"Comparison gallery: http://{args.bind}:{args.port}/gallery.html", flush=True)
try:
    server.serve_forever()
except KeyboardInterrupt:
    server.server_close()
