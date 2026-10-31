#!/usr/bin/env python3
"""Independent OpenSSL HTTP/1.1 peers verify the real DoH IO boundary."""
import argparse
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from product_dns_dot_io_test import bootstrap_reply, certificates, read_exact

QUESTION = bytes([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7]) + b"example" + b"\x03com\x00\x00\x01\x00\x01"
HTTP_OK = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
# HTTP failure classes follow product_dns_proxy.h; ALPN states follow product_dns_alpn.h.
FRAMING, STATUS, REDIRECT, CONTENT_TYPE, ENCODING, HEADER_LIMIT, BODY_LIMIT, EMPTY, TRAILING, CLOSED, AGE, ALPN = range(1, 13)
NONE, HTTP11, ABSENT, REFUSED = range(4)

# name: (family, identity, certificate, alpn offered by peer, expect, http_error, status, client alpn, age)
SCENARIOS = {
    "plain": (4, "dot.test", "http/1.1", "answer", 0, 200, HTTP11, 0),
    "ipv6-ip-identity": (6, "::1", "http/1.1", "answer", 0, 200, HTTP11, 0),
    "ipv4-ip-identity": (4, "127.0.0.1", "http/1.1", "answer", 0, 200, HTTP11, 0),
    "chunked": (4, "dot.test", "http/1.1", "answer", 0, 200, HTTP11, 0),
    "age": (4, "dot.test", "http/1.1", "answer", 0, 200, HTTP11, 30),
    "age-huge": (4, "dot.test", "http/1.1", "answer", 0, 200, HTTP11, 4294967295),
    "close-delimited": (4, "dot.test", "http/1.1", "answer", 0, 200, HTTP11, 0),
    "no-alpn": (4, "dot.test", None, "answer", 0, 200, ABSENT, 0),
    "bad-type": (4, "dot.test", "http/1.1", "failure", CONTENT_TYPE, 200, HTTP11, 0),
    "status-404": (4, "dot.test", "http/1.1", "failure", STATUS, 404, HTTP11, 0),
    "redirect": (4, "dot.test", "http/1.1", "failure", REDIRECT, 301, HTTP11, 0),
    "gzip": (4, "dot.test", "http/1.1", "failure", ENCODING, 200, HTTP11, 0),
    "trailing": (4, "dot.test", "http/1.1", "failure", TRAILING, 200, HTTP11, 0),
    "truncated": (4, "dot.test", "http/1.1", "failure", CLOSED, 200, HTTP11, 0),
    "reset": (4, "dot.test", "http/1.1", "failure", CLOSED, 200, HTTP11, 0),
    "huge-header": (4, "dot.test", "http/1.1", "failure", HEADER_LIMIT, 200, HTTP11, 0),
    "huge-body": (4, "dot.test", "http/1.1", "failure", BODY_LIMIT, 200, HTTP11, 0),
    "empty-body": (4, "dot.test", "http/1.1", "failure", EMPTY, 200, HTTP11, 0),
    "bad-age": (4, "dot.test", "http/1.1", "failure", AGE, 200, HTTP11, 0),
    "http2-bytes": (4, "dot.test", None, "failure", FRAMING, 0, ABSENT, 0),
    "alpn-alert": (4, "dot.test", "alert", "failure", ALPN, 0, REFUSED, 0),
    "wrong-identity": (4, "wrong.test", "http/1.1", "failure", 0, 0, NONE, 0),
    "bootstrap": (4, "dot.test", "http/1.1", "answer", 0, 200, HTTP11, 0),
    "cancel": (4, "dot.test", "http/1.1", "cancel", 0, 0, 0, 0),
}


def dns_reply(message):
    reply = bytearray(message); reply[2:4] = b"\x81\x80"
    return bytes(reply)


def read_request(stream):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        piece = stream.recv(4096)
        if not piece: raise EOFError("closed before a complete request head")
        data.extend(piece)
    head, _, body = bytes(data).partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    fields = {}
    for line in lines[1:]:
        name, _, value = line.partition(b": ")
        fields[name.lower().decode()] = value.decode()
    length = int(fields["content-length"])
    body = bytearray(body)
    while len(body) < length:
        piece = stream.recv(length - len(body))
        if not piece: raise EOFError("closed during request body")
        body.extend(piece)
    return lines[0].decode(), fields, bytes(body)


def pieces(stream, data, size):
    for at in range(0, len(data), size):
        stream.sendall(data[at:at + size]); time.sleep(0.002)


def respond(name, stream, message):
    reply = dns_reply(message)
    length = b"Content-Length: " + str(len(reply)).encode() + b"\r\n"
    if name in ("plain", "ipv6-ip-identity", "ipv4-ip-identity", "no-alpn", "bootstrap"):
        pieces(stream, HTTP_OK + length + b"Connection: close\r\n\r\n" + reply, 3)
    elif name == "chunked":
        body = b""
        for at in range(0, len(reply), 7):
            chunk = reply[at:at + 7]; body += b"%x\r\n" % len(chunk) + chunk + b"\r\n"
        pieces(stream, HTTP_OK + b"Transfer-Encoding: chunked\r\n\r\n" + body + b"0\r\nX-Trailer: ignored\r\n\r\n", 5)
    elif name in ("age", "age-huge", "bad-age"):
        value = {"age": b"30", "age-huge": b"99999999999", "bad-age": b"-1"}[name]
        pieces(stream, HTTP_OK + b"Age: " + value + b"\r\n" + length + b"\r\n" + reply, 11)
    elif name == "close-delimited":
        stream.sendall(HTTP_OK + b"Connection: close\r\n\r\n" + reply); stream.unwrap()
    elif name == "bad-type":
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" + length + b"\r\n" + reply)
    elif name == "status-404":
        stream.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Type: application/dns-message\r\n" + length + b"\r\n" + reply)
    elif name == "redirect":
        stream.sendall(b"HTTP/1.1 301 Moved\r\nLocation: https://elsewhere.test/dns-query\r\nContent-Length: 0\r\n\r\n")
    elif name == "gzip":
        stream.sendall(HTTP_OK + b"Content-Encoding: gzip\r\n" + length + b"\r\n" + reply)
    elif name == "trailing":
        stream.sendall(HTTP_OK + length + b"\r\n" + reply + b"X")
    elif name == "truncated":
        stream.sendall(HTTP_OK + length + b"\r\n" + reply[:10]); stream.unwrap()
    elif name == "reset":
        stream.sendall(HTTP_OK + length + b"\r\n" + reply[:10])   # bare TCP end, no close_notify
    elif name == "huge-header":
        stream.sendall(b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 9000 + b"\r\n\r\n")
    elif name == "huge-body":
        stream.sendall(HTTP_OK + b"Content-Length: 70000\r\n\r\n" + reply)
    elif name == "empty-body":
        stream.sendall(HTTP_OK + b"Content-Length: 5\r\n\r\n12345")
    elif name == "http2-bytes":
        stream.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
    elif name == "cancel":
        time.sleep(1.5)   # hold the response; the client cancels first


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path); parser.add_argument("--output", type=Path)
    parser.add_argument("--only", nargs="*")
    args = parser.parse_args()
    output = (args.output or Path(tempfile.mkdtemp(prefix="s323-doh-io-"))).resolve()
    output.mkdir(exist_ok=True); trust = certificates(output)
    cases = []
    for name, (family, identity, alpn, expect, error, status, client_alpn, age) in SCENARIOS.items():
        if args.only and name not in args.only: continue
        rows = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(output / "leaf.crt", output / "leaf.key")
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        if alpn and alpn != "alert": context.set_alpn_protocols([alpn])
        listener = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6)
        listener.bind(("127.0.0.1" if family == 4 else "::1", 0)); listener.listen(8); listener.settimeout(4)
        port = listener.getsockname()[1]

        def peer():
            try:
                raw, _ = listener.accept(); raw.settimeout(3)
                rows.append(dict(kind="connected"))
                if alpn == "alert":
                    # No mutual ALPN protocol: the server's plaintext no_application_protocol alert.
                    rows.append(dict(kind="hello-bytes", size=len(raw.recv(4096))))
                    raw.sendall(b"\x15\x03\x03\x00\x02\x02\x78"); raw.close(); return
                with context.wrap_socket(raw, server_side=True) as stream:
                    rows.append(dict(kind="authenticated", version=stream.version(),
                                     alpn=stream.selected_alpn_protocol()))
                    line, fields, body = read_request(stream)
                    rows.append(dict(kind="request", line=line, fields=fields, body=body.hex()))
                    respond(name, stream, body)
            except (OSError, ssl.SSLError, EOFError) as error_: rows.append(dict(kind="closed", error=str(error_)))
            finally: listener.close()

        worker = threading.Thread(target=peer); worker.start()
        resolver = None
        if name == "bootstrap":
            # Original-network resolver: the service name is discovered here, never by the proxy.
            resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            resolver.bind(("127.0.0.1", 0)); resolver.settimeout(4)
            queries = []

            def discover():
                try:
                    query, client = resolver.recvfrom(512); queries.append(query.hex())
                    resolver.sendto(bootstrap_reply(query, 0), client)
                except OSError as error_: queries.append("error: " + str(error_))
            discovery = threading.Thread(target=discover); discovery.start()
        command = ["rtk", "proxy", str(args.binary.resolve()), str(family), str(port), identity,
                   str(trust), expect if expect != "cancel" else "cancel", str(error), str(status),
                   str(client_alpn), str(age)]
        if expect == "cancel": command.append("cancel")
        if resolver: command += ["bootstrap", str(resolver.getsockname()[1])]
        result = subprocess.run(command, capture_output=True, text=True, timeout=8)
        worker.join(6)
        if resolver:
            discovery.join(5); resolver.close()
            assert len(queries) == 1 and not queries[0].startswith("error"), queries
            assert b"\x03dot\x04test\x00" in bytes.fromhex(queries[0]), queries
        case = dict(name=name, exit=result.returncode, stdout=result.stdout, stderr=result.stderr,
                    peer=rows, peer_terminal=not worker.is_alive())
        cases.append(case); (output / "result.json").write_text(json.dumps(cases, indent=2) + "\n")
        print(json.dumps(case), flush=True)
        assert result.returncode == 0 and not worker.is_alive(), case
        requests = [row for row in rows if row["kind"] == "request"]
        if name in ("alpn-alert", "wrong-identity"):
            assert not requests, case          # nothing is sent before authentication
        else:
            assert len(requests) == 1, case
            request = requests[0]
            host = f"[{identity}]" if ":" in identity else identity
            assert request["line"] == "POST /dns-query HTTP/1.1", request
            assert request["fields"]["host"] == f"{host}:{port}", request
            assert request["fields"]["content-type"] == "application/dns-message", request
            assert request["fields"]["accept"] == "application/dns-message", request
            assert request["fields"]["connection"] == "close", request
            assert request["fields"]["content-length"] == str(len(QUESTION)), request
            assert request["body"] == QUESTION.hex(), request
            for banned in ("accept-encoding", "authorization", "cookie", "proxy-connection"):
                assert banned not in request["fields"], request
            auth = [row for row in rows if row["kind"] == "authenticated"][0]
            assert auth["alpn"] == (alpn if alpn != "alert" else None), auth


if __name__ == "__main__": main()
