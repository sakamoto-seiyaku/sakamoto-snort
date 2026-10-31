#!/usr/bin/env python3
"""Independent OpenSSL peers verify the real nonblocking Adapter IO boundary."""
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


def run(argv, **options):
    return subprocess.run(["rtk", "proxy", *map(str, argv)], check=True, **options)


def certificates(directory):
    directory.mkdir(exist_ok=True)
    base = ("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=dot.test\n[ext]\n"
            "subjectAltName={san}\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    (directory / "leaf.conf").write_text(base.format(san="DNS:dot.test,IP:127.0.0.1,IP:::1"))
    with (directory / "certificate-commands.log").open("wb") as log:
        commands = [
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
             "-subj", "/CN=S322 isolated offline fixture CA", "-keyout", directory / "ca.key", "-out", directory / "ca.crt"],
            ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-config", directory / "leaf.conf",
             "-keyout", directory / "leaf.key", "-out", directory / "leaf.csr"],
        ]
        for command in commands: run(command, stdout=log, stderr=log)
        for kind, san in (("leaf", "DNS:dot.test,IP:127.0.0.1,IP:::1"),
                          ("numeric-dns", "DNS:127.0.0.1"), ("uri", "URI:https://dot.test")):
            config = directory / (kind + ".conf"); config.write_text(base.format(san=san))
            run(["openssl", "x509", "-req", "-in", directory / "leaf.csr", "-CA", directory / "ca.crt",
                 "-CAkey", directory / "ca.key", "-CAserial", directory / "ca.srl", "-CAcreateserial",
                 "-days", "2", "-sha256", "-extfile", config, "-extensions", "ext", "-out", directory / (kind + ".crt")], stdout=log, stderr=log)
        (directory / "database").write_text(""); (directory / "serial").write_text("1000\n")
        (directory / "issued").mkdir()
        ca_config = directory / "ca.conf"
        ca_config.write_text("[ca]\ndefault_ca=fixture\n[fixture]\ndatabase=" + str(directory / "database")
            + "\nnew_certs_dir=" + str(directory / "issued") + "\nserial=" + str(directory / "serial")
            + "\ncertificate=" + str(directory / "ca.crt") + "\nprivate_key=" + str(directory / "ca.key")
            + "\ndefault_md=sha256\npolicy=policy\nx509_extensions=ext\n[policy]\ncommonName=supplied\n[ext]\n"
              "subjectAltName=DNS:dot.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        run(["openssl", "ca", "-batch", "-config", ca_config, "-in", directory / "leaf.csr", "-out", directory / "expired.crt",
             "-startdate", "20200101000000Z", "-enddate", "20210101000000Z"], stdout=log, stderr=log)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
             "-subj", "/CN=S322 untrusted offline fixture CA", "-keyout", directory / "other.key", "-out", directory / "other.crt"], stdout=log, stderr=log)
    trust = directory / "trust"; trust.mkdir()
    (trust / "ca.crt").write_bytes((directory / "ca.crt").read_bytes())
    for kind in ("empty", "other", "over-capacity"):
        folder = directory / kind; folder.mkdir()
        if kind == "other": (folder / "ca.crt").write_bytes((directory / "other.crt").read_bytes())
        if kind == "over-capacity":
            for index in range(257): (folder / str(index)).write_bytes((directory / "ca.crt").read_bytes())
    return trust


def read_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        piece = stream.recv(size - len(result))
        if not piece: raise EOFError("closed during framed DNS")
        result.extend(piece)
    return result


def bootstrap_reply(query, mode):
    assert query[12:-4] == b"\x03dot\x04test\x00" and query[-2:] == b"\x00\x01", query.hex()
    qtype = int.from_bytes(query[-4:-2], "big")
    assert qtype in (1, 28)
    records = b""
    if mode == 5 and qtype == 28:
        records = b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" + socket.inet_pton(socket.AF_INET6, "::1")
    elif mode != 5 and qtype == 1:
        if mode == 7:
            alias = b"\x03alt\x04test\x00"
            records = b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c" + struct.pack("!H", len(alias)) + alias
            records += alias + b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
        else:
            for address in (("127.0.0.2", "127.0.0.1") if mode == 10 else ("127.0.0.1",)):
                records += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(address)
    count = 2 if mode in (7, 10) and records else int(bool(records))
    return query[:2] + struct.pack("!5H", 0x8180, 1, count, 0, 0) + query[12:] + records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path); parser.add_argument("--output", type=Path)
    parser.add_argument("--case", choices=("all", "addresses"), default="all")
    args = parser.parse_args()
    output = (args.output or Path(tempfile.mkdtemp(prefix="s322-dot-io-"))).resolve()
    output.mkdir(exist_ok=True); trust = certificates(output)
    cases = []
    scenarios = [(4,"dot.test",0,"leaf","trust"),(6,"dot.test",0,"leaf","trust"),
        (4,"wrong.test",1,"leaf","trust"),(6,"::1",0,"leaf","trust"),(4,"127.0.0.1",0,"leaf","trust"),
        (4,"dot.test",2,"leaf","trust"),(4,"dot.test",4,"leaf","trust"),
        (6,"dot.test",5,"leaf","trust"),(4,"dot.test",6,"leaf","trust"),
        (4,"dot.test",7,"leaf","trust"),(4,"dot.test",9,"leaf","trust"),
        (4,"dot.test",8,"leaf","trust"),(4,"dot.test",11,"leaf","trust"),(4,"dot.test",12,"leaf","trust"),
        (4,"127.0.0.1",1,"numeric-dns","trust"),(4,"dot.test",1,"uri","trust"),
        (4,"dot.test",1,"expired","trust"),(4,"dot.test",1,"leaf","other"),
        (4,"dot.test",3,"leaf","empty"),(4,"dot.test",3,"leaf","over-capacity"),
        (4,"dot.test",13,"leaf","trust"),(4,"dot.test",14,"leaf","trust"),
        (4,"dot.test",15,"leaf","trust"),(4,"dot.test",16,"leaf","trust"),
        (4,"dot.test",17,"leaf","trust"),(4,"dot.test",10,"leaf","trust")]
    if args.case == "addresses": scenarios = [scenarios[-1]]
    for family, identity, mode, certificate, anchors in scenarios:
        rows, original_rows = [], []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(output / (certificate + ".crt"), output / "leaf.key")
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        listener = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6)
        listener.bind(("127.0.0.1" if family == 4 else "::1", 0)); listener.listen(8); listener.settimeout(4)

        def peer():
            try:
                raw, _ = listener.accept(); raw.settimeout(3)
                rows.append(dict(kind="connected",accepted_us=time.monotonic_ns()//1000))
                if mode == 8:
                    with raw:
                        data = raw.recv(4096)
                        assert b"\x07example\x03com" not in data
                        rows.append(dict(kind="handshake-held", bytes=len(data)))
                        while raw.recv(4096): pass
                    return
                with context.wrap_socket(raw, server_side=True) as stream:
                    rows.append(dict(kind="authenticated", version=stream.version()))
                    size = int.from_bytes(read_exact(stream, 2), "big")
                    message = read_exact(stream, size)
                    rows.append(dict(kind="dns", wire=message.hex()))
                    message[2:4] = b"\x81\x80"; framed = struct.pack("!H", len(message)) + message
                    for offset in range(0, len(framed), 3): stream.sendall(framed[offset:offset+3])
            except (OSError, ssl.SSLError, EOFError) as error: rows.append(dict(kind="closed", error=str(error)))
            finally: listener.close()

        worker = threading.Thread(target=peer); worker.start()
        original = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        original.bind(("127.0.0.1", 0)); original.settimeout(3.5); original_port = original.getsockname()[1]
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("127.0.0.1", original_port)); tcp.listen(1); tcp.settimeout(3.5)

        def original_dns():
            try:
                query, client = original.recvfrom(512); original_rows.append(dict(transport="udp", wire=query.hex(),received_us=time.monotonic_ns()//1000))
                if mode == 16:
                    retry, again = original.recvfrom(512)
                    original_rows.append(dict(transport="udp",wire=retry.hex(),received_us=time.monotonic_ns()//1000))
                    assert retry == query and again == client
                    return
                if mode in (13,14,15):
                    reply = bytearray(bootstrap_reply(query,mode))
                    if mode==13:
                        reply[0]^=1;original.sendto(reply,client)
                    elif mode==14:
                        reply[13]=ord('x');original.sendto(reply,client);return
                    else:
                        reply=query[:2]+struct.pack("!5H",0x8180,1,1,0,0)+query[12:]+b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x02\xc0\x0c"
                        original.sendto(reply,client);return
                if mode == 6:
                    original.sendto(query[:2] + struct.pack("!5H", 0x8380, 1, 0, 0, 0) + query[12:], client)
                    stream, _ = tcp.accept()
                    with stream:
                        stream.settimeout(3)
                        full = read_exact(stream, int.from_bytes(read_exact(stream, 2), "big"))
                        assert full == query; original_rows.append(dict(transport="tcp", wire=full.hex()))
                        reply = bootstrap_reply(full, mode); framed = struct.pack("!H", len(reply)) + reply
                        for at in range(0, len(framed), 2): stream.sendall(framed[at:at+2])
                else:
                    original.sendto(bootstrap_reply(query, mode), client)
                    if mode == 5:
                        query, client = original.recvfrom(512)
                        original_rows.append(dict(transport="udp", wire=query.hex(),received_us=time.monotonic_ns()//1000))
                        assert query[-4:-2] == b"\x00\x1c"
                        original.sendto(bootstrap_reply(query, mode), client)
            except (OSError, EOFError) as error: original_rows.append(dict(error=str(error)))
            finally: original.close(); tcp.close()

        bootstrap_mode = mode in (4,5,6,7,9,10,13,14,15,16)
        bootstrap = threading.Thread(target=original_dns) if bootstrap_mode else None
        if bootstrap: bootstrap.start()
        else: original.close(); tcp.close()
        command = ["rtk", "proxy", str(args.binary.resolve()), str(family), str(listener.getsockname()[1]),
                   identity, str(output / anchors), str(mode)]
        if bootstrap_mode: command.append(str(original_port))
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        worker.join(5)
        if bootstrap: bootstrap.join(5)
        case = dict(family=family,identity=identity,mode=mode,certificate=certificate,anchors=anchors,
            exit=result.returncode,stdout=result.stdout,stderr=result.stderr,peer=rows,peer_terminal=not worker.is_alive())
        if bootstrap: case.update(original_dns=original_rows,bootstrap_terminal=not bootstrap.is_alive())
        cases.append(case); (output / "result.json").write_text(json.dumps(cases,indent=2)+"\n"); print(json.dumps(case),flush=True)
        assert result.returncode == 0 and not worker.is_alive() and (not bootstrap or not bootstrap.is_alive()), case
        assert sum(row["kind"] == "dns" for row in rows) == (0 if mode in (1,3,8,11,12,14,15,16,17) else 1), case
        if bootstrap: assert not any("error" in row for row in original_rows), case
        grants=[int(line.partition("=")[2])for line in result.stdout.splitlines()if line.startswith("authorization_grant_us=")]
        if mode in(2,9):
            assert len(grants)==(2 if mode==9 else 1)
            assert next(row["accepted_us"]for row in rows if row["kind"]=="connected")>=grants[-1],case
            if mode==9:assert original_rows[0]["received_us"]>=grants[0],case


if __name__ == "__main__": main()
