#!/usr/bin/env python3
"""Real DoT IO through the source-linked Adapter's ordinary view replacement."""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
from product_dns_dot_io_test import certificates, read_exact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('libraries', nargs='+')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    output = (args.output or Path(tempfile.mkdtemp(prefix='s322-adapter-tls-view-'))).resolve()
    output.mkdir(parents=True, exist_ok=True)
    trust = certificates(output)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(output/'leaf.crt', output/'leaf.key')
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0)); listener.listen(8); listener.settimeout(5)
    port = listener.getsockname()[1]
    rows = []

    def peer():
        try:
            for cycle in range(12):
                raw, _ = listener.accept(); raw.settimeout(3)
                with context.wrap_socket(raw, server_side=True) as stream:
                    message = read_exact(stream, int.from_bytes(read_exact(stream, 2), 'big'))
                    assert message[12:] == b'\x07example\x03com\x00\x00\x01\x00\x01'
                    rows.append(dict(cycle=cycle, wire=message.hex(), tls=stream.version()))
                    message[2:4] = b'\x81\x80'
                    stream.sendall(struct.pack('!H', len(message))+message)
        except (OSError, ssl.SSLError, EOFError) as error:
            rows.append(dict(error=str(error)))
        finally:
            listener.close()

    worker = threading.Thread(target=peer); worker.start()
    env = os.environ.copy()
    env['SAKAMOTO_TEST_DOT_PORT'] = str(port)
    env['SAKAMOTO_PRODUCT_DNS_TEST_TRUST_DIRECTORY'] = str(trust)
    command = ['rtk', 'proxy', 'python3', str(Path(__file__).with_name('product_root_dns_adapter_test.py')),
               *args.libraries, '--case', 'tls-view', '--evidence', str(output/'execution')]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, env=env)
    worker.join(6)
    evidence = dict(command=command, exit=result.returncode, stdout=result.stdout, stderr=result.stderr,
                    peer=rows, peer_terminal=not worker.is_alive(),
                    scope='Real TLS IO and root_dns_sync; VPP file dispatch, raw return and SO_MARK controlled')
    (output/'result.json').write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps(evidence), flush=True)
    assert result.returncode == 0 and not worker.is_alive() and len(rows) == 12 and all('wire' in row for row in rows), evidence


if __name__ == '__main__':
    main()
