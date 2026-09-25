#!/usr/bin/env python3
"""Independent RFC9001 wire generator, using Python cryptography/OpenSSL.

No Product library or expected-value derivation from the decoder. Hand-decided
result/stop literals below exercise the public owner producer in a subprocess.
"""
import argparse
import hashlib
import hmac
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes

SALT = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')

def varint(value, width=None):
    width = width or next(n for n in (1, 2, 4, 8) if value < 1 << (8*n-2))
    return (value | ((width.bit_length()-1) << (8*width-2))).to_bytes(width, 'big')

def label(secret, name, length):
    name = b'tls13 '+name
    info = length.to_bytes(2, 'big')+bytes([len(name)])+name+b'\0'
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)

def protect(frames, *, pn=2, pn_bytes=4, dcid=bytes.fromhex('8394c8f03e515708'),
            scid=b'', token=b'', first=None, minimum=1200, version=1):
    secret = hmac.new(SALT, dcid, hashlib.sha256).digest()
    client = label(secret, b'client in', 32)
    key, iv, hp = (label(client, n, size) for n, size in
                   ((b'quic key', 16), (b'quic iv', 12), (b'quic hp', 16)))
    prefix = bytes([first if first is not None else 0xc0+pn_bytes-1])
    prefix += version.to_bytes(4, 'big')+bytes([len(dcid)])+dcid+bytes([len(scid)])+scid
    prefix += varint(len(token))+token
    body = frames+bytes(max(0, minimum-len(prefix)-2-pn_bytes-16-len(frames)))
    header = prefix+varint(pn_bytes+len(body)+16, 2)
    pn_at = len(header)
    header += (pn & ((1 << (8*pn_bytes))-1)).to_bytes(pn_bytes, 'big')
    nonce = (int.from_bytes(iv, 'big') ^ pn).to_bytes(12, 'big')
    encrypted = AESGCM(key).encrypt(nonce, body, header)
    packet = bytearray(header+encrypted)
    cipher = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = cipher.update(packet[pn_at+4:pn_at+20])+cipher.finalize()
    packet[0] ^= mask[0] & 15
    for i in range(pn_bytes): packet[pn_at+i] ^= mask[i+1]
    return bytes(packet)

def hello(name=None):
    # Literal TLS ClientHello framing. TLS version negotiation is not inferred.
    body = b'\x03\x03'+bytes(32)+b'\x00\x00\x02\x13\x01\x01\x00'
    if name is not None:
        data = name.encode('ascii')
        names = b'\x00'+len(data).to_bytes(2, 'big')+data
        extension = len(names).to_bytes(2, 'big')+names
        extensions = b'\x00\x00'+len(extension).to_bytes(2, 'big')+extension
        body += len(extensions).to_bytes(2, 'big')+extensions
    return b'\x01'+len(body).to_bytes(3, 'big')+body

def crypto(data, offset=0):
    return b'\x06'+varint(offset)+varint(len(data))+data

def cases():
    absent, named = hello(), hello('Example.TEST')
    yield 'absent', protect(crypto(absent)), 2, 1, ''
    yield 'name', protect(crypto(named)), 1, 1, 'example.test'
    for pn_bytes in (1, 2, 3, 4):
        for pn in (0, 1, (1 << (8*pn_bytes))-1):
            yield f'pn-{pn_bytes}-{pn}', protect(crypto(named),pn=pn,pn_bytes=pn_bytes), 1, 1, 'example.test'
    for cut in range(1, len(named)):
        # Every header/vector boundary, reversed wire order within one Initial.
        wire = protect(crypto(named[cut:],cut)+b'\x01'+crypto(named[:cut]))
        yield f'spans-{cut}', wire, 1, 1, 'example.test'
    for size in range(len(absent)):
        yield f'incomplete-{size}', protect(crypto(absent[:size])), 0, 11, ''
    yield 'gap', protect(crypto(named[1:],1)), 0, 11, ''
    yield 'overlap', protect(crypto(named[:20])+crypto(named[19:],19)), 0, 11, ''
    yield 'malformed-hello', protect(crypto(b'\x01\x00\x00\x01\x03')), 0, 2, ''
    yield 'malformed-name', protect(crypto(hello('bad..test'))), 0, 2, ''
    yield 'unknown-frame', protect(crypto(named)+b'\x1f'), 0, 3, ''
    yield 'ack', protect(b'\x02\x02\x00\x00\x01'+crypto(named)), 1, 1, 'example.test'
    yield 'ack-ecn', protect(b'\x03\x02\x00\x00\x01\x00\x00\x00'+crypto(absent)), 2, 1, ''
    yield 'bad-ack', protect(b'\x02\x00\x00\x00\x01'+crypto(named)), 0, 2, ''
    yield 'ack-budget', protect(b'\x02\x02\x00\x21\x01'+crypto(named)), 0, 5, ''
    yield 'frame-budget', protect(b'\x01'*65+crypto(named)), 0, 5, ''
    yield 'span-budget', protect(b''.join(crypto(bytes([v]),i) for i,v in enumerate(named))), 0, 5, ''
    yield 'offset-budget', protect(crypto(named,4096)), 0, 5, ''
    yield 'reserved-bits', protect(crypto(named),first=0xcf), 0, 2, ''
    yield 'token', protect(crypto(named),token=b'test-token',scid=b'client-id'), 1, 1, 'example.test'
    valid = protect(crypto(named))
    for at in (50, 300, 1199):
        bad = bytearray(valid);bad[at] ^= 1
        yield f'authentication-{at}', bytes(bad), 0, 10, ''
    bad = bytearray(valid);bad[4] = 2
    yield 'version', bytes(bad), 0, 9, ''
    yield 'truncated', valid[:-1], 0, 2, ''
    yield 'byte-budget', valid+bytes(4097-len(valid)), 0, 5, ''
    yield 'coalesced', valid+b'\x40opaque-following-packet', 1, 1, 'example.test'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    subprocess.run([str(args.binary)], check=True)
    with tempfile.TemporaryDirectory(prefix='t15-quic-vectors-') as directory:
        count = 0
        for name, wire, result, stop, sni in cases():
            path = Path(directory)/name;path.write_bytes(wire)
            subprocess.run([str(args.binary),str(path),str(result),str(stop),sni],check=True)
            count += 1
    print(f'{count} independent protected Initial cases: PASS')

if __name__ == '__main__': main()
