#!/usr/bin/env python3
"""T16 independent aioquic Hello, protected CRYPTO sequences and QUIC endpoint.

Valid Initials are emitted by aioquic 1.3.0, not the Product or hand-built TLS.
The server processes them with its real QUIC/TLS engine and logs its flight.
This slice proves Initial exchange, explicitly not a completed handshake.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import select
import socket
import ssl
import sys
import time

from aioquic import __version__ as aioquic_version
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.packet import pull_quic_header
from aioquic.tls import pull_client_hello
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('wire', ROOT/'tests/host/quic_initial_vectors.py')
wire = importlib.util.module_from_spec(spec);spec.loader.exec_module(wire)
MODES = ('named','absent','conflict','ranges','offset','timeout','packets','named_cutoff','absent_cutoff','named_child','named_boundary','named_suffix','named_alabel')

def emit(**fields): print(json.dumps(dict(time_ns=time.time_ns(),**fields)),flush=True)

def decode_initial(packet):
    """Independent library decryption and TLS parser; not a Product oracle copy."""
    buf = Buffer(data=packet);header = pull_quic_header(buf,host_cid_length=8)
    pair = CryptoPair();pair.setup_initial(header.destination_cid,is_client=False,version=1)
    _header, payload, pn = pair.decrypt_packet(packet[:header.packet_length],buf.tell(),0)
    frames = Buffer(data=payload);data = bytearray()
    while not frames.eof():
        kind = frames.pull_uint_var()
        if kind in (0,1): continue
        assert kind==6,kind
        offset,size = frames.pull_uint_var(),frames.pull_uint_var()
        assert offset==len(data)
        data.extend(frames.pull_bytes(size))
    hello = pull_client_hello(Buffer(data=bytes(data)))
    return dict(name=hello.server_name,pn=pn,cryptoHex=data.hex(),dcid=header.destination_cid.hex())

def prepare(directory,domains=False):
    assert aioquic_version=='1.3.0'
    directory.mkdir(parents=True,exist_ok=False)
    key=ec.generate_private_key(ec.SECP256R1())
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'example.test')])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=2))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('example.test')]),False)
          .sign(key,hashes.SHA256()))
    (directory/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    fixtures={}
    names={'named':'example.test','absent':None,'named_cutoff':'example.test','absent_cutoff':None}
    if domains:names.update(named_child='a.example.test',named_boundary='badexample.test',named_suffix='example.test.evil',named_alabel='xn--bcher-kva.example')
    for mode,name in names.items():
        config=QuicConfiguration(is_client=True,alpn_protocols=['t15'],verify_mode=ssl.CERT_NONE,
            supported_versions=[1],server_name=name or '127.0.0.1')
        connection=QuicConnection(configuration=config);connection.connect(('127.0.0.1',40650),now=0)
        initial=connection.datagrams_to_send(now=0)[0][0]
        oracle=decode_initial(initial)
        assert oracle['name']==name
        fixtures[mode]=dict(hex=initial.hex(),result=1 if mode.startswith('named') else 2,
            stop=1,name=oracle['name'] or '',oracle=oracle,raw=False)
    for mode,fixture in fixtures.items():
        data=bytes.fromhex(fixture['oracle']['cryptoHex'])
        header=pull_quic_header(Buffer(data=bytes.fromhex(fixture['hex'])),host_cid_length=8)
        # Real aioquic ClientHello, independently protected after cutting its
        # CRYPTO offset space. Named paths reverse, duplicate and overlap.
        chunks=[(20,data[20:40]),(20,data[20:40]),(30,data[30:]),(0,data[:30])] if mode.startswith('named') else [(0,data[:20]),(20,data[20:])]
        fixture['sequence']=[wire.protect(wire.crypto(part,offset),pn=i,
            dcid=header.destination_cid,scid=header.source_cid,
            minimum=600 if mode.startswith('named') and i in (1,2) else 1200).hex() for i,(offset,part) in enumerate(chunks)]
        if mode.startswith('named'):
            fixture['sequence']=[fixture['sequence'][0],fixture['sequence'][1]+fixture['sequence'][2],fixture['sequence'][3]]
        fixture['segments']=[dict(offset=offset,hex=part.hex()) for offset,part in chunks]
        fixture['hex']=fixture['sequence'][-1]
    partial=wire.hello('Example.TEST')[:20]
    sparse=b''.join(wire.crypto(b'x',i*2+1) for i in range(32))
    raw={
        'conflict':([wire.crypto(partial),wire.crypto(b'bad',10)],2),
        'ranges':([sparse,wire.crypto(b'x',65)],5),
        'offset':([wire.crypto(b'x',4095),wire.crypto(b'xx',4095)],5),
        'timeout':([wire.crypto(partial)],7),
        'packets':([wire.crypto(partial)]*10,6),
    }
    for mode,(frames,stop) in raw.items():
        sequence=[wire.protect(frame,pn=i).hex() for i,frame in enumerate(frames)]
        fixtures[mode]=dict(hex=sequence[-1],sequence=sequence,result=0,stop=stop,name='',raw=True)
    transaction=hashlib.sha256(str(time.time_ns()).encode()).digest()[:12]
    prelude=b'\x00\x01\x00\x00\x21\x12\xa4\x42'+transaction
    value=dict(nonce=str(time.time_ns()),aioquic=aioquic_version,cases=fixtures,
        preludeHex=prelude.hex(),preludeReplyHex=(b'\x01\x01'+prelude[2:]).hex(),
        certificateSha256=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())
    (directory/'fixtures.json').write_text(json.dumps(value,indent=2)+'\n')
    emit(kind='prepared',directory=str(directory))

def server(host,directory):
    configuration=QuicConfiguration(is_client=False,alpn_protocols=['t15'],supported_versions=[1])
    configuration.load_cert_chain(directory/'cert.pem',directory/'key.pem')
    fixtures=json.loads((directory/'fixtures.json').read_text())
    sockets=[];connections={}
    for port in (40650,40651):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind((host,port));sockets.append(sock)
    emit(kind='ready',host=host,port=40650,aioquic=aioquic_version)
    while True:
        for sock in select.select(sockets,[],[])[0]:
            packet,peer=sock.recvfrom(65536)
            emit(kind='received',peer=peer,port=sock.getsockname()[1],hex=packet.hex())
            if packet.hex()==fixtures['preludeHex']:
                reply=bytes.fromhex(fixtures['preludeReplyHex'])
                sock.sendto(reply,peer);emit(kind='stun_response',peer=peer,hex=reply.hex())
            elif packet.startswith(b'T15-') or sock is sockets[1]:
                sock.sendto(packet,peer);emit(kind='echo',peer=peer,hex=packet.hex())
            else:
                try:
                    if peer not in connections:
                        header=pull_quic_header(Buffer(data=packet),host_cid_length=8)
                        emit(kind='initial',peer=peer,hex=packet.hex(),dcid=header.destination_cid.hex())
                        connections[peer]=QuicConnection(configuration=configuration,
                            original_destination_connection_id=header.destination_cid)
                    connection=connections[peer];connection.receive_datagram(packet,peer,now=time.monotonic())
                    while (event:=connection.next_event()) is not None:
                        emit(kind='quic_event',peer=peer,event=type(event).__name__,detail=str(event))
                    for reply,address in connection.datagrams_to_send(now=time.monotonic()):
                        sock.sendto(reply,address);emit(kind='quic_response',peer=peer,hex=reply.hex())
                except Exception as error: emit(kind='quic_error',peer=peer,error=repr(error))

def client(host,source,mode,nonce,directory):
    fixtures=json.loads((directory/'fixtures.json').read_text());fixture=fixtures['cases'][mode]
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',source))
    sock.connect((host,40651 if fixture['raw'] else 40650));sock.settimeout(5)
    for _ in range(2):
        sock.send(bytes.fromhex(fixtures['preludeHex']));assert sock.recv(4096).hex()==fixtures['preludeReplyHex']
    replies=[]
    for index,encoded in enumerate(fixture['sequence']):
        data=bytes.fromhex(encoded);sock.send(data)
        if fixture['raw']:
            assert sock.recv(4096)==data
        else:
            sock.settimeout(.05)
            try:
                while True:replies.append(sock.recv(4096).hex())
            except socket.timeout:pass
    if mode=='timeout':time.sleep(5.1)
    emit(kind='quic_ready',replies=replies,raw=fixture['raw'])
    for line in sys.stdin:
        command=json.loads(line);operation=command['op']
        if operation=='close':break
        sock.settimeout(command.get('timeout',5))
        if operation=='blocked':
            data=('T15-'+nonce+':blocked').encode();sock.send(data)
            try:sock.recv(4096);raise AssertionError('expected policy timeout')
            except socket.timeout:emit(kind='timeout',hex=data.hex())
        elif operation=='echo':
            for i in range(25):
                data=('T15-'+nonce+':'+str(i)).encode();sock.send(data);assert sock.recv(4096)==data
            emit(kind='received',count=25)
        else:raise ValueError(operation)
    sock.close();emit(kind='closed')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('operation',choices=['prepare','server','client'])
    parser.add_argument('--directory',type=Path,required=True);parser.add_argument('--host',default='127.0.0.2')
    parser.add_argument('--source',type=int);parser.add_argument('--mode',choices=MODES);parser.add_argument('--nonce')
    parser.add_argument('--domains',action='store_true')
    args=parser.parse_args()
    if args.operation=='prepare':prepare(args.directory,args.domains)
    elif args.operation=='server':server(args.host,args.directory)
    else:client(args.host,args.source,args.mode,args.nonce,args.directory)
