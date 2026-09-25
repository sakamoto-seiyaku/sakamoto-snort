#!/usr/bin/env python3
"""Test-only ordinary socket endpoints, TLS upgrade and aioquic protocol oracle.

The mobile UDP probe uses a fresh authenticated Initial generated here. Linux
also drives a complete aioquic handshake on its application socket. Neither
endpoint uses Product APIs, libprotoident, Flow state or packet injection.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import socket
import signal
import ssl
import sys
import threading
import time

from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted, ProtocolNegotiated
from aioquic.quic.packet import pull_quic_header
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DNS = bytes.fromhex('120c01000001000000000000') + b'\x07example\x04test\0\0\1\0\1'
MDNS = bytes.fromhex('000000000001000000000000') + b'\x07example\x05local\0\0\1\0\1'
MDNS_REPLY = bytes.fromhex('000084000001000100000000') + MDNS[12:] + bytes.fromhex('c00c00018001000000780004c0000201')
HTTP_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: TLS/1.2\r\n\r\n'

def emit(**fields):
    print(json.dumps(dict(time_ns=time.time_ns(), **fields)), flush=True)

def client_configuration():
    return QuicConfiguration(is_client=True, alpn_protocols=['t12'], server_name='example.test',
                             verify_mode=ssl.CERT_NONE, supported_versions=[1])

def prepare(directory, mdns=False):
    directory.mkdir(parents=True, exist_ok=False)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.test')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('example.test')]),False)
            .sign(key,hashes.SHA256()))
    (directory/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    connection = QuicConnection(configuration=client_configuration())
    connection.connect(('127.0.0.1',40612),now=0)
    initial = connection.datagrams_to_send(now=0)[0][0]
    assert len(initial)>=1200
    value=dict(certificateSha256=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
               dnsHex=(MDNS if mdns else DNS).hex(),quicHex=initial.hex(),quicScope='authenticated-v1-Initial-generated-by-aioquic-1.3.0')
    (directory/'fixtures.json').write_text(json.dumps(value,indent=2)+'\n')
    emit(kind='prepared',directory=str(directory),initial_bytes=len(initial))

def server(host, port, directory, udp_port):
    signal.signal(signal.SIGTERM, lambda _signal, _frame: sys.exit(0))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory/'cert.pem',directory/'key.pem')
    configuration=QuicConfiguration(is_client=False,alpn_protocols=['t12'],supported_versions=[1])
    configuration.load_cert_chain(directory/'cert.pem',directory/'key.pem')
    tcp=socket.socket();tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    tcp.bind((host,port));tcp.listen()
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    # mDNS daemons normally share their wildcard socket; this unicast fixture
    # binds the explicit test address without stopping another local service.
    if udp_port==5353:udp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    udp.bind((host,udp_port))
    connections={}
    def serve_tcp(connection,peer):
        emit(kind='tcp_connect',peer=peer)
        try:
            connection.settimeout(120)
            request=b''
            while not request.endswith(b'\r\n\r\n') and len(request)<4096:
                data=connection.recv(1)
                if not data: raise EOFError('HTTP request')
                request+=data
            assert request.startswith(b'GET /')
            emit(kind='http_request',peer=peer,data=request.hex())
            connection.sendall(HTTP_RESPONSE)
            with context.wrap_socket(connection,server_side=True) as tls:
                emit(kind='tls_handshake',peer=peer,version=tls.version(),cipher=tls.cipher())
                while True:
                    data=tls.recv(4096)
                    if not data: break
                    emit(kind='tls_data',peer=peer,data=data.hex())
                    tls.sendall(data)
        except Exception as error:
            emit(kind='tcp_error',peer=peer,error=repr(error))
        finally:
            connection.close();emit(kind='tcp_close',peer=peer)
    def serve_udp():
        while True:
            data,peer=udp.recvfrom(65536)
            emit(kind='udp_receive',peer=peer,data=data.hex())
            if data==MDNS:
                udp.sendto(MDNS_REPLY,peer);emit(kind='mdns_response',peer=peer,data=MDNS_REPLY.hex())
            elif data==DNS:
                reply=data[:2]+b'\x81\x80'+data[4:]
                udp.sendto(reply,peer);emit(kind='dns_response',peer=peer,data=reply.hex())
            elif data.startswith((b'T12-opaque-',b'T12-unknown-')):
                udp.sendto(data,peer);emit(kind='udp_echo',peer=peer,data=data.hex())
            else:
                try:
                    if peer not in connections:
                        header=pull_quic_header(Buffer(data=data),host_cid_length=8)
                        connections[peer]=QuicConnection(configuration=configuration,
                            original_destination_connection_id=header.destination_cid)
                    connection=connections[peer]
                    connection.receive_datagram(data,peer,now=time.monotonic())
                    while (event:=connection.next_event()) is not None:
                        emit(kind='quic_event',peer=peer,event=type(event).__name__,detail=str(event))
                    for reply,address in connection.datagrams_to_send(now=time.monotonic()):
                        udp.sendto(reply,address);emit(kind='quic_response',peer=peer,data=reply.hex())
                except Exception as error:
                    emit(kind='quic_error',peer=peer,error=repr(error))
    threading.Thread(target=serve_udp,daemon=True).start()
    emit(kind='ready',host=host,tcp_port=port,udp_port=udp_port)
    while True:
        connection,peer=tcp.accept()
        threading.Thread(target=serve_tcp,args=(connection,peer),daemon=True).start()

def client(host,port,source,protocol,nonce):
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if protocol=='tcp':sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    sock.bind(('127.0.0.1',source));sock.settimeout(10);sock.connect((host,port))
    emit(kind='connected',local=sock.getsockname(),peer=sock.getpeername())
    for line in sys.stdin:
        command=json.loads(line);op=command['op']
        try:
            if op=='close':break
            if op=='http':
                sock.sendall(('GET /'+nonce+' HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: TLS/1.2\r\n\r\n').encode())
                response=b''
                while not response.endswith(b'\r\n\r\n'):response+=sock.recv(1)
                assert response==HTTP_RESPONSE
                emit(kind='http_ready',data=response.hex())
            elif op=='tls':
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
                context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
                sock=context.wrap_socket(sock,server_hostname='example.test')
                emit(kind='tls_ready',version=sock.version())
            elif op=='mdns':
                sock.send(MDNS);response=sock.recv(4096);assert response==MDNS_REPLY
                emit(kind='mdns_ready',data=response.hex())
            elif op=='dns':
                sock.send(DNS);response=sock.recv(4096);assert response[:4]==b'\x12\x0c\x81\x80'
                emit(kind='dns_ready',data=response.hex())
            elif op=='quic':
                connection=QuicConnection(configuration=client_configuration())
                peer=(host,port);connection.connect(peer,now=time.monotonic());done=False
                deadline=time.monotonic()+10
                while not done and time.monotonic()<deadline:
                    for data,_ in connection.datagrams_to_send(now=time.monotonic()):sock.send(data)
                    sock.settimeout(.2)
                    try:connection.receive_datagram(sock.recv(4096),peer,now=time.monotonic())
                    except socket.timeout:
                        timer=connection.get_timer()
                        if timer is not None and time.monotonic()>=timer:connection.handle_timer(now=time.monotonic())
                    while (event:=connection.next_event()) is not None:
                        if isinstance(event,HandshakeCompleted):done=True
                assert done
                for data,_ in connection.datagrams_to_send(now=time.monotonic()):sock.send(data)
                # Consume any final Handshake/ACK flight before raw budget traffic.
                sock.settimeout(.2)
                try:
                    for _ in range(8):sock.recv(4096)
                except socket.timeout:pass
                emit(kind='quic_ready',handshake_complete=True)
            elif op in ('send','recv','repeat'):
                data=('T12-opaque-'+nonce).encode();sock.settimeout(command.get('timeout',1))
                count=24 if op=='repeat' else 1
                for _ in range(count):
                    if op!='recv':sock.sendall(data)
                    response=b''
                    while len(response)<len(data):response+=sock.recv(4096)
                    assert response==data,(response,data)
                emit(kind='received',count=count,data=data.hex())
            else:raise ValueError(op)
        except socket.timeout:emit(kind='timeout')
        except Exception as error:emit(kind='error',error=repr(error))
    sock.close();emit(kind='closed')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('role',choices=['prepare','server','client'])
    p.add_argument('--directory',type=Path);p.add_argument('--host',default='127.0.0.2')
    p.add_argument('--mdns',action='store_true')
    p.add_argument('--udp-port',type=int,default=53)
    p.add_argument('--port',type=int,default=40610);p.add_argument('--source',type=int,default=45100)
    p.add_argument('--protocol',choices=['tcp','udp'],default='tcp');p.add_argument('--nonce',default='t12')
    a=p.parse_args()
    if a.role=='prepare':prepare(a.directory,a.mdns)
    elif a.role=='server':server(a.host,a.port,a.directory,a.udp_port)
    else:client(a.host,a.port,a.source,a.protocol,a.nonce)
