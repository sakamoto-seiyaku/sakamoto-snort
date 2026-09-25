#!/usr/bin/env python3
"""Independent ordinary SMTP/FTP endpoints and paced FTP RETR data transfer.

Test-only: no Product API, recognizer, packet injection or production Flow access.
TLS uses Python/OpenSSL TLS1.2. FTP data uses PASV with TCP20 deliberately selected
for the documented data-port heuristic; passive arbitrary ports are not claimed.
NOOP paces chunks of one held RETR transfer to make policy windows reproducible.
"""
import argparse
import json
from pathlib import Path
import signal
import socket
import ssl
import sys
import threading
import time

PORTS={'smtp':2525,'ftp':2121,'explicit':40612,'implicit':990,'data':40613}
BANNERS={'smtp':b'220 mail.example.test ESMTP R2 ready\r\n',
         'ftp':b'220 file.example.test FTPd R2 ready\r\n'}

def emit(**fields):
    print(json.dumps(dict(time_ns=time.time_ns(),**fields)),flush=True)

def line(sock):
    value=b''
    while not value.endswith(b'\r\n'):
        part=sock.recv(1)
        if not part:raise EOFError('line')
        value+=part
        if len(value)>1024:raise ValueError('line limit')
    return value

def context(directory=None):
    result=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if directory else ssl.PROTOCOL_TLS_CLIENT)
    result.minimum_version=result.maximum_version=ssl.TLSVersion.TLSv1_2
    if directory:result.load_cert_chain(directory/'cert.pem',directory/'key.pem')
    else:result.check_hostname=False;result.verify_mode=ssl.CERT_NONE
    return result

def data_chunk(nonce,index):
    return ('R2-file:'+nonce+':'+str(index)+'\r\n').encode()

def server(host,directory,applications):
    signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
    tls_context=context(directory)
    listeners=[]
    def serve(connection,peer,application):
        data_listener=data_socket=None
        nonce=None;index=0
        def send(value):
            connection.sendall(value)
            emit(kind='reply',application=application,peer=peer,data=value.hex(),nonce=nonce)
        try:
            connection.settimeout(180)
            emit(kind='connect',application=application,peer=peer)
            if application=='implicit':
                connection=tls_context.wrap_socket(connection,server_side=True)
                emit(kind='tls_handshake',application=application,peer=peer,version=connection.version())
            send(BANNERS['smtp' if application=='smtp' else 'ftp'])
            while True:
                request=line(connection)
                emit(kind='command',application=application,peer=peer,data=request.hex(),nonce=nonce)
                verb,_,argument=request[:-2].partition(b' ')
                if verb in (b'EHLO',b'USER'):
                    nonce=argument.decode('ascii')
                    send((b'250 ' if verb==b'EHLO' else b'331 ')+argument+b'\r\n')
                elif verb==b'PASS':send(b'230 Logged in\r\n')
                elif verb==b'AUTH' and argument==b'TLS' and application=='explicit':
                    send(b'234 Ready for TLS\r\n')
                    connection=tls_context.wrap_socket(connection,server_side=True)
                    emit(kind='tls_handshake',application=application,peer=peer,version=connection.version())
                elif verb==b'PASV' and application=='data':
                    data_listener=socket.socket();data_listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                    data_listener.bind((host,20));data_listener.listen(1);data_listener.settimeout(20)
                    send(('227 Entering Passive Mode ('+host.replace('.',',')+',0,20)\r\n').encode())
                elif verb==b'RETR' and application=='data':
                    assert nonce==argument.decode('ascii')
                    data_socket,data_peer=data_listener.accept();data_socket.settimeout(30)
                    send(b'150 Opening data connection\r\n')
                    chunk=data_chunk(nonce,index);index+=1;data_socket.sendall(chunk)
                    emit(kind='file_chunk',application=application,peer=data_peer,control_peer=peer,nonce=nonce,index=index-1,data=chunk.hex())
                elif verb==b'NOOP':
                    send((b'250 ' if application=='smtp' else b'200 ')+argument+b'\r\n')
                    if application=='data' and data_socket:
                        chunk=data_chunk(nonce,index);index+=1;data_socket.sendall(chunk)
                        emit(kind='file_chunk',application=application,peer=data_peer,control_peer=peer,nonce=nonce,index=index-1,data=chunk.hex())
                elif verb==b'QUIT':
                    if data_socket:
                        data_socket.close();data_socket=None;send(b'226 Transfer complete\r\n')
                    send(b'221 Goodbye\r\n');break
                else:send(b'500 Unsupported test command\r\n')
        except Exception as error:emit(kind='error',application=application,peer=peer,error=repr(error))
        finally:
            if data_socket:data_socket.close()
            if data_listener:data_listener.close()
            connection.close();emit(kind='close',application=application,peer=peer,nonce=nonce)
    def accept(listener,application):
        while True:
            connection,peer=listener.accept()
            threading.Thread(target=serve,args=(connection,peer,application),daemon=True).start()
    for application in applications:
        listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind((host,PORTS[application]));listener.listen();listeners.append(listener)
        threading.Thread(target=accept,args=(listener,application),daemon=True).start()
    emit(kind='ready',host=host,ports={a:PORTS[a] for a in applications})
    signal.pause()

def client(host,source,application,nonce):
    def connect(port,local_port):
        sock=socket.socket();sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        sock.bind(('127.0.0.1',local_port));sock.settimeout(15);sock.connect((host,port));return sock
    sock=connect(PORTS[application],source if application!='data' else source+1000)
    control=sock;index=0;pending=None
    if application=='data':
        assert line(control)==BANNERS['ftp']
        control.sendall(b'USER '+nonce.encode()+b'\r\n');assert line(control).startswith(b'331 ')
        control.sendall(b'PASS test\r\n');assert line(control).startswith(b'230 ')
        control.sendall(b'PASV\r\n');assert line(control).startswith(b'227 ')
        sock=connect(20,source)
    emit(kind='connected',application=application,local=sock.getsockname(),peer=sock.getpeername())
    def noop(index):
        argument=(nonce+':'+str(index)).encode()
        control.sendall(b'NOOP '+argument+b'\r\n')
        expected=(b'250 ' if application=='smtp' else b'200 ')+argument+b'\r\n'
        if application=='data':
            assert line(control)==expected
            return data_chunk(nonce,index+1)
        return expected
    try:
        for raw in sys.stdin:
            command=json.loads(raw);op=command['op']
            try:
                if op=='close':
                    control.sendall(b'QUIT\r\n')
                    response=line(control)
                    if application=='data':assert response.startswith(b'226 ');response=line(control)
                    assert response.startswith(b'221 ');break
                if op=='first':
                    banner=None
                    if application not in ('implicit','data'):
                        banner=line(sock);assert banner==BANNERS['smtp' if application=='smtp' else 'ftp']
                    emit(kind='first_ready',data=banner.hex() if banner else '')
                elif op=='added':
                    if application=='explicit':
                        sock.sendall(b'AUTH TLS\r\n');assert line(sock)==b'234 Ready for TLS\r\n'
                    if application in ('explicit','implicit'):
                        sock=context().wrap_socket(sock,server_hostname='example.test');control=sock
                        if application=='implicit':assert line(sock)==BANNERS['ftp']
                        emit(kind='tls_ready',version=sock.version())
                    if application=='data':
                        control.sendall(b'RETR '+nonce.encode()+b'\r\n');assert line(control).startswith(b'150 ')
                        response=line(sock);assert response==data_chunk(nonce,0)
                        emit(kind='added_ready',data=response.hex())
                    else:
                        sock.sendall((b'EHLO ' if application=='smtp' else b'USER ')+nonce.encode()+b'\r\n')
                        response=line(sock);assert response.startswith(b'250 ' if application=='smtp' else b'331 ')
                        if application!='smtp':sock.sendall(b'PASS test\r\n');assert line(sock).startswith(b'230 ')
                        emit(kind='added_ready',data=response.hex())
                elif op in ('send','recv','repeat'):
                    sock.settimeout(command.get('timeout',15))
                    count=24 if op=='repeat' else 1
                    delivered=[]
                    for _ in range(count):
                        if op!='recv':pending=noop(index);index+=1
                        response=line(sock);assert response==pending,(response,pending)
                        delivered.append(response.hex());pending=None
                    emit(kind='received',count=count,data=delivered)
                else:raise ValueError(op)
            except socket.timeout:emit(kind='timeout')
            except Exception as error:emit(kind='client_error',error=repr(error))
    finally:
        sock.close()
        if control is not sock:control.close()
        emit(kind='closed')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('role',choices=['server','client'])
    parser.add_argument('--host',default='127.0.0.2');parser.add_argument('--directory',type=Path)
    parser.add_argument('--source',type=int,default=45100);parser.add_argument('--nonce',default='r2')
    parser.add_argument('--application',choices=tuple(PORTS),default='explicit')
    parser.add_argument('--applications',default=','.join(PORTS))
    args=parser.parse_args()
    if args.role=='server':server(args.host,args.directory,args.applications.split(','))
    else:client(args.host,args.source,args.application,args.nonce)
