#!/usr/bin/env python3
"""Independent R3 ordinary socket endpoints.

SOCKS4/5 execute CONNECT and relay to an independent TCP echo listener. OpenVPN
and RDP endpoints implement selected reset/negotiation exchanges only, expressly
not complete VPN/desktop sessions. WireGuard authenticates Noise and inner ICMP.
No Product detector, Flow access, packet injection or policy writer is used.
"""
import argparse
import hashlib
import json
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path

PORTS={'openvpn_udp':1195,'openvpn_tcp':1196,'wireguard':51821,
       'socks4':1084,'socks5':1085,'rdp_tcp':3390,'rdp_udp':3389}
TRANSPORT={name:'udp' if name in ('openvpn_udp','wireguard','rdp_udp') else 'tcp' for name in PORTS}
TARGETS={'openvpn_udp':1011,'openvpn_tcp':1011,'wireguard':1012,'socks4':1013,'socks5':1014,'rdp_tcp':1015,'rdp_udp':1015}

def emit(**fields):print(json.dumps(dict(time_ns=time.time_ns(),**fields)),flush=True)
def exact(sock,length):
    data=b''
    while len(data)<length:
        piece=sock.recv(length-len(data))
        if not piece:raise EOFError('short response')
        data+=piece
    return data

def cstring(sock):
    data=b''
    for _ in range(512):
        value=exact(sock,1);data+=value
        if value==b'\0':return data
    raise ValueError('string bound')
def line(sock):
    value=b''
    while len(value)<256:
        value+=exact(sock,1)
        if value.endswith(b'\n'):return value
    raise ValueError('line bound')
def identity(label):return hashlib.sha256(label.encode()).digest()[:8]
def openvpn_request(label):return b'\x38'+identity(label)+b'\0'*5

def openvpn_reply(request):
    assert len(request)==14 and request[0]==56 and request[9:]==bytes(5)
    return b'\x40'+hashlib.sha256(request[1:9]).digest()[:8]+b'\x01'+bytes(4)+request[1:9]+bytes(4)

def rdp_request(label):
    cookie=b'Cookie: mstshash='+label.encode()+b'\r\n'
    tail=b'\xe0\0\0\0\0\0'+cookie+b'\x01\0\x08\0\x01\0\0\0'
    return struct.pack('!BBH',3,0,len(tail)+5)+bytes([len(tail)])+tail

def rdp_reply(request):
    assert len(request)>=19 and request[:2]==b'\x03\0' and int.from_bytes(request[2:4],'big')==len(request)
    assert request[4]==len(request)-5 and request[5:11]==b'\xe0\0\0\0\0\0'
    assert request[11:-8].startswith(b'Cookie: mstshash=') and request[-10:-8]==b'\r\n'
    assert request[-8:]==b'\x01\0\x08\0\x01\0\0\0'
    return bytes.fromhex('030000130ed000001234000200080001000000')

def rdp_udp_request(label):return bytes.fromhex('ffffffff00400001')+identity(label)[:4]+bytes.fromhex('04b004b0')
def rdp_udp_reply(request):
    assert len(request)==16 and request[:8]==bytes.fromhex('ffffffff00400001') and request[12:]==bytes.fromhex('04b004b0')
    return request[8:12]+bytes.fromhex('00400003')+hashlib.sha256(request).digest()[:4]+request[12:]

def frame(sock,application):
    if application=='openvpn_tcp':return exact(sock,int.from_bytes(exact(sock,2),'big'))
    head=exact(sock,4);return head+exact(sock,int.from_bytes(head[2:4],'big')-4)

def server(host,applications,fixtures):
    signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
    listeners=[]
    def echo(connection,peer):
        try:
            while True:
                data=line(connection)
                emit(kind='target_received',peer=peer,data=data.hex())
                connection.sendall(data);emit(kind='target_sent',peer=peer,data=data.hex())
        except EOFError:pass
        finally:connection.close()
    target=socket.socket();target.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);target.bind((host,40619));target.listen()
    def echo_accept():
        while True:
            connection,peer=target.accept();threading.Thread(target=echo,args=(connection,peer),daemon=True).start()
    threading.Thread(target=echo_accept,daemon=True).start();listeners.append(target)
    def tcp(connection,peer,application):
        upstream=None
        def send(data,kind='reply'):
            connection.sendall(data);emit(kind=kind,application=application,peer=peer,data=data.hex())
        try:
            connection.settimeout(180);connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            emit(kind='connect',application=application,peer=peer)
            if application.startswith('socks'):
                if application=='socks4':
                    req=exact(connection,8)+cstring(connection)
                    assert req[:2]==b'\x04\x01' and req[2:4]==struct.pack('!H',40619) and req[4:8]==socket.inet_aton(host)
                    emit(kind='negotiation_request',application=application,peer=peer,data=req.hex())
                    upstream=socket.create_connection((host,40619),timeout=10)
                    send(b'\0\x5a'+req[2:8],'negotiation_reply')
                else:
                    head=exact(connection,2);assert head[0]==5 and 1<=head[1]<=32
                    req=head+exact(connection,head[1]);assert 0 in req[2:]
                    emit(kind='negotiation_request',application=application,peer=peer,data=req.hex());send(b'\x05\0','negotiation_reply')
                    req=exact(connection,10)
                    assert req[:4]==b'\x05\x01\0\x01' and req[4:8]==socket.inet_aton(host) and req[8:]==struct.pack('!H',40619)
                    emit(kind='connect_request',application=application,peer=peer,data=req.hex())
                    upstream=socket.create_connection((host,40619),timeout=10)
                    send(b'\x05\0\0\x01'+socket.inet_aton(host)+struct.pack('!H',40619),'connect_reply')
                emit(kind='proxy_connected',application=application,peer=peer,target=upstream.getpeername(),relay=upstream.getsockname())
                while True:
                    data=line(connection);emit(kind='command',application=application,peer=peer,data=data.hex())
                    upstream.sendall(data);response=line(upstream);assert response==data;send(response)
            else:
                while True:
                    req=frame(connection,application)
                    emit(kind='command',application=application,peer=peer,data=req.hex())
                    response=openvpn_reply(req) if application=='openvpn_tcp' else rdp_reply(req)
                    wire=struct.pack('!H',len(response))+response if application=='openvpn_tcp' else response
                    send(wire)
        except EOFError:pass
        except Exception as error:emit(kind='error',application=application,peer=peer,error=repr(error))
        finally:
            if upstream:upstream.close()
            connection.close();emit(kind='close',application=application,peer=peer)
    def tcp_accept(listener,application):
        while True:
            connection,peer=listener.accept();threading.Thread(target=tcp,args=(connection,peer,application),daemon=True).start()
    def udp(listener,application):
        sessions={}
        while True:
            request,peer=listener.recvfrom(4096)
            try:
                emit(kind='command',application=application,peer=peer,data=request.hex())
                if application=='wireguard':
                    import r3_wireguard as wg
                    if request[:4]==b'\x01\0\0\0':
                        fixture=next(f for f in fixtures if f['initial']==request.hex())
                        responder=wg.Responder(bytes.fromhex(fixture['server_private']),bytes.fromhex(fixture['client_public']),
                            bytes.fromhex(fixture['responder_ephemeral']),fixture['server_index'])
                        response=responder.initiation(request);sessions[peer]=responder
                        emit(kind='authenticated_handshake',application=application,peer=peer,label=fixture['label'])
                    else:
                        text,response=sessions[peer].data(request)
                        emit(kind='inner_icmp',application=application,peer=peer,text=text)
                else:response=openvpn_reply(request) if application=='openvpn_udp' else rdp_udp_reply(request)
                listener.sendto(response,peer);emit(kind='reply',application=application,peer=peer,data=response.hex())
            except Exception as error:emit(kind='error',application=application,peer=peer,error=repr(error))
    for application in applications:
        listener=socket.socket(type=socket.SOCK_DGRAM if TRANSPORT[application]=='udp' else socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind((host,PORTS[application]));listeners.append(listener)
        if TRANSPORT[application]=='tcp':listener.listen()
        threading.Thread(target=udp if TRANSPORT[application]=='udp' else tcp_accept,args=(listener,application),daemon=True).start()
    emit(kind='ready',host=host,ports={a:PORTS[a] for a in applications},target_port=40619)
    signal.pause()

def client(host,source,application,label,fixtures):
    udp=TRANSPORT[application]=='udp';sock=socket.socket(type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if not udp:sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    sock.bind(('127.0.0.1',source));sock.settimeout(10);sock.connect((host,PORTS[application]))
    fixture=next((f for f in fixtures if f['label']==label),None);index=0;pending=None
    emit(kind='connected',application=application,local=sock.getsockname(),peer=sock.getpeername())
    def receive(expected):
        response=sock.recv(4096) if udp else exact(sock,len(expected))
        assert response==expected,(response.hex(),expected.hex());return response
    def packet(index):
        text=label+':'+str(index)
        if application.startswith('socks'):return (text+'\n').encode(),(text+'\n').encode()
        if application=='wireguard':
            pair=fixture['pairs'][index];return bytes.fromhex(pair['request']),bytes.fromhex(pair['reply'])
        if application.startswith('openvpn'):
            req=openvpn_request(label);res=openvpn_reply(req)
            return (req,res) if udp else (struct.pack('!H',len(req))+req,struct.pack('!H',len(res))+res)
        if application=='rdp_udp':
            req=rdp_udp_request(label);return req,rdp_udp_reply(req)
        req=rdp_request(text);return req,rdp_reply(req)
    try:
        for raw in sys.stdin:
            command=json.loads(raw);op=command['op']
            try:
                if op=='close':break
                if op=='first':emit(kind='first_ready');continue
                if op=='added':
                    if application=='socks4':
                        request=b'\x04\x01'+struct.pack('!H',40619)+socket.inet_aton(host)+label.encode()+b'\0'
                        sock.sendall(request);response=receive(b'\0\x5a'+request[2:8]);emit(kind='negotiated',data=response.hex())
                    elif application=='socks5':
                        sock.sendall(b'\x05\x02\0\x80');receive(b'\x05\0')
                        request=b'\x05\x01\0\x01'+socket.inet_aton(host)+struct.pack('!H',40619)
                        sock.sendall(request);response=receive(b'\x05\0'+request[2:]);emit(kind='negotiated',data=response.hex())
                    elif application=='wireguard':
                        sock.send(bytes.fromhex(fixture['initial']));response=receive(bytes.fromhex(fixture['response']))
                        emit(kind='handshake_response',data=response.hex())
                    req,expected=packet(index);sock.sendall(req);response=receive(expected);index+=1
                    emit(kind='added_ready',data=response.hex());continue
                sock.settimeout(command.get('timeout',10));count=24 if op=='repeat' else 1;delivered=[]
                for _ in range(count):
                    if op!='recv':
                        req,pending=packet(index);sock.sendall(req);index+=1
                    elif udp:sock.sendall(req) # retry the dropped transport datagram after recovery
                    delivered.append(receive(pending).hex());pending=None
                emit(kind='received',count=count,data=delivered)
            except socket.timeout:emit(kind='timeout')
            except Exception as error:emit(kind='client_error',error=repr(error))
    finally:sock.close();emit(kind='closed')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('role',choices=['server','client']);p.add_argument('--host',default='127.0.0.2')
    p.add_argument('--source',type=int,default=45110);p.add_argument('--application',choices=tuple(PORTS),default='socks5')
    p.add_argument('--applications',default=','.join(PORTS));p.add_argument('--nonce',default='r3');p.add_argument('--fixtures',type=Path,required=True)
    args=p.parse_args();fixtures=json.loads(args.fixtures.read_text())['wireguard']
    if args.role=='server':server(args.host,args.applications.split(','),fixtures)
    else:client(args.host,args.source,args.application,args.nonce,fixtures)
