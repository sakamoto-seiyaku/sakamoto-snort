#!/usr/bin/env python3
"""Controlled live STUN, RTP/RTCP, SIP and DTLS-cookie peers, no Product imports.

DTLS is deliberately a cookie exchange, not an authenticated channel.
RTP carries 20ms PCMU sample blocks; the receiver validates sequence and samples.
"""
import argparse
import hashlib
import json
import socket
import struct
import sys
import threading
import time

PORTS={'stun_udp':3479,'stun_tcp':3480,'rtp_udp':5004,'rtp_tcp':5006,
       'rtcp_udp':5005,'rtcp_tcp':5007,'sip_udp':5060,'sip_tcp':5061,'dtls_udp':4444}
TARGETS={'stun_udp':1016,'stun_tcp':1016,'rtp_udp':1017,'rtp_tcp':1017,
         'rtcp_udp':1018,'rtcp_tcp':1018,'sip_udp':1019,'sip_tcp':1019,'dtls_udp':1020}
lock=threading.Lock()
def emit(kind,**values):
    with lock: print(json.dumps(dict(kind=kind,time_ns=time.time_ns(),**values)),flush=True)
def seed(nonce):return hashlib.sha256(nonce.encode()).digest()
def stun(nonce,index,response=False):
    tx=hashlib.sha256((nonce+':'+str(index)).encode()).digest()[:12]
    body=b'\x80\x22'+struct.pack('!H',len(nonce))+nonce.encode()
    body+=bytes((-len(nonce))%4)
    if response:
        # XOR-MAPPED-ADDRESS uses a controlled diagnostic value. Transport peer
        # address is independently logged, including VPN's actual egress port.
        body+=bytes.fromhex('002000080001')+struct.pack('!H',5004^0x2112)+bytes(a^b for a,b in zip(socket.inet_aton('192.0.2.1'),bytes.fromhex('2112a442')))
    return struct.pack('!HHI',0x101 if response else 1,len(body),0x2112a442)+tx+body
def rtp(nonce,index,response=False):
    h=seed(nonce);ssrc=h[4:8] if response else h[:4]
    sequence=(1000 if response else 100)+index
    samples=bytes([0xff if response else 0x7f])*160
    return struct.pack('!BBHI',0x80,0,sequence&65535,(index*160)&0xffffffff)+ssrc+samples
def rtcp(nonce,index,response=False):
    h=seed(nonce);ssrc=h[4:8] if response else h[:4]
    if response:return bytes.fromhex('80c90001')+ssrc
    return bytes.fromhex('80c80006')+ssrc+struct.pack('!IIIII',0xe0000000+index,0,index*160,index+1,(index+1)*160)
def sip(nonce,index,response=False):
    first='SIP/2.0 200 OK' if response else 'OPTIONS sip:peer@example.test SIP/2.0'
    return (first+'\r\nVia: SIP/2.0/UDP client.test;branch=z9hG4bK'+nonce+str(index)+
      '\r\nFrom: <sip:client@example.test>;tag=r4\r\nTo: <sip:peer@example.test>\r\nCall-ID: '+nonce+
      '\r\nCSeq: '+str(index+1)+' OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n').encode()
def dtls(nonce,index,response=False):
    h=seed(nonce);cookie=hashlib.sha256(b'r4-cookie'+h).digest()[:16]
    if response:
        body=b'\xfe\xfd'+bytes([len(cookie)])+cookie;kind=3
    else:
        present=cookie if index else b''
        body=b'\xfe\xfd'+h+b'\0'+bytes([len(present)])+present+bytes.fromhex('0002002f0100')
        kind=1
    handshake=bytes([kind])+len(body).to_bytes(3,'big')+struct.pack('!H',index)+bytes(3)+len(body).to_bytes(3,'big')+body
    return bytes.fromhex('16fefd0000')+index.to_bytes(6,'big')+struct.pack('!H',len(handshake))+handshake
def payload(app,nonce,index,response=False):
    return {'stun':stun,'rtp':rtp,'rtcp':rtcp,'sip':sip,'dtls':dtls}[app.split('_')[0]](nonce,index,response)
def frame(app,data):
    return struct.pack('!H',len(data))+data if app.endswith('tcp') and not app.startswith('sip') else data
def read_exact(sock,n):
    data=b''
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part:raise EOFError('peer closed')
        data+=part
    return data
def receive(sock,app):
    if app.endswith('udp'):return sock.recv(4096)
    if app.startswith('sip'):
        data=b''
        while not data.endswith(b'\r\n\r\n'):
            data+=read_exact(sock,1)
            if len(data)>4096:raise ValueError('SIP message budget')
        return data
    return read_exact(sock,int.from_bytes(read_exact(sock,2),'big'))
def workload(app,nonce):
    return dict(first=stun(nonce,99) if app.startswith(('rtp_','rtcp_')) else None,
                count=3 if app.startswith('rtp_') else 4 if app.startswith('rtcp_') else 1,
                requests=[payload(app,nonce,i) for i in range(30)],
                replies=[payload(app,nonce,i,True) for i in range(30)])

def server(args):
    fixtures=json.loads(args.fixtures.read_text())
    definitions={v['nonce']:v for v in fixtures['sessions'] if v['application'] in args.applications.split(',')}
    def handle(app,data,peer,sock):
        for nonce,definition in definitions.items():
            if definition['application']!=app:continue
            w=workload(app,nonce)
            if data==w['first']:
                answer=stun(nonce,99,True);index=-1;kind='stun_bootstrap'
                break
            try:index=w['requests'].index(data)
            except ValueError:continue
            answer=w['replies'][index];kind=app.split('_')[0]
            break
        else:raise ValueError('unknown or malformed controlled message')
        emit('command',application=app,nonce=nonce,index=index,data=data.hex(),peer=list(peer),message=kind)
        if app.endswith('udp'):sock.sendto(answer,peer)
        else:sock.sendall(frame(app,answer))
        emit('reply',application=app,nonce=nonce,index=index,data=answer.hex(),peer=list(peer),message=kind)
    def udp(app):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind((args.host,PORTS[app]))
        ready(app)
        while True:
            data,peer=sock.recvfrom(4096)
            try:handle(app,data,peer,sock)
            except Exception as e:emit('error',application=app,error=repr(e))
    def connection(app,sock,peer):
        try:
            with sock:
                sock.settimeout(120)
                while True:handle(app,receive(sock,app),peer,sock)
        except EOFError:pass
        except Exception as e:emit('error',application=app,error=repr(e))
    def tcp(app):
        listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind((args.host,PORTS[app]));listener.listen();ready(app)
        while True:
            sock,peer=listener.accept();sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            threading.Thread(target=connection,args=(app,sock,peer),daemon=True).start()
    ready_apps=set();ready_lock=threading.Lock();apps=args.applications.split(',')
    def ready(app):
        with ready_lock:
            ready_apps.add(app)
            if ready_apps==set(apps):emit('ready',ports={app:PORTS[app] for app in apps})
    for app in apps:threading.Thread(target=udp if app.endswith('udp') else tcp,args=(app,),daemon=True).start()
    threading.Event().wait()

def client(args):
    app=args.application;nonce=args.nonce;w=workload(app,nonce)
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if app.endswith('udp') else socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if app.endswith('tcp'):sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    sock.bind(('',args.source));sock.settimeout(10);sock.connect((args.host,PORTS[app]))
    emit('connected',nonce=nonce,local=list(sock.getsockname()),application=app)
    index=0
    def exchange(data,expected):
        sock.sendall(frame(app,data));reply=receive(sock,app)
        assert reply==expected,('response mismatch',reply.hex(),expected.hex())
        return reply.hex()
    try:
        for line in sys.stdin:
            op=json.loads(line);sock.settimeout(op.get('timeout',10))
            if op['op']=='first':
                reply=exchange(w['first'],stun(nonce,99,True)) if w['first'] else None
                emit('first_ready',data=reply)
            elif op['op']=='added':
                answers=[]
                for index in range(w['count']):answers.append(exchange(w['requests'][index],w['replies'][index]))
                index+=1;emit('added_ready',data=answers)
            elif op['op']=='send':
                sock.sendall(frame(app,w['requests'][index]))
                try:receive(sock,app);raise AssertionError('expected blocked timeout')
                except socket.timeout:emit('timeout',index=index)
            elif op['op']=='recv':
                if app.endswith('udp'):answer=exchange(w['requests'][index],w['replies'][index])
                else:
                    answer=receive(sock,app).hex();assert answer==w['replies'][index].hex()
                emit('received',count=1,data=[answer]);index+=1
            elif op['op']=='repeat':
                answers=[]
                for _ in range(24):
                    answers.append(exchange(w['requests'][index],w['replies'][index]));index+=1
                    time.sleep(.03)
                emit('received',count=24,data=answers)
            elif op['op']=='close':sock.close();emit('closed');return
    except Exception as e:emit('client_error',error=repr(e));raise
    finally:sock.close()

if __name__=='__main__':
    from pathlib import Path
    p=argparse.ArgumentParser();p.add_argument('role',choices=['server','client','fixtures'])
    p.add_argument('--host',default='127.0.0.2');p.add_argument('--fixtures',type=Path)
    p.add_argument('--applications',default=','.join(PORTS));p.add_argument('--application',choices=PORTS)
    p.add_argument('--nonce');p.add_argument('--source',type=int);p.add_argument('--output',type=Path)
    a=p.parse_args()
    if a.role=='fixtures':
        prefix='R4-'+str(time.time_ns())
        sessions=[dict(application=app,nonce=prefix+'-linux-'+app) for app in PORTS]
        sessions += [dict(application='rtp_udp',nonce=prefix+'-'+profile+'-rtp_udp') for profile in ('root','vpn')]
        a.output.write_text(json.dumps(dict(sessions=sessions),indent=2)+'\n')
    elif a.role=='server':server(a)
    else:client(a)
