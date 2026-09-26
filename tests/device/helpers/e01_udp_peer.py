#!/usr/bin/env python3
"""Real-packet E01 oracle. Every payload has run identity and sequence."""
import argparse,json,socket,time,sys
p=argparse.ArgumentParser();p.add_argument('mode',choices=['server','client']);p.add_argument('--host',required=True);p.add_argument('--peer');p.add_argument('--port',type=int,default=42141);p.add_argument('--source',type=int,default=43000);p.add_argument('--nonce',default='e01');a=p.parse_args()
def emit(v): print(json.dumps(v),flush=True)
if a.mode=='server':
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((a.host,a.port));emit({'ready':True})
    while True:
        data,peer=s.recvfrom(65536);now=time.time_ns();s.sendto(data,peer)
        emit({'peer':peer,'payload':data.hex(),'received_ns':now,'replied_ns':time.time_ns()})
else:
    sockets=[];sequence=0
    def new(port):
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((a.host,port));s.connect((a.peer,a.port));s.settimeout(1);return s
    try:
        sockets=[new(a.source+i) for i in range(128)]
        emit({'ready':True})
        for name in sys.stdin:
            name=name.strip();count={'idle':0,'low':20,'burst':256,'sustained':1000,'active':512,'short':128,'pause':1024,'recovery':128,'freshness':1}[name]
            start=time.monotonic_ns();rows=[]
            if name=='idle':time.sleep(10)
            for i in range(count):
                short=name in ('short','pause');s=new(a.source+(256 if name=='pause' else 128)+i) if short else sockets[i%128 if name in ('active','recovery') else 0]
                payload=(f'{sequence:08d}:'+a.nonce).encode().ljust(64,b'x')[:64];sequence+=1
                begin=time.monotonic_ns();wall=time.time_ns();s.send(payload);echoed=False
                try: echoed=s.recv(256)==payload
                except socket.timeout: pass
                rows.append({'id':sequence-1,'sentMonoNs':begin,'sentUtcNs':wall,'endMonoNs':time.monotonic_ns(),'echoed':echoed,'sourcePort':s.getsockname()[1],'payload':payload.hex()})
                if short:s.close()
                if name in ('low','sustained'):time.sleep(.1 if name=='low' else .002)
            emit({'name':name,'startedMonoNs':start,'completedMonoNs':time.monotonic_ns(),'sent':count,'received':sum(x['echoed'] for x in rows),'exchanges':rows})
    finally:
        for s in sockets:s.close()
