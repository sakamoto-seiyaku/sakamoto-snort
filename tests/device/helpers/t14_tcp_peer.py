#!/usr/bin/env python3
"""Independent kernel TCP endpoint and literal RFC ClientHello test fixtures."""
import argparse, hashlib, json, socket, ssl, subprocess, threading, time
from pathlib import Path

def emit(**fields):
    print(json.dumps(dict(time_ns=time.time_ns(), **fields)), flush=True)

def prepare(directory):
    directory.mkdir(parents=True, exist_ok=False)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
      '-subj','/CN=example.test','-addext','subjectAltName=DNS:example.test',
      '-keyout',str(directory/'key.pem'),'-out',str(directory/'cert.pem')],check=True,capture_output=True)
    (directory/'key.pem').chmod(0o644)
    absent=bytes.fromhex('160301002d010000290303')+bytes(32)+bytes.fromhex('000002002f0100')
    name=b'example.test'
    entry=b'\x00'+len(name).to_bytes(2,'big')+name
    names=len(entry).to_bytes(2,'big')+entry
    extension=b'\x00\x00'+len(names).to_bytes(2,'big')+names
    def hello(extensions, total=None):
        if total:
            padding=total-len(absent)-2-len(extensions)-4
            extensions+=b'\x00\x15'+padding.to_bytes(2,'big')+bytes(padding)
        wire=bytearray(absent+len(extensions).to_bytes(2,'big')+extensions)
        wire[3:5]=(len(wire)-5).to_bytes(2,'big')
        wire[6:9]=(len(wire)-9).to_bytes(3,'big')
        return bytes(wire)
    values={'named':hello(extension),'absent':absent,
            'maximum':hello(b'',4096),'exhausted':hello(b'',4097)}
    fixtures={'nonce':str(time.time_ns()),'certificateSha256':hashlib.sha256(
        ssl.PEM_cert_to_DER_cert((directory/'cert.pem').read_text())).hexdigest()}
    for mode,wire in values.items():
        fixtures[mode+'Hex']=wire.hex();(directory/(mode+'.bin')).write_bytes(wire)
    (directory/'fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n')

def server(host,directory):
    fixtures=json.loads((directory/'fixtures.json').read_text())
    allowed={bytes.fromhex(fixtures[k+'Hex']) for k in ('named','absent','maximum','exhausted')}
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory/'cert.pem',directory/'key.pem')
    context.set_servername_callback(lambda sock,name,_context:emit(kind='sni',peer=list(sock.getpeername()),name=name))
    def serve(conn,peer,tls):
        try:
            conn.settimeout(40)
            if tls:
                conn=context.wrap_socket(conn,server_side=True)
                emit(kind='handshake',peer=list(peer),version=conn.version())
                while data:=conn.recv(8192):
                    emit(kind='received',peer=list(peer),hex=data.hex());conn.sendall(data)
            else:
                data=bytearray()
                while len(data)<5 or len(data)<5+int.from_bytes(data[3:5],'big'):
                    chunk=conn.recv(8192)
                    if not chunk:raise RuntimeError('truncated endpoint stream')
                    data.extend(chunk)
                    emit(kind='chunk',peer=list(peer),length=len(chunk),total=len(data))
                if bytes(data) not in allowed:raise RuntimeError('wire differs from literal fixture')
                emit(kind='raw_received',peer=list(peer),hex=data.hex(),sha256=hashlib.sha256(data).hexdigest())
                conn.sendall(b'A')
                while conn.recv(8192):pass
        except Exception as error:emit(kind='endpoint_error',peer=list(peer),error=repr(error))
        finally:conn.close()
    def accept(listener,tls):
        while True:
            conn,peer=listener.accept()
            threading.Thread(target=serve,args=(conn,peer,tls),daemon=True).start()
    listeners=[]
    for port in (40640,40641):
        listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind((host,port));listener.listen(128);listeners.append(listener)
        threading.Thread(target=accept,args=(listener,port==40640),daemon=True).start()
    emit(kind='ready',host=host,port=40641)
    threading.Event().wait()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('role',choices=['prepare','server'])
    p.add_argument('--directory',type=Path,required=True);p.add_argument('--host',default='127.0.0.2')
    a=p.parse_args()
    if a.role=='prepare':prepare(a.directory)
    else:server(a.host,a.directory)
