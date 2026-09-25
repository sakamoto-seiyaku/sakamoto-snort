#!/usr/bin/env python3
"""Ordinary TLS1.2 client/server and literal invalid-prefix receipt witnesses."""
import argparse,hashlib,json,socket,ssl,subprocess,threading,time
from pathlib import Path

def emit(**fields): print(json.dumps(dict(time_ns=time.time_ns(),**fields)),flush=True)
def prepare(path):
    path.mkdir(parents=True,exist_ok=False)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
      '-subj','/CN=example.test','-addext','subjectAltName=DNS:example.test',
      '-keyout',str(path/'key.pem'),'-out',str(path/'cert.pem')],check=True,capture_output=True)
    certificate=ssl.PEM_cert_to_DER_cert((path/'cert.pem').read_text())
    # Truncated after legacy-version/random prefix; malformed complete Hello has
    # zero cipher-suite vector. Expectations are literal, not Product-derived.
    absent=bytes.fromhex('160301002d010000290303')+bytes(32)+bytes.fromhex('000002002f0100')
    malformed=bytearray(absent);malformed[45]=0
    (path/'fixtures.json').write_text(json.dumps(dict(certificateSha256=hashlib.sha256(certificate).hexdigest(),
      malformedHex=malformed.hex(),truncatedHex=absent[:20].hex(),nonce=str(time.time_ns())),indent=2))
    (path/'key.pem').chmod(0o644) # ephemeral test-only key read by isolated endpoint UID

def server(host,port,path):
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(path/'cert.pem',path/'key.pem')
    def sni(sock,name,_context): emit(kind='sni',peer=list(sock.getpeername()),name=name)
    context.set_servername_callback(sni)
    def serve(conn,peer,raw):
        try:
            conn.settimeout(40)
            if raw:
                data=conn.recv(8192);emit(kind='raw_received',peer=list(peer),hex=data.hex())
                conn.sendall(b'A')
                while conn.recv(1024): pass
            else:
                with context.wrap_socket(conn,server_side=True) as tls:
                    emit(kind='handshake',peer=list(peer),version=tls.version())
                    while True:
                        data=tls.recv(8192)
                        if not data:break
                        emit(kind='received',peer=list(peer),hex=data.hex());tls.sendall(data)
        except Exception as e:emit(kind='endpoint_error',peer=list(peer),error=repr(e))
        finally:conn.close()
    def accept(listener,raw):
        while True:
            conn,peer=listener.accept();threading.Thread(target=serve,args=(conn,peer,raw),daemon=True).start()
    listeners=[]
    for offset in (0,1):
        listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind((host,port+offset));listener.listen();listeners.append(listener)
        threading.Thread(target=accept,args=(listener,bool(offset)),daemon=True).start()
    emit(kind='ready',host=host,port=port)
    threading.Event().wait()

def client(host,port,source,mode,path,nonce):
    raw=mode in ('malformed','truncated')
    sock=socket.socket();sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    sock.bind(('',source));sock.settimeout(10);sock.connect((host,port+raw))
    fixtures=json.loads((path/'fixtures.json').read_text())
    if raw:
        data=bytes.fromhex(fixtures[mode+'Hex']);sock.sendall(data)
        assert sock.recv(1)==b'A';emit(kind='raw_ready',hex=data.hex())
    else:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False
        context.load_verify_locations(path/'cert.pem')
        context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
        sock=context.wrap_socket(sock,server_hostname='example.test' if mode=='named' else None)
        emit(kind='tls_ready',version=sock.version())
    pending=None
    for line in __import__('sys').stdin:
        command=json.loads(line);op=command['op'];sock.settimeout(command.get('timeout',10))
        if op=='close':sock.close();emit(kind='closed');return
        if op=='send':
            pending=(nonce+':blocked\n').encode();sock.sendall(pending)
            try:answer=sock.recv(len(pending));emit(kind='unexpected',hex=answer.hex())
            except socket.timeout:emit(kind='timeout')
        elif op=='recv':
            answer=sock.recv(len(pending));assert answer==pending;emit(kind='received',hex=answer.hex())
        elif op=='echo':
            data=(nonce+':echo\n').encode();sock.sendall(data);answer=sock.recv(len(data));assert answer==data
            emit(kind='received',hex=answer.hex())
        else:raise ValueError(op)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('role',choices=['prepare','server','client'])
    p.add_argument('--directory',type=Path,required=True);p.add_argument('--host',default='127.0.0.2')
    p.add_argument('--port',type=int,default=40640);p.add_argument('--source',type=int)
    p.add_argument('--mode',choices=['named','absent','malformed','truncated']);p.add_argument('--nonce')
    a=p.parse_args()
    if a.role=='prepare':prepare(a.directory)
    elif a.role=='server':server(a.host,a.port,a.directory)
    else:client(a.host,a.port,a.source,a.mode,a.directory,a.nonce)
