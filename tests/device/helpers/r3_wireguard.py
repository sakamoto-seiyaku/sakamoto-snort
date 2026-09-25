#!/usr/bin/env python3
"""Test-only WireGuard Noise IKpsk2 and authenticated inner ICMP exchange.

Independent protocol endpoint, never imports Product code or recognition output.
Wire layout: https://www.wireguard.com/protocol/ . Cryptographic primitives come
from cryptography/OpenSSL. This deliberately omits production timers/cookies,
routing and roaming; it is an interoperable single-session test peer.
"""
import hashlib
import hmac
import os
import struct
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CONSTRUCTION=b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s'
IDENTIFIER=b'WireGuard v1 zx2c4 Jason@zx2c4.com'

def hash32(value):return hashlib.blake2s(value).digest()
def mac16(key,value):return hashlib.blake2s(value,key=key,digest_size=16).digest()
def kdf(key,value,count=1):
    salt=hmac.new(key,value,hashlib.blake2s).digest();part=b'';result=[]
    for index in range(1,count+1):
        part=hmac.new(salt,part+bytes([index]),hashlib.blake2s).digest();result.append(part)
    return result

def public(private):return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()
def dh(private,peer):return X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(peer))
def nonce(counter):return struct.pack('<IQ',0,counter)
def encrypt(key,counter,data,aad=b''):return ChaCha20Poly1305(key).encrypt(nonce(counter),data,aad)
def decrypt(key,counter,data,aad=b''):return ChaCha20Poly1305(key).decrypt(nonce(counter),data,aad)

def initial_state(server_public):
    ck=hash32(CONSTRUCTION)
    return ck,hash32(hash32(ck+IDENTIFIER)+server_public)

def checksum(value):
    if len(value)%2:value+=b'\0'
    total=sum(struct.unpack('!'+str(len(value)//2)+'H',value))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535

def inner_packet(text,reply=False):
    data=text.encode();icmp=struct.pack('!BBHHH',0 if reply else 8,0,0,0x5233,0)+data
    icmp=icmp[:2]+struct.pack('!H',checksum(icmp))+icmp[4:]
    src,dst=(b'\x0a\x11\0\x02',b'\x0a\x11\0\x01') if reply else (b'\x0a\x11\0\x01',b'\x0a\x11\0\x02')
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(icmp),0,0,64,1,0,src,dst)
    return ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]+icmp

def inner_text(packet,reply=False):
    assert len(packet)>=28 and packet[:2]==b'\x45\0' and packet[9]==1
    size=int.from_bytes(packet[2:4],'big');assert 28<=size<=len(packet)
    assert not checksum(packet[:20]) and not checksum(packet[20:size])
    assert not any(packet[size:]) and packet[20]==(0 if reply else 8) and packet[21]==0
    text=packet[28:size].decode('ascii');assert packet[:size]==inner_packet(text,reply)
    return text

class Initiator:
    def __init__(self,private,server_public,ephemeral,index,timestamp=None):
        self.private,self.server,self.ephemeral,self.index=private,server_public,ephemeral,index
        self.ck,self.h=initial_state(server_public)
        ep=public(ephemeral);self.h=hash32(self.h+ep);self.ck=kdf(self.ck,ep)[0]
        self.ck,key=kdf(self.ck,dh(ephemeral,server_public),2)
        static=encrypt(key,0,public(private),self.h);self.h=hash32(self.h+static)
        self.ck,key=kdf(self.ck,dh(private,server_public),2)
        stamp=timestamp or struct.pack('!QI',0x400000000000000a+int(time.time()),time.time_ns()%1000000000)
        encrypted_time=encrypt(key,0,stamp,self.h);self.h=hash32(self.h+encrypted_time)
        head=struct.pack('<II',1,index)+ep+static+encrypted_time
        self.initiation=head+mac16(hash32(b'mac1----'+server_public),head)+bytes(16)
        self.send_counter=0;self.received=set()
    def response(self,packet):
        assert len(packet)==92 and packet[:4]==b'\x02\0\0\0' and struct.unpack_from('<I',packet,8)[0]==self.index
        assert hmac.compare_digest(packet[60:76],mac16(hash32(b'mac1----'+public(self.private)),packet[:60]))
        self.peer_index=struct.unpack_from('<I',packet,4)[0];ep=packet[12:44]
        self.h=hash32(self.h+ep);self.ck=kdf(self.ck,ep)[0]
        self.ck=kdf(self.ck,dh(self.ephemeral,ep))[0]
        self.ck=kdf(self.ck,dh(self.private,ep))[0]
        self.ck,mix,key=kdf(self.ck,bytes(32),3);self.h=hash32(self.h+mix)
        assert decrypt(key,0,packet[44:60],self.h)==b''
        self.h=hash32(self.h+packet[44:60]);self.send_key,self.receive_key=kdf(self.ck,b'',2)
    def data(self,text):
        inner=inner_packet(text);inner+=bytes((-len(inner))%16)
        counter=self.send_counter;self.send_counter+=1
        return struct.pack('<IIQ',4,self.peer_index,counter)+encrypt(self.send_key,counter,inner)
    def receive(self,packet):
        assert len(packet)>=32 and packet[:4]==b'\x04\0\0\0' and struct.unpack_from('<I',packet,4)[0]==self.index
        counter=struct.unpack_from('<Q',packet,8)[0];assert counter not in self.received
        inner=decrypt(self.receive_key,counter,packet[16:]);text=inner_text(inner,True)
        self.received.add(counter);return text

class Responder:
    def __init__(self,private,allowed_public,ephemeral=None,index=None):
        self.private,self.allowed=private,allowed_public
        self.ephemeral=ephemeral or os.urandom(32);self.index=index if index is not None else int.from_bytes(os.urandom(4),'little')
        self.received=set();self.send_counter=0;self.timestamp=None
    def initiation(self,packet):
        assert len(packet)==148 and packet[:4]==b'\x01\0\0\0'
        pub=public(self.private)
        assert hmac.compare_digest(packet[116:132],mac16(hash32(b'mac1----'+pub),packet[:116]))
        ck,h=initial_state(pub);ep=packet[8:40];h=hash32(h+ep);ck=kdf(ck,ep)[0]
        ck,key=kdf(ck,dh(self.private,ep),2)
        client=decrypt(key,0,packet[40:88],h);assert client==self.allowed;h=hash32(h+packet[40:88])
        ck,key=kdf(ck,dh(self.private,client),2)
        stamp=decrypt(key,0,packet[88:116],h);assert len(stamp)==12
        assert self.timestamp is None or stamp>self.timestamp;self.timestamp=stamp
        h=hash32(h+packet[88:116]);self.peer_index=struct.unpack_from('<I',packet,4)[0]
        response_ep=public(self.ephemeral);h=hash32(h+response_ep);ck=kdf(ck,response_ep)[0]
        ck=kdf(ck,dh(self.ephemeral,ep))[0];ck=kdf(ck,dh(self.ephemeral,client))[0]
        ck,mix,key=kdf(ck,bytes(32),3);h=hash32(h+mix)
        empty=encrypt(key,0,b'',h)
        head=struct.pack('<III',2,self.index,self.peer_index)+response_ep+empty
        self.receive_key,self.send_key=kdf(ck,b'',2)
        return head+mac16(hash32(b'mac1----'+client),head)+bytes(16)
    def data(self,packet):
        assert len(packet)>=32 and packet[:4]==b'\x04\0\0\0' and struct.unpack_from('<I',packet,4)[0]==self.index
        counter=struct.unpack_from('<Q',packet,8)[0];assert counter not in self.received
        text=inner_text(decrypt(self.receive_key,counter,packet[16:]));self.received.add(counter)
        inner=inner_packet(text,True);inner+=bytes((-len(inner))%16)
        index=self.send_counter;self.send_counter+=1
        return text,struct.pack('<IIQ',4,self.peer_index,index)+encrypt(self.send_key,index,inner)

def fixture(label):
    client,server,ci,si=(os.urandom(32) for _ in range(4))
    client_index,server_index=(int.from_bytes(os.urandom(4),'little') for _ in range(2))
    initiator=Initiator(client,public(server),ci,client_index)
    responder=Responder(server,public(client),si,server_index)
    response=responder.initiation(initiator.initiation);initiator.response(response)
    pairs=[]
    for index in range(26):
        text=label+':'+str(index);request=initiator.data(text);decoded,reply=responder.data(request)
        assert decoded==text==initiator.receive(reply)
        pairs.append(dict(text=text,request=request.hex(),reply=reply.hex()))
    return dict(label=label,initial=initiator.initiation.hex(),response=response.hex(),pairs=pairs,
                server_private=server.hex(),client_public=public(client).hex(),
                responder_ephemeral=si.hex(),server_index=server_index)

if __name__=='__main__':
    import argparse
    import json
    from pathlib import Path
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        value={'wireguard':[fixture('R3-'+label+'-'+str(time.time_ns())) for label in ('linux','root','vpn')]}
        with args.output.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')
        print('Fresh WireGuard session fixtures written:',args.output)
    else:
        f=fixture('r3-selfcheck');assert len(bytes.fromhex(f['initial']))==148
        print('WireGuard authenticated initiation/response and26 encrypted ICMP request/replies: PASS')
