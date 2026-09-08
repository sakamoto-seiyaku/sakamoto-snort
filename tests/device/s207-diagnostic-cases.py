"""Supplemental GRAPH_INJECTED cases; never wire or platform acquisition evidence."""
import struct

def ipv4(protocol,body):
    return struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(body),0,0,64,protocol,0,bytes((192,0,2,1)),bytes((198,51,100,2)))+body

def ipv6(protocol,body):
    a=bytes.fromhex('20010db8000000000000000000000001');b=bytes.fromhex('20010db8000000000000000000000002')
    return struct.pack('!IHBB16s16s',6<<28,len(body),protocol,64,a,b)+body

def cases():
    packets=[('udp4-zero-ports',ipv4(17,struct.pack('!HHHH',0,0,8,0))),
             ('udp4-unavailable',ipv4(17,struct.pack('!HHHH',123,456,7,0))),
             ('tcp6-unavailable',ipv6(6,bytes(10))),
             ('other6',ipv6(59,b'')),
             ('icmp4-other',ipv4(1,struct.pack('!BBHI',3,1,0,0))),
             ('invalid-version',b'\0'),('invalid-truncated-ipv4',b'\x45\0')]
    result=[]
    for name,packet in packets:
        for worker in (0,1):
            result.append(dict(case=len(result)+1,name=name,worker=worker,raw=packet.hex(),invalid=name.startswith('invalid')))
    return result
