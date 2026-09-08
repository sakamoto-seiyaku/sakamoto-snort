"""Independent typed-key oracle; no product library or selector is invoked."""
import struct

def assignment(d, workers=2, seed=0x6f776e65722d3137):
    if d['l3'] != 1 or d['family'] not in (4,6):
        return dict(valid=0,owner=65535,hash=0,key_kind=0)
    kind=2 if d['l4']==1 and d['protocol'] in (6,17) else 1
    if d['icmp_known'] and d['icmp_code']==0 and ((d['family'],d['protocol'],d['icmp_type']) in ((4,1,0),(4,1,8),(6,58,128),(6,58,129))):kind=3
    source=(bytes.fromhex(d['src']),d['src_port'] if kind==2 else 0)
    destination=(bytes.fromhex(d['dst']),d['dst_port'] if kind==2 else 0)
    a,b=sorted((source,destination))
    query_class=1 if kind==3 else 0
    query_id=d['icmp_id'] if kind==3 else 0
    raw=bytes((kind,d['family'],d['protocol']))+a[0]+b[0]
    if kind==2:raw+=struct.pack('!HH',a[1],b[1])
    elif kind==3:raw+=struct.pack('!BH',query_class,query_id)
    h=14695981039346656037^seed
    for x in raw:h=((h^x)*1099511628211)&((1<<64)-1)
    return dict(valid=1,owner=h%workers,hash=h,source_is_a=int(source<=destination),key_kind=kind,key_family=d['family'],key_protocol=d['protocol'],query_class=query_class,query_id=query_id,port_a=a[1],port_b=b[1],key_a=a[0].hex(),key_b=b[0].hex())

def owner(d):return assignment(d)['owner']
