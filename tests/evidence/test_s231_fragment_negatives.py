#!/usr/bin/env python3
"""Corrupt independent link/NFQ evidence in memory; never rewrite raw runs."""
import argparse
import importlib.util
import json
import re
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('oracle',ROOT/'tests/device/s231-fragment-verify.py')
oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
d=args.run/'g0';case=json.loads((d/'case.json').read_text())
trace=(d/'vpp.log').read_text();runtime=(d/'runtime.txt').read_text();wire=(d/'wire.pcap').read_bytes();capture=(d/'capture.log').read_text()
sends={f['nonce']:(d/f'raw-{f["reverse"]}.txt').read_text() for f in case['fragments']}
endpoint=[l.split('nonce=',1)[1] for l in (d/'endpoint.log').read_text().splitlines() if 'nonce=' in l]
oracle.verify_case(case,trace,runtime,wire,capture,sends,endpoint)
nonce=case['fragments'][0]['nonce']
row=next(r for r in oracle.rows(trace,'s231 ') if nonce.encode() in bytes.fromhex(r['raw']))
line=next(l for l in trace.splitlines() if l.startswith('s231 ') and 'token='+row['token']+' ' in l)
changed=bytearray.fromhex(row['raw']);changed[6:8]=b'\x20\x00';changed[10:12]=b'\0\0'
changed[10:12]=oracle.checksum(bytes(changed[:20])).to_bytes(2,'big')
fake_shape=trace.replace('raw='+row['raw'],'raw='+changed.hex())
verdict=next(l for l in trace.splitlines() if l.startswith('s203 event=verdict ') and re.search(r'\bobligation='+row['token']+r'\b',l))
bad_id=trace.replace(line,re.sub(r'\bpacket=\d+','packet=999999',line),1)
bad_presence=trace.replace(line,line.replace('cap_len=0','cap_len=500'),1)
bad_source=trace.replace(line,line.replace('source=NFQ_CAPTURED','source=GRAPH_INJECTED'),1)
bad_sends=dict(sends)
first_send=oracle.rows(sends[nonce],'send ')[0];bytes_sent=bytearray.fromhex(first_send['raw']);bytes_sent[-1]^=1
bad_sends[nonce]=sends[nonce].replace('raw='+first_send['raw'],'raw='+bytes_sent.hex(),1)
position,index=24,0
while position<len(wire):
    size=struct.unpack_from('<I',wire,position+8)[0];frame=wire[position+16:position+16+size]
    ip=oracle.packet(frame[14:]) if frame[12:14] in (b'\x08\x00',b'\x86\xdd') else None
    if ip and ip['fragmented'] and ip['id']==case['fragments'][0]['id']:break
    position+=16+size;index+=1
else:raise AssertionError('fixture lacks original link fragment')
missing_wire=wire[:position]+wire[position+16+size:]
capture_lines=[]
for l in capture.splitlines():
    if l.startswith('capture.packet '):
        old=int(re.search(r'index=(\d+)',l).group(1))
        if old==index:continue
        l=re.sub(r'index=\d+','index='+str(old-(old>index)),l)
    elif l.startswith('capture.closed '):
        old=int(re.search(r'packets=(\d+)',l).group(1));l='capture.closed packets='+str(old-1)
    capture_lines.append(l)
tests=[('false_original_fragment_claim',fake_shape,wire,capture,sends),
       ('missing_independent_fragment',trace,missing_wire,'\n'.join(capture_lines),sends),
       ('changed_nfqueue_packet_id',bad_id,wire,capture,sends),
       ('duplicate_verdict',trace+verdict+'\n',wire,capture,sends),
       ('fabricated_missing_attribute',bad_presence,wire,capture,sends),
       ('graph_injection_mislabeled_nfqueue',bad_source,wire,capture,sends),
       ('invalid_sender_udp_checksum',trace,wire,capture,bad_sends)]
results=[]
for name,t,w,c,s in tests:
    try:oracle.verify_case(case,t,runtime,w,c,s,endpoint)
    except AssertionError as error:results.append(dict(name=name,status='EXPECTED_HOLD',reason=str(error) or repr(error)))
    else:raise AssertionError('corruption accepted: '+name)
result=dict(status='PASS',negatives=results);args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
