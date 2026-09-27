#!/usr/bin/env python3
"""Pair native T30 packet admissions/terminals and classify POST cache paths."""
import argparse
import hashlib
import json
import math
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--evidence',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
root=a.evidence.resolve()
matrix=(('linux-baseline-c','first-vpp.log','linux'),
        ('linux-scaled-c','first-vpp.log','linux'),
        ('linux-supplement-f','first-vpp.log','linux-supplement'),
        ('pixel-baseline-b','root-before-stop.log','root'),
        ('pixel-baseline-b','vpn-before-stop.log','vpn'),
        ('pixel-scaled-d','root-before-stop.log','root'),
        ('pixel-scaled-d','vpn-before-stop.log','vpn'))

def fields(line):
    return dict(piece.split('=',1) for piece in line.split()[1:] if '=' in piece)

def quantiles(values):
    if not values:return None
    values=sorted(values)
    return dict(n=len(values),p50_ns=values[math.ceil(.50*len(values))-1],
        p90_ns=values[math.ceil(.90*len(values))-1],
        p99_ns=values[math.ceil(.99*len(values))-1],max_ns=values[-1])

answer={}
for case,filename,profile in matrix:
    path=root/case/filename
    admissions={};terminals={};post={}
    for line in path.read_text().splitlines():
        if line.startswith('s216 stage=admit ') or line.startswith('s216 stage=terminal '):
            row=fields(line)
            if row.get('protocol') not in ('6','17') or row.get('family')!='4':continue
            ports={int(row['src_port']),int(row['dst_port'])}
            protocol=('rtp' if 5004 in ports else 'quic' if 40650 in ports else
                      'smtp' if 2525 in ports else 'openvpn' if 1195 in ports else None)
            if protocol is None:continue
            token=row['token'];row['test_protocol']=protocol
            target=admissions if 'stage=admit' in line else terminals
            assert token not in target,(case,profile,token)
            target[token]=row
        elif line.startswith('t11 event=cache '):
            row=fields(line)
            if row.get('position')=='2':post.setdefault(row['token'],[]).append(row['hit'])
    assert admissions and set(admissions)==set(terminals),(case,profile,len(admissions),len(terminals))
    groups={}
    for token,start in admissions.items():
        end=terminals[token]
        assert start['test_protocol']==end['test_protocol']
        assert start['generation']==end['generation']
        elapsed=int(end['mono_ns'])-int(start['mono_ns'])
        assert 0<=elapsed<5_000_000_000,(case,profile,token,elapsed)
        values=post.get(token,[])
        path_kind='hot_post' if '1' in values else 'cold_post' if values else 'no_post'
        groups.setdefault((start['test_protocol'],path_kind),[]).append(elapsed)
    assert sum(len(v) for v in groups.values())==len(admissions)
    assert sum(len(v) for (kind,_),v in groups.items() if kind=='rtp')>=25
    assert sum(len(v) for (kind,_),v in groups.items() if kind=='quic')>=25
    if case=='linux-supplement-f':
        assert sum(len(v) for (kind,_),v in groups.items() if kind=='smtp')>=15
        assert sum(len(v) for (kind,_),v in groups.items() if kind=='openvpn')>=6
    key=case+':'+profile
    answer[key]=dict(source_log=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        paired_packets=len(admissions),groups={kind+':'+path_kind:quantiles(values)
        for (kind,path_kind),values in sorted(groups.items())})
output=dict(status='VALID',runs=answer,verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
a.output.write_text(json.dumps(output,indent=2)+'\n')
print(json.dumps({k:{'paired_packets':v['paired_packets'],'groups':{g:x['n'] for g,x in v['groups'].items()}}
                  for k,v in answer.items()},indent=2))
