#!/usr/bin/env python3
"""Verify each real NFQUEUE original separately from its reassembled lease."""
import argparse, collections, hashlib, importlib.util, json, re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--run',type=Path,required=True);a=p.parse_args()
spec=importlib.util.spec_from_file_location('chain',ROOT/'tests/evidence/product_chain.py');chain=importlib.util.module_from_spec(spec);spec.loader.exec_module(chain)
errors=[]
def need(ok,message):
 if not ok:errors.append(message)
def rows(text,prefix):return [dict(re.findall(r'(\w+)=([^\s]+)',l)) for l in text.splitlines() if l.startswith(prefix)]
def normalize(raw):
 b=bytearray.fromhex(raw);b[10:12]=b'\0\0';return b.hex()
b=json.loads(a.build.read_text());r=json.loads((a.run/'result.json').read_text())
need(b['files']==chain.source_files(),'current source differs from build')
need(r['status']=='RAW_COMPLETE','Linux run incomplete')
need(not b['host_evidence'],'host fixture is not native evidence')
artifact=Path(b['artifact'])
need(all(chain.digest(artifact/name)==h for name,h in b['artifact_hashes'].items()),'runtime artifact changed')
case=r['cases'][0];run=a.run/'g0';log=(run/'vpp.log').read_text();generation=str(case['generation'])
payloads=rows(log,'s231 event=nfq_payload ')
fragments=[e for e in payloads if e['family']=='4' and int(e['raw'][12:16],16)&0x3fff]
expected=collections.Counter(normalize(raw) for c in case['fragments'] for raw in c['packets'])
need(collections.Counter(normalize(e['raw']) for e in fragments)==expected,'raw originals differ from actual NFQUEUE payloads')
tokens={e['token']:e for e in fragments}
events=collections.defaultdict(list)
for e in rows(log,'s212 '):events[e['event']].append(e)
for event in ('fragment_ingress','completion_publish','origin_release'):
 need(collections.Counter(e['token'] for e in events[event])==collections.Counter({t:1 for t in tokens}),event+' is not once per NFQUEUE original')
completed={e['token']:e for e in events['completion_publish']};released={e['token']:e for e in events['origin_release']}
verdicts=collections.defaultdict(list)
for e in rows(log,'s203 event=verdict '):verdicts[e['obligation']].append(e)
by_raw=collections.defaultdict(list)
for token,e in tokens.items():by_raw[normalize(e['raw'])].append(token)
for token,e in tokens.items():
 c=completed.get(token,{});f=released.get(token,{});v=verdicts[token]
 need(c.get('generation')==generation and c.get('kind')=='1',token+' changed generation/adapter')
 need(c.get('buffer')==e['buffer']==f.get('buffer'),token+' physical original changed')
 need(c.get('refs')==f.get('refs')=='1',token+' pin was not retired')
 need(len(v)==1,token+' did not get exactly one NFQUEUE verdict attempt')
 if len(v)==1:
  need(v[0]['thread']==e['thread']==f.get('thread') and v[0]['lane']==e['lane'] and v[0]['packet']==e['packet'],token+' verdict missed origin lane/ID')
  need(v[0]['verdict']==('0' if c.get('intent')=='2' else '1'),token+' verdict disagrees with intent')
physical=collections.Counter(e['obligation'] for e in rows(log,'s203 event=buffer_free ') if e['obligation'] in tokens)
need(physical==collections.Counter({t:1 for t in tokens}),'original physical buffer return is not exactly once')
success_tokens=collections.Counter(e['token'] for e in events['native_success'])
for stage in ('admit','policy','terminal'):
 owners=collections.Counter(e['token'] for e in rows(log,'s207 stage='+stage+' ') if e['token'] in tokens)
 need(owners==success_tokens,'fragment OwnerAssignment/policy must occur once, after native success: '+stage)
capacity=[]
for entry in case['fragments']:
 label=entry['label']
 for raw in entry['packets']:
  for token in by_raw[normalize(raw)]:
   c=completed.get(token,{})
   intent,reason,bypass='1','0','0'
   if label=='conflict':intent,reason='2','12'
   elif label=='timeout':intent,reason='2','13'
   elif label=='policy-drop':intent,reason='2','7'
   elif label in ('oversize','bundle-capacity'):intent,bypass='3','3'
   elif label=='capacity-stop':capacity.append((c.get('intent'),c.get('drop_reason'),c.get('bypass_reason')));continue
   need((c.get('intent'),c.get('drop_reason'),c.get('bypass_reason'))==(intent,reason,bypass),label+' disposition mismatch')
need(('3','0','3') in capacity and ('2','14','0') in capacity,'capacity bypass/native stop did not both execute')
wire_spec=importlib.util.spec_from_file_location('wire',ROOT/'tests/device/s231-fragment-verify.py')
wire=importlib.util.module_from_spec(wire_spec);wire_spec.loader.exec_module(wire)
wire_packets,wire_records=wire.pcap((run/'wire.pcap').read_bytes())
wire_expected=collections.Counter(normalize(raw) for c in case['fragments']
 for raw in c['packets'] if c['label'] not in ('conflict','timeout','policy-drop','capacity-stop'))
wire_actual=collections.Counter(normalize(e['raw'].hex()) for e in wire_packets
 if e['family']==4 and e['fragmented'])
need(wire_actual==wire_expected,'NF_ACCEPT originals differ from peer-link bytes, or a DROP escaped')
pins=collections.Counter(e['token'] for e in events['pin'])
need(pins==collections.Counter(e['token'] for e in events['completion_publish'] if e['pinned']=='1'),'pin completion mismatch')
need(any(e['originals']=='6' for e in events['native_success']),'missing six-original bundle')
final=(run/'runtime.txt').read_text();s=rows(final,'reassembly.status ')
need(len(s)==1 and all(s[0][k]=='0' for k in ('contexts','originals','retained')),'native reassembly debt')
for e in rows(final,'completion.status '):need(all(e[k]=='0' for k in ('pending','frames','buffers','obligations')),'completion debt')
need(all(v==0 for v in json.loads((run/'queues-free.json').read_text()).values()),'NFQUEUE descriptors not released')
need(json.loads((run/'stop.json').read_text())['process_absent'],'VPP process survived stop')
out=dict(status='HOLD' if errors else 'PASS',source='NFQ_CAPTURED',originals=len(tokens),generation=generation,errors=errors)
(a.run/'verification.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2));raise SystemExit(bool(errors))
