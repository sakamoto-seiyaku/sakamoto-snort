#!/usr/bin/env python3
"""Read the bounded T01 UDP smoke, including both W2 owners' cleanup."""
import argparse
import json
from pathlib import Path
from verify_t01_rule import digest, props, rows, verify_product_build

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True)
p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
a=p.parse_args()
build=verify_product_build(a.build)
d=a.directory;r=json.loads((d/'result.json').read_text())
assert r['status']=='SMOKE_ECHO_COMPLETE' and r['fault']=='none'
assert not r.get('error') and not r.get('cleanup_error') and not r.get('diagnostic_clear_stale_iif')
assert r['build_sha256']==digest(a.build) and r['apk_sha256']==build['apk_sha256']
assert build['completed_ns']<r['started_ns']<r['completed_ns']
assert (d/'installed-apk.txt').read_text().split()[0]==build['apk_sha256']
installed={Path(line.split()[1]).name:line.split()[0] for line in (d/'installed-native.txt').read_text().splitlines()}
assert installed==build['native_sha256']
for name,expected in r['test_inputs'].items():assert digest(d/'test-source'/name)==expected
assert digest(d/'udp-endpoint')==r['endpoint_sha256']
running=props((d/'running.properties').read_text())
assert running['profile']=='vpn' and running['state']=='running' and running['protectionRunning']=='false'
assert running['generation']==str(r['generation'])
probe=props((d/'probe.properties').read_text());endpoint=(d/'endpoint.log').read_text()
assert probe['nonce']==r['nonce'] and probe['uid']==str(r['uid'])
trace=(d/'native-stop.log').read_text();generation=str(r['generation'])
for i in range(3):
    assert probe['packet.'+str(i)]=='echo'
    assert r['nonce'][1:]+':'+str(i) in endpoint
    payload=(r['nonce']+':'+str(i)).encode()
    incoming=[e for e in rows(trace,'s216 stage=admit source=TUN_CAPTURED ')
              if e.get('family')=='4' and e.get('protocol')=='17'
              and bytes.fromhex(e.get('raw',''))[28:]==payload]
    assert len(incoming)==1
    event=incoming[0]
    assert event['generation']==generation and event['uid']==str(r['uid'])
    assert event['src_port']==str(r['source_port']) and event['dst_port']==str(r['endpoint_port'])
    copies=[e for e in rows(trace,'s237 event=input_copy ') if e['token']==event['token']]
    assert len(copies)==1 and copies[0]['result']=='0'
    assert copies[0]['owner']==event['owner'] and int(copies[0]['thread'])==int(event['owner'])+1
returns=rows(trace,'s237 event=return_copy ')
assert len(returns)==3
for returned in returns:
    assert returned['generation']==generation and returned['uid']==str(r['uid'])
    completions=[e for e in rows(trace,'s213 event=completion source=FLOW_STACK_RETURN ')
                 if e['token']==returned['token']]
    frees=[e for e in rows(trace,'s203 event=buffer_free ') if e['obligation']==returned['token']]
    assert len(completions)==len(frees)==1 and completions[0]['policy_drop']=='0'
heap={}
for event in rows(trace,'s237 event='):
    if 'generation' in event:assert event['generation']==generation
    if 'owner' in event and 'thread' in event:assert int(event['thread'])==int(event['owner'])+1
    if 'tls' in event:assert event['tls']==event['thread']
    if event['event']=='pbuf_alloc':
        assert event['object'] not in heap;heap[event['object']]=(event['owner'],event['kind'])
    elif event['event']=='pbuf_free':assert heap.pop(event['object'])==(event['owner'],event['kind'])
assert not heap
stops=rows(trace,'s237 event=owner_stopped ')
assert {s['owner'] for s in stops}=={'0','1'} and len(stops)==2
for stopped in stops:
    assert all(stopped[k]=='0' for k in ('sessions','inputs','pbufs','buffers','obligations','frames'))
    assert stopped['sockets_created']==stopped['sockets_closed']
    assert stopped['timer_fd']==stopped['broker_fd']=='-1'
state=props((d/'stopped.properties').read_text())
assert state['state']=='stopped' and state['mayBeActive']=='false' and state['errorCode']==''
assert 'libvpp_runtime.so' not in (d/'processes-after.txt').read_text()
result=dict(status='PASS',scope='T01 controlled VPN IPv4 UDP echo smoke only; protectionRunning=false',
            generation=r['generation'],datagrams=3,owners_cleaned=2,verifier_sha256=digest(__file__))
if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
