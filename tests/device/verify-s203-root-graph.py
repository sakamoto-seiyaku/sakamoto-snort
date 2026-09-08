#!/usr/bin/env python3
"""Verify recorded real-node ordering and exact native/NFQUEUE settlement."""
import json,re,sys
from pathlib import Path
from collections import defaultdict

def props(path):return dict(l.split('=',1) for l in path.read_text().splitlines() if '=' in l and not l.startswith('#'))
def verify(path):
 path=Path(path);r=json.loads((path/'result.json').read_text());errors=[]
 def require(value,message):
  if not value:errors.append(message)
 require(r.get('status')=='RAW_COMPLETE','runner did not complete its bounded matrix')
 require(r.get('source')=='NFQ_CAPTURED' and r.get('profile')=='root' and r.get('family')==4 and r.get('protocol')==17,'claim scope mismatch')
 require(r.get('serial')=='28201JEGR0XPAJ','wrong device')
 all_records=[]
 for prefix,expected in [('before-stop',4),('restart-before-stop',1)]:
  file=path/(prefix+'-vpp-stdout.log')
  if not file.exists():errors.append('missing '+str(file));continue
  records=[]
  for line in file.read_text().splitlines():
   if not line.startswith('s203 event='):continue
   records.append(dict(re.findall(r'(\w+)=([^\s]+)',line)))
  groups=defaultdict(list)
  for d in records:groups[d.get('obligation','missing')].append(d)
  require(len(groups)==expected,prefix+' exact captured packet count')
  generations=set()
  for obligation,rows in groups.items():
   names=[d['event'] for d in rows]
   admit=next((d for d in rows if d['event']=='admit'),{})
   remote=admit.get('owner')=='1'
   order=['capture','frame_accept','admit']+([] if remote else ['policy'])+['terminal','verdict','buffer_free']
   require(names==order,prefix+' one native node/settlement path '+obligation+': '+repr(names))
   require(all(d.get('source')=='NFQ_CAPTURED' for d in rows),'origin changed')
   require(all(d.get('thread')=='1' for d in rows),'execution escaped origin worker')
   require(all(d.get('worker','0')=='0' for d in rows),'logical worker mismatch')
   require(admit.get('parse')=='1' and admit.get('assignment')=='1','parse/assignment count')
   require(admit.get('family')=='4' and admit.get('protocol')=='17','packet family/protocol')
   require(admit.get('src_port')==('30000' if remote else '30001') and admit.get('dst_port')=='40403','canonical tuple mismatch')
   buffers={d['buffer'] for d in rows if 'buffer' in d};require(len(buffers)==1,'buffer identity changed')
   capture=rows[0];require(capture.get('tls')=='1' and capture.get('polling_thread')=='1' and capture.get('lane')=='0' and capture.get('queue')=='176','actual lane/thread mismatch')
   policy=next((d for d in rows if d['event']=='policy'),{})
   verdict=next((d for d in rows if d['event']=='verdict'),{})
   require(verdict.get('verdict')==('0' if remote or policy.get('verdict')=='2' else '1'),'NFQUEUE verdict disagrees with terminal/policy')
   free=rows[-1];require(free.get('buffer_debt')=='0' and free.get('obligation_debt')=='0','packet did not settle storage/obligation')
   generations.add(admit.get('generation'))
   all_records.append(dict(generation=admit.get('generation'),obligation=obligation,events=rows))
  require(len(generations)==1,'mixed generation log')
  status=props(path/(prefix+'-status.properties'))
  for field in ['origin_verdict_attempts','internal_settlements','buffer_returns','origin_local_completions','lane0_verdict_attempts','verdict_succeeded']:
   require(status.get(field)==str(expected),prefix+' '+field)
  for field in ['graph_submit_fail_opens','verdict_failed_definite','verdict_outcome_unknown','duplicate_completion_drops','stale_completion_drops','origin_remote_completions']:
   require(status.get(field)=='0',prefix+' '+field+' must be zero')
  runtime=(path/(prefix+'-vpp-runtime.txt')).read_text()
  for node in ['product-packet-admit','product-packet-policy','product-packet-terminal']:
   require(node in runtime,'missing actual VPP runtime counter '+node)
  require('product-packet-owner-guard' not in runtime,'Owner Guard executed')
 require(r.get('restart_generation') and r.get('restart_generation')!=r.get('generation'),'restart must use fresh generation')
 for label in ['first','restart']:
  stopped=props(path/(label+'-stopped.properties'))
  require(stopped.get('state')=='stopped' and stopped.get('mayBeActive')=='false' and stopped.get('errorCode')=='','stop state')
  require(props(path/(label+'-cleanup.properties')).get('productRootNfqueueResidueClean')=='true','hook/socket residue')
  require('libvpp_runtime.so' not in (path/(label+'-process-after.txt')).read_text(),'VPP process residue')
 for label,wanted in [('allow','udp_echo_matched'),('drop','udp_datagram_failed'),('recover','udp_echo_matched'),('remote-closed','udp_datagram_failed'),('restart','udp_echo_matched')]:
  data=props(path/(label+'-probe.properties'));require(data.get('result')==wanted and data.get('bindToVpn')=='false','real app case '+label)
 endpoint=(path/'restart-before-stop-endpoint.log').read_text()
 for key in ['allow_nonce','recover_nonce','restart_nonce']:require(r.get(key,'MISSING') in endpoint,'endpoint delivery '+key)
 for key in ['drop_nonce','unsupported_remote_nonce']:require(r.get(key,'') and r[key] not in endpoint,'denied packet reached endpoint '+key)
 # Policy DROP must be distinct from the deliberately unsupported remote owner.
 policies=[d for row in all_records for d in row['events'] if d['event']=='policy']
 require(sum(d.get('stage')=='1' and d.get('verdict')=='2' and d.get('rule')!='0' for d in policies)==1,'exact explicit Gate DROP')
 result={'status':'HOLD' if errors else 'PASS','errors':errors,'packets':all_records,'apk_sha256':r.get('apk_sha256')}
 (path/'verification.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
 result=verify(sys.argv[1]);print(json.dumps({k:v for k,v in result.items() if k!='packets'},indent=2));raise SystemExit(result['status']!='PASS')
