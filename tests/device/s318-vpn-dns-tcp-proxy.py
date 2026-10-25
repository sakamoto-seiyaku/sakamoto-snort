#!/usr/bin/env python3
"""S318 real ordinary App VPN TCP DNS replacement and committed SQLite."""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shlex
import sqlite3
import struct
import time
import traceback
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
root=load('s318_root','tests/device/s317-root-dns-tcp-proxy.py')
vpn=load('s318_vpn','tests/device/s316-vpn-dns-proxy.py')
shared,fixtures,props,digest=root.shared,root.fixtures,root.props,root.digest
PKG,SERIAL=root.PKG,root.SERIAL
DNS_APP_RELIABLE=1 << int(re.search(r'PRODUCT_PLATFORM_DNS_APP_RELIABLE\s*=\s*1\s*<<\s*(\d+)',
 (ROOT/'src/product/vpp/product_packet.h').read_text())[1])
# The ordinary App already supports bounded split writes. Keep UI preparation
# before the complete message that starts the unchanged Product deadline.
UI_TCP_WRITE_OPTIONS=dict(dnsTcpWriteSizes=[1,1,1],dnsTcpWriteDelayMs=1000)
UI_TCP_PRE_SEND_MS=3000
def stopped_tcp_identity(tun_rows,source,resolver,query):
 # Complete old App bytes and the locally generated handshake identify this
 # connection independently of the later underlay control packet.
 outgoing=[r for r in tun_rows if r.get('kind')=='tcp'and r['source_port']==source
  and r['destination_port']==53 and ipaddress.ip_address(r['destination'])==ipaddress.ip_address(resolver)]
 syns={r['sequence']for r in outgoing if r['flags']==2};assert len(syns)==1
 original_source={r['source']for r in outgoing};assert len(original_source)==1
 returning=[r for r in tun_rows if r.get('kind')=='tcp'and r['source_port']==53
  and r['destination_port']==source and ipaddress.ip_address(r['source'])==ipaddress.ip_address(resolver)]
 synacks={r['sequence']for r in returning if r['flags']==18};assert len(synacks)==1
 framed=struct.pack('!H',len(query))+query
 assert stream(tun_rows,source,53)==framed and stream(tun_rows,53,source)==b''
 return dict(source=next(iter(original_source)),source_port=source,resolver=resolver,
  sequence=(next(iter(syns))+1+len(framed))&0xffffffff,acknowledgement=(next(iter(synacks))+1)&0xffffffff)

def qualify_stopped_tcp_controls(rows,identity):
 for name in('pending_query_proved','native_original_tcp_fd_absent','normal_stop_resource_zero',
             'app_finished_no_reply','normal_sqlite_query_stopped'):
  assert identity.get(name)is True,('unproved stopped local TCP boundary',name)
 controls=[]
 for row in rows:
  if row.get('kind')!='tcp'or row['destination_port']!=53 or ipaddress.ip_address(row['destination'])!=ipaddress.ip_address(identity['resolver']):continue
  packet=bytes.fromhex(row['packet_hex']);family=packet[0]>>4
  offset=(packet[0]&15)*4 if family==4 else 40
  assert family in(4,6)and packet[9 if family==4 else 6]==6 and len(packet)>=offset+20
  tcp=packet[offset:];header=(tcp[12]>>4)*4
  assert row['source_port']==identity['source_port']and ipaddress.ip_address(row['source'])==ipaddress.ip_address(identity['source'])
  raw_source=ipaddress.ip_address(packet[12:16]if family==4 else packet[8:24])
  raw_destination=ipaddress.ip_address(packet[16:20]if family==4 else packet[24:40])
  assert raw_source==ipaddress.ip_address(identity['source'])and raw_destination==ipaddress.ip_address(identity['resolver'])
  assert row['packet_type']==4 and row['flags']==tcp[13]==20 and not row['payload_hex']and len(tcp)==header
  assert row['sequence']==int.from_bytes(tcp[4:8],'big')==identity['sequence']
  assert int.from_bytes(tcp[8:12],'big')==identity['acknowledgement']
  assert int.from_bytes(tcp[:2],'big')==identity['source_port']and int.from_bytes(tcp[2:4],'big')==53
  controls.append(row)
 assert len(controls)<=1,'more than one old App terminal control is unqualified'
 return controls

class Device(root.Device):
 def release_probe(self,label,nonce):
  # Only the explicit single-read gate belongs to this S318 probe plan.
  matches=[plan for path in self.out.glob('*-plan.json')if(plan:=json.loads(path.read_text())).get('nonce')==nonce]
  assert len(matches)<=1,'ambiguous owned probe plan'
  if matches and 'dnsTcpGateAfterRead'in matches[0]:self.release_tcp_phase(label,nonce,'dns_tcp_read_'+str(matches[0]['dnsTcpGateAfterRead']))
  super().release_probe(label,nonce)
 def __init__(self,args):
  super().__init__(args);self.vpn_tcp_fences=[]
 def verify_tcp_route_fences(self,rows):
  # VPN Direct allocates a different outer source port. Match the original
  # resolver destination across the complete ON interval instead.
  for fence in self.tcp_route_fences:
   item=self.witnesses['wlan0']
   assert {key:item[key]for key in('pid','start','uid','exe')}==fence['witness']
   end=fence.get('stop_boundary_rows',fence.get('end_rows',len(rows)))
   escaped=[r for r in rows[fence['baseline_rows']:end]if r.get('kind')=='tcp'
    and r['destination_port']==53 and ipaddress.ip_address(r['destination'])==ipaddress.ip_address(fence['resolver'])]
   assert not escaped,(fence,escaped)
   terminal=[]
   if 'stop_boundary_rows'in fence:terminal=qualify_stopped_tcp_controls(rows[end:],fence.get('stopped_local',{}))
   self.save(fence['label']+'-original-tcp-fence.json',json.dumps(dict(status='PASS',fence=fence,
    full_rows_through=len(rows),strict_on_rows_through=end,qualified_old_terminal_controls=terminal,
    interval='strict ordinary ON prefix; explicit stopped local identity qualifies only one exact payload-free old App terminal control, without a cross-clock causal claim'),indent=2)+'\n')
 def native_original_tcp_absent(self,label,pid,expected_start,resolver,source):
  assert isinstance(pid,int)and pid>0
  script=(f'echo STAT_BEFORE; cat /proc/{pid}/stat; echo UID; grep "^Uid:" /proc/{pid}/status; '
   f'echo FDS; ls -l /proc/{pid}/fd; '
   f'echo TCP4; cat /proc/net/tcp; echo TCP6; cat /proc/net/tcp6; echo STAT_AFTER; cat /proc/{pid}/stat')
  raw=self.save(label+'-native-sockets.txt',self.root(script));sections={};current=None
  for line in raw.splitlines():
   if line in('STAT_BEFORE','UID','FDS','TCP4','TCP6','STAT_AFTER'):current=line;sections[current]=[]
   else:sections[current].append(line)
  before=sections['STAT_BEFORE'][0].rsplit(') ',1)[1].split()[19];after=sections['STAT_AFTER'][0].rsplit(') ',1)[1].split()[19]
  assert before==after==expected_start and int(sections['UID'][0].split()[2])==self.uid
  native={int(match[1])for line in sections['FDS']if(match:=re.search(r' -> socket:\[(\d+)\]$',line))}
  def endpoint(text):
   address,port=text.split(':');packed=bytes.fromhex(address)
   packed=packed[::-1]if len(packed)==4 else b''.join(packed[i:i+4][::-1]for i in range(0,16,4))
   ip=ipaddress.ip_address(packed)
   return (ip.ipv4_mapped or ip)if ip.version==6 else ip,int(port,16)
  tables=[line.split()for name in('TCP4','TCP6')for line in sections[name]if line.split()and line.split()[0].removesuffix(':').isdigit()]
  selected=[fields for fields in tables if endpoint(fields[2])==(ipaddress.ip_address(resolver),53)]
  assert not any(int(fields[9])in native for fields in selected),'native Direct fd to original resolver exists'
  app=[fields for fields in selected if int(fields[1].rsplit(':',1)[1],16)==source]
  assert len(app)==1 and int(app[0][7])==self.uid and int(app[0][9])not in native
  report=dict(status='PASS_NATIVE_ORIGINAL_TCP_ABSENT_WITH_OLD_APP_SOCKET',native_pid=pid,native_start=before,
   native_socket_inodes=sorted(native),original_resolver_tcp_rows=selected,old_app_socket=app[0])
  self.save(label+'-native-sockets.json',json.dumps(report,indent=2)+'\n');return report
 def close_on_route_fences(self,label):
  rows=self.wire_coverage(label)['wlan0']
  for fence in self.tcp_route_fences:fence.setdefault('end_rows',len(rows))
 def wire(self,label,interface='wlan0'):
  rows=super().wire(label,interface)
  if interface=='wlan0':self.verify_tcp_route_fences(rows)
  return rows
 def forbid_tcp_return(self,label,before,source,reply=None):
  interface=self.tun_interface;item=self.witnesses[interface]
  self.vpn_tcp_fences.append(dict(label=label,interface=interface,generation=self.generation,source=source,
   baseline_rows=len(before[interface]),reply_hex=reply.hex()if reply is not None else None,
   witness={k:item[k]for k in('pid','start','uid','exe')}))
 def verify_vpn_tcp_fences(self,interface,rows,identity):
  for fence in self.vpn_tcp_fences:
   if fence['interface']!=interface or fence['witness']!=identity:continue
   relevant=[r for r in rows[fence['baseline_rows']:]if r.get('kind')=='tcp'and r['source_port']==53 and r['destination_port']==fence['source']and r['payload_hex']]
   if fence['reply_hex']is None:assert not relevant,(fence,relevant)
   else:
    reply=bytes.fromhex(fence['reply_hex']);assert struct.pack('!H',len(reply))+reply not in stream(relevant,53,fence['source']),(fence,relevant)
   self.save(fence['label']+'-vpn-return-fence.json',json.dumps(dict(status='PASS',fence=fence,rows_through=len(rows),scope='same exact owned TUN witness through this sample; final sample bounded by collector Stop'),indent=2)+'\n')
 def wire_coverage(self,label):
  rows=super().wire_coverage(label)
  for interface,item in self.witnesses.items():
   self.verify_vpn_tcp_fences(interface,rows[interface],{k:item[k]for k in('pid','start','uid','exe')})
  return rows
 def wire_stop(self,interfaces=None,*,defer_files=False):
  identities={name:{k:item[k]for k in('pid','start','uid','exe')}for name,item in self.witnesses.items()if interfaces is None or name in interfaces}
  generation=getattr(self,'generation',0)
  super().wire_stop(interfaces,defer_files=defer_files)
  for interface,identity in identities.items():
   final=self.out/('wire-final-'+interface+'.jsonl')
   frozen=self.out/(f'wire-final-g{generation}-{interface}-pid{identity["pid"]}-start{identity["start"]}.jsonl')
   assert not frozen.exists();frozen.write_bytes(final.read_bytes())
   rows=[json.loads(line)for line in frozen.read_text().splitlines()if line.startswith('{')]
   self.verify_vpn_tcp_fences(interface,rows,identity)
 def launch_queries(self, label, address, source, wires, **options):
     if options.get('system_name'):
         return shared.Device.launch_queries(self, label, address, source, wires, **options)
     nonce = 's316-'+label+'-'+str(time.time_ns())
     plan = dict(nonce=nonce, endpoint=address, port=53, source=source, bindDefault=True,
                 dnsQueries=[wire.hex() for wire in wires], dnsProxyTimeoutMs=options.get('timeout', 5000),
                 dnsQueryDelayMs=options.get('query_delay', 0 if options.get('pipeline') else 150),
                 dnsPipeline=options.get('pipeline', False))
     if options.get('initial_delay'): plan['dnsInitialDelayMs'] = options['initial_delay']
     if options.get('gate_reads'): plan['dnsGateAfterReads'] = True
     if 'gate_send' in options: plan['dnsGateAfterSend'] = options['gate_send']
     self.save(label+'-plan.json', json.dumps(plan, indent=2)+'\n')
     if options.get('gate_reads') or 'gate_send' in options:
         phases = ['dns_udp_read_'+str(i) for i in range(len(wires)-1)] if options.get('gate_reads') else []
         if 'gate_send' in options: phases.append('dns_udp_sent_'+str(options['gate_send']))
         self.pending_dns_gates = getattr(self, 'pending_dns_gates', []) + [(nonce, phase) for phase in phases]
     preserve = options.get('preserve_ui')
     if preserve: self.adb('shell', 'input', 'keyevent', '3')
     flags = ['-f', '0x18000000'] if preserve else []
     self.save(label+'-launch.txt', self.action(*flags, '--es', 't12ProbePlan', shlex.quote(json.dumps(plan))))
     if preserve: self.save(label+'-return-ui.txt', self.action())
     return nonce
 def start(self,owners):
  assert not getattr(self,'deferred_wire_files',[]),'archived collector file debt blocks a new TUN generation'
  if hasattr(self,'generation'):del self.generation
  if hasattr(self,'selected_dns'):del self.selected_dns
  before=props(self.save(f'n{owners}-before-start-state.properties',self.app('files/runtime-state/snapshot.properties')))
  self.before_start_generation=int(before['generation'])
  assert before['state']=='stopped'and before['mayBeActive']=='false'
  self.stop_owed=True
  result=root.tcp.Device.start(self,owners)
  state=props((self.out/f'n{owners}-running.properties').read_text())
  assert state['profile']=='vpn'and state['health']==state['coreHealth']=='ok'and self.generation>self.before_start_generation
  ledger=props(self.save(f'n{owners}-running-ledger.properties',self.app('files/product-state/product-core-generation.properties')))
  assert int(ledger['generation'])==self.generation
  links=self.save(f'n{owners}-interfaces.txt',self.root('ip -o link show'));names=re.findall(r'(?m)^\d+: (tun\d+)(?:@[^:]+)?:',links)
  assert len(names)==1;self.tun_interface=names[0];self.tun_witness();return result
 def qualified_stop(self,label):
  if not hasattr(self,'generation'):return shared.Device.qualified_stop(self,label)
  result=root.tcp.Device.stop(self,label)
  raw=(self.out/(label+'-stop.log')).read_text()
  for owner in range(self.owners):
   rows=[props(line.replace(' ','\n'))for line in raw.splitlines()if f'dns.proxy event=stop generation={self.generation} owner={owner} 'in line]
   assert rows and all(r['transactions']==r['upstream_sockets']==r['raw_sockets']==r['replies']=='0'and r['raw_opened']==r['raw_closed']for r in rows),rows
  hooks=self.save(label+'-all-hooks-after.txt',self.root('iptables-save -t mangle; ip6tables-save -t mangle; iptables-save -t nat'))
  assert'SAKAMOTO_PRODUCT_'not in hooks
  return result
 def tun_witness(self):
  interface=self.tun_interface;remote='/data/local/tmp/s317-wire';stop=remote+'-'+interface+'.stop';log=remote+'-'+interface+'.jsonl'
  absent=self.root('for p in '+stop+' '+log+'; do if [ -e "$p" ]; then echo PRESENT:$p; fi; done');assert not absent.strip()
  item=dict(pid=None,start=None,uid=None,exe=remote,stop=stop,log=log,launch_pending=True);self.witnesses[interface]=item
  addresses=[self.args.endpoint4,self.args.endpoint6,'1.1.1.1','2606:4700:4700::1111']
  pid=int(self.save('wire-'+interface+'-start.txt',self.root(remote+' '+interface+' '+stop+' '+' '.join(addresses)+' > '+log+' 2>&1 < /dev/null & echo $!')).strip());item.update(pid=pid,launch_pending=False)
  raw=self.save('wire-'+interface+'-identity.txt',self.root(f'cat /proc/{pid}/stat; grep "^Uid:" /proc/{pid}/status; readlink /proc/{pid}/exe'))
  lines=raw.splitlines();assert len(lines)==3 and lines[2]==remote
  item.update(start=int(lines[0].split(') ',1)[1].split()[19]),uid=int(lines[1].split()[2]));assert item['uid']==0
  deadline=time.monotonic()+5
  while time.monotonic()<deadline:
   if'"kind":"ready"'in self.adb('shell','cat',log,check=False):return
   time.sleep(.05)
  raise AssertionError('owned TUN witness not ready')

def stream(rows,source,destination):
 # TUN is packet-in/packet-out; both AF_PACKET directions are real observations.
 selected=[dict(r,packet_type=4)for r in rows if r.get('kind')=='tcp' and r['source_port']==source and r['destination_port']==destination]
 return root.stream_bytes(selected,source,destination)

def sqlite_snapshot(path):
 with sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)as database:
  assert database.execute('pragma integrity_check').fetchall()==[('ok',)]
  metadata=json.loads(database.execute("select value from observation where kind=0 and key=''").fetchone()[0])
  rows=dict(database.execute('select key,value from observation where kind=20'))
 fields=('dns_accepted','dns_rejected','dns_evicted')
 missing=[key for key in fields if key not in metadata]
 if missing:
  # Original pre-DNS schema1 metadata uses the same serde defaults as the
  # normal store. Only its wholly absent DNS namespace and empty DNS table
  # qualify; partial counters or existing rows must never be hidden by defaults.
  assert metadata.get('schema')==1 and len(missing)==len(fields)and not rows and not any(key.startswith('dns_')for key in metadata),'unqualified partial DNS metadata'
  metadata=dict(metadata,**{key:0 for key in fields})
 return metadata,rows

def start_run(d,owners):
 label=f'run{len(getattr(d,"sqlite_baselines",[]))+1}-before-start'
 state=props(d.save(label+'-state.properties',d.app('files/runtime-state/snapshot.properties')))
 ledger=props(d.save(label+'-ledger.properties',d.app('files/product-state/product-core-generation.properties')))
 assert state['state']=='stopped'and state['mayBeActive']=='false'and state['generation']==ledger['generation']
 sidecars=d.save(label+'-sidecars.txt',d.adb('shell','run-as',PKG,'sh','-c',shlex.quote(
  'for p in files/observation/overall.sqlite3-wal files/observation/overall.sqlite3-shm; do if [ -e "$p" ]; then stat -c "%n %s" "$p"; fi; done')))
 assert all(line.endswith(' 0')for line in sidecars.splitlines()),sidecars
 path=d.binary(label+'-overall.sqlite3','files/observation/overall.sqlite3',limit=1024*1024*1024)
 metadata,rows=sqlite_snapshot(path)
 d.sqlite_baselines=getattr(d,'sqlite_baselines',[])+[dict(path=path,metadata=metadata,rows=rows)]
 report=dict(status='PASS_COMMITTED_BEFORE_START',generation=state['generation'],sha256=digest(path),
  dns_rows=len(rows),dns_rejected=metadata['dns_rejected'],dns_evicted=metadata['dns_evicted'],
  present_received_clocks=sum(json.loads(v).get('received_clock')is not None for v in rows.values()))
 d.save(label+'-baseline.json',json.dumps(report,indent=2)+'\n')
 result=d.start(owners);result['committed_before_start']=report;return result

def preserve_sqlite_history(d,label,report):
 baseline=d.sqlite_baselines[-1];path=d.out/(label+'-overall.sqlite3');metadata,rows=sqlite_snapshot(path)
 assert metadata['dns_rejected']==baseline['metadata']['dns_rejected'],(baseline['metadata'],metadata)
 assert metadata['dns_evicted']==baseline['metadata']['dns_evicted']
 for key,value in baseline['rows'].items():assert rows.get(key)==value,('historical key/value changed',key)
 added={k:v for k,v in rows.items()if k not in baseline['rows']}
 assert all(':proxy2:'in k for k,v in added.items()if json.loads(v)['record']['proxy_flags']&1)
 report['history_conservation']=dict(status='PASS',before_sha256=digest(baseline['path']),
  before_rows=len(baseline['rows']),after_rows=len(rows),old_key_and_raw_value_bytes_exact=len(baseline['rows']),
  old_present_received_clocks_exact=sum(json.loads(v).get('received_clock')is not None for v in baseline['rows'].values()),
  dns_rejected_before=baseline['metadata']['dns_rejected'],dns_rejected_after=metadata['dns_rejected'],dns_rejected_delta=0)
 d.save(label+'-sqlite-readback.json',json.dumps(report,indent=2)+'\n');return report

def smoke(d,peer,result,owners):
 d.rules('n'+str(owners)+'-allow')
 for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
  label=f'n{owners}-vpn-tcp{family}-full';d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
  source=d.reserve_source_port(label);query=d.question(label,65280);name,qtype,end=fixtures.decode_question(query)
  full=query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:end]+fixtures.rr(name,qtype,bytes([0xa5])*600)
  tc=query[:2]+struct.pack('!5H',0x8380,1,0,0,0)+query[12:end]
  cursor=peer.cursor();peer.register(query,tc,protocol='udp');peer.register(query,full,protocol='tcp',split=True)
  before=d.wire_coverage(label+'-before');d.forbid_original_tcp(label,before,source,resolver)
  nonce=d.launch_tcp(label,resolver,source,[query],split=True,timeout=8000,hold=True)
  client=None
  try:
   client=d.wait(label+'-client-open','files/product-state/t12-'+nonce+'.json',lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=30,json_value=True)
   assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
   assert client['dnsExchanges']==[dict(sentHex=query.hex(),replyHex=full.hex())],client
   current=lambda row:row['generation']==d.generation and row['id']==int.from_bytes(query[:2],'big')and row['source_port']==source
   observed=d.observation_matching(label,lambda value:any(current(row)and row['stage']==4 for row in shared.dns_rows(value)),timeout=10)
   records=[r for r in shared.dns_rows(observed)if current(r)];assert {r['stage']for r in records}=={1,2,4},records
   for r in records:
    assert r['adapter_profile']==2 and r['protocol']==6 and r['transport_session'] and r['family']==family
    assert r['reply_capacity']==65535 and r['resolver_port']==53
    assert (r['caller']==0 and r['uid']==4294967295)or(r['caller']==1 and r['uid']==d.uid),r
   delivered,=[r for r in records if r['stage']==4]
   assert delivered['delivery']==2 and delivered['output_bytes']==len(full)and delivered['upstream_transport']==2,delivered
   assert delivered['return_provenance']==3 and delivered['return_policy_revision']>0,delivered
   assert len(peer.received(query,'udp',53053,after=cursor))==len(peer.received(query,'tcp',53053,after=cursor))==1
   wires=d.wire_coverage(label+'-after');assert stream(wires[d.tun_interface],source,53)==struct.pack('!H',len(query))+query
   assert stream(wires[d.tun_interface],53,source)==struct.pack('!H',len(full))+full
   d.expected_durable.extend(records)
   result['cases'].append(dict(status='PASS',label=label,generation=d.generation,source_port=source,query_hex=query.hex(),reply_hex=full.hex(),records=records,ordinary_app=True,actual_tun_framed_query_reply=True,actual_same_resolver_udp_tc_tcp=True))
   d.save('progress.json',json.dumps(result,indent=2)+'\n')
  finally:
   d.release_probe(label,nonce);d.active_probe=None
  if client and client.get('phase')=='dns_tcp_read_complete':assert d.client(label,nonce)['dnsExchanges']==client['dnsExchanges']

def paired_exchange(d,peer,result,label,resolver,queries,replies,*,rcodes=None,options=None,
                    peer_counts=None,reverse=False,match_identifier=False,hot=None,hot_upstream_reply=None):
    """One ordinary App socket; assertions include exact complete questions."""
    source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
    d.forbid_original_tcp(label,before,source,resolver)
    if hot:options=dict(UI_TCP_WRITE_OPTIONS,**(options or{}))
    nonce=d.launch_tcp(label,resolver,source,queries,pipeline=True,split=True,hold=True,options=options,preserve_ui=hot is not None)
    client=None
    try:
        publication=None
        if hot:
            point,gate,old=hot
            d.verify_ui_focus(label+'-hot-ready')
            d.await_peer_query(peer,label,queries[0],after=cursor,initial_delay=UI_TCP_PRE_SEND_MS)
            peer_observed=time.monotonic_ns()
            d.save(label+'-hot-tap.txt',d.adb('shell','input','tap',*map(str,point)))
            applied=d.applied_status(label+'-hot',old['queryElapsedMillis'],previous_revision=int(old['activeRevision']))
            pending=d.proxy_ready(label+'-hot-pending')
            assert sum(int(r['transactions'])for r in pending)==1,pending
            pending_observed=time.monotonic_ns()
            gate.touch();d.verify_saved_source(label+'-hot')
            publication=dict(applied=applied,pending=pending,pre_complete_message_ui_preparation_ms=UI_TCP_PRE_SEND_MS,
                peer_observed_monotonic_ns=peer_observed,pending_observed_monotonic_ns=pending_observed)
            d.save(label+'-hot-publication.json',json.dumps(publication,indent=2)+'\n')
            if hot_upstream_reply is not None:d.forbid_tcp_return(label+'-upstream-answer',before,source,hot_upstream_reply)
        client=d.wait(label+'-reads','files/product-state/t12-'+nonce+'.json',
            lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=30,json_value=True)
        assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
        facts=d.observation(label+'-preassert')
        original=[r for r in shared.dns_rows(facts)if r['generation']==d.generation and r['source_port']==source and r['stage']==1]
        assert len(original)==len(queries) and all(r['packet_uid']==d.uid and r['packet_availability']&DNS_APP_RELIABLE for r in original),original
        actual=[bytes.fromhex(x['replyHex'])for x in client['dnsExchanges']]
        assert len(actual)==len(queries)
        unmatched=list(range(len(queries)))
        for received in actual:
            if match_identifier:
                # These local errors deliberately return only a safe header.
                # Valid responses still require complete Question matching.
                assert len(received)==12 and int.from_bytes(received[2:4],'big')&0x8000
                assert struct.unpack('!4H',received[4:12])==(0,0,0,0)
                opcode=int.from_bytes(received[2:4],'big')&0x7800
                matches=[i for i in unmatched if queries[i][:2]==received[:2]
                    and int.from_bytes(queries[i][2:4],'big')&0x7800==opcode]
            else:
                name,qtype,end=fixtures.decode_question(received)
                matches=[i for i in unmatched if fixtures.decode_question(queries[i])[:2]==(name,qtype)]
            assert len(matches)==1,(label,received.hex(),queries)
            index=matches[0];unmatched.remove(index)
            if match_identifier:assert replies[index]is None and rcodes[index]in(1,4)
            if replies[index]is not None:assert received==replies[index]
            if rcodes:assert int.from_bytes(received[2:4],'big')&15==rcodes[index]
            # The shared local-error helper requires an empty answer section.
            # Complete upstream answers retain their independently exact bytes.
            shared.legal_reply(received,queries[index],rcode=rcodes[index]
                if replies[index]is None and rcodes else None)
        assert not unmatched
        if reverse:assert actual==list(reversed(replies)),[q.hex()for q in actual]
        ids={int.from_bytes(q[:2],'big')for q in queries}
        selected=lambda value:[r for r in shared.dns_rows(value)if r['generation']==d.generation
            and r['source_port']==source and r['id']in ids and r['protocol']==6]
        observed=d.observation_matching(label,lambda value:len([r for r in selected(value)if r['stage']==4])==len(queries),timeout=10)
        records=selected(observed);delivered=[r for r in records if r['stage']==4]
        assert len({r['token']for r in delivered})==len(queries)
        assert len({r['transport_session']for r in delivered})==1
        for r in delivered:
            assert r['caller']==1 and r['uid']==d.uid and r['delivery']==2 and r['reply_capacity']==65535
            assert r['message_sequence']==r['token']and r['return_provenance']==3 and r['return_policy_revision']>0
        for query,count in zip(queries,peer_counts or [1]*len(queries)):
            received=peer.received(query,after=cursor)
            allowed=count if isinstance(count,tuple)else(count,)
            assert len(received)in allowed,(label,received,count)
            if isinstance(count,tuple):
                assert hot and count==(1,2)
                assert all(bytes.fromhex(r['request_hex'])[2:]==query[2:]for r in received)
                assert len({r['request_hex']for r in received})==1
                assert len({tuple(r['peer'])for r in received})==len({tuple(r['resolver'])for r in received})==1
        if hot:
            assert len([r for r in records if r['stage']==1])==len(queries)
            assert len([r for r in records if r['stage']==4])==len(queries)
            assert not any(r['stage']==3 for r in records)
        wires=d.wire_coverage(label+'-after');wire={k:v[len(before[k]):]for k,v in wires.items()}
        assert not any(r.get('kind')=='tcp'and r['destination_port']==53 and ipaddress.ip_address(r['destination'])==ipaddress.ip_address(resolver) for r in wire['wlan0'])
        assert stream(wire[d.tun_interface],53,source)==b''.join(struct.pack('!H',len(r))+r for r in actual)
        d.expected_durable.extend(records)
        case=dict(status='PASS',label=label,generation=d.generation,source_port=source,queries=[q.hex()for q in queries],
            replies=[q.hex()for q in actual],records=records,options=options or{},same_socket=True,
            original_tcp53_absent_from_underlay=True,peer_counts=peer_counts or [1]*len(queries))
        if publication:case['hot_policy_publication']=publication
        if hot:
            case['gated_upstream']=[dict(receipts=peer.received(q,after=cursor),
                allowed_datagrams=[1,2],single_same_candidate_retransmission=True)for q in queries]
        result['cases'].append(case);d.save('progress.json',json.dumps(result,indent=2)+'\n')
        return case
    finally:
        if hot:hot[1].touch()
        d.release_probe(label,nonce)
        if getattr(d,'active_probe',None)==nonce:d.active_probe=None
        if client and client.get('phase')=='dns_tcp_read_complete':
            finished=d.client(label,nonce);assert finished['dnsExchanges']==client['dnsExchanges']


def core(device,peer,result,owners):
    d=device
    if d.args.matrix=='core':smoke(d,peer,result,owners)
    for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
        d.upstream(f'n{owners}-core{family}-upstream',upstream);d.proxy_ready(f'n{owners}-core{family}-ready')
        for variant in (('query-deny',)if d.args.matrix=='query-deny'else('same-id-ooo','query-deny','alias-deny','half-close','partial-fin')):
            label=f'n{owners}-v{family}-'+variant
            d.rules(label+'-rules',variant if variant in('query-deny','alias-deny')else'allow')
            first=d.question(label+'-first');d.next_identifier+=1
            second=fixtures.question(int.from_bytes(first[:2],'big')if variant=='same-id-ooo'else d.next_identifier,
                label+'-second.allowed.test')
            first_reply,_=fixtures.answer(first,'alias'if variant=='alias-deny'else'ordinary')
            second_reply,_=fixtures.answer(second,'ordinary')
            peer.register(first,first_reply,delay=400 if variant=='same-id-ooo'else 0)
            peer.register(second,second_reply)
            denied=variant in('query-deny','alias-deny')
            paired_exchange(d,peer,result,label,resolver,[first,second],[None if denied else first_reply,second_reply],
                rcodes=[5 if denied else 0,0],peer_counts=[0 if variant=='query-deny'else 1,1],
                reverse=variant=='same-id-ooo',options=dict(dnsTcpShutdownOutput=True,
                    dnsTcpPartialFin=variant=='partial-fin')if variant in('half-close','partial-fin')else None)


def tcp_records(d,value,queries,source):
    ids={int.from_bytes(q[:2],'big')for q in queries}
    rows=[r for r in shared.dns_rows(value)if r['generation']==d.generation and r['protocol']==6
        and r['source_port']==source and r['id']in ids and r['proxy_flags']&1]
    for r in rows:
        assert r['caller']==1 and r['uid']==d.uid and r['transport_session']
        assert r['message_sequence']==r['token']and r['reply_capacity']==65535
        assert r['stage']!=4 or(r['return_provenance']==3 and(r['delivery']!=2 or r['return_policy_revision']>0))
    return rows


def late_arrival(d,peer,label,query,gate,cursor,before):
    with d.control_budget(2):
        released=time.monotonic();gate.touch()
        while True:
            with peer.lock:
                sent=[r for r in peer.messages if r.get('kind')=='exchange'and r['request']>cursor
                    and bytes.fromhex(r['request_hex'])[2:]==query[2:]]
            if sent:break
            assert time.monotonic()<d.capture_deadline,'released old upstream reply did not actually send'
            time.sleep(.01)
        after,arrived=shared.await_late_wire(d,label,before,sent)
        assert time.monotonic()-released<2
        return dict(released_monotonic=released,observed_monotonic=time.monotonic(),writes=sent,arrived=arrived)


def single_positive(d,peer,result,label,resolver):
    query=d.question(label);reply,_=fixtures.answer(query,'ordinary');peer.register(query,reply)
    return paired_exchange(d,peer,result,label,resolver,[query],[reply],rcodes=[0])


def lifecycle(d,peer,result,owners):
    for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
        prefix=f'n{owners}-life-v{family}'
        d.rules(prefix+'-allow');d.upstream(prefix+'-upstream',upstream);d.proxy_ready(prefix+'-ready')
        # An actual deadline precedes an independently released old answer.
        # Keep its negative interval through fresh success and normal Stop.
        label=prefix+'-deadline';query=d.question(label);reply,_=fixtures.answer(query,'ordinary')
        gate=d.out/(label+'.gate');peer.register(query,reply,gate=gate)
        source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
        d.forbid_original_tcp(label,before,source,resolver)
        nonce=d.launch_tcp(label,resolver,source,[query],pipeline=True,hold=True,split=True)
        try:
            client=d.wait(label+'-read','files/product-state/t12-'+nonce+'.json',
                lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=15,json_value=True)
            assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
            actual=bytes.fromhex(client['dnsExchanges'][0]['replyHex']);shared.legal_reply(actual,query,rcode=2)
            d.forbid_tcp_return(label,before,source,reply)
            arrival=late_arrival(d,peer,label+'-late',query,gate,cursor,before)
            observed=d.observation_matching(label,lambda value:any(r['stage']==4 for r in tcp_records(d,value,[query],source)))
            records=tcp_records(d,observed,[query],source);d.expected_durable.extend(records)
            assert any(r['stage']==3 and r['proxy_result']==3 for r in records),records
            assert any(r['stage']==4 and r['delivery']==2 and r['reply_rcode']==2 for r in records),records
            assert len(peer.received(query,after=cursor))==2
            result['cases'].append(dict(status='PASS',label=label,generation=d.generation,source_port=source,
                query_hex=query.hex(),reply_hex=actual.hex(),records=records,late=arrival))
        finally:
            gate.touch();d.release_probe(label,nonce);d.active_probe=None
        d.client(label,nonce)
        single_positive(d,peer,result,prefix+'-after-deadline',resolver)

        # A real FIN followed by SO_LINGER(0) RST retires the pending query
        # before the unchanged three-second upstream deadline.
        label=prefix+'-fin-rst';query=d.question(label);reply,_=fixtures.answer(query,'ordinary')
        gate=d.out/(label+'.gate');peer.register(query,reply,gate=gate)
        source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
        d.forbid_original_tcp(label,before,source,resolver)
        nonce=d.launch_tcp(label,resolver,source,[query],pipeline=True,split=True,
            options=dict(dnsTcpShutdownOutput=True,dnsTcpResetAfterWrite=True,dnsTcpGate=True))
        try:
            d.await_peer_query(peer,label,query,after=cursor)
            d.release_tcp_phase(label,nonce,'dns_tcp_written')
            client=d.client(label,nonce);assert client['resetAfterWrite']and client['outputShutdown']
            d.active_probe=None;d.forbid_tcp_return(label,before,source)
            current=d.wire_coverage(label+'-reset')
            packets=[r for r in current[d.tun_interface][len(before[d.tun_interface]):]if r.get('kind')=='tcp'and r['source_port']==source]
            fin=[r for r in packets if r['flags']&1];rst=[r for r in packets if r['flags']&4]
            assert fin and rst and min(r['mono_ns']for r in rst)>=min(r['mono_ns']for r in fin)
            sent=[r for r in packets if r['payload_hex']]
            assert sent and min(r['mono_ns']for r in rst)-min(r['mono_ns']for r in sent)<3_000_000_000
            arrival=late_arrival(d,peer,label+'-late',query,gate,cursor,before)
            observed=d.observation_matching(label,lambda value:any(r['stage']==3 and r['proxy_result']==7
                for r in tcp_records(d,value,[query],source)))
            records=tcp_records(d,observed,[query],source);d.expected_durable.extend(records)
            assert not any(r['stage']==4 and r['delivery']==2 for r in records)
            result['cases'].append(dict(status='PASS',label=label,generation=d.generation,source_port=source,
                query_hex=query.hex(),client=client,records=records,fin=fin,rst=rst,late=arrival))
        finally:
            gate.touch();d.release_probe(label,nonce);d.active_probe=None
        single_positive(d,peer,result,prefix+'-after-rst',resolver)


def capacity(d,peer,result,owners):
    label=f'n{owners}-tcp-65-capacity';d.rules(label+'-allow');d.upstream(label+'-upstream',d.args.endpoint4)
    before_status=d.proxy_ready(label+'-ready');assert all(r['transactions']=='0'for r in before_status),before_status
    queries=[d.question(label+'-'+str(i))for i in range(65)]
    for query in queries:peer.register(query,fixtures.answer(query,'ordinary')[0],drop=True)
    source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
    d.forbid_original_tcp(label,before,source,'1.1.1.1')
    nonce=d.launch_tcp(label,'1.1.1.1',source,queries,pipeline=True,hold=True,split=True)
    try:
        early=d.observation_matching(label+'-early',lambda value:len({r['id']for r in tcp_records(d,value,queries,source)
            if r['stage']==1})==65 and any(r['stage']==3 and r['proxy_result']==6 for r in tcp_records(d,value,queries,source)),timeout=2)
        early_rows=tcp_records(d,early,queries,source);d.expected_durable.extend(early_rows)
        status=d.proxy_ready(label+'-capacity-status')
        assert any(int(r['transaction_high_water'])==64 and int(r['proxy_capacity'])>=1 for r in status),status
        assert all(int(r['transaction_high_water'])<=int(r['transaction_limit'])==64
            and int(r['proxy_high_water_bytes'])<=int(r['owner_work_bound'])for r in status)
        client=d.wait(label+'-reads','files/product-state/t12-'+nonce+'.json',
            lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=20,json_value=True)
        assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
        answers=[bytes.fromhex(item['replyHex'])for item in client['dnsExchanges']]
        assert len(answers)==65
        by_id={int.from_bytes(q[:2],'big'):q for q in queries}
        assert len({int.from_bytes(r[:2],'big')for r in answers})==65
        for reply in answers:shared.legal_reply(reply,by_id[int.from_bytes(reply[:2],'big')],rcode=2)
        received=[peer.received(q,after=cursor)for q in queries]
        assert sum(bool(x)for x in received)==64 and sum(map(len,received))==128,[len(x)for x in received]
        after=d.wire_coverage(label+'-after')
        assert stream(after[d.tun_interface][len(before[d.tun_interface]):],53,source)==b''.join(struct.pack('!H',len(r))+r for r in answers)
        assert not any(r.get('kind')=='tcp'and r['destination_port']==53 and ipaddress.ip_address(r['destination'])==ipaddress.ip_address('1.1.1.1')
            for r in after['wlan0'][len(before['wlan0']):])
        for query in queries:d.required_durable.append(dict(generation=d.generation,id=int.from_bytes(query[:2],'big'),source=source,proxy=True,stages=[1,3,4]))
        settled=d.proxy_ready(label+'-settled');assert all(r['transactions']==r['replies']=='0'for r in settled)
        native=d.cli(label+'-tcp-bounds','show product dns proxy')
        io_rows=[props(line.replace(' ','\n'))for line in native.splitlines()if'dns.vpn_tcp owner='in line]
        assert len(io_rows)==owners and all(int(r['clients'])<=int(r['client_limit'])==8 and
            int(r['outputs'])<=int(r['pending_limit'])==128 and int(r['bytes'])<=int(r['byte_limit'])==2*1024*1024 for r in io_rows)
        result['cases'].append(dict(status='PASS',label=label,generation=d.generation,source_port=source,
            queries=[q.hex()for q in queries],replies=[r.hex()for r in answers],early_records=early_rows,
            capacity_status=status,settled=settled,tcp_bounds=io_rows,unique_upstream_requests=64,total_upstream_datagrams=128,
            durable_requirement='each of65 current-generation real query identities retains phase1/3/4 in normal committed MAIN after Stop'))
    finally:d.release_probe(label,nonce);d.active_probe=None
    d.client(label,nonce)
    single_positive(d,peer,result,f'n{owners}-after-capacity','1.1.1.1')


def finish_run(d,result,label,*,pending=False):
 run=result['runs'][-1]
 if not pending:run['durable_before_stop']=d.durable(label+'-durable')
 else:
  d.durable_target=max(getattr(d,'durable_target',0),2)
  run['durable_before_stop']=dict(scope='actual pending query Stop; complete query/stopped identity required after normal close')
 # The local TUN disappears at normal Stop. Its exact collector is closed first;
 # the same underlay collector stays alive through Stop/restart/late release.
 if getattr(d,'tun_interface',None)in d.witnesses:d.wire_stop([d.tun_interface],defer_files=pending)
 stop_error=None
 try:run.update(d.stop(label))
 except BaseException as error:stop_error=error
 try:d.settle_deferred_wire_files()
 except BaseException as cleanup:
  if stop_error:raise BaseExceptionGroup('normal Stop and terminal capture file settlement',[stop_error,cleanup])
  raise
 if stop_error:raise stop_error
 run['sqlite_after_stop']=preserve_sqlite_history(d,label,d.durable_readback(label));return run


def stop_late(d,peer,result,owners):
    label=f'n{owners}-pending-stop-oldgen';d.rules(label+'-allow');d.upstream(label+'-upstream',d.args.endpoint4);d.proxy_ready(label+'-ready')
    query=d.question(label);reply,_=fixtures.answer(query,'ordinary');gate=d.out/(label+'.gate')
    peer.register(query,reply,gate=gate,gate_seconds=120)
    source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before');old=d.generation
    d.forbid_original_tcp(label,before,source,'1.1.1.1')
    native_processes=d.save(label+'-native-owner-before-probe.txt',d.root('ps -A -o PID,UID,ARGS'))
    native=[fields for line in native_processes.splitlines()if len(fields:=line.split())>=5
        and Path(fields[2]).name=='libvpp_runtime.so'and fields[1]==str(d.uid)
        and fields[3:]==['-c',d.base+'startup.conf']]
    assert len(native)==1,'normal Product native owner is not uniquely identified'
    native_pid=int(native[0][0]);native_stat=d.save(label+'-native-identity-before-probe.txt',d.root(f'cat /proc/{native_pid}/stat'))
    native_start=native_stat.rsplit(') ',1)[1].split()[19]
    d.prepare_stop_capture(label)
    nonce=d.launch_tcp(label,'1.1.1.1',source,[query],pipeline=True,split=True)
    try:
        d.await_peer_query(peer,label,query,after=cursor)
        pending_raw=d.cli(label+'-pending-local','show product dns proxy')
        pending=[props(line.replace(' ','\n'))for line in pending_raw.splitlines()if'dns.proxy owner='in line]
        local=[props(line.replace(' ','\n'))for line in pending_raw.splitlines()if'dns.vpn_tcp owner='in line]
        assert len(pending)==owners and sum(int(row['transactions'])for row in pending)==1,pending
        assert sum(int(row['clients'])for row in local)==1 and sum(int(row['pending'])for row in local)==1,local
        native_sockets=d.native_original_tcp_absent(label,native_pid,native_start,'1.1.1.1',source)
        prefix=d.wire(label+'-strict-pre-stop','wlan0')
        route_fence,=[f for f in d.tcp_route_fences if f['label']==label]
        route_fence['stop_boundary_rows']=len(prefix)
        d.required_durable.append(dict(generation=old,id=int.from_bytes(query[:2],'big'),source=source,proxy=True,stages=[1,3]))
        d.forbid_tcp_return(label,before,source)
        stopped=finish_run(d,result,label,pending=True)
        records=[r for r in stopped['sqlite_after_stop']['current_generation_records']if r['id']==int.from_bytes(query[:2],'big')and r['source_port']==source and r['protocol']==6]
        assert all(r['caller']==1 and r['uid']==d.uid and r['transport_session']
            and r['message_sequence']==r['token']and r['reply_capacity']==65535 for r in records)
        assert len(records)==2 and{r['stage']for r in records}=={1,3},records
        assert any(r['stage']==3 and r['proxy_result']==8 for r in records),records
        raw=(d.out/(label+'-stop.log')).read_text()
        assert re.search(rf'dns.proxy event=quiesce generation={old} owner=\d+ active_before=1 cancelled_now=1',raw)
        client=d.wait(label+'-client','files/product-state/t12-'+nonce+'.json',lambda c:c.get('phase')=='finished',timeout=10,json_value=True)
        assert not any(item.get('replyHex')for item in client['dnsExchanges']),client
        tun_path=next(d.out.glob(f'wire-final-g{old}-'+d.tun_interface+'-pid*-start*.jsonl'))
        tun_rows=[json.loads(line)for line in tun_path.read_text().splitlines()if line.startswith('{')]
        old_identity=stopped_tcp_identity(tun_rows,source,'1.1.1.1',query)
        old_identity.update(pending_query_proved=True,native_original_tcp_fd_absent=True,normal_stop_resource_zero=True,
            app_finished_no_reply=True,normal_sqlite_query_stopped=True)
        route_fence['stopped_local']=old_identity
        result['runs'].append(start_run(d,owners));assert d.generation>old
        restarted=d.wire_coverage(label+'-restart-before-late')
        d.forbid_tcp_return(label+'-new-tun-old-source',restarted,source)
        d.upstream(label+'-newgen-upstream',d.args.endpoint4);d.proxy_ready(label+'-newgen-ready')
        arrival=late_arrival(d,peer,label+'-late',query,gate,cursor,before)
        fresh=single_positive(d,peer,result,f'n{owners}-newgen-after-late','1.1.1.1')
        result['cases'].append(dict(status='PASS',label=label,generation=old,new_generation=d.generation,source_port=source,
            query_hex=query.hex(),client=client,records=records,late=arrival,fresh_positive=fresh['label'],
            stopped_local_wire_identity=old_identity,pending_local_status=pending,native_socket_snapshot=native_sockets,
            strict_pre_stop_wlan_rows=len(prefix),new_tun_old_source_fenced=True,
            interval='old query through actual pending Stop, native zero, restart, actual late arrival, fresh positive and final Stop'))
    finally:gate.touch()


def toggle(d,peer,result,owners):
    for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
        label=f'n{owners}-toggle-v{family}'
        d.rules(label+'-allow');d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
        old=d.query_rules(label+'-before-config')
        d.save(label+'-prefill.txt',d.action('--es','completeRuleText',shlex.quote('off')))
        d.foreground_ui(label+'-prepared');point=d.tap(label+'-off-point','Set DNS upstream',click=False)
        query=d.question(label);reply,_=fixtures.answer(query,'ordinary');gate=d.out/(label+'.gate')
        peer.register(query,reply,gate=gate)
        followup=d.question(label+'-same-local-off');followup_reply,_=fixtures.answer(followup,'ordinary')
        peer.register(followup,followup_reply)
        same_on=d.question(label+'-same-local-on');same_on_reply,_=fixtures.answer(same_on,'ordinary')
        peer.register(same_on,same_on_reply)
        source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
        d.forbid_original_tcp(label,before,source,resolver)
        nonce=d.launch_tcp(label,resolver,source,[query,followup,same_on],pipeline=False,hold=True,preserve_ui=True,split=True,
            options=dict(UI_TCP_WRITE_OPTIONS,dnsTcpGateAfterRead=1))
        try:
            d.await_peer_query(peer,label,query,after=cursor,initial_delay=UI_TCP_PRE_SEND_MS)
            d.save(label+'-off-tap.txt',d.adb('shell','input','tap',*point))
            status=d.applied_status(label+'-off',old['queryElapsedMillis'],previous_revision=int(old['activeRevision']))
            assert status['dns.enabled']==status['dns.active.enabled']=='0'
            d.selected_dns=dict(endpoint=(None,0),route_revision=int(status['activeRevision']),active_revision=int(status['activeRevision']))
            disabled=d.proxy_ready(label+'-off-ready',False)
            client=d.wait(label+'-old-read','files/product-state/t12-'+nonce+'.json',
                lambda c:c.get('phase')in('dns_tcp_read_1','finished'),timeout=10,json_value=True)
            assert client['phase']=='dns_tcp_read_1'and not client.get('error'),client
            assert len(client['dnsExchanges'])==3 and 'replyHex'not in client['dnsExchanges'][2]
            actual=bytes.fromhex(client['dnsExchanges'][0]['replyHex']);shared.legal_reply(actual,query,rcode=2)
            local_off=bytes.fromhex(client['dnsExchanges'][1]['replyHex']);shared.legal_reply(local_off,followup,rcode=2)
            assert client['dnsExchanges'][1]['sentHex']==followup.hex()
            observed=d.observation_matching(label,lambda value:any(r['stage']==3 and r['proxy_result']==9
                for r in tcp_records(d,value,[query],source))and any(r['stage']==4 for r in tcp_records(d,value,[followup],source)))
            records=tcp_records(d,observed,[query,followup],source);d.expected_durable.extend(records)
            assert any(r['stage']==4 and r['delivery']==2 and r['reply_rcode']==2 for r in records),records
            followup_records=tcp_records(d,observed,[followup],source)
            assert any(r['stage']==4 and r['delivery']==2 and r['reply_rcode']==2 for r in followup_records)
            assert len({r['transport_session']for r in records})==1 and not peer.received(followup,after=cursor)
            d.forbid_tcp_return(label,before,source,reply)
            d.forbid_tcp_return(label+'-same-local-off',before,source,followup_reply)
            arrival=late_arrival(d,peer,label+'-old-late',query,gate,cursor,before)

            # Off means an ordinary new connection uses its original public
            # destination. Resolver availability is recorded separately from
            # this real original-path SYN and zero selected-upstream admission.
            off_label=label+'-original';off_query=d.question(off_label);off_source=d.reserve_source_port(off_label)
            d.close_on_route_fences(off_label+'-end-on-interval')
            off_before=d.wire_coverage(off_label+'-before');off_cursor=peer.cursor()
            off_nonce=d.launch_tcp(off_label,resolver,off_source,[off_query],pipeline=True,timeout=1000)
            off_client=d.wait(off_label+'-client','files/product-state/t12-'+off_nonce+'.json',
                lambda c:c.get('phase')=='finished',timeout=10,json_value=True)
            off_after=d.wire_coverage(off_label+'-after')
            original=[r for r in off_after['wlan0'][len(off_before['wlan0']):]if r.get('kind')=='tcp'
                and r['destination_port']==53 and r['flags']&2
                and ipaddress.ip_address(r['destination'])==ipaddress.ip_address(resolver)]
            assert original and not peer.received(off_query,after=off_cursor),(original,off_client)
            off_observed=d.observation(off_label+'-observed');assert not tcp_records(d,off_observed,[off_query],off_source)
            assert not peer.received(same_on,after=cursor)
            before_on=d.wire_coverage(label+'-before-on')
            d.upstream(label+'-on',upstream);enabled=d.proxy_ready(label+'-on-ready')
            assert all(int(row['route_revision'])>int(status['activeRevision'])for row in enabled)
            d.forbid_original_tcp(label+'-same-local-on',before_on,source,resolver)
            d.release_tcp_phase(label,nonce,'dns_tcp_read_1')
            on_client=d.wait(label+'-same-on-read','files/product-state/t12-'+nonce+'.json',
                lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=10,json_value=True)
            assert on_client['phase']=='dns_tcp_read_complete'and not on_client.get('error'),on_client
            assert on_client['dnsTcpGateReadIndex']==1 and on_client['dnsTcpGateReleased'] and 0<=on_client['dnsTcpGateWaitMs']<=60020
            assert on_client['local']==client['local']and on_client['resolver']==client['resolver']
            actual_on=bytes.fromhex(on_client['dnsExchanges'][2]['replyHex']);shared.legal_reply(actual_on,same_on)
            assert actual_on==same_on_reply and on_client['dnsExchanges'][2]['sentHex']==same_on.hex()
            on_observed=d.observation_matching(label+'-same-on',lambda value:{r['stage']for r in tcp_records(d,value,[same_on],source)}=={1,2,4})
            on_records=tcp_records(d,on_observed,[same_on],source);d.expected_durable.extend(on_records)
            assert len(on_records)==3 and len(peer.received(same_on,after=cursor))==1,on_records
            assert len({r['transport_session']for r in records+on_records})==1
            assert len({r['incarnation']for r in records+on_records})==1
            assert all(r['route_revision']==int(enabled[0]['route_revision'])and r['network_revision']==int(enabled[0]['network_revision'])for r in on_records)
            after_on=d.wire_coverage(label+'-same-on-after')
            assert stream(after_on[d.tun_interface][len(before[d.tun_interface]):],source,53)==b''.join(struct.pack('!H',len(q))+q for q in(query,followup,same_on))
            assert stream(after_on[d.tun_interface][len(before[d.tun_interface]):],53,source)==b''.join(struct.pack('!H',len(q))+q for q in(actual,local_off,actual_on))
            fresh=single_positive(d,peer,result,label+'-fresh',resolver)
            result['cases'].append(dict(status='PASS',label=label,generation=d.generation,source_port=source,
                query_hex=query.hex(),reply_hex=actual.hex(),records=records,disabled=disabled,enabled=enabled,
                old_late=arrival,original_path=dict(source_port=off_source,query_hex=off_query.hex(),client=off_client,
                    actual_original_syn=original,selected_upstream_admitted=False,resolver_success_asserted=False),
                same_connection_while_off=dict(query_hex=followup.hex(),reply_hex=local_off.hex(),records=followup_records,
                    selected_upstream_admitted=False,original_resolver_tcp53_absent_through_this_followup_and_old_late=True),
                same_connection_after_on=dict(query_hex=same_on.hex(),reply_hex=actual_on.hex(),records=on_records,client=on_client,
                    original_query_session_preserved=True,current_view_used=True,selected_upstream_datagrams=1),
                fresh_positive=fresh['label'],ordinary_config_publication=True))
        finally:
            gate.touch();d.release_probe(label,nonce);d.active_probe=None
        d.client(label,nonce)


def udp_regression(d,peer,result,owners):
 d.rules(f'n{owners}-udp-regression-allow')
 for family,address,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
  label=f'n{owners}-vpn-udp{family}-shared'
  d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
  query=d.question(label);reply,_=fixtures.answer(query,'ordinary');peer.register(query,reply)
  vpn.exchange(d,peer,result,label,address,query,reply)


def semantics(d,peer,result,owners):
 for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
  prefix=f'n{owners}-semantics-v{family}'
  d.rules(prefix+'-allow');d.upstream(prefix+'-upstream',upstream);d.proxy_ready(prefix+'-ready')
  if not(family==4 and d.args.matrix=='semantics-rest'):
   queries=[d.question(prefix+'-rr'+str(kind),kind,edns=True)for kind in(28,16,15,33,65,65000)]
   replies=[fixtures.answer(q,'ordinary')[0]for q in queries]
   for q,r in zip(queries,replies):peer.register(q,r)
   paired_exchange(d,peer,result,prefix+'-rr-edns',resolver,queries,replies,rcodes=[0]*len(queries))
   queries=[];replies=[]
   for code in(0,3,5,2):
    q=d.question(prefix+'-upstream-rcode'+str(code));_,_,end=fixtures.decode_question(q)
    r=q[:2]+struct.pack('!5H',0x8180|code,1,0,0,0)+q[12:end]
    queries.append(q);replies.append(r);peer.register(q,r)
   upstream_case=paired_exchange(d,peer,result,prefix+'-upstream-rcodes',resolver,queries,replies,rcodes=[0,3,5,2])
   assert all(r['actual_action']==1 and r['declared_action']==1 for r in upstream_case['records']if r['stage']==2)
   for code in(1,4):
    label=prefix+'-local-error'+str(code);q=d.question(label)
    q=q[:4]+bytes(8)if code==1 else q[:2]+b'\x09\x00'+q[4:]
    case=paired_exchange(d,peer,result,label,resolver,[q],[None],rcodes=[code],peer_counts=[0],match_identifier=True)
    assert all(not r['winner']for r in case['records'])
   label=prefix+'-observe';d.rules(label+'-rules','query-deny',mode=1)
   q=d.question(label);r,_=fixtures.answer(q,'ordinary');peer.register(q,r)
   case=paired_exchange(d,peer,result,label,resolver,[q],[r],rcodes=[0]);shared.assert_policy(case['records'],1)
  d.rules(prefix+'-before-hot-allow')
  label=prefix+'-pending-current-policy';q=d.question(label);r,_=fixtures.answer(q,'alias')
  gate=d.out/(label+'.gate');peer.register(q,r,gate=gate)
  point,old=d.rules(label+'-prefill','alias-deny',prefill=True)
  case=paired_exchange(d,peer,result,label,resolver,[q],[None],rcodes=[5],peer_counts=[(1,2)],hot=(point,gate,old),hot_upstream_reply=r)
  shared.assert_hot(case['records'])
  single_positive(d,peer,result,prefix+'-after-hot-positive',resolver)


def client_retry(d,peer,result,owners):
 d.rules(f'n{owners}-vpn-client-retry-allow');result['client_udp_tcp_retries']=[]
 for family,resolver,upstream in ((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
  label=f'n{owners}-vpn-client-tc-v{family}'
  d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
  query=d.question(label,65280);name,qtype,end=fixtures.decode_question(query)
  full=query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:end]+fixtures.rr(name,qtype,bytes([0xa5])*600)
  tc=query[:2]+struct.pack('!5H',0x8380,1,0,0,0)+query[12:end]
  peer.register(query,tc);peer.register(query,full,protocol='tcp',split=True);cursor=peer.cursor()
  udp_records=vpn.exchange(d,peer,result,label+'-udp',resolver,query,None,tcp_retry=True,truncated=True,capacity=512)
  udp=result['cases'][-1];actual_tc=bytes.fromhex(udp['reply']);assert int.from_bytes(actual_tc[2:4],'big')&0x0200
  tcp=paired_exchange(d,peer,result,label+'-client-tcp',resolver,[query],[full],rcodes=[0])
  assert tcp['queries']==[udp['query']]==[query.hex()]and tcp['source_port']!=udp['source_port']
  assert len(peer.received(query,after=cursor))==len(peer.received(query,'tcp',after=cursor))==2
  assert all(r['protocol']==17 and r['reply_capacity']==512 for r in udp_records)
  assert all(r['protocol']==6 and r['reply_capacity']==65535 for r in tcp['records'])
  result['client_udp_tcp_retries'].append(dict(status='PASS',family=family,generation=d.generation,
   query_hex=query.hex(),udp_case=udp['label'],tcp_case=tcp['label'],app_udp_tc_hex=actual_tc.hex(),app_tcp_full_hex=full.hex(),
   sequence='actual ordinary App UDP TC received before separate ordinary App TCP query with same ID and complete Question',
   upstream='each client transaction separately continued same selected UDP-TC candidate on TCP'))


def timer_progress(d,peer,result,owners):
 label=f'n{owners}-timer-upstream-quiet';d.rules(label+'-allow');d.upstream(label+'-upstream',d.args.endpoint4);d.proxy_ready(label+'-ready')
 query=d.question(label);reply,_=fixtures.answer(query,'ordinary');gate=d.out/(label+'.gate')
 peer.register(query,reply,gate=gate,gate_seconds=120)
 source=d.reserve_source_port(label);cursor=peer.cursor();before_wire=d.wire_coverage(label+'-before')
 d.forbid_original_tcp(label,before_wire,source,'1.1.1.1')
 nonce=d.launch_tcp(label,'1.1.1.1',source,[query],pipeline=True,hold=True,split=True,options=UI_TCP_WRITE_OPTIONS)
 def counter_sample(name):
  began=time.monotonic_ns();raw=d.cli(name,'show product dns proxy','show product flow-stack');ended=time.monotonic_ns()
  proxy=[props(line.replace(' ','\n'))for line in raw.splitlines()if'dns.proxy owner='in line]
  local=[props(line.replace(' ','\n'))for line in raw.splitlines()if'dns.vpn_tcp owner='in line]
  drivers=[props(line.replace(' ','\n'))for line in raw.splitlines()if'flow_stack.driver owner='in line]
  assert len(proxy)==len(local)==len(drivers)==owners
  assert sum(int(r['transactions'])for r in proxy)==1,proxy
  assert sum(int(r['pending'])for r in local)==1 and sum(int(r['outputs'])for r in local)==0,local
  return dict(began_host_monotonic_ns=began,ended_host_monotonic_ns=ended,proxy=proxy,local=local,drivers=drivers)
 try:
  d.await_peer_query(peer,label,query,after=cursor,initial_delay=UI_TCP_PRE_SEND_MS)
  first=counter_sample(label+'-first')
  quiet_began=time.monotonic_ns();time.sleep(.15);quiet_ended=time.monotonic_ns()
  second=counter_sample(label+'-second')
  elapsed=(second['ended_host_monotonic_ns']-first['ended_host_monotonic_ns'])/1e9
  delta={key:sum(int(r[key])for r in second['drivers'])-sum(int(r[key])for r in first['drivers'])
   for key in('timer_wakes','nodes','empty_steps','timer_arms','ready_wakes')}
  # Real lwIP TCP timers remain valid progress sources. This deliberately loose
  # 32Hz+8-event bound distinguishes the original100Hz occupancy polling;
  # it is not a CPU or throughput claim or a cross-device-clock conversion.
  check=dict(label=label,phase='pending-upstream-only',generation=d.generation,first=first,second=second,
   quiet_began_host_monotonic_ns=quiet_began,quiet_ended_host_monotonic_ns=quiet_ended,
   host_boundary_elapsed_seconds=elapsed,deltas=delta,allowed_timer_wakes=int(32*elapsed+8)+1,
   no_peer_reply_before_second=not any(r.get('kind')=='exchange'and r.get('request',0)>cursor for r in peer.messages),
   clock_qualification='Host sample-return interval and native cumulative counters; no absolute clock equivalence or exact transmit-time claim')
  assert check['no_peer_reply_before_second']
  d.save(label+'-timer-contract.json',json.dumps(check,indent=2)+'\n');result.setdefault('timer_progress_checks',[]).append(check)
  gate.touch()
  client=d.wait(label+'-app-read','files/product-state/t12-'+nonce+'.json',lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=10,json_value=True)
  assert client['phase']=='dns_tcp_read_complete'and not client.get('error')and client['dnsExchanges']==[dict(sentHex=query.hex(),replyHex=reply.hex())],client
  observed=d.observation_matching(label,lambda value:{r['stage']for r in tcp_records(d,value,[query],source)}=={1,2,4})
  records=tcp_records(d,observed,[query],source);assert len(records)==3;d.expected_durable.extend(records)
  after=d.wire_coverage(label+'-after');assert stream(after[d.tun_interface][len(before_wire[d.tun_interface]):],53,source)==struct.pack('!H',len(reply))+reply
  result['cases'].append(dict(status='PASS_APP_WIRE_AND_NORMAL_RECORDS',label=label,generation=d.generation,source_port=source,
   queries=[query.hex()],replies=[reply.hex()],records=records,client=client,timer_contract=check,
   progress='actual held upstream release followed by App receipt before later CLI or observation control'))
 finally:gate.touch();d.release_probe(label,nonce);d.active_probe=None
 d.client(label,nonce)


def timer_progress_extended(d,peer,result,owners):
 timer_progress(d,peer,result,owners)
 for family,resolver,upstream in((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6)):
  label=f'n{owners}-timer-large-v{family}'
  d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
  query=d.question(label,65280);name,qtype,end=fixtures.decode_question(query)
  reply=query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:end]+fixtures.rr(name,qtype,bytes([0xa5])*60000)
  tc=query[:2]+struct.pack('!5H',0x8380,1,0,0,0)+query[12:end]
  assert 16384<len(reply)<65535
  peer.register(query,tc);peer.register(query,reply,protocol='tcp',split=True)
  paired_exchange(d,peer,result,label,resolver,[query],[reply],rcodes=[0])
 stop_late(d,peer,result,owners)


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for k in('apk','stage','backup','output'):parser.add_argument('--'+k,type=Path,required=True)
 for k in('endpoint4','endpoint6'):parser.add_argument('--'+k,required=True)
 parser.add_argument('--profile',choices=('root','vpn'),default='vpn')
 parser.add_argument('--owners',choices=('1','3'),default='1');parser.add_argument('--trace',action='store_true');parser.add_argument('--installed',action='store_true')
 parser.add_argument('--matrix',choices=('smoke','query-deny','core','lifecycle','capacity','toggle','stop-late','udp-regression','semantics','semantics-rest','client-retry','timer-progress','timer-progress-extended'),default='smoke');parser.add_argument('--replace-preserved',type=Path)
 parser.add_argument('--cc',default='/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
 args=parser.parse_args();args.upstream_port=53053
 if args.profile=='root':assert args.matrix in('smoke','core','udp-regression','client-retry')
 for k in('apk','stage','backup','output'):setattr(args,k,getattr(args,k).resolve())
 args.output.mkdir(parents=True,exist_ok=False)
 baseline=json.loads((args.backup/'manifest.json').read_text());assert baseline['status']=='PASS'and baseline['all_nodes_archived_exact']
 result=dict(status='HOLD',task='SAKAMOTO-318',apk_sha256=digest(args.apk),source_sha256=digest(Path(__file__)),cases=[],runs=[],started_monotonic_ns=time.monotonic_ns())
 d=(Device if args.profile=='vpn'else root.Device)(args);d.capture_deadline=time.monotonic()+900;peer=None
 try:
  peer=root.Peer([args.endpoint4,args.endpoint6],args.output,d.capture_deadline);assert [r['ports']for r in peer.messages if r.get('kind')=='ready']==[[53053]]
  result['native']=d.install();d.wire_start();owners=int(args.owners);d.owners=owners
  result['runs'].append(start_run(d,owners))
  if args.profile=='root':
   dict(smoke=root.smoke,core=root.core,**{'udp-regression':root.udp_regression,'client-retry':root.client_retry})[args.matrix](d,peer,result,owners)
  else:dict(smoke=smoke,core=core,**{'query-deny':core,'lifecycle':lifecycle,'capacity':capacity,'toggle':toggle,'stop-late':stop_late,'udp-regression':udp_regression,'semantics':semantics,'semantics-rest':semantics,'client-retry':client_retry,'timer-progress':timer_progress,'timer-progress-extended':timer_progress_extended})[args.matrix](d,peer,result,owners)
  if args.profile=='vpn':
   final=finish_run(d,result,f'n{owners}')
   for case in result['cases']:
    if 'stopped_local_wire_identity'in case:
     revived=[r for r in final['sqlite_after_stop']['current_generation_records']if r['protocol']==6
      and r['source_port']==case['source_port']and r['id']==int.from_bytes(bytes.fromhex(case['query_hex'])[:2],'big')]
     assert not revived,revived
     case['new_generation_old_identity_records']=0
   d.wire_stop()
  else:
   root.finish_run(d,result,f'n{owners}');preserve_sqlite_history(d,f'n{owners}',result['runs'][-1]['sqlite_after_stop']);d.wire_stop()
  for check in result.get('timer_progress_checks',[]):assert check['deltas']['timer_wakes']<=check['allowed_timer_wakes'],check
  result['status']='PASS_ACTUAL_APP_'+args.profile.upper()+'_'+args.matrix.upper()
 except BaseException as error:result.update(error=repr(error),traceback=traceback.format_exc())
 finally:
  cleanup=[];envelope=shared.CleanupEnvelope(90,[('wire',20),('stop',35),('reader',5),('peer',20),('trace',10)])
  def phase(name,action):
   try:
    with envelope.phase(d,name)as deadline:action(deadline)
   except BaseException as error:cleanup.append(name+':'+repr(error))
  if d.witnesses or getattr(d,'deferred_wire_files',[]):phase('wire',lambda _:(d.wire_stop()if d.witnesses else None,d.settle_deferred_wire_files()))
  if(d.stop_owed or d.active)and getattr(d,'stop_retry_authorized',True):phase('stop',lambda _:d.stop('failure-cleanup'))
  if d.reader:phase('reader',lambda _:d.settle_reader('final'))
  if peer:phase('peer',lambda deadline:(setattr(peer,'cleanup_deadline',deadline),peer.close()))
  phase('trace',lambda _:d.close_trace())
  if cleanup:result.update(cleanup_errors=cleanup,status='HOLD')
  result['completed_monotonic_ns']=time.monotonic_ns();(args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps({k:result.get(k)for k in('status','error','cleanup_errors')}),flush=True)
 return 0 if result['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())
