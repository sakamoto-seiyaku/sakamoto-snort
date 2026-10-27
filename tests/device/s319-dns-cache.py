#!/usr/bin/env python3
"""S319 ordinary App DNS answer reuse through public UI, wire and normal SQLite."""
import argparse,importlib.util,ipaddress,json,re,shlex,sqlite3,struct,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('s319_previous',ROOT/'tests/device/s318-vpn-dns-tcp-proxy.py')
previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
root,shared,fixtures,props,digest=previous.root,previous.shared,previous.fixtures,previous.props,previous.digest
PKG,SERIAL,Device=root.PKG,root.SERIAL,previous.Device
start_run,finish_run,preserve_sqlite_history=previous.start_run,previous.finish_run,previous.preserve_sqlite_history
spec=importlib.util.spec_from_file_location('s319_dispatch',ROOT/'tests/device/helpers/s319_dns_dispatch.py')
dispatch_reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(dispatch_reader)

class UiState:
 def qualify_peer_dispatches(self,label,queries,records,received_by_question,wire,expected_counts):
  # S319 also reaches the older S317/S318 paired-exchange helpers after Stop.
  # Their legacy default datagram assertions stay unchanged outside this mixin.
  assert len(queries)==len(received_by_question)==len(expected_counts)
  proofs=[]
  for query,received,count in zip(queries,received_by_question,expected_counts):
   assert isinstance(count,int)and count>=0,'S319 scoped logical count requires one exact expectation'
   identity=int.from_bytes(query[:2],'big')
   native=[row for row in records if row['id']==identity]
   proof=dispatch_reader.qualify_udp_dispatches(query,received,wire[self.physical_interface],native)
   assert proof['logical_dispatches']==count,(label,proof,count)
   proof.update(expected_logical_dispatches=count,peer_receipts=received)
   proofs.append(proof)
  self.save(label+'-scoped-dispatch-qualification.json',json.dumps(proofs,indent=2)+'\n')
  return proofs

 def begin_capture_cleanup(self):
  # Only the task-local relay's explicit reserved phase changes. No Android
  # action is replayed and neither cumulative connection counter is reset.
  import os
  marker=os.environ.get('SAKAMOTO_ADB_CLEANUP_MARKER')
  if marker:
   path=Path(marker);assert path.is_absolute()and path.name=='cleanup.phase'
   assert path==self.out.with_name(self.out.name+'-route')/'cleanup.phase','cleanup reserve marker is outside this owned route'
   with path.open('x')as stream:stream.write('cleanup\n')
   self.save('route-cleanup-reserve.json',json.dumps(dict(marker=marker,started_monotonic_ns=time.monotonic_ns()),indent=2)+'\n')

 def verify_test_network(self,label,*,baseline=False):
  began=time.monotonic_ns()
  uptime_before=self.save(label+'-network-uptime-before.txt',self.adb('shell','cat','/proc/uptime'))
  wifi=self.save(label+'-network-wifi.txt',self.adb('shell','cmd','wifi','status'))
  addresses=self.save(label+'-network-addresses.txt',self.root('ip -o addr show'))
  connectivity=self.save(label+'-network-connectivity.txt',self.adb('shell','dumpsys','connectivity'))
  defaults={family:self.save(label+f'-network-default-route{family}.txt',self.root(f'ip -{family} route get '+shlex.quote(endpoint)))
   for family,endpoint in((4,self.args.endpoint4),(6,self.args.endpoint6))}
  connected=re.search(r'Wifi is connected to "([^"]+)"',wifi)
  wifi_identity=re.search(r'BSSID: ([^,]+),.*?IP: /([^,]+),',wifi)
  agents=[line for line in connectivity.splitlines()if 'NetworkAgentInfo{network{'in line and connected and wifi_identity
   and 'SSID="'+connected[1]+'"'in line and 'BSSID='+wifi_identity[1]in line and re.search(r'InterfaceName: wlan\d+ ',line)]
  interface=re.search(r'InterfaceName: (wlan\d+) ',agents[0])[1]if len(agents)==1 else None
  vpn_active=self.args.profile=='vpn'and getattr(self,'active',False)
  routes={};commands={}
  for family,endpoint in((4,self.args.endpoint4),(6,self.args.endpoint6)):
   command=f'ip -{family} route get '+shlex.quote(endpoint)
   if vpn_active and interface:command+=' oif '+interface
   commands[str(family)]=command
   route=self.root(command)if vpn_active and interface else defaults[family]
   routes[family]=self.save(label+f'-network-route{family}.txt',route)
  uptime_after=self.save(label+'-network-uptime-after.txt',self.adb('shell','cat','/proc/uptime'))
  receipt=dict(host_before_monotonic_ns=began,host_after_monotonic_ns=time.monotonic_ns(),
   device_uptime_before=uptime_before.strip(),device_uptime_after=uptime_after.strip(),
   profile=self.args.profile,baseline=baseline)
  self.save(label+'-network-window.json',json.dumps(receipt,indent=2)+'\n')
  expected=(self.args.backup/'wifi.stdout').read_text()
  original=re.search(r'Wifi is connected to "([^"]+)"',expected)
  assert connected and original and connected[1]==original[1],'test Wi-Fi changed'
  assert wifi_identity,'test Wi-Fi identity unavailable'
  identity=(connected[1],wifi_identity[1],wifi_identity[2])
  physical={family:set()for family in(4,6)};interfaces={}
  for line in addresses.splitlines():
   parsed=re.search(r'^\d+:\s+(\S+)\s+inet(6?)\s+(\S+)',line)
   if parsed:
    address_interface,version,address=parsed.groups();family=6 if version else 4
    address=str(ipaddress.ip_interface(address).ip)
    interfaces.setdefault(address_interface,{4:set(),6:set()})[family].add(address)
  assert len(agents)==1 and interface,'test physical network identity unavailable'
  selected=[re.search(r'\bdev (\S+)',route)for route in routes.values()]
  assert all(selected)and {item[1]for item in selected}=={interface},'selected peer paths disagree with physical network'
  ifindex=int(re.search(r'(?m)^(\d+):\s+'+re.escape(interface)+r'\s',addresses)[1])
  if self.witnesses:assert interface==self.physical_interface,'physical interface changed while collector is active'
  if interface in self.witnesses:
   assert self.witnesses[interface]['ifindex']==ifindex,'physical interface was recreated after collector bind'
  self.physical_interface=interface
  physical=interfaces.get(interface,physical)
  assert identity[2]in physical[4],'test Wi-Fi IPv4 is absent from observed physical interface'
  for family,route in routes.items():
   source=re.search(r'\bsrc (\S+)',route)
   assert source and str(ipaddress.ip_address(source[1]))in physical[family],'selected peer route left test Wi-Fi'
  network=int(re.search(r'NetworkAgentInfo\{network\{(\d+)\}',agents[0])[1])
  vpn_network=None
  if vpn_active:
   vpn_agents=[line for line in connectivity.splitlines()if 'NetworkAgentInfo{network{'in line and 'VPN:'+PKG in line
    and 'InterfaceName: '+self.tun_interface+' 'in line and 'OwnerUid: '+str(self.uid)+' 'in line]
   assert len(vpn_agents)==1,'actual VPN network agent unavailable'
   underlying=re.search(r'UnderlyingNetworks: (\[[^\]]*\]|Null)',vpn_agents[0])
   available=None if not underlying or underlying[1]=='Null'else list(map(int,re.findall(r'\d+',underlying[1])))
   vpn_network=dict(network_id=int(re.search(r'NetworkAgentInfo\{network\{(\d+)\}',vpn_agents[0])[1]),
    tun_interface=self.tun_interface,underlying_networks=available)
   self.save(label+'-network-vpn-underlying.json',json.dumps(vpn_network,indent=2)+'\n')
   assert available==[network],'actual VPN underlying network does not identify the current physical test network'
   for family,route in defaults.items():
    selected_default=re.search(r'\bdev (\S+)',route);source=re.search(r'\bsrc (\S+)',route)
    assert selected_default and selected_default[1]in(interface,self.tun_interface)and source
    assert str(ipaddress.ip_address(source[1]))in interfaces[selected_default[1]][family]
  identity=(*identity,interface,network)
  self.test_interface_addresses=interfaces
  if baseline:
   if self.witnesses:assert identity==self.test_network_identity,'test Wi-Fi identity changed while collector is active'
   self.test_network_identity=identity
  else:assert identity==self.test_network_identity,'test Wi-Fi identity changed during run'
  self.current_network_evidence=dict(identity=list(identity),physical_interface=interface,
   physical_ifindex=ifindex,vpn_network=vpn_network,
   physical_addresses={str(family):sorted(values)for family,values in physical.items()},
   window_file=label+'-network-window.json',wifi_file=label+'-network-wifi.txt',
   addresses_file=label+'-network-addresses.txt',connectivity_file=label+'-network-connectivity.txt',
   route_files={str(family):label+f'-network-route{family}.txt'for family in routes},
   default_route_files={str(family):label+f'-network-default-route{family}.txt'for family in defaults},
   physical_route_commands=commands,
   route_scope='VPN physical-oif path probe plus independent actual underlyingNetwork; actual protected Product routing requires physical wire and controlledpeer proof'if vpn_active else'Root/unprotected current physical route')
  self.save(label+'-network-verified.json',json.dumps(self.current_network_evidence,indent=2)+'\n')
  return identity

 def verify_test_source(self,label,records):
  self.verify_test_network(label+'-normal-source')
  interface=self.tun_interface if self.args.profile=='vpn'else self.physical_interface
  expected=self.test_interface_addresses.get(interface)
  assert expected and records,'profile source requires actual interface addresses and normal records'
  for record in records:
   family=record['family'];raw=bytes(record['source_address'])
   source=str(ipaddress.ip_address(raw[:4]if family==4 else raw))
   assert source in expected[family],('normal App source left profile interface',interface,source,expected)

 def launch_tcp(self,label,*args,**options):
  self.verify_test_network(label+'-before-app')
  return super().launch_tcp(label,*args,**options)

 def launch_queries(self,label,*args,**options):
  self.verify_test_network(label+'-before-app')
  return super().launch_queries(label,*args,**options)

 def wire_coverage(self,label,interfaces=None):
  if getattr(self,'active',False):self.verify_test_network(label+'-wire')
  return super().wire_coverage(label,interfaces=interfaces)

 def late_wire_coverage(self,label):
  # prepare_late_wire validates the full current network and all collectors
  # before release. Read only the exact underlay witness inside the 2s bound;
  # the full network/lo/TUN fences are checked again after that boundary.
  return super().wire_coverage(label,interfaces=[self.physical_interface])

 def wire_start(self):
  # Capacity exercises 513 small answers plus 40 TC/TCP 60KB answers. Retain
  # their complete finite witness instead of the legacy 1024-packet sample.
  self.wire_packet_limit=8192 if self.args.matrix=='capacity'else 1024
  self.save('wire-capture-budget.json',json.dumps(dict(packet_limit=self.wire_packet_limit,byte_limit=16*1024*1024),indent=2)+'\n')
  self.verify_test_network('before-wire-start',baseline=True)
  return super().wire_start()

 def wire_stop(self,interfaces=None,**options):
  selected=[name for name in self.witnesses if interfaces is None or name in interfaces]
  result=super().wire_stop(interfaces,**options)
  for interface in selected:
   path=self.out/('wire-final-'+interface+'.jsonl')
   rows=[json.loads(line)for line in path.read_text().splitlines()if line.startswith('{')]
   terminal,=[row for row in rows if row.get('kind')=='stopped']
   assert terminal['timestamp_scope']=='userspace_after_socket_close'and terminal['mono_ns']>0
   assert all(row['mono_ns']<=terminal['mono_ns']for row in rows if row.get('kind')in('udp','tcp','udp_fragment_first'))
  return result

 def verify_ui_state(self,label):
  # The ordinary wake predicate does not need Android's unbounded historical
  # power-event dump. Keep its original exact Awake/keyguard/focus assertions.
  power=self.save(label+'-power.txt',self.adb('shell','dumpsys','power','|','grep',shlex.quote('^  mWakefulness=')))
  self.last_ui_power=power
  policy=self.save(label+'-keyguard.txt',self.adb('shell','dumpsys','window','policy'))
  assert re.search(r'(?m)^\s*mWakefulness=Awake\s*$',power),'device is not awake'
  assert re.search(r'(?m)^\s*showing=false\s*$',policy),'keyguard is still showing'
  self.verify_ui_focus(label)

 def foreground_ui(self,label):
  previous=getattr(self,'capture_deadline',None)
  self.capture_deadline=min(previous or float('inf'),time.monotonic()+30)
  try:
   attempt=0
   while True:
    # These are convergent UI preparation operations. A successful input ACK
    # alone never proves the screen woke, and reading a still-dozing screen
    # repeatedly cannot restore the actual precondition.
    self.save(label+f'-wake-{attempt}.txt',self.adb('shell','input','keyevent','224'))
    self.save(label+f'-dismiss-{attempt}.txt',self.adb('shell','wm','dismiss-keyguard'))
    self.save(label+f'-foreground-{attempt}.txt',self.action())
    try:
     self.verify_ui_state(label+f'-ready-{attempt}');break
    except AssertionError:
     if self.capture_deadline-time.monotonic()<5:raise
     if re.search(r'(?m)^\s*mWakefulness=(Dozing|Asleep)\s*$',getattr(self,'last_ui_power','')):
      self.save(label+f'-power-button-{attempt}.txt',self.adb('shell','input','keyevent','26'))
     attempt+=1
  finally:self.capture_deadline=previous

 def capture_current_platform(self,owners):
  label=f'n{owners}-platform-{time.monotonic_ns()}'
  self.verify_test_network(label,baseline=True)
  self.current_ipv6_rules=self.save(label+'-ipv6-rules-before.txt',self.root('ip -6 -o rule show'))
  table=self.save(label+'-ipv6-table-before.txt',self.root('ip -6 route show table 1396985427'))
  assert '1396985427'not in self.current_ipv6_rules and not table.strip()
  self.save(label+'-connectivity-before.txt',self.adb('shell','dumpsys','connectivity'))
  self.current_platform_before=dict(label=label,ipv6_rules_sha256=digest(self.out/(label+'-ipv6-rules-before.txt')),
   physical_network=self.current_network_evidence)
  return self.current_platform_before

 def verify_current_platform(self,label,result):
  hooks=self.save(label+'-all-hooks-after.txt',self.root('iptables-save -t mangle; ip6tables-save -t mangle; iptables-save -t nat'))
  rules=self.save(label+'-ipv6-rules-after.txt',self.root('ip -6 -o rule show'))
  table=self.save(label+'-ipv6-table-after.txt',self.root('ip -6 route show table 1396985427'))
  assert 'SAKAMOTO_PRODUCT_'not in hooks and not table.strip()
  assert rules==self.current_ipv6_rules,'actual pre-start IPv6 rules changed or Product-owned rule remains'
  result.update(owned_nat_tproxy_ct_hooks_absent=True,original_ipv6_rules_exact=True,
   ipv6_baseline_scope='complete current pre-start rules, without normalization',
   platform_before_start=self.current_platform_before,owned_route_table_empty=True)
  return result

class Device(UiState,previous.Device):
 def start(self,owners):
  baseline=self.capture_current_platform(owners)
  result=super().start(owners);result['platform_before_start']=baseline;return result

 def qualified_stop(self,label):
  return self.verify_current_platform(label,super().qualified_stop(label))

class RootDevice(UiState,root.Device):
 def start(self,owners):
  # System netIds can change between a ticket's original backup and its next
  # run. Preserve the actual complete pre-start rules; never normalize fields
  # or write an obsolete platform network back during Product cleanup.
  baseline=self.capture_current_platform(owners)
  result=super().start(owners);result['platform_before_start']=baseline;return result

 def qualified_stop(self,label):
  # Retain the complete ordinary Root native/queue/socket settlement, then
  # apply the same exact routing assertion to this actual run's baseline.
  return self.verify_current_platform(label,super(root.Device,self).qualified_stop(label))


def message_layout(wire):
 # Independently find RR TTL words; all other bytes must remain exact.
 def skip(at):
  start=at
  while wire[at]:
   n=wire[at];at+=1
   if n&0xc0==0xc0:return at+1
   assert n<64 and at+n<=len(wire);at+=n
   assert at-start<=255
  return at+1
 at=skip(12)+4;fields=[]
 for section,count in enumerate(struct.unpack('!3H',wire[6:12])):
  for _ in range(count):
   at=skip(at);kind,klass,ttl,n=struct.unpack('!HHIH',wire[at:at+10])
   assert at+10+n<=len(wire)
   if kind!=41:fields.append((at+4,kind,ttl,at+10,n,section))
   at+=10+n
 assert at==len(wire);return fields

def verify_data_reply(actual,expected,query,elapsed,cached=False,cache_age_us=None):
 assert len(actual)==len(expected)and actual[:2]==query[:2]
 qname,qtype,end=fixtures.decode_question(query)
 assert fixtures.decode_question(actual)==(qname,qtype,end)and actual[12:end]==query[12:end]
 masked=bytearray(actual);want=bytearray(expected);want[:2]=query[:2]
 if cached:
  assert cache_age_us is not None and cache_age_us>=0,'cached TTL requires the full same-source resolution age'
  age=(cache_age_us+999999)//1000000
 else:age=0
 for offset,kind,ttl,data,n,section in message_layout(expected):
  if cached and kind==6 and (expected[3]&15==3 or not int.from_bytes(expected[6:8],'big')):
   assert n>=20;ttl=min(ttl,int.from_bytes(expected[data+n-4:data+n],'big'))
  value=int.from_bytes(actual[offset:offset+4],'big')
  assert value==max(0,ttl-age),(ttl,value,cache_age_us if cached else 0)
  masked[offset:offset+4]=want[offset:offset+4]=bytes(4)
 assert masked==want,(actual.hex(),expected.hex())

def cache_status(d,label):
 raw=d.save(label+'-cache-status.txt',d.cli(label+'-cache','show product dns proxy'))
 rows=shared.dns_rows_from_status(raw,'dns.cache')if hasattr(shared,'dns_rows_from_status')else[
  dict(item.split('=',1)for item in line.split()[1:])for line in raw.splitlines()if line.startswith('dns.cache ')]
 assert len(rows)==d.owners
 for row in rows:
  assert int(row['generation'])==d.generation and int(row['entry_limit'])==512 and int(row['byte_limit'])==2097152
  assert int(row['entries'])<=512 and int(row['bytes'])<=2097152 and int(row['high_water_bytes'])<=2097152
 return rows

def resolution_key(query,row):
 return(row['generation'],row['owner'],row['route_revision'],row['network_revision'],
  row['upstream_family'],tuple(row['upstream_address']),row['upstream_port'],row['upstream_transport'],query[2:].hex())

def response_row(records,query):
 identity=int.from_bytes(query[:2],'big')
 delivered=[r for r in records if r['stage']==4 and r['name_index']==0 and r['id']==identity]
 assert len(delivered)==1,('one delivered proxy transaction required',delivered)
 final=delivered[0]
 fields=('generation','owner','token','incarnation','request_attempt','transport_session','protocol','source_port','id')
 selected=[r for r in records if r['stage']==2 and r['name_index']==0 and r['id']==identity
  and r['proxy_flags']&20 and all(r[k]==final[k]for k in fields)]
 assert len(selected)==1,('one actual complete response observation required',selected)
 row=selected[0]
 assert row['correlation']==1 and row['coverage']==1 and row['query_token']==row['token'] and row['request_attempt']>0,row
 assert row['query_incarnation']==row['incarnation'] and row['proxy_flags']==final['proxy_flags'],(row,final)
 return row

def exchange(d,peer,result,label,resolver,queries,replies,expected_requests,*,protocol=6,delay=0,
             expected_cached=None,rcodes=None,hot=None,reliable_app=False):
 source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before');began=time.monotonic()
 if protocol==6:
  d.forbid_original_tcp(label,before,source,resolver)
  # The existing S318 ordinary split-write seam leaves time for Android's
  # actual TCP owner lookup before the complete DNS message starts its timer.
  options=dict(previous.UI_TCP_WRITE_OPTIONS if(hot or reliable_app)and d.args.profile=='vpn'else{},dnsQueryDelayMs=delay)
  if hot:options['dnsTcpGateAfterRead']=0
  nonce=d.launch_tcp(label,resolver,source,queries,pipeline=False,hold=True,options=options,preserve_ui=bool(hot))
 else:nonce=d.launch_queries(label,resolver,source,queries,pipeline=False,timeout=6000)
 client=None
 try:
  if hot:
   client=d.wait(label+'-first-read','files/product-state/t12-'+nonce+'.json',
    lambda c:c.get('phase')in('dns_tcp_read_0','finished'),timeout=20,json_value=True)
   assert client['phase']=='dns_tcp_read_0'and client['dnsExchanges'][0]['replyHex']==replies[0].hex(),client
   first_id=int.from_bytes(queries[0][:2],'big')
   first=lambda value:[r for r in shared.dns_rows(value)if r['generation']==d.generation and r['source_port']==source and r['protocol']==6 and r['id']==first_id]
   facts=d.observation_matching(label+'-caller-precondition',lambda value:len([r for r in first(value)if r['stage']==4])==1,timeout=15)
   first_records=first(facts);d.verify_test_source(label+'-caller-precondition',first_records)
   known=bool(first_records)and all(r['caller']==1 and r['uid']==d.uid and r['packet_availability']&previous.DNS_APP_RELIABLE for r in first_records)
   result.setdefault('policy_caller_preconditions',[]).append(dict(label=label,reliable_app=known,records=first_records,
    vpn_precomplete_split_write_ms=previous.UI_TCP_PRE_SEND_MS if d.args.profile=='vpn'else 0,
    unknown_contract='Unknown identity is allowed; unavailable reliable identity cannot qualify per-App refusal'))
   d.save(label+'-caller-precondition.json',json.dumps(result['policy_caller_preconditions'][-1],indent=2)+'\n')
   assert known,'per-App policy requires actual reliable caller before hot rule; Unknown allow remains valid'
   hot();d.release_tcp_phase(label,nonce,'dns_tcp_read_0')
  if protocol==6:
   client=d.wait(label+'-reads','files/product-state/t12-'+nonce+'.json',
    lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=30,json_value=True)
   assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
  else:client=d.client(label,nonce)
  assert client['uid']==d.uid and len(client['dnsExchanges'])==len(queries),client
  actual=[bytes.fromhex(x['replyHex'])for x in client['dnsExchanges']]
  elapsed=time.monotonic()-began
  ids={int.from_bytes(q[:2],'big')for q in queries}
  selected=lambda v:[r for r in shared.dns_rows(v)if r['generation']==d.generation and r['source_port']==source and r['protocol']==protocol and r['id']in ids]
  observed=d.observation_matching(label,lambda v:len([r for r in selected(v)if r['stage']==4])==len(queries),timeout=15)
  records=selected(observed)
  d.verify_test_source(label,records)
  if reliable_app:
   known=bool(records)and all(r['caller']==1 and r['uid']==d.uid and r['packet_availability']&previous.DNS_APP_RELIABLE for r in records)
   evidence=dict(label=label,reliable_app=known,records=records)
   result.setdefault('policy_identity_qualifications',[]).append(evidence)
   d.save(label+'-reliable-app-precondition.json',json.dumps(evidence,indent=2)+'\n')
   assert known,'policy cache scenario requires actual reliable App identity on every connection; Unknown allow remains valid'
  delivered=[r for r in records if r['stage']==4]
  assert len({r['token']for r in delivered})==len(queries)
  for r in records:
   assert r['adapter_profile']==(2 if d.args.profile=='vpn'else 1)
   assert (r['caller']==0 and r['uid']==4294967295)or(r['caller']==1 and r['uid']==d.uid),r
  origins=dict(getattr(d,'known_resolution_times',{}));age_evidence=[]
  for i,(a,e,q)in enumerate(zip(actual,replies,queries)):
   if expected_cached and expected_cached[i]:
    key=resolution_key(q,response_row(records,q));present=key in origins
    evidence=dict(label=label,id=int.from_bytes(q[:2],'big'),actual_key=key,earlier_same_view_resolution=present)
    d.save(label+f'-{evidence["id"]}-cache-view-precondition.json',json.dumps(evidence,indent=2)+'\n')
    assert present,'expected cache hit requires the earlier actual resolution in this owner/network/resolver/configuration view'
   resolved=[r for r in records if r['stage']==2 and r['name_index']==0 and r['id']==int.from_bytes(q[:2],'big')and r['proxy_flags']&20]
   if resolved:
    row=response_row(records,q)
    if row['proxy_flags']&4:origins[resolution_key(q,row)]=row['mono_us']
   if rcodes and rcodes[i]is not None:
    shared.legal_reply(a,q,rcode=rcodes[i]);assert int.from_bytes(a[6:8],'big')==0
   else:
    cached=bool(expected_cached and expected_cached[i]);age=None
    if cached:
     row=response_row(records,q);key=resolution_key(q,row)
     assert key in origins,'cached data needs its earlier actual resolution in this view/owner'
     age=row['mono_us']-origins[key]
     age_evidence.append(dict(id=int.from_bytes(q[:2],'big'),first_resolution_mono_us=origins[key],
      response_mono_us=row['mono_us'],elapsed_us=age))
    verify_data_reply(a,e,q,elapsed,cached=cached,cache_age_us=age)
  if expected_cached is not None:
   for q,cached in zip(queries,expected_cached):
    rows=[r for r in delivered if r['id']==int.from_bytes(q[:2],'big')];assert len(rows)==1
    assert bool(rows[0]['proxy_flags']&16)==cached,rows
    if cached:assert rows[0]['upstream_session']==0 and rows[0]['proxy_result']in(2,11)
  peer_rows=peer.received(queries[0],after=cursor)
  after=d.wire_coverage(label+'-after');wire={k:v[len(before[k]):]for k,v in after.items()}
  dispatches=dispatch_reader.qualify_udp_dispatches(queries[0],peer_rows,wire[d.physical_interface],records)
  check=dict(label=label,expected_upstream_requests=expected_requests,actual_upstream_requests=dispatches['logical_dispatches'],
   actual_upstream_datagrams=len(peer_rows),peer_receipts=peer_rows,dispatch_qualification=dispatches)
  result.setdefault('cache_checks',[]).append(check);assert dispatches['logical_dispatches']==expected_requests,check
  interface=d.tun_interface if d.args.profile=='vpn'else'lo'
  if protocol==6:
   assert previous.stream(wire[interface],53,source)==b''.join(struct.pack('!H',len(a))+a for a in actual)
  else:
   for a in actual:assert any(r.get('kind')=='udp'and r['source_port']==53 and r['destination_port']==source and r['payload_hex']==a.hex()for r in wire[interface])
   assert not any(r.get('kind')=='udp'and r['source_port']==source and r['destination_port']==53 and ipaddress.ip_address(r['destination'])==ipaddress.ip_address(resolver)for r in wire[d.physical_interface])
  d.expected_durable.extend(records)
  d.known_resolution_times=origins
  case=dict(status='PASS',label=label,generation=d.generation,ordinary_app=True,protocol=protocol,
   family=ipaddress.ip_address(resolver).version,source_port=source,queries=[q.hex()for q in queries],
   replies=[a.hex()for a in actual],records=records,cache_status=cache_status(d,label),elapsed=elapsed,full_cache_age_evidence=age_evidence)
  result['cases'].append(case);d.save('progress.json',json.dumps(result,indent=2)+'\n');return case
 finally:
  if protocol==6:
   # Release only gates belonging to this exact newly created App plan.
   if hot:d.release_tcp_phase(label,nonce,'dns_tcp_read_0')
   d.release_probe(label,nonce);d.active_probe=None
   if client and client.get('phase')=='dns_tcp_read_complete':assert d.client(label,nonce)['dnsExchanges']==client['dnsExchanges']

def duplicate(query,index=1):
 return ((int.from_bytes(query[:2],'big')+index)&65535).to_bytes(2,'big')+query[2:]

def ttl_reply(query,ttl=60,kind=None):
 name,qtype,end=fixtures.decode_question(query);kind=qtype if kind is None else kind
 data=ipaddress.ip_address('192.0.2.44').packed if kind==1 else bytes([0xa5])*5
 return query[:2]+struct.pack('!5H',0x8180|(int.from_bytes(query[2:4],'big')&0x10),1,1,0,int(bool(query[10:12]!=bytes(2))))+query[12:end]+fixtures.rr(name,kind,data,ttl)+query[end:]

def negative_reply(query,rcode=3,ttl=30,minimum=7):
 name,_,end=fixtures.decode_question(query)
 soa=fixtures.rr(name,6,fixtures.name('ns.test')+fixtures.name('hostmaster.test')+struct.pack('!5I',1,2,3,4,minimum),ttl)
 return query[:2]+struct.pack('!5H',0x8180|rcode,1,0,1,0)+query[12:end]+soa

def paths(d):
 return((4,'1.1.1.1',d.args.endpoint4),(6,'2606:4700:4700::1111',d.args.endpoint6))

def cache_smoke(d,peer,result,owners):
 d.rules('n'+str(owners)+'-allow')
 for family,resolver,upstream in paths(d):
  d.upstream(f'base{family}-upstream',upstream);d.proxy_ready(f'base{family}-ready')
  for protocol in(6,17):
   coverage=set()
   for repetition in range(1 if owners==1 else 9):
    label=f'n{owners}-cache-{protocol}-{family}-{repetition}';q=d.question(label);a=ttl_reply(q)
    peer.register(q,a)
    c=exchange(d,peer,result,label,resolver,[q,duplicate(q)],[a,a],1,protocol=protocol,expected_cached=[False,True])
    coverage|={r['owner']for r in c['records']if r['stage']==4}
    if owners==3 and coverage=={0,1,2}:break
   assert coverage==set(range(owners)),(family,protocol,coverage)

def cache_semantics(d,peer,result,owners):
 d.rules(f'n{owners}-semantics-allow')
 for family,resolver,upstream in paths(d):
  d.upstream(f'sem{family}-upstream',upstream);d.proxy_ready(f'sem{family}-ready')
  for protocol in(6,17):
   for variant in('ttl0','soa-nx','soa-nodata','edns-empty','edns-unknown','txt','mx','srv','https','opaque'):
    label=f'n{owners}-{protocol}-{family}-{variant}';q=d.question(label,dict(txt=16,mx=15,srv=33,https=65,opaque=65000).get(variant,1))
    if variant=='edns-empty':
     q=q[:10]+b'\0\1'+q[12:]+b'\0'+struct.pack('!HHIH',41,1232,0x8000,0)
    elif variant=='edns-unknown':q=fixtures.question(int.from_bytes(q[:2],'big'),fixtures.decode_question(q)[0],edns=True)
    if variant.startswith('soa'):a=negative_reply(q,3 if variant=='soa-nx'else 0)
    elif variant=='ttl0':a=ttl_reply(q,0)
    else:a,_=fixtures.answer(q,'ordinary')
    peer.register(q,a);cached=variant not in('ttl0','edns-unknown')
    exchange(d,peer,result,label,resolver,[q,duplicate(q)],[a,a],1 if cached else 2,protocol=protocol,expected_cached=[False,cached])

def cache_policy(d,peer,result,owners):
 assert owners==1
 for family,resolver,upstream in paths(d):
  label=f'n{owners}-policy-{family}';d.rules(label+'-allow');d.upstream(label+'-upstream',upstream);d.proxy_ready(label+'-ready')
  q=d.question(label);a,_=fixtures.answer(q,'alias');a=bytearray(a)
  # Two ordinary rule UI publications and the bounded UID preparation must
  # finish while the same data is live; expiry is qualified in other cases.
  for offset,*_ in message_layout(a):struct.pack_into('!I',a,offset,600)
  a=bytes(a);peer.register(q,a)
  case=exchange(d,peer,result,label,resolver,[q,duplicate(q)],[a,None],1,protocol=6,expected_cached=[False,True],rcodes=[None,5],hot=lambda:d.rules(label+'-current-alias-deny','alias-deny'),reliable_app=True)
  assert all(r['caller']==1 and r['uid']==d.uid for r in case['records'])
  denied=[r for r in case['records']if r['stage']==4 and r['reply_rcode']==5];assert len(denied)==1 and denied[0]['actual_action']==2
  d.rules(label+'-allow-again')
  exchange(d,peer,result,label+'-still-data',resolver,[duplicate(q,2)],[a],0,protocol=6,expected_cached=[True],reliable_app=True)

def cache_view(d,peer,result,owners):
 assert owners==1;d.rules('view-allow');resolver='1.1.1.1'
 q=d.question('same-network-view');a=ttl_reply(q);peer.register(q,a)
 d.upstream('view4-upstream',d.args.endpoint4);d.proxy_ready('view4-ready')
 first=exchange(d,peer,result,'view4',resolver,[q,duplicate(q)],[a,a],1,expected_cached=[False,True])
 old=int(first['records'][0]['route_revision'])
 b=bytearray(a);b[-1]=99;b=bytes(b);peer.register(q,b)
 d.upstream('view6-upstream',d.args.endpoint6);d.proxy_ready('view6-ready')
 second=exchange(d,peer,result,'view6',resolver,[duplicate(q,2),duplicate(q,3)],[b,b],1,expected_cached=[False,True])
 assert all(int(r['route_revision'])>old and r['upstream_family']==6 for r in second['records'])

def capacity(d,peer,result,owners):
 assert owners==1;d.rules('capacity-allow');d.upstream('capacity-upstream',d.args.endpoint4);d.proxy_ready('capacity-ready')
 resolver='1.1.1.1';queries=[];answers=[]
 for i in range(513):
  q=d.question('cache-entry-'+str(i));a=ttl_reply(q,600);peer.register(q,a);queries.append(q);answers.append(a)
 for offset in range(0,512,32):
  # Distinct complete questions in each ordinary socket; the N1 cache is
  # shared as data across these sessions, not as a transport/verdict.
  batch_exchange(d,peer,result,f'entry-{offset}',resolver,queries[offset:offset+32],answers[offset:offset+32])
 rows=cache_status(d,'entry512');assert int(rows[0]['entries'])==512,rows
 exchange(d,peer,result,'entry-touch-zero',resolver,[duplicate(queries[0])],[answers[0]],0,expected_cached=[True])
 exchange(d,peer,result,'entry513',resolver,[queries[512]],[answers[512]],1,expected_cached=[False])
 exchange(d,peer,result,'entry-touched-survives',resolver,[duplicate(queries[0],2)],[answers[0]],0,expected_cached=[True])
 exchange(d,peer,result,'entry-oldest-evicted',resolver,[duplicate(queries[1])],[answers[1]],1,expected_cached=[False])
 assert int(cache_status(d,'entry-eviction')[0]['evicted'])>=1
 large_q=[];large_a=[]
 for i in range(40):
  q=d.question('cache-byte-'+str(i),65280);name,kind,end=fixtures.decode_question(q)
  a=q[:2]+struct.pack('!5H',0x8180,1,1,0,0)+q[12:end]+fixtures.rr(name,kind,bytes([0xa5])*60000,600)
  tc=q[:2]+struct.pack('!5H',0x8380,1,0,0,0)+q[12:end]
  peer.register(q,tc);peer.register(q,a,protocol='tcp');large_q.append(q);large_a.append(a)
 for offset in range(0,40,8):batch_exchange(d,peer,result,f'bytes-{offset}',resolver,large_q[offset:offset+8],large_a[offset:offset+8],tcp_retry=True)
 rows=cache_status(d,'bytes-full');assert int(rows[0]['entries'])<40 and int(rows[0]['bytes'])>1900000 and int(rows[0]['evicted'])>512,rows
 # The oldest large data was genuinely evicted; it cannot rescue transport.
 exchange(d,peer,result,'bytes-oldest-evicted',resolver,[duplicate(large_q[0])],[large_a[0]],1,expected_cached=[False])
 result['capacity_summary']=dict(entries_full=512,entry_lru_proved=True,byte_full_status=rows,
  ordinary_tcp_queries=sum(len(c.get('queries',[]))for c in result['cases']),actual_upstream_tc_tcp=True)

def batch_exchange(d,peer,result,label,resolver,queries,answers,tcp_retry=False):
 source=d.reserve_source_port(label);cursor=peer.cursor();before=d.wire_coverage(label+'-before')
 d.forbid_original_tcp(label,before,source,resolver);nonce=d.launch_tcp(label,resolver,source,queries,pipeline=False,hold=True,timeout=12000)
 client=None
 try:
  client=d.wait(label+'-reads','files/product-state/t12-'+nonce+'.json',lambda c:c.get('phase')in('dns_tcp_read_complete','finished'),timeout=40,json_value=True)
  assert client['phase']=='dns_tcp_read_complete'and not client.get('error'),client
  actual=[bytes.fromhex(x['replyHex'])for x in client['dnsExchanges']];assert actual==answers
  ids={int.from_bytes(q[:2],'big')for q in queries}
  select=lambda v:[r for r in shared.dns_rows(v)if r['generation']==d.generation and r['source_port']==source and r['id']in ids and r['protocol']==6]
  observed=d.observation_matching(label,lambda v:len([r for r in select(v)if r['stage']==4])==len(queries),timeout=20)
  records=select(observed);d.verify_test_source(label,records);delivered=[r for r in records if r['stage']==4]
  assert len(delivered)==len(queries)and not any(r['proxy_flags']&16 for r in delivered)
  after=d.wire_coverage(label+'-after');wire={k:v[len(before[k]):]for k,v in after.items()};dispatches=[]
  for q in queries:
   identity=int.from_bytes(q[:2],'big');native=[row for row in records if row['id']==identity]
   qualified=dispatch_reader.qualify_udp_dispatches(q,peer.received(q,after=cursor),wire[d.physical_interface],native)
   assert qualified['logical_dispatches']==1,qualified
   dispatches.append(qualified)
   assert len(peer.received(q,'tcp',after=cursor))==int(tcp_retry)
  interface=d.tun_interface if d.args.profile=='vpn'else'lo'
  assert previous.stream(after[interface][len(before[interface]):],53,source)==b''.join(struct.pack('!H',len(a))+a for a in answers)
  d.expected_durable.extend(records)
  origins=getattr(d,'known_resolution_times',{})
  for q in queries:
   row=response_row(records,q);assert row['proxy_flags']&4
   origins[resolution_key(q,row)]=row['mono_us']
  d.known_resolution_times=origins
  result['cases'].append(dict(label=label,status='PASS',generation=d.generation,ordinary_app=True,protocol=6,
   source_port=source,query_count=len(queries),queries=[q.hex()for q in queries],replies=[a.hex()for a in answers],records=records,
   tcp_retry=tcp_retry,dispatch_qualifications=dispatches,cache_status=cache_status(d,label)))
  d.save('progress.json',json.dumps(result,indent=2)+'\n')
 finally:
  d.release_probe(label,nonce);d.active_probe=None
  if client and client.get('phase')=='dns_tcp_read_complete':assert d.client(label,nonce)['dnsExchanges']==client['dnsExchanges']

def stop_late(d,peer,result,owners):
 d.rules('cache-stop-allow');d.upstream('cache-stop-upstream',d.args.endpoint4);d.proxy_ready('cache-stop-ready')
 q=d.question('before-stop-data');a=ttl_reply(q,600);peer.register(q,a)
 exchange(d,peer,result,'before-stop-cache', '1.1.1.1',[q,duplicate(q)],[a,a],1,expected_cached=[False,True],reliable_app=True)
 if d.args.profile=='vpn':previous.stop_late(d,peer,result,owners,tcp_options=previous.UI_TCP_WRITE_OPTIONS,
  initial_delay=previous.UI_TCP_PRE_SEND_MS)
 else:root.stop_late(d,peer,result,owners)
 pending=next(case for case in reversed(result['cases'])if case.get('new_generation')==d.generation and 'query_hex'in case)
 old_question=bytes.fromhex(pending['query_hex']);old_answer,_=fixtures.answer(old_question,'ordinary')
 requery_started=time.monotonic()
 late_query=exchange(d,peer,result,'restart-late-question-cold','1.1.1.1',
  [duplicate(old_question,100),duplicate(old_question,101)],[old_answer,old_answer],1,
  expected_cached=[False,True],reliable_app=True)
 requery_completed=time.monotonic();released=pending['late']['released_monotonic']
 old_ttl=min(field[2]for field in message_layout(old_answer))
 pending['new_generation_late_question_requery']=dict(label=late_query['label'],
  question_hex=old_question.hex(),cache_sources=[False,True],logical_upstream_dispatches=1,
  requery_started_monotonic=requery_started,requery_completed_monotonic=requery_completed,
  old_reply_release_monotonic=released,old_reply_ttl_seconds=old_ttl,
  release_to_requery_completion_seconds=requery_completed-released,
  scope='same old pending Question in current generation: first fresh upstream, then current cache; IDs deliberately differ')
 d.save('progress.json',json.dumps(result,indent=2)+'\n')
 assert 0<=requery_started-released<=requery_completed-released<old_ttl,'old late answer must still have lifetime throughout the cold-query proof'
 exchange(d,peer,result,'restart-cache-cold','1.1.1.1',[duplicate(q,2),duplicate(q,3)],[a,a],1,expected_cached=[False,True],reliable_app=True)

def dispatch(d,peer,result,owners):
 {'smoke':cache_smoke,'semantics':cache_semantics,'policy':cache_policy,'view':cache_view,'capacity':capacity,'stop-late':stop_late}[d.args.matrix](d,peer,result,owners)
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for k in('apk','stage','backup','output'):parser.add_argument('--'+k,type=Path,required=True)
 for k in('endpoint4','endpoint6'):parser.add_argument('--'+k,required=True)
 parser.add_argument('--profile',choices=('root','vpn'),default='vpn')
 parser.add_argument('--owners',choices=('1','3'),default='1');parser.add_argument('--trace',action='store_true');parser.add_argument('--installed',action='store_true')
 parser.add_argument('--matrix',choices=('smoke','semantics','policy','capacity','stop-late','view'),default='smoke');parser.add_argument('--replace-preserved',type=Path)
 parser.add_argument('--cc',default='/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
 args=parser.parse_args();args.upstream_port=53053

 for k in('apk','stage','backup','output'):setattr(args,k,getattr(args,k).resolve())
 args.output.mkdir(parents=True,exist_ok=False)
 baseline=json.loads((args.backup/'manifest.json').read_text());assert baseline['status']=='PASS'and baseline['all_nodes_archived_exact']
 result=dict(status='HOLD',task='SAKAMOTO-319',apk_sha256=digest(args.apk),source_sha256=digest(Path(__file__)),cases=[],runs=[],started_monotonic_ns=time.monotonic_ns())
 d=(Device if args.profile=='vpn'else RootDevice)(args);d.capture_deadline=time.monotonic()+900;peer=None
 try:
  peer=root.Peer([args.endpoint4,args.endpoint6],args.output,d.capture_deadline);assert [r['ports']for r in peer.messages if r.get('kind')=='ready']==[[53053]]
  result['native']=d.install();d.wire_start();owners=int(args.owners);d.owners=owners
  result['runs'].append(start_run(d,owners))
  if args.profile=='root':
   dispatch(d,peer,result,owners)
  else:dispatch(d,peer,result,owners)
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
  assert all(c['actual_upstream_requests']==c['expected_upstream_requests'] for c in result.get('cache_checks',[])),result.get('cache_checks')
  result['status']='PASS_ACTUAL_APP_'+args.profile.upper()+'_'+args.matrix.upper()
 except BaseException as error:result.update(error=repr(error),traceback=traceback.format_exc())
 finally:
  cleanup=[]
  try:d.begin_capture_cleanup()
  except BaseException as error:cleanup.append('route-cleanup-reserve:'+repr(error))
  envelope=shared.CleanupEnvelope(90,[('wire',20),('stop',35),('reader',5),('peer',20),('trace',10)])
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
