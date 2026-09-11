"""Product reassembly failures and both real worker-handoff boundaries."""
import importlib.util,ipaddress,struct,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
 s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
wire=module('wire','tests/device/s219-fragment-matrix.py');oracle=module('oracle','tests/device/s207-owner-oracle.py')
def datagram(family,identity,port=45600,size=40,step=16):
 source=ipaddress.ip_address('198.18.229.1' if family==4 else 'fd00:229::1').packed
 destination=ipaddress.ip_address('198.18.229.2' if family==4 else 'fd00:229::2').packed
 payload=struct.pack('!HHHH',port,40639,size+8,0)+bytes((identity+i)%251 for i in range(size))
 pseudo=source+destination+(struct.pack('!BBH',0,17,len(payload)) if family==4 else struct.pack('!I3xB',len(payload),17))
 payload=payload[:6]+struct.pack('!H',wire.checksum(pseudo+payload) or 65535)+payload[8:]
 def header(data,offset,more,fragmented):
  if family==4:
   h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(data),identity,offset//8|(0x2000 if more else 0),64,17,0,source,destination)
   return h[:10]+struct.pack('!H',wire.checksum(h))+h[12:]+data
  if not fragmented:return struct.pack('!IHBB16s16s',6<<28,len(data),17,64,source,destination)+data
  return struct.pack('!IHBB16s16s',6<<28,8+len(data),44,64,source,destination)+struct.pack('!BBHI',17,0,offset|int(more),identity)+data
 return [header(payload[o:o+step],o,o+step<len(payload),True).hex() for o in range(0,len(payload),step)],header(payload,0,False,False).hex()
def owner_port(family,owner,start):
 for port in range(start,start+100):
  src=ipaddress.ip_address('198.18.229.1' if family==4 else 'fd00:229::1').packed
  dst=ipaddress.ip_address('198.18.229.2' if family==4 else 'fd00:229::2').packed
  if oracle.owner(dict(l3=1,l4=1,family=family,protocol=17,src=(bytes(12)+src if family==4 else src).hex(),dst=(bytes(12)+dst if family==4 else dst).hex(),src_port=port,dst_port=40639,icmp_known=0))==owner:return port
 raise RuntimeError('owner tuple not found')

def reassembly_worker(family):
 source=ipaddress.ip_address('198.18.229.1' if family==4 else 'fd00:229::1').packed
 destination=ipaddress.ip_address('198.18.229.2' if family==4 else 'fd00:229::2').packed
 source=source.rjust(16,b'\0');destination=destination.rjust(16,b'\0')
 a,b=sorted((source,destination));h=14695981039346656037
 for value in bytes([family])+bytes(v for pair in zip(a,b) for v in pair):
  h=((h^value)*1099511628211)&((1<<64)-1)
 return h%2

class Scenarios:
 def __init__(self,call,save,policy,await_hold):
  self.call=call;self.save=save;self.policy=policy;self.await_hold=await_hold;self.case_id=0;self.hold_id=0;self.cases=[];self.holds=[]
 def command(self,name,command,marker):return self.save(name+'.txt',self.call(command,marker))
 def inject(self,packet,worker):
  self.case_id+=1;assert self.case_id<=32
  self.command('inject-'+str(self.case_id),f'product reassembly inject {self.case_id} {packet} worker {worker} uid 22900','reassembly.inject=accepted')
  return dict(case=self.case_id,hex=packet,worker=worker)
 def status(self,label):return self.command(label,'show product reassembly\nshow product completion','completion.status')
 def wait(self,label,empty=True):
  import re
  deadline=time.monotonic()+12
  while time.monotonic()<deadline:
   status=self.status(label)
   completion=[dict(x.split('=',1) for x in line.split()[1:] if '=' in x)
               for line in status.splitlines() if line.startswith('completion.status ')]
   drained=completion and all(completion[0].get(k)=='0' for k in ('pending','frames','buffers','obligations'))
   if (('contexts=0 originals=0 retained=0' in status and drained) if empty else ('contexts=0 ' not in status)):return status
   time.sleep(.04)
  raise RuntimeError('reassembly did not reach '+label)
 def config(self,timeout=10000,contexts=64):self.command('config-'+str(self.case_id),f'product reassembly configure timeout-ms {timeout} contexts {contexts}','reassembly.configured')
 def hold(self,family,worker):
  if hasattr(self,'activity_hold'):
   self.holds.extend(self.activity_hold(family,worker));return
  # Stagger existing diagnostic policy holds so the sender is active while
  # the native destination remains held. No wake mechanism is introduced.
  commands=[];tokens=[]
  for target,duration in ((1-worker,300000),(worker,500000)):
   self.hold_id+=1;port=owner_port(family,target,46000+self.hold_id*100)
   full=datagram(family,24000+self.hold_id,port)[1]
   commands.extend([f'product policy hold-next {target} {duration}',f'product metadata inject {self.hold_id} {full} worker {target}'])
   self.holds.append(dict(case=self.hold_id,family=family,worker=target,hex=full,us=duration))
   tokens.append(216000000+self.hold_id)
  self.command('hold-batch-'+str(self.hold_id),'\n'.join(commands),f'case={self.hold_id} generation=')
  for token in tokens:self.await_hold(token)
 def ready(self,label,contexts,originals):
  import re
  deadline=time.monotonic()+12
  while time.monotonic()<deadline:
   status=self.status(label)
   if f'contexts={contexts} originals={originals} retained=0' in status and all(int(n)==0 for n in re.findall(r'reassembly.handoff [^\n]*pending=(\d+)',status)):return
   time.sleep(.03)
  raise RuntimeError('native context placement not ready '+label)
 def add(self,label,family,entries,kind):
  c=dict(label=f'{family}-{label}',family=family,packets=entries,kind=kind);self.cases.append(c);return c
 def basic(self):
  self.policy(False)
  for family in (4,6):
   identity=22900+(100 if family==6 else 0)
   self.config(100);packets=datagram(family,identity,size=24)[0]
   self.add('timeout',family,[self.inject(packets[0],0)],'timeout');self.wait(f'{family}-timeout')
   self.config();bad=bytearray.fromhex(datagram(family,identity+1,size=24)[0][0])
   if family==4:bad[2:4]=(1000).to_bytes(2,'big')
   else:bad[4:6]=(1000).to_bytes(2,'big')
   self.add('malformed',family,[self.inject(bad.hex(),1)],'malformed');self.wait(f'{family}-malformed')
   pair=datagram(family,identity+2,size=24)[0];bad=bytearray.fromhex(pair[0]);bad[-1]^=255
   self.add('conflict',family,[self.inject(pair[0],0),self.inject(bad.hex(),1)],'conflict');self.wait(f'{family}-conflict')
   pair=datagram(family,identity+3,size=24)[0]
   # Establish one native context before the independent duplicate arrives.
   # CLI admission alone does not prove the first worker has processed it.
   entries=[self.inject(pair[0],0)];self.ready(f'{family}-duplicate-context',1,1)
   entries.append(self.inject(pair[0],1))
   self.add('duplicate',family,entries,'duplicate')
   self.wait(f'{family}-duplicate')
   middle=datagram(family,identity+7)[0]
   entries=[self.inject(middle[0],0),self.inject(middle[1],1),self.inject(middle[1],0)]
   self.ready(f'{family}-middle-duplicates-ready',1,3)
   entries.append(self.inject(middle[2],1))
   self.add('middle-duplicate',family,entries,'middle-duplicate')
   self.wait(f'{family}-middle-duplicate')
   self.config(contexts=1);a=datagram(family,identity+4,size=24)[0];b=datagram(family,identity+5,size=24)[0]
   self.add('context-capacity',family,[self.inject(a[0],0),self.inject(b[0],0),self.inject(a[1],0)],'context-capacity');self.wait(f'{family}-context-capacity');self.config()
   self.policy(True);pair=datagram(family,identity+6,size=24)[0]
   self.add('policy-drop',family,[self.inject(pair[0],0),self.inject(pair[1],1)],'policy-drop');self.wait(f'{family}-policy-drop');self.policy(False)
  for family in (4,6):
   pair=datagram(family,23200+family,size=24)[0];self.add('stop',family,[self.inject(pair[0],family%3)],'stop')
  self.wait('held-before-stop',False)
  for attempt in range(100):
   result=self.command('native-stop', 'product root stop','root.stop=')
   if 'root.stop=ok' in result:break
   time.sleep(.02)
  else:raise RuntimeError('native stop drain timeout')
  self.status('after-native-stop')
 def geometry(self):
  self.policy(False);self.config()
  self.command('geometry-capacity','product reassembly configure timeout-ms 10000 contexts 65 originals 33','reassembly.configured')
  def lengths(packet,family):
   packet=bytearray(packet)
   if family==4:
    packet[2:4]=len(packet).to_bytes(2,'big');packet[10:12]=b'\0\0'
    packet[10:12]=wire.checksum(packet[:(packet[0]&15)*4]).to_bytes(2,'big')
   else:packet[4:6]=(len(packet)-40).to_bytes(2,'big')
   return packet.hex()
  def run(label,family,packets,assembled=None,transport_offset=0,drop_reason=12):
   entries=[]
   for i,packet in enumerate(packets):
    entries.append(self.inject(packet,i%2))
    if i+1<len(packets):self.ready(label+'-'+str(i),1,i+1)
   case=self.add(label,family,entries,'geometry' if assembled else 'geometry-conflict')
   case.update(assembled_hex=assembled,transport_offset=transport_offset,drop_reason=drop_reason)
   self.wait(label+'-drained')
  for family in (4,6):
   for conflict in (False,True):
    parts,full=datagram(family,24100+family*10+int(conflict),size=24,step=8)
    header=20 if family==4 else 48
    old=bytearray.fromhex(parts[1])+bytes.fromhex(parts[2])[header:]
    old[-1]^=255
    selected=[parts[0],lengths(old,family)]
    if not conflict:selected.append(parts[1])
    selected.extend([parts[2],parts[3]])
    run(('overlap-conflict-' if conflict else 'overlap-newest-')+str(family),family,
        selected,None if conflict else full,20 if family==4 else 40)
  parts,full=datagram(4,24200,size=24,step=8)
  def options(packet):
   packet=bytearray.fromhex(packet);packet[0]=0x46
   return lengths(packet[:20]+b'\x01\x01\x01\x01'+packet[20:],4)
  parts[0]=options(parts[0]);run('ipv4-options',4,parts,options(full),24)
  _,full=datagram(6,24201,size=24)
  raw=bytes.fromhex(full);fragmentable=bytes([17,0,0,0,0,0,0,0])+raw[40:]
  base=bytearray(raw[:40]);base[6]=0
  parts=[]
  for offset in range(0,len(fragmentable),16):
   piece=fragmentable[offset:offset+16];more=int(offset+len(piece)<len(fragmentable))
   parts.append(lengths(base+bytes([44,0,0,0,0,0,0,0])+
     struct.pack('!BBHI',60,0,offset|more,24201)+piece,6))
  assembled=lengths(base+bytes([60,0,0,0,0,0,0,0])+fragmentable,6)
  run('ipv6-extension-chain',6,parts,assembled,56)
  _,full=datagram(6,24202,size=24)
  raw=bytes.fromhex(full);base=bytearray(raw[:40]);base[6]=0
  extension=bytearray(256);extension[0]=44;extension[1]=31
  parts=[]
  for offset in (0,16):
   parts.append(lengths(base+extension+struct.pack('!BBHI',17,0,offset|int(offset==0),24202)+raw[40+offset:56+offset],6))
  extension[0]=17
  run('ipv6-extension-budget',6,parts,lengths(base+extension+raw[40:],6),296)
  extension=bytearray(264);extension[0]=44;extension[1]=32
  parts=[]
  for offset in (0,16):
   parts.append(lengths(base+extension+struct.pack('!BBHI',17,0,offset|int(offset==0),24203)+raw[40+offset:56+offset],6))
  run('ipv6-extension-budget-exhausted',6,parts,drop_reason=16)

 def pressure(self,suite):
  for family in (4,6):
   reass=reassembly_worker(family);remote=1-reass
   self.policy(suite=='policy-return');self.config(timeout=10000)
   if suite=='policy-return':self.command('capacity-'+str(family),'product capacity credits 32 primary-slots 64 completion-slots 2','capacity.configured')
   elif suite=='sendout-handoff':self.command('capacity-'+str(family),'product capacity credits 32 primary-slots 2 completion-slots 128','capacity.configured')
   else:self.command('capacity-'+str(family),'product reassembly handoff-capacity slots 2','reassembly.handoff_capacity')
   identity=23300+family*100
   if suite=='ingress-handoff':
    pair=datagram(family,identity,size=24)[0];entries=[self.inject(pair[0],reass)];self.wait(f'{family}-context-ready',False);self.hold(family,reass)
    # Two queued inputs keep the sender's first post-hold turn productive.
    # Wait for actual ingress, then publish more inputs in later turns while
    # the destination still holds its first native queue slot.
    for n in range(2):entries.append(self.inject(pair[1],remote))
    self.await_hold(212000000+entries[-1]['case'],'fragment_ingress')
    for n in range(6):entries.append(self.inject(pair[1],remote))
    self.add(suite,family,entries,suite)
   else:
    pending=[]
    for n in range(4):
     port=owner_port(family,reass if suite=='policy-return' else remote,45700+n*20)
     parts=datagram(family,identity+n,port)[0]
     order=[(parts[0],remote),(parts[1],remote)] if suite=='policy-return' else [(parts[1],reass),(parts[0],remote)]
     entries=[self.inject(*order[0])];self.ready(f'{family}-memory-{n}',n+1,2*n+1);entries.append(self.inject(*order[1]));self.ready(f'{family}-head-{n}',n+1,2*n+2);c=self.add(suite+'-'+str(n),family,entries,suite);pending.append((c,parts[2]))
    self.wait(f'{family}-contexts-ready',False);self.hold(family,remote)
    for c,last in pending:c['packets'].append(self.inject(last,reass))
   # Do not request a CLI worker barrier during the bounded holds. Give the
   # other worker its real scheduling window before reading global status.
   time.sleep(.55)
   if hasattr(self,'activity_finish'):self.activity_finish()
   self.wait(f'{family}-pressure-drained')
   if suite in ('policy-return','sendout-handoff'):self.command('capacity-reset-'+str(family),'product capacity off','capacity.configured')
   else:self.command('capacity-reset-'+str(family),'product reassembly handoff-capacity default','reassembly.handoff_capacity')
   self.status(f'{family}-capacity-restored')
   self.policy(False)
