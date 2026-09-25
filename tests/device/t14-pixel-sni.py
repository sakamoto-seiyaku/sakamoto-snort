#!/usr/bin/env python3
"""T14: actual Root/VPN TCP reassembly and bounded resource acceptance."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
PKG = 'com.sakamoto.snort.androidruntime'
SERIAL = None
BASE = '/data/user/0/'+PKG+'/files/profiles/root/vpp'
p = argparse.ArgumentParser()
p.add_argument('--serial')
p.add_argument('--serial-from',type=Path)
p.add_argument('--endpoint',default='192.168.4.5')
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--fixtures',type=Path,required=True)
p.add_argument('--python',default='python3')
p.add_argument('--helper',type=Path,required=True)
p.add_argument('--profiles',choices=['root','vpn','both'],default='both')

args = p.parse_args()

SERIAL = args.serial or (json.loads(args.serial_from.read_text())['serial'] if args.serial_from else None) or subprocess.check_output([str(ROOT/'dev/adb'),'get-serialno'],text=True).strip()
assert SERIAL and SERIAL != 'unknown'
build_path, output = args.build.resolve(), args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
build = json.loads(build_path.read_text())
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(name, text): (output/name).write_text(text); return text
def props(text): return dict(line.split('=',1) for line in text.splitlines() if '=' in line and not line.startswith('#'))
result = dict(status='HOLD', profile='root', source='NFQ_CAPTURED+TUN_ORIGIN', serial=SERIAL,
              build=str(build_path), build_sha256=digest(build_path), source_sha256=build['source_sha256'],
              runner_sha256=digest(__file__), started_ns=time.time_ns(), cases=[])
save('runner.py',Path(__file__).read_text())
adb_prefix = [str(ROOT/'dev/adb'), '-s', SERIAL]
def adb(*argv, check=True, timeout=35):
    # Only replay idempotent reads/captures after the observed WSL launch error.
    # Runtime/app starts, taps, rule applies and installation are never replayed.
    safe=argv[0]=='pull' or (argv[0]=='shell' and (
        argv[1] in ('getprop','uname','dumpsys','sha256sum','screencap','uiautomator','wm')
        or argv[1:3]==('input','keyevent') or argv[1:3]==('settings','get')
        or argv[1:3]==('ip','address')
        or (argv[1]=='run-as' and len(argv)>3 and argv[3] in ('cat','stat','id','touch','sh'))))
    for attempt in range(3 if safe else 1):
        started = time.time_ns()
        run = subprocess.run(adb_prefix+list(map(str,argv)), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, timeout=timeout)
        text = run.stdout.replace('\r','')
        with (output/'operations.jsonl').open('a') as f:
            f.write(json.dumps(dict(started_ns=started, completed_ns=time.time_ns(),
                                   argv=list(map(str,argv)), code=run.returncode,attempt=attempt))+'\n')
        if not (safe and run.returncode and 'UtilAcceptVsock' in text and attempt<2):break
        save('wsl-transport-'+str(started)+'.txt',text)
        time.sleep(.2)
    if check and run.returncode: raise RuntimeError(text)
    return text

def root(command, check=True): return adb('shell','su','-c',shlex.quote(command),check=check)
def app(path, check=True): return adb('shell','run-as',PKG,'cat',path,check=check)
def state(): return props(app('files/runtime-state/snapshot.properties'))
def wait_state(label, wanted):
    end = time.monotonic()+30
    while time.monotonic()<end:
        text = app('files/runtime-state/snapshot.properties'); value=props(text)
        save(label+'-latest.properties',text)
        if value.get('state') == wanted:
            save(label+'.properties',text);return value
        if value.get('errorCode') == 'root_authorization_required':
            raise RuntimeError('KernelSU Superuser grant must be restored for this install')
        time.sleep(.15)
    raise RuntimeError('state deadline '+str(value))
def capture(label):
    adb('shell','input','keyevent','224')
    adb('shell','wm','dismiss-keyguard')
    remote='/sdcard/t12-'+label
    adb('shell','screencap','-p',remote+'.png')
    adb('pull',remote+'.png',output/(label+'.png'))
    answer=adb('shell','uiautomator','dump',remote+'.xml')
    if 'dumped to:' not in answer: raise RuntimeError('UI capture did not complete: '+answer)
    adb('pull',remote+'.xml',output/(label+'.xml'))
    adb('shell','rm',remote+'.png',remote+'.xml')
    return ET.parse(output/(label+'.xml'))
def tap(label, text):
    for attempt in range(8):
        tree=capture(label+'-before' if attempt==0 else label+f'-scroll{attempt}')
        nodes=[n for n in tree.iter('node') if n.get('text')==text and n.get('enabled')=='true']
        if len(nodes)==1:
            numbers=list(map(int,re.findall(r'\d+',nodes[0].get('bounds'))))
            x,y=(numbers[0]+numbers[2])//2,(numbers[1]+numbers[3])//2
            adb('shell','input','tap',x,y);return
        adb('shell','input','swipe','550','1700','550','600','250')
    raise RuntimeError('missing UI button '+text)
def config(): return props(app('files/product-state/complete-rule-config.properties',check=False))
def wait_config(label, predicate):
    end=time.monotonic()+10
    while time.monotonic()<end:
        text=app('files/product-state/complete-rule-config.properties',check=False);value=props(text)
        if predicate(value):save(label+'.properties',text);return value
        time.sleep(.1)
    raise RuntimeError('config deadline '+str(value))

# Reuse the audited prompt-before-command diagnostic transport, never a policy writer.
spec=importlib.util.spec_from_file_location('t01_target',ROOT/'tests/device/s233-fail-open.py')
target_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(target_module)
target_module.SERIAL=SERIAL
target=object.__new__(target_module.Target);target.pixel=True
def cli(label,*commands):return save(label+'.txt',target.cli(BASE+'/runtime',list(commands)))


endpoint=None;endpoint_log=None;started=False;current_profile=None
held=None
previous_power=adb('shell','settings','get','global','stay_on_while_plugged_in').strip()
def action(*argv):return adb('shell','am','start','-n',PKG+'/.DebugControlActivity',*argv)
def source_file(label):
    # Pull binary source without converting bytes through a text transport.
    remote='/data/local/tmp/t02-source-'+str(time.time_ns())
    root('cp /data/user/0/'+PKG+'/files/rule-configuration/rules.conf '+remote+' && chmod 644 '+remote)
    adb('pull',remote,output/(label+'-source.conf'));adb('shell','rm',remote)
    save(label+'-owner.txt',adb('shell','run-as',PKG,'stat','-c','%u:%g:%a','files/rule-configuration/rules.conf'))
    return (output/(label+'-source.conf')).read_bytes()
def query(label):
    old=config().get('queryElapsedMillis')
    action();tap(label+'-query','Query all rules')
    return wait_config(label+'-query',lambda c:c.get('queryElapsedMillis') not in (None,old))
def start(label,profile):
    global BASE,started,current_profile
    current_profile=profile
    BASE='/data/user/0/'+PKG+'/files/profiles/'+profile+'/vpp'
    args=['--ez','debugVpnHevValidation','true'] if profile=='vpn' else ['--ez','runtimeStart','true','--es','runtimeProfile','root']
    started=True  # an ambiguous command failure must still enter cleanup
    save(label+'-start.txt',action(*args))
    running=wait_state(label+'-running','running');assert running['profile']==profile,running
    assert running['protectionRunning']==('true' if profile=='root' else 'false')
    cli(label+'-startup','product packet-trace limit 4096','show threads','show product completion')
    processes=save(label+'-processes.txt',root('ps -A -o PID,UID,ARGS'))
    candidates=[int(parts[0]) for line in processes.splitlines() if len(parts:=line.split(None,2))==3
                and parts[0].isdigit() and Path(parts[2].split()[0]).name=='libvpp_runtime.so']
    assert len(candidates)==1,candidates
    pid=candidates[0]
    save(label+'-process.txt',root('cat /proc/'+str(pid)+'/status; readlink /proc/'+str(pid)+'/exe'))
    save(label+'-owner.properties',app('files/profiles/'+profile+'/vpp/owner.properties'))
    result.setdefault('lifetimes',[]).append(dict(label=label,profile=profile,generation=int(running['generation']),pid=pid))
    return query(label)
def stop(label,profile):
    global started
    save(label+'-before-stop.log',app('files/profiles/'+profile+'/vpp/logs/vpp-stdout.log'))
    save(label+'-stop.txt',action('--ez','runtimeStop','true'))
    stopped=wait_state(label+'-stopped','stopped');started=False
    assert stopped['mayBeActive']=='false'
    save(label+'-stop.log',app('files/product-state/'+('s242' if profile=='root' else 's237')+'-last-stop.log'))
    save(label+'-hooks-after.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
    save(label+'-queues-after.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
    life=result['lifetimes'][-1]
    assert root('test ! -d /proc/'+str(life['pid'])+' && echo absent').strip()=='absent'
    life['process_absent']=True
    source_file(label+'-stopped')
def configure(label,prior,protocol,expected_protocol_id,mode=1):
    expression='1001'
    versions=[prior.get(f'rule.{i}.version','0') for i in range(3)]
    lines=[f'0 {versions[0]} 4294967295 4294967295 4294967295 10 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}',
           f'0 {versions[1]} 4294967295 4294967295 4294967295 20 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}03',
           f'0 {versions[2]} {uid} 4294967295 4294967295 100 0 {protocol} 0 1 * * 0 65535 0 65535',
           'group 10','edge 10 1 0','group 20','edge 20 1 1',
           f'bind 1 {uid} 2 10 {mode}',f'bind 2 {uid} 2 20 {mode}']
    text='\n'.join(lines);save(label+'-request.txt',text+'\n')
    save(label+'-prefill.txt',action('--es','completeRuleText',shlex.quote(text)))
    old=config().get('queryElapsedMillis');tap(label,'Replace all rules')
    status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
    assert status['result']=='0' and status['savedRevision']==status['activeRevision'],status
    assert status['effectiveRules']=='3' and status['activeCount']=='3',status
    source_file(label)
    result.setdefault('configurations',[]).append(dict(label=label,profile=result['lifetimes'][-1]['profile'],
        revision=int(status['activeRevision']),source=label+'-source.conf',query=label+'-apply.properties',
        expression=expression,mode=mode,protocol=protocol,target=expected_protocol_id))
    return status

def launch(label,profile,mode,source):
    global held
    fixtures=json.loads(args.fixtures.read_text())
    nonce='t14-'+profile+'-'+mode+'-'+fixtures['nonce']
    application=mode;protocol='tcp'
    plan=dict(nonce=nonce,endpoint=args.endpoint,port=40640,source=source,mode=protocol,
              bindDefault=profile=='root',t13Direct=True,t13Absent=mode=='absent',
              certificateSha256=fixtures['certificateSha256'])
    if mode in ('malformed','truncated'):
        plan.update(port=40641,t13RawHex=fixtures[mode+'Hex'])
    assert re.fullmatch(r'[a-zA-Z0-9_-]{1,80}',nonce),'invalid fixture nonce'
    # Gate files deliberately survive app reinstall. A reused fixture must fail
    # before launching, never skip gates from an earlier accepted/failed run.
    check=('for f in files/product-state/t12-'+nonce+'.json '
           'files/product-state/t12-release-'+nonce+'-*; do '
           'if [ -e "$f" ]; then echo used; exit 0; fi; done; echo fresh')
    unused=save(label+'-nonce-check.txt',adb('shell','run-as',PKG,'sh','-c',shlex.quote(check))).strip()
    assert unused=='fresh','probe nonce already used; generate fresh realtime fixtures'
    started_ns=time.time_ns()
    save(label+'-launch.txt',action('--es','t12ProbePlan',shlex.quote(json.dumps(plan))))
    case=dict(label=label,profile=profile,nonce=nonce,port=source,protocol=protocol,application=application,plan=plan,
              generation=result['lifetimes'][-1]['generation'],started_ns=started_ns)
    result.setdefault('sessions',[]).append(case);held=case
    return case

def phase(case,wanted):
    deadline=time.monotonic()+35
    while time.monotonic()<deadline:
        text=app('files/product-state/t12-'+case['nonce']+'.json',check=False)
        try:value=json.loads(text)
        except json.JSONDecodeError:value={}
        if value.get('phase')==wanted:
            save(case['label']+'-'+wanted+'.json',text);return value
        if value.get('error'):
            save(case['label']+'-error.json',text)
            raise RuntimeError('protocol probe failed: '+value['error'])
        time.sleep(.15)
    raise RuntimeError('protocol phase deadline '+wanted+' '+str(value))

def release(case,name):
    adb('shell','run-as',PKG,'touch','files/product-state/t12-release-'+case['nonce']+'-'+name)

def sni_query(label,identity,stale=False):
    nonce='query-'+label+'-'+str(time.time_ns())
    save(label+'-sni-action.txt',action('--es','sniNonce',nonce,'--ei','sniWorker',identity[0],
       '--ei','sniSlot',identity[1],'--el','sniIncarnation',int(identity[2])+(100000 if stale else 0)))
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        text=app('files/product-state/t13-sni-'+nonce+'.properties',check=False)
        value=props(text)
        if 'code' in value:
            save(label+'-sni.properties',text)
            assert (value['code']!='0') if stale else (value['code']=='0'),value
            return value
        time.sleep(.1)
    raise RuntimeError('typed SNI query deadline')

def evidence(case,status,phase_name,expected,fast=False):
    label=case['label']+'-'+phase_name
    if not fast:query(label)
    text=cli(label+'-flow','show product flows')
    rows=[dict(item.split('=',1) for item in line.split()[1:] if '=' in item)
          for line in text.splitlines() if line.startswith('flow.entry ')]
    row=next(r for r in rows if str(case['port']) in (r['port_a'],r['port_b']))
    identity=[row['worker'],row['slot'],row['incarnation']]
    facts=sni_query(label,identity)
    if not fast:sni_query(label+'-stale',identity,True)
    assert facts['result']==str(expected),(case,phase_name,facts)
    assert facts['name']==('example.test' if expected==1 else '')
    result['cases'].append(dict(label=label,client=case['label'],profile=case['profile'],protocol='tcp',
        port=case['port'],nonce=case['nonce'],phase=phase_name,mode=case['application'],revision=int(status['activeRevision']),
        query=(label+'-query.properties') if not fast else None,flow=label+'-flow.txt',sni=label+'-sni.properties',
        identity=identity,generation=case['generation'],fast=fast))
    return facts

def configure_ack(label,prior,port):
    # An ordinary highest-priority packet DROP, installed after TCP connect.
    # Only reverse packets for this one app socket are blocked, causing real
    # kernel retransmission of the incomplete ClientHello on Root and VPN.
    versions=[prior.get(f'rule.{i}.version','0') for i in range(3)]
    lines=[f'0 {versions[0]} 4294967295 4294967295 4294967295 10 0 6 0 2 * * 0 65535 0 65535 1001',
           f'0 {versions[1]} 4294967295 4294967295 4294967295 20 0 6 0 2 * * 0 65535 0 65535 100103',
           f'0 {versions[2]} {uid} 4294967295 4294967295 100 0 6 0 1 * * 0 65535 0 65535',
           f'0 0 {uid} 4294967295 4294967295 0 0 6 0 2 * * 40641 40641 {port} {port}',
           'group 10','edge 10 1 0','group 20','edge 20 1 1',f'bind 1 {uid} 2 10 1',f'bind 2 {uid} 2 20 1']
    text='\n'.join(lines);save(label+'-request.txt',text+'\n')
    save(label+'-prefill.txt',action('--es','completeRuleText',shlex.quote(text)))
    old=config().get('queryElapsedMillis');tap(label,'Replace all rules')
    status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
    assert status['result']=='0' and status['savedRevision']==status['activeRevision'],status
    assert status['activeCount']=='4',status
    source_file(label)
    result.setdefault('configurations',[]).append(dict(label=label,profile=current_profile,
        revision=int(status['activeRevision']),source=label+'-source.conf',query=label+'-apply.properties',
        expression='1001',mode=1,protocol=6,target=1003,ack_drop_port=port))
    return status

def prepare_ack_recovery(label,prior):
    # Prepare the existing management UI before bytes start. Capturing/scrolling
    # the UI after a retransmit begins can itself consume the five-second budget.
    versions=[prior.get(f'rule.{i}.version','0') for i in range(3)]
    lines=[f'0 {versions[0]} 4294967295 4294967295 4294967295 10 0 6 0 2 * * 0 65535 0 65535 1001',
           f'0 {versions[1]} 4294967295 4294967295 4294967295 20 0 6 0 2 * * 0 65535 0 65535 100103',
           f'0 {versions[2]} {uid} 4294967295 4294967295 100 0 6 0 1 * * 0 65535 0 65535',
           'group 10','edge 10 1 0','group 20','edge 20 1 1',f'bind 1 {uid} 2 10 1',f'bind 2 {uid} 2 20 1']
    text='\n'.join(lines);save(label+'-request.txt',text+'\n')
    save(label+'-prefill.txt',action('--es','completeRuleText',shlex.quote(text)))
    for attempt in range(8):
        tree=capture(label+'-prepared-'+str(attempt))
        nodes=[n for n in tree.iter('node') if n.get('text')=='Replace all rules' and n.get('enabled')=='true']
        if len(nodes)==1:
            bounds=list(map(int,re.findall(r'\d+',nodes[0].get('bounds'))))
            x,y=(bounds[0]+bounds[2])//2,(bounds[1]+bounds[3])//2
            break
        adb('shell','input','swipe','550','1700','550','600','250')
    else:raise RuntimeError('missing recovery action')
    old=config().get('queryElapsedMillis')
    def apply():
        adb('shell','input','tap',x,y)
        status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
        assert status['result']=='0' and status['savedRevision']==status['activeRevision'] and status['activeCount']=='3',status
        source_file(label)
        result.setdefault('configurations',[]).append(dict(label=label,profile=current_profile,
            revision=int(status['activeRevision']),source=label+'-source.conf',query=label+'-apply.properties',
            expression='1001',mode=1,protocol=6,target=1003))
        return status
    return apply

def launch_literal(label,profile,mode,source,fixture,count=1,hold=False):
    global held
    nonce='t14-'+profile+'-'+mode+'-'+fixtures['nonce']
    plan=dict(nonce=nonce,endpoint=args.endpoint,port=40641,source=source,mode='tcp',
        bindDefault=profile=='root',t14WireHex=fixtures[fixture+'Hex'],t14Count=count,
        t14Prefix=20,t14DelayMs=1600 if mode=='retransmit' else 80,t14HoldPrefix=hold)
    unused=app('files/product-state/t12-'+nonce+'.json',check=False)
    assert '"nonce"' not in unused,'reused probe nonce'
    save(label+'-launch.txt',action('--es','t12ProbePlan',shlex.quote(json.dumps(plan))))
    case=dict(label=label,profile=profile,nonce=nonce,port=source,protocol='tcp',application=mode,plan=plan,
        fixture=fixture,count=count,generation=result['lifetimes'][-1]['generation'],started_ns=time.time_ns())
    result.setdefault('sessions',[]).append(case);held=case;return case

raw_clients=[];raw_hooks=[];remote_dir=None
class RawClient:
    def __init__(self,mode,port,fixture):
        self.mode,self.port=mode,port;self.base=remote_dir+'/'+mode
        hook=f'iptables -t raw -I OUTPUT -p tcp --sport {port} --dport 40641 --tcp-flags RST RST -j DROP'
        root(hook);raw_hooks.append(hook)
        command=f'{remote_dir}/wire {uid} {args.endpoint} {port} {mode} {remote_dir}/{fixture}.bin {self.base}'
        self.pid=int(root(command+' > '+self.base+'.jsonl 2>&1 & echo $!').strip())
        raw_clients.append(self)
        self.case=dict(label='root-wire-'+mode,profile='root',nonce=fixtures['nonce'],port=port,protocol='tcp',
            application=mode,fixture=fixture,generation=result['lifetimes'][-1]['generation'],started_ns=time.time_ns(),raw=True)
        result.setdefault('sessions',[]).append(self.case)
    def phase(self,name):
        deadline=time.monotonic()+15
        while root('test -f '+self.base+'.'+name+' && echo ready',check=False).strip()!='ready':
            assert time.monotonic()<deadline,root('cat '+self.base+'.jsonl')
            time.sleep(.05)
    def release(self,name):root('touch '+self.base+'.release-'+name)
    def close(self):
        self.release('complete')
        save(self.case['label']+'-client.jsonl',root('cat '+self.base+'.jsonl'))
        self.case['completed_ns']=time.time_ns()

try:
    before=state();assert before.get('state')=='stopped' and before.get('mayBeActive')=='false',before
    assert digest(build['apk'])==build['apk_sha256']
    save('install.txt',adb('install','-r',build['apk'],timeout=60))
    package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package)[1]+'/lib/arm64'
    installed=save('installed-native.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(build['native_sha256'])]))
    assert {Path(line.split()[1]).name:line.split()[0] for line in installed.splitlines()}==build['native_sha256']
    assert save('installed-apk.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==build['apk_sha256']
    uid=int(adb('shell','run-as',PKG,'id','-u').strip());result['uid']=uid
    save('device.txt',adb('shell','getprop','ro.product.device')+adb('shell','uname','-a'))
    save('network.txt',adb('shell','ip','address'));source_file('before')
    fixtures=json.loads(args.fixtures.read_text());save('fixtures.json',args.fixtures.read_text())
    result['fixtures_sha256']=digest(args.fixtures)
    peer=ROOT/'tests/device/helpers/t14_tcp_peer.py';save('protocol-peer.py',peer.read_text())
    result['peer_sha256']=digest(peer);result['endpoint']=args.endpoint
    helper=args.helper.resolve();(output/'wire-helper').write_bytes(helper.read_bytes())
    save('wire-helper.c',(ROOT/'tests/device/helpers/t14-tcp-wire.c').read_text())
    result['helper_sha256']=digest(helper);result['helper_source_sha256']=digest(output/'wire-helper.c')
    remote_dir='/data/local/tmp/t14-'+fixtures['nonce'];root('mkdir '+remote_dir+' && chmod 777 '+remote_dir)
    adb('push',helper,remote_dir+'/wire');root('chmod 755 '+remote_dir+'/wire')
    for fixture in ('named','maximum'):adb('push',args.fixtures.resolve().parent/(fixture+'.bin'),remote_dir+'/'+fixture+'.bin')
    save('installed-helper.txt',root('sha256sum '+remote_dir+'/wire'))
    endpoint_log=(output/'endpoint.jsonl').open('w')
    endpoint=subprocess.Popen([args.python,'-u',str(peer),'server','--host',args.endpoint,'--directory',str(args.fixtures.resolve().parent)],stdout=endpoint_log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+5
    while '"kind": "ready"' not in (output/'endpoint.jsonl').read_text():
        assert endpoint.poll() is None
        assert time.monotonic()<deadline
        time.sleep(.03)
    adb('shell','settings','put','global','stay_on_while_plugged_in','3')
    adb('shell','input','keyevent','224');adb('shell','wm','dismiss-keyguard')
    for profile,baseport in [('root',46700),('vpn',46900)]:
        if args.profiles not in ('both',profile):continue
        status=start(profile,profile);status=configure(profile+'-observe',status,6,1003)
        if profile=='root':
            for index,(mode,fixture,wanted) in enumerate((('reorder','named',1),('bytes','maximum',2),
                ('sparse','named',0),('span','named',0),('packets','named',0))):
                client=RawClient(mode,46620+index,fixture);client.phase('prefix_ready')
                evidence(client.case,status,'prefix',0,True)
                client.release('prefix_ready');client.phase('complete')
                evidence(client.case,status,'complete',wanted)
                client.close()
        for index,(mode,fixture,wanted,count,hold) in enumerate((('segmented','named',1,1,False),
            ('retransmit','named',1,1,False),('exhausted','exhausted',0,1,False),
            ('timeout','named',0,1,True),('concurrent','absent',2,48,True))):
            label=profile+'-'+mode
            case=launch_literal(label,profile,mode,baseport+index*20,fixture,count,hold)
            phase(case,'connected_ready')
            if mode=='retransmit':
                status=configure_ack(label+'-ack-drop',status,case['port'])
                recover=prepare_ack_recovery(label+'-ack-recover',status)
            release(case,'connected_ready')
            if mode=='retransmit':
                time.sleep(.4);status=recover()
            if hold:
                phase(case,'prefix_ready')
                evidence(case,status,'prefix',0,True)
                if mode=='timeout':
                    time.sleep(5.2);evidence(case,status,'expired',0,True)
                release(case,'prefix_ready')
            phase(case,'raw_ready');evidence(case,status,'complete',wanted)
            release(case,'raw_ready');value=phase(case,'finished');assert not value.get('error'),value
            case['completed_ns']=time.time_ns();held=None
        # An ordinary TLS stack handshake and observe/enforce/recover lifecycle
        # accompany the deliberately rearranged literal-ClientHello samples.
        label=profile+'-named';case=launch(label,profile,'named',baseport+150)
        phase(case,'tls_ready');evidence(case,status,'ready',1)
        status=configure(label+'-enforce',status,6,1003,0)
        release(case,'tls_ready');phase(case,'blocked');evidence(case,status,'blocked',1)
        status=configure(label+'-recover',status,6,1003)
        release(case,'blocked');phase(case,'budget_done');evidence(case,status,'recovered',1)
        release(case,'budget_done');value=phase(case,'finished');assert not value.get('error'),value
        case['completed_ns']=time.time_ns();held=None
        cli(profile+'-final','show product flows','show product completion')
        save(profile+'-memory.txt',root('cat /proc/'+str(result['lifetimes'][-1]['pid'])+'/status'))
        stop(profile,profile)
    result['status']='RAW_COMPLETE';result['process_absent']=True
except Exception as error:
    result['error']=repr(error);raise
finally:
    if held:
        for gate in ('connected_ready','prefix_ready','raw_ready','tls_ready','blocked','budget_done'):release(held,gate)
    for client in raw_clients:
        save(client.case['label']+'-client.jsonl',root('cat '+client.base+'.jsonl',check=False))
        root('if [ -r /proc/'+str(client.pid)+'/cmdline ] && '
             'tr "\\000" " " < /proc/'+str(client.pid)+'/cmdline | grep -F '+shlex.quote(remote_dir+'/wire')+
             ' >/dev/null; then kill '+str(client.pid)+'; fi',check=False)
    hook_errors=[]
    for hook in raw_hooks:
        try:root(hook.replace(' -I ',' -D '))
        except Exception as error:hook_errors.append(repr(error))
    if hook_errors:result['cleanup_error']=hook_errors
    if started:
        save('failure-vpp.log',app('files/profiles/'+current_profile+'/vpp/logs/vpp-stdout.log',check=False))
        action('--ez','runtimeStop','true')
        try:wait_state('cleanup-stopped','stopped')
        except Exception as error:result['cleanup_error']=repr(error)
    if endpoint:endpoint.terminate();endpoint.wait(timeout=3)
    if endpoint_log:endpoint_log.close()
    save('raw-hooks-after.txt',root('iptables-save -t raw',check=False))
    adb('shell','settings','put','global','stay_on_while_plugged_in',previous_power,check=False)
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
print('T14 Pixel Root/VPN TCP reconstruction and typed queries collected')
