#!/usr/bin/env python3
"""T07: real application TCP sessions under CT/direction rules, Root then VPN."""
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
p.add_argument('--cache-validation',action='store_true')
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
    started = time.time_ns()
    run = subprocess.run(adb_prefix+list(map(str,argv)), stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, timeout=timeout)
    text = run.stdout.replace('\r','')
    with (output/'operations.jsonl').open('a') as f:
        f.write(json.dumps(dict(started_ns=started, completed_ns=time.time_ns(),
                               argv=list(map(str,argv)), code=run.returncode))+'\n')
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
    remote='/sdcard/t01-'+label
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


endpoint=None;endpoint_log=None;started=False
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
    global BASE,started
    BASE='/data/user/0/'+PKG+'/files/profiles/'+profile+'/vpp'
    args=['--ez','debugVpnHevValidation','true'] if profile=='vpn' else ['--ez','runtimeStart','true','--es','runtimeProfile','root']
    save(label+'-start.txt',action(*args));started=True
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
def configure(label,prior,expression,mode=0,static_priority=100):
    base0=prior.get('rule.0.version','0');base1=prior.get('rule.1.version','0')
    lines=[f'0 {base0} 4294967295 4294967295 4294967295 10 0 6 0 2 * * 0 65535 0 65535 {expression}',
           f'0 {base1} {uid} 4294967295 4294967295 {static_priority} 0 6 0 1 * * 0 65535 0 65535',
           'group 10','edge 10 1 0',f'bind 1 {uid} 2 10 {mode}']
    text='\n'.join(lines);save(label+'-request.txt',text+'\n')
    save(label+'-prefill.txt',action('--es','completeRuleText',shlex.quote(text)))
    old=config().get('queryElapsedMillis');tap(label,'Replace all rules')
    status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
    assert status['result']=='0' and status['savedRevision']==status['activeRevision'],status
    assert status['effectiveRules']=='2' and status['activeCount']=='2',status
    source_file(label)
    result.setdefault('configurations',[]).append(dict(label=label,profile=result['lifetimes'][-1]['profile'],
        revision=int(status['activeRevision']),source=label+'-source.conf',query=label+'-apply.properties',
        expression=expression,mode=mode,protocol=6,static_priority=static_priority))
    return status

def launch(label,profile,port,mode='policy'):
    global held
    nonce='T07-'+label+'-'+str(time.time_ns())
    plan=[dict(address=args.endpoint,port=40610,source=port,mode=mode,bytes=256,
               bindDefault=profile=='root',holdTimeoutMs=60000,readDeadlineMs=45000)]
    save(label+'-launch.txt',action('--es','s240ProbeNonce',nonce,'--es','s240ProbePlan',shlex.quote(json.dumps(plan))))
    case=dict(label=label,profile=profile,nonce=nonce,port=port,mode=mode,plan=plan,
              generation=result['lifetimes'][-1]['generation'],started_ns=time.time_ns())
    result['cases'].append(case);held=case
    return case

def phase(case,wanted):
    deadline=time.monotonic()+22
    while time.monotonic()<deadline:
        text=app('files/product-state/s240-'+case['nonce']+'-0.json',check=False)
        try:value=json.loads(text)
        except json.JSONDecodeError:value={}
        if value.get('phase')==wanted:
            save(case['label']+'-'+wanted+'.json',text);return value
        assert not value.get('error'),value
        time.sleep(.15)
    raise RuntimeError('TCP phase deadline '+wanted+' '+str(value))

def release(case):
    adb('shell','run-as',PKG,'touch','files/product-state/s240-release-'+case['nonce']+'-0')

def finished(case):
    global held
    deadline=time.monotonic()+50
    while time.monotonic()<deadline:
        text=app('files/product-state/s240-probe.json',check=False)
        try:value=json.loads(text)
        except json.JSONDecodeError:value={}
        if value.get('nonce')==case['nonce']:
            save(case['label']+'-result.json',text)
            assert not value.get('error') and len(value['flows'])==1,value
            flow=value['flows'][0]
            assert not flow.get('error') and flow['echoes']==3 and flow['echoBytes']==768 and flow['remoteEof'],flow
            assert flow['source']==case['port'] and flow['outcome']=='echo_closed'
            if case['mode']=='policy':assert flow['timeouts']>=1,flow
            else:assert flow['timeouts']==0,flow
            case['completed_ns']=time.time_ns();held=None;return value
        time.sleep(.15)
    raise RuntimeError('TCP completion deadline '+str(value))

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
    save('network.txt',adb('shell','ip','address'))
    source_file('before')
    peer=ROOT/'tests/device/helpers/t07_socket_peer.py';save('socket-peer.py',peer.read_text())
    result['peer_sha256']=digest(peer);result['endpoint']=args.endpoint
    endpoint_log=(output/'endpoint.jsonl').open('w')
    endpoint=subprocess.Popen(['python3','-u',str(peer),'server','--host',args.endpoint,'--port','40610'],
                              stdout=endpoint_log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+5
    while '"kind": "ready"' not in (output/'endpoint.jsonl').read_text():
        assert endpoint.poll() is None
        assert time.monotonic()<deadline
        time.sleep(.03)
    adb('shell','settings','put','global','stay_on_while_plugged_in','3')
    adb('shell','input','keyevent','224');adb('shell','wm','dismiss-keyguard')
    for profile,baseport in [('root',44100),('vpn',44200)]:
        status=start(profile,profile)
        for index,(condition,expression) in enumerate([('state','0d020e0101'),('direction','0e02')]):
            label=profile+'-'+condition
            status=configure(label+'-observe',status,expression,1)
            case=launch(label,profile,baseport+index)
            case['initial_revision']=int(status['activeRevision'])
            phase(case,'first_echo')
            case['initial_query']=label+'-initial-query.properties';query(label+'-initial')
            cli(label+'-initial-flow','show product flows')
            status=configure(label+'-enforce',status,expression,0)
            case['blocked_revision']=int(status['activeRevision'])
            case['before']=label+'-blocked-before-query.properties';query(label+'-blocked-before')
            release(case);phase(case,'return_timeout')
            cli(label+'-blocked-flow','show product flows')
            case['blocked_query']=label+'-blocked-query.properties';q=query(label+'-blocked')
            assert int(q['actualDrops'])>0,q
            save(label+'-blocked.log',app('files/profiles/'+profile+'/vpp/logs/vpp-stdout.log'))
            status=configure(label+'-recover',status,expression,1)
            case['recovered_revision']=int(status['activeRevision'])
            finished(case)
            case['query']=label+'-recovered-query.properties';query(label+'-recovered')
            cli(label+'-recovered-flow','show product flows')
        status=configure(profile+'-static-first',status,'0e02',0,0)
        case=launch(profile+'-static-first',profile,baseport+2,'fin')
        case['initial_revision']=int(status['activeRevision']);finished(case)
        case['query']=profile+'-static-first-query.properties';query(profile+'-static-first')
        cli(profile+'-final-flow','show product flows','show product flow-stack')
        if args.cache_validation:
            text=cli(profile+'-cache-counters','show product flows')
            cache=[dict(w.split('=',1) for w in line.split()[1:] if '=' in w)
                   for line in text.splitlines() if line.startswith('policy.cache ')]
            assert len(cache)==2 and sum(int(c['hits']) for c in cache)>0
            assert sum(int(c['misses']) for c in cache)>0
            result.setdefault('cache_counters',{})[profile]=cache
            result['cache_validation']=True
        stop(profile,profile)
    result['status']='RAW_COMPLETE';result['process_absent']=True
except Exception as error:
    result['error']=repr(error);raise
finally:
    if held:
        release(held)
    if started:
        save('failure-vpp.log',app('files/profiles/'+result['lifetimes'][-1]['profile']+'/vpp/logs/vpp-stdout.log'))
        action('--ez','runtimeStop','true')
        try:wait_state('cleanup-stopped','stopped')
        except Exception as error:result['cleanup_error']=repr(error)
    if endpoint:
        endpoint.terminate();endpoint.wait(timeout=3)
    if endpoint_log:endpoint_log.close()
    adb('shell','settings','put','global','stay_on_while_plugged_in',previous_power,check=False)
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
print('T07 real Pixel TCP CT/direction/Rank/live recovery Root and VPN collected')
