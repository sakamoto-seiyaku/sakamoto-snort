#!/usr/bin/env python3
"""T03: serial Root/VPN invalid-source startup, online UI repair and capture."""
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
SERIAL = '28201JEGR0XPAJ'
BASE = '/data/user/0/'+PKG+'/files/profiles/root/vpp'
p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
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
target=object.__new__(target_module.Target);target.pixel=True
def cli(label,*commands):return save(label+'.txt',target.cli(BASE+'/runtime',list(commands)))


import socket
import threading
endpoint_pid=None;temporary=None;started=False
previous_power=adb('shell','settings','get','global','stay_on_while_plugged_in').strip()
lan_server=None; lan_thread=None; lan_done=threading.Event();lan_records=[]
def action(*argv):return adb('shell','am','start','-n',PKG+'/.DebugControlActivity',*argv)
def source_file(label):
    # Pull binary source without converting bytes through a text transport.
    remote='/data/local/tmp/t03-source-'+str(time.time_ns())
    root('cp /data/user/0/'+PKG+'/files/rule-configuration/rules.conf '+remote+' && chmod 644 '+remote)
    adb('pull',remote,output/(label+'-source.conf'));adb('shell','rm',remote)
    save(label+'-owner.txt',adb('shell','run-as',PKG,'stat','-c','%u:%g:%a','files/rule-configuration/rules.conf'))
    return (output/(label+'-source.conf')).read_bytes()
def query(label):
    old=config().get('queryElapsedMillis')
    action();tap(label+'-query','Query all rules')
    return wait_config(label+'-query',lambda c:c.get('queryElapsedMillis') not in (None,old))
def start(label,profile,ready=True):
    global BASE,started
    BASE='/data/user/0/'+PKG+'/files/profiles/'+profile+'/vpp'
    args=['--ez','debugVpnHevValidation','true'] if profile=='vpn' else ['--ez','runtimeStart','true','--es','runtimeProfile','root']
    save(label+'-start.txt',action(*args));started=True
    running=wait_state(label+('-running' if ready else '-management'),'running' if ready else 'error');assert running['profile']==profile,running
    assert running['protectionRunning']==('true' if ready and profile=='root' else 'false')
    if not ready: assert running['errorCode']=='rule_configuration_not_active' and running['mayBeActive']=='true',running
    cli(label+'-startup','product packet-trace limit 4096','show threads','show product completion')
    processes=save(label+'-processes.txt',root('ps -A -o PID,UID,ARGS'))
    candidates=[int(parts[0]) for line in processes.splitlines() if len(parts:=line.split(None,2))==3
                and parts[0].isdigit() and Path(parts[2].split()[0]).name=='libvpp_runtime.so']
    assert len(candidates)==1,candidates
    pid=candidates[0]
    save(label+'-process.txt',root('cat /proc/'+str(pid)+'/status; readlink /proc/'+str(pid)+'/exe'))
    save(label+'-owner.properties',app('files/profiles/'+profile+'/vpp/owner.properties'))
    result.setdefault('lifetimes',[]).append(dict(label=label,profile=profile,generation=int(running['generation']),pid=pid,initially_ready=ready))
    return query(label)
def stop(label,profile):
    global started
    save(label+'-before-stop.log',app('files/profiles/'+profile+'/vpp/logs/vpp-stdout.log'))
    action();adb('shell','input','swipe','550','600','550','1800','200');tap(label+'-stop','Stop')
    stopped=wait_state(label+'-stopped','stopped');started=False
    assert stopped['mayBeActive']=='false'
    save(label+'-stop.log',app('files/product-state/'+('s242' if profile=='root' else 's237')+'-last-stop.log'))
    save(label+'-hooks-after.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
    save(label+'-queues-after.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
    life=result['lifetimes'][-1]
    assert root('test ! -d /proc/'+str(life['pid'])+' && echo absent').strip()=='absent'
    life['process_absent']=True
    source_file(label+'-stopped')
def submit(label,prior,action_value,profile='root',excess=False):
    lines=[]
    cidrs=[('127.0.0.0/8','127.0.0.0/8'),('::1/128','::1/128')] if profile=='root' else [('10.111.0.2/32','192.168.4.5/32'),('fd00:111:111::2/128','::/0')]
    for i,(source,destination) in enumerate(cidrs):
        base=prior.get(f'rule.{i}.version','0') if prior.get('count')=='2' or int(prior.get('count','0'))>2 else '0'
        first,last,dport=(31999,32001,40608) if profile=='root' else (42000,42010,40609)
        lines.append(f'0 {base} {uid} 4294967295 4294967295 0 {i} 17 3 {action_value} {source} {destination} {first} {last} {dport} {dport}')
    if excess:
        for i in range(127):lines.append(f'0 0 {20000+i} 4294967295 4294967295 0 0 6 0 2 0.0.0.0/0 0.0.0.0/0 0 65535 0 65535')
    text='\n'.join(lines);save(label+'-request.txt',text+'\n')
    save(label+'-prefill.txt',action('--es','completeRuleText',shlex.quote(text)))
    old=config().get('queryElapsedMillis');tap(label,'Replace all rules')
    status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
    source_file(label);capture(label+'-result');return status

def root_probes(label,status,active,revision,lifetime,delivered):
    for i,host in enumerate(['127.0.0.2','::1']):
        nonce=f't03-{label}-v{4 if i==0 else 6}-{time.time_ns()}'
        action('--ez','debugUdpTraffic','true','--es','debugUdpHost',host,'--ei','debugUdpPort','40608',
            '--ei','debugUdpSourcePort','32000','--es','debugUdpNonce',nonce,'--ez','debugUdpExpectReply','true',
            '--ei','debugUdpTimeoutMillis','1000','--ez','debugTrafficBindToVpn','false')
        end=time.monotonic()+10
        while time.monotonic()<end:
            probe=app('files/debug/udp-traffic-probe.properties')
            if props(probe).get('nonce')==nonce:break
            time.sleep(.1)
        else:raise RuntimeError('UDP probe deadline')
        save(label+f'-v{i}-probe.properties',probe)
        assert (props(probe)['result']=='udp_echo_matched')==delivered,probe
        queried=query(label+f'-v{i}')
        assert int(queried['winnerVersion'])==active[i] and int(queried['winnerRevision'])==revision,queried
        assert int(queried['winnerAction'])==(1 if delivered else 2),queried
        endpoint=save(label+f'-v{i}-endpoint.txt',root('cat '+temporary+'/endpoint.log'))
        assert (nonce in endpoint)==delivered
        result['cases'].append(dict(phase=label,profile='root',family=4 if i==0 else 6,nonce=nonce,delivered=delivered,
            rule_version=active[i],revision=revision,saved_revision=int(status['savedRevision']),
            generation=result['lifetimes'][-1]['generation'],lifetime=lifetime,query=label+f'-v{i}-query.properties',
            probe=label+f'-v{i}-probe.properties',endpoint=label+f'-v{i}-endpoint.txt'))

def vpn_probe(label,status,delivered):
    nonce='t03-'+label+'-'+str(time.time_ns())
    save(label+'-send.txt',action('--es','s237ProbeNonce',nonce,'--ei','s237SourcePort','42001',
        '--es','s237Endpoint','192.168.4.5','--ei','s237EndpointPort','40609','--ei','s237Packets','1'))
    end=time.monotonic()+10
    while time.monotonic()<end:
        probe=app('files/product-state/s237-probe.properties',check=False)
        if props(probe).get('nonce')==nonce:break
        time.sleep(.1)
    else:raise RuntimeError('VPN probe deadline')
    save(label+'-probe.properties',probe)
    assert (props(probe).get('packet.0')=='echo')==delivered,probe
    queried=query(label)
    assert queried['winnerVersion']==status['rule.0.version'] and queried['winnerRevision']==status['activeRevision'],queried
    assert int(queried['winnerAction'])==(1 if delivered else 2),queried
    assert (nonce+':0' in lan_records)==delivered
    result['cases'].append(dict(phase=label,profile='vpn',family=4,nonce=nonce,delivered=delivered,
        rule_version=int(status['rule.0.version']),revision=int(status['activeRevision']),saved_revision=int(status['savedRevision']),
        generation=result['lifetimes'][-1]['generation'],lifetime=result['lifetimes'][-1]['label'],query=label+'-query.properties',probe=label+'-probe.properties'))

def submit_text(label,text):
    save(label+'-request.txt',text+'\n')
    save(label+'-prefill.txt',action('--es','completeRuleText',shlex.quote(text)))
    old=config().get('queryElapsedMillis');tap(label,'Replace all rules')
    status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
    source_file(label);capture(label+'-result');return status

def management_checks(label,profile):
    capture(label+'-ui')
    readiness=save(label+'-readiness.properties',app('files/product-state/startup-readiness.properties'))
    r=props(readiness)
    assert r['managementReady']=='true' and r['policyReady']==r['captureStarted']==r['protectionRunning']=='false',r
    assert r['adapterReady']=='false' and r['compileError']=='5'
    hooks=save(label+'-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
    queues=save(label+'-queues.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
    assert 'SAKAMOTO' not in hooks and not queues.strip()
    save(label+'-links.txt',root('ip -o link show'))
    pid=result['lifetimes'][-1]['pid']
    fds=save(label+'-fds.txt',root('ls -l /proc/'+str(pid)+'/fd'))
    assert '/dev/tun' not in fds
    cli(label+'-native','show product tun','show product root lanes','show product completion')
    nonce='t03-management-'+label+'-'+str(time.time_ns())
    host='127.0.0.2' if profile=='root' else '192.168.4.5';port='40608' if profile=='root' else '40609'
    action('--ez','debugUdpTraffic','true','--es','debugUdpHost',host,'--ei','debugUdpPort',port,
           '--ei','debugUdpSourcePort','32000','--es','debugUdpNonce',nonce,'--ez','debugUdpExpectReply','true',
           '--ei','debugUdpTimeoutMillis','1000','--ez','debugTrafficBindToVpn','false')
    end=time.monotonic()+10
    while time.monotonic()<end:
        probe=app('files/debug/udp-traffic-probe.properties',check=False)
        if props(probe).get('nonce')==nonce:break
        time.sleep(.1)
    assert props(probe).get('result')=='udp_echo_matched',probe
    save(label+'-ordinary-network.properties',probe)
    if profile=='root':
        endpoint=save(label+'-ordinary-endpoint.txt',root('cat '+temporary+'/endpoint.log'));assert nonce in endpoint
    else:assert nonce in lan_records
    result.setdefault('uncontrolled',[]).append(dict(label=label,profile=profile,nonce=nonce,generation=result['lifetimes'][-1]['generation']))

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
    source_file('before')
    compiler=Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
    helper_source=ROOT/'tests/device/helpers/s207-echo.c'
    subprocess.run([str(compiler),'-O2','-Wall','-Wextra','-Werror',str(helper_source),'-o',str(output/'echo')],check=True)
    save('echo.c',helper_source.read_text());result['endpoint_build']=dict(source_sha256=digest(helper_source),binary_sha256=digest(output/'echo'),compiler_sha256=digest(compiler))
    temporary=adb('shell','mktemp','-d','/data/local/tmp/t03.XXXXXX').strip();assert re.fullmatch(r'/data/local/tmp/t03\.[A-Za-z0-9]+',temporary)
    adb('push',output/'echo',temporary+'/echo');adb('shell','chmod','755',temporary+'/echo')
    endpoint_pid=root('nohup '+temporary+'/echo 40608 127.0.0.2 ::1 >'+temporary+'/endpoint.log 2>&1 </dev/null & echo $!').strip();assert endpoint_pid.isdigit()
    save('endpoint-start.txt',root('cat '+temporary+'/endpoint.log'))
    lan_server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);lan_server.bind(('192.168.4.5',40609));lan_server.settimeout(.1)
    def lan_endpoint():
        while not lan_done.is_set():
            try:data,peer=lan_server.recvfrom(2048)
            except socket.timeout:continue
            lan_records.append(data.decode());lan_server.sendto(data,peer)
    lan_thread=threading.Thread(target=lan_endpoint);lan_thread.start()
    adb('shell','settings','put','global','stay_on_while_plugged_in','3')
    adb('shell','input','keyevent','224');adb('shell','wm','dismiss-keyguard')
    for profile in ['root','vpn']:
        seed=profile+'-seed';status=start(seed,profile)
        status=submit(profile+'-drop',status,2,profile=profile);assert status['result']=='0'
        active=[int(status[f'rule.{i}.version']) for i in range(2)];revision=int(status['activeRevision'])
        if profile=='root':root_probes(profile+'-drop',status,active,revision,seed,False)
        else:vpn_probe(profile+'-drop',status,False)
        failed=submit(profile+'-compile-failure',status,1,profile=profile,excess=True)
        assert failed['result']==failed['compileError']=='5' and failed['count']=='129'
        assert failed['activeRevision']==status['activeRevision']
        if profile=='root':root_probes(profile+'-compile-failure',failed,active,revision,seed,False)
        else:
            previous_active=dict(failed,activeRevision=status['activeRevision'])
            previous_active['rule.0.version']=status['rule.0.version']
            vpn_probe(profile+'-compile-failure',previous_active,False)
        invalid_source=source_file(profile+'-invalid');stop(seed,profile)
        # Normal stop must also work before the user has repaired the source.
        abandoned=profile+'-unrepaired';failed=start(abandoned,profile,ready=False)
        management_checks(abandoned,profile)
        assert source_file(abandoned)==invalid_source
        stop(abandoned,profile)
        repair_life=profile+'-repair';failed=start(repair_life,profile,ready=False)
        assert failed['activeRevision']=='0' and failed['count']=='129'
        management_checks(repair_life,profile)
        assert source_file(repair_life)==invalid_source
        # Resubmit exactly the saved identities through the same visible request entry.
        lines=(output/(profile+'-compile-failure-request.txt')).read_text().splitlines()
        text='\n'.join(' '.join([failed[f'rule.{i}.version'],'0',*line.split()[2:]]) for i,line in enumerate(lines))
        retry=submit_text(profile+'-retry',text)
        assert retry['result']==retry['compileError']=='5' and retry['count']=='129'
        assert retry['savedRevision']==failed['savedRevision'] and retry['activeRevision']=='0'
        assert source_file(profile+'-retried')==invalid_source
        repaired=submit(profile+'-repair-apply',failed,1,profile=profile)
        assert repaired['result']=='0' and repaired['savedRevision']==repaired['activeRevision']
        assert all(repaired[f'rule.{i}.version']==failed[f'rule.{i}.version'] for i in range(2))
        action();tap(profile+'-refresh-before-start','Refresh');time.sleep(.3)
        before=state();assert before['state']=='error' and before['errorCode']=='capture_not_started',before
        assert before['protectionRunning']=='false'
        save(profile+'-repaired-not-started.properties',app('files/runtime-state/snapshot.properties'))
        save(profile+'-repaired-readiness.properties',app('files/product-state/startup-readiness.properties'))
        adb('shell','input','swipe','550','600','550','1800','200');tap(profile+'-resume','Start')
        running=wait_state(repair_life+'-running','running')
        assert running['generation']==before['generation'] and running['protectionRunning']==('true' if profile=='root' else 'false')
        save(profile+'-running-readiness.properties',app('files/product-state/startup-readiness.properties'))
        capture(profile+'-running-ui')
        active=[int(repaired[f'rule.{i}.version']) for i in range(2)];revision=int(repaired['activeRevision'])
        if profile=='root':root_probes(profile+'-recovered',repaired,active,revision,repair_life,True)
        else:vpn_probe(profile+'-recovered',repaired,True)
        status=submit(profile+'-recovered-drop',repaired,2,profile=profile);assert status['result']=='0'
        active=[int(status[f'rule.{i}.version']) for i in range(2)];revision=int(status['activeRevision'])
        if profile=='root':root_probes(profile+'-recovered-drop',status,active,revision,repair_life,False)
        else:vpn_probe(profile+'-recovered-drop',status,False)
        # Leave a valid explicit ALLOW configuration in the one VPP source.
        status=submit(profile+'-final-allow',status,1,profile=profile);assert status['result']=='0'
        stop(repair_life,profile)
    result['process_absent']=True;result['status']='RAW_COMPLETE'
except Exception as error:
    result['error']=repr(error);raise
finally:
    if started:
        action('--ez','runtimeStop','true')
        try:wait_state('cleanup-stopped','stopped')
        except Exception as error:result['cleanup_error']=repr(error)
    if endpoint_pid and temporary:
        root('test "$(readlink /proc/'+endpoint_pid+'/exe)" = '+temporary+'/echo && kill '+endpoint_pid,check=False)
        root('rm -f '+temporary+'/echo '+temporary+'/endpoint.log; rmdir '+temporary,check=False)
    lan_done.set()
    if lan_thread:lan_thread.join(2)
    if lan_server:lan_server.close()
    save('lan-endpoint.json',json.dumps(lan_records))
    adb('shell','settings','put','global','stay_on_while_plugged_in',previous_power,check=False)
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
print('T03 Pixel complete rules, failures, restart and Root/VPN persistence collected')
