#!/usr/bin/env python3
"""T10: bounded direct/factor/residual plans and compile limits on Root/VPN."""
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
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--allow-downgrade', action='store_true')
args = p.parse_args()
SERIAL = args.serial or subprocess.check_output([str(ROOT/'dev/adb'),'get-serialno'],text=True).strip()
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


import socket
import threading
endpoint_pid=None;temporary=None;started=False
previous_power=adb('shell','settings','get','global','stay_on_while_plugged_in').strip()
lan_server=None; lan_thread=None; lan_done=threading.Event();lan_records=[]
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
def submit(label, prior, expression, observe=False):
    lines=[]
    for i in range(2):
        base=prior.get(f'rule.{i}.version','0') if int(prior.get('count','0'))>=2 else '0'
        subject=4294967295 if observe and i==0 else uid
        extra=' '+expression if i==0 else ''
        lines.append(f'0 {base} {subject} 4294967295 4294967295 {1+i*99} 0 17 3 {2-i} * * 0 65535 0 65535{extra}')
    if observe: lines += ['group 10','edge 10 1 0',f'bind 1 {uid} 2 10 1']
    text='\n'.join(lines);save(label+'-request.txt',text+'\n')
    save(label+'-prefill.txt',action('--es','completeRuleText',shlex.quote(text)))
    old=config().get('queryElapsedMillis');tap(label,'Replace all rules')
    status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
    assert status['result']=='0' and status['savedRevision']==status['activeRevision'],status
    assert status['effectiveRules']=='2' and status['activeCount']=='2',status
    source_file(label);capture(label+'-result')
    cli(label+'-resources','show product policy-index','show product rule-budget','show memory')
    save(label+'-memory.txt',root('cat /proc/'+str(result['lifetimes'][-1]['pid'])+'/status'))
    return status


def over_limit(label, prior, expression):
    lines = [f"0 {prior['rule.0.version']} {uid} 4294967295 4294967295 1 0 17 3 1 * * 0 65535 0 65535 {expression}",
             f"{prior['rule.1.version']} 0 {uid} 4294967295 4294967295 100 0 17 3 1 * * 0 65535 0 65535"]
    # Let VPP allocate fresh identities so this works against an existing phone source.
    lines += [f"0 0 {uid} 4294967295 4294967295 {200+i} 0 17 3 1 * * 0 65535 0 65535" for i in range(127)]
    text='\n'.join(lines);save(label+'-request.txt',text+'\n')
    save(label+'-prefill.txt',action('--es','completeRuleText',shlex.quote(text)))
    old=config().get('queryElapsedMillis');tap(label,'Replace all rules')
    status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
    assert status['result']=='5' and status['compilerStatus']=='2' and status['saveError']=='0',status
    assert status['count']=='129' and status['activeCount']=='2',status
    assert int(status['savedRevision'])==int(prior['activeRevision'])+1
    assert status['activeRevision']==prior['activeRevision']
    source_file(label);capture(label+'-result')
    cli(label+'-resources','show product policy-index','show product rule-budget','show memory')
    save(label+'-memory.txt',root('cat /proc/'+str(result['lifetimes'][-1]['pid'])+'/status'))
    return status


def root_probe(label,status,host,delivered,winner=0,sport=32000,mode=0):
    before=query(label+'-before')
    nonce=f't10-{label}-{time.time_ns()}'
    action('--ez','debugUdpTraffic','true','--es','debugUdpHost',host,'--ei','debugUdpPort','40609',
        '--ei','debugUdpSourcePort',str(sport),'--es','debugUdpNonce',nonce,'--ez','debugUdpExpectReply','true',
        '--ei','debugUdpTimeoutMillis','1000','--ez','debugTrafficBindToVpn','false')
    end=time.monotonic()+10
    while time.monotonic()<end:
        probe=app('files/debug/udp-traffic-probe.properties')
        if props(probe).get('nonce')==nonce:break
        time.sleep(.1)
    else:raise RuntimeError('UDP probe deadline')
    save(label+'-probe.properties',probe)
    assert (props(probe)['result']=='udp_echo_matched')==delivered,probe
    queried=query(label)
    assert queried['winnerVersion']==status[f'rule.{winner}.version'] and queried['winnerRevision']==status['activeRevision'],queried
    assert int(queried['winnerAction'])==(2 if winner==0 else 1),queried
    assert int(queried['logicalHits'])==int(before['logicalHits'])+1,queried
    assert int(queried['actualDrops'])==int(before['actualDrops'])+int(not delivered),queried
    endpoint=save(label+'-endpoint.txt',root('cat '+temporary+'/endpoint.log')) if host=='127.0.0.2' else None
    assert (nonce in (endpoint if endpoint is not None else lan_records))==delivered
    result['cases'].append(dict(phase=label,profile='root',family=4,nonce=nonce,delivered=delivered,
        rule_version=int(status[f'rule.{winner}.version']),revision=int(status['activeRevision']),
        saved_revision=int(queried['savedRevision']),generation=result['lifetimes'][-1]['generation'],
        lifetime='root',query=label+'-query.properties',before=label+'-before-query.properties',mode=mode,source_port=sport,destination_port=40609,
        uid=uid,declared_action=2 if winner==0 else 1,probe=label+'-probe.properties',host=host,
        endpoint=label+'-endpoint.txt' if endpoint is not None else 'lan-endpoint.json',source_file=label+'-source.conf'))


def vpn_probe(label,status,delivered,winner=0,sport=42001,mode=0):
    before=query(label+'-before')
    nonce='t10-'+label+'-'+str(time.time_ns())
    save(label+'-send.txt',action('--es','s237ProbeNonce',nonce,'--ei','s237SourcePort',str(sport),
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
    query_winner=status[f'rule.{winner}.version']
    assert queried['winnerVersion']==query_winner and queried['winnerRevision']==status['activeRevision'],queried
    assert int(queried['winnerAction'])==(2 if winner==0 else 1),queried
    assert int(queried['logicalHits'])==int(before['logicalHits'])+1,queried
    assert int(queried['actualDrops'])==int(before['actualDrops'])+int(not delivered),queried
    assert (nonce+':0' in lan_records)==delivered
    result['cases'].append(dict(phase=label,profile='vpn',family=4,nonce=nonce,delivered=delivered,
        rule_version=int(status[f'rule.{winner}.version']),revision=int(status['activeRevision']),saved_revision=int(queried['savedRevision']),
        generation=result['lifetimes'][-1]['generation'],lifetime='vpn',query=label+'-query.properties',before=label+'-before-query.properties',mode=mode,uid=uid,declared_action=2 if winner==0 else 1,source_port=sport,destination_port=40609,
        probe=label+'-probe.properties',host='192.168.4.5',source_file=label+'-source.conf'))

try:
    before=state();assert before.get('state')=='stopped' and before.get('mayBeActive')=='false',before
    assert digest(build['apk'])==build['apk_sha256']
    save('install.txt',adb('install','-r',*(['-d'] if args.allow_downgrade else []),build['apk'],timeout=60))
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
    temporary=adb('shell','mktemp','-d','/data/local/tmp/t02.XXXXXX').strip();assert re.fullmatch(r'/data/local/tmp/t02\.[A-Za-z0-9]+',temporary)
    adb('push',output/'echo',temporary+'/echo');adb('shell','chmod','755',temporary+'/echo')
    endpoint_pid=root('nohup '+temporary+'/echo 40609 127.0.0.2 ::1 >'+temporary+'/endpoint.log 2>&1 </dev/null & echo $!').strip();assert endpoint_pid.isdigit()
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
        status=start(profile,profile)
        first=32000 if profile=='root' else 42000
        exact=(first+1).to_bytes(2,'little').hex()*2
        large=(first+1).to_bytes(2,'little').hex()+'feff'
        fallback=first.to_bytes(2,'little').hex()*2
        for operator,expression in [
            ('direct','0b'+exact+'0c0100feff01'),
            ('factorized','0b'+large+'0c0100feff01'),
            ('residual','0b'+fallback+'03'),
            ('observe','0b'+large+'0c0100feff01')]:
            phase=profile+'-'+operator
            status=submit(phase,status,expression,operator=='observe')
            for sport in [first,first+1]:
                label=phase+'-'+str(sport)
                matched=sport==first+1; winner=0 if matched else 1
                mode=int(operator=='observe' and matched)
                delivered=not matched or bool(mode)
                source_file(label)
                if profile=='root':root_probe(label,status,'127.0.0.2',delivered,winner,sport,mode)
                else:vpn_probe(label,status,delivered,winner,sport,mode)
            if operator=='factorized':
                old_status=status.copy(); failed=profile+'-over-limit'
                status=over_limit(failed,status,expression)
                for sport in [first,first+1]:
                    label=failed+'-'+str(sport); matched=sport==first+1
                    # Traffic must still bind to the previous active source, not saved edits.
                    (output/(label+'-source.conf')).write_bytes((output/(phase+'-source.conf')).read_bytes())
                    if profile=='root':root_probe(label,old_status,'127.0.0.2',not matched,0 if matched else 1,sport)
                    else:vpn_probe(label,old_status,not matched,0 if matched else 1,sport)
                result.setdefault('failures',[]).append(dict(profile=profile,active_source=phase+'-source.conf',
                    saved_source=failed+'-source.conf',apply=failed+'-apply.properties',
                    resources=failed+'-resources.txt',old_resources=phase+'-resources.txt'))
        source_file(profile+'-final');stop(profile,profile)
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
print('T10 Pixel direct/factor/residual/compile-limit Root and VPN collected')
