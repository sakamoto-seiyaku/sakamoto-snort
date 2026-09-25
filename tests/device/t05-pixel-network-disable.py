#!/usr/bin/env python3
"""T05: existing Android network switch controls ordinary rules in Root and VPN."""
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
def submit(label,prior,profile='root'):
    # One shared observe group and a lower ordinary allow; direct disable wins.
    lines=[]
    for i in range(2):
        base=prior.get(f'rule.{i}.version','0') if int(prior.get('count','0'))>=2 else '0'
        lines.append(f'0 {base} 4294967295 4294967295 4294967295 {10+i*10} 0 17 3 {2-i} 0.0.0.0/0 0.0.0.0/0 0 65535 40609 40609')
    lines += ['group 10','group 20','edge 10 1 0','edge 20 2 10','edge 20 1 0','edge 20 1 1',
              f'bind 1 {uid} 2 20 1',f'bind 2 {uid} 1 0 1']
    text='\n'.join(lines);save(label+'-request.txt',text+'\n')
    save(label+'-prefill.txt',action('--es','completeRuleText',shlex.quote(text)))
    old=config().get('queryElapsedMillis');tap(label,'Replace all rules')
    status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
    assert status['groupCount']=='2' and status['edgeCount']=='4' and status['bindingCount']=='2',status
    assert status['effectiveRules']=='2' and status['activeCount']=='2',status
    source_file(label);capture(label+'-result');return status

def toggle(label,prior,context,blocked):
    old=config().get('queryElapsedMillis')
    if blocked:
        save(label+'-operation.txt',action('--es','debugSetNetworkGateSubject','android.uid:'+str(uid),
            '--es','debugSetNetworkGateContext',context,'--ez','debugSetNetworkGateBlocked','true'))
    else:
        # The VPN probe is headless and finishes its Activity. Re-select the
        # target through the existing idempotent debug switch before UI input.
        save(label+'-select.txt',action('--es','debugSetNetworkGateSubject','android.uid:'+str(uid),
            '--es','debugSetNetworkGateContext',context,'--ez','debugSetNetworkGateBlocked','true'))
        selected=wait_config(label+'-select',lambda c:c.get('queryElapsedMillis') not in (None,old))
        assert selected['savedRevision']==prior['savedRevision'] and selected['rule.2.version']==prior['rule.2.version'],selected
        old=selected['queryElapsedMillis']
        tap(label,'Open '+context)
        save(label+'-operation.txt','UI tap: Open '+context+'\n')
    status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
    assert status['result']=='0' and status['savedRevision']==status['activeRevision'],status
    assert status['groupCount']=='2' and status['edgeCount']=='4' and status['bindingCount']=='2',status
    for i in range(2):assert status[f'rule.{i}.version']==prior[f'rule.{i}.version']
    assert int(status['count'])==(3 if blocked else 2),status
    source_file(label);capture(label+'-result');return status


def root_probe(label,status,host,delivered,winner=0):
    before=query(label+'-before')
    nonce=f't05-{label}-{time.time_ns()}'
    action('--ez','debugUdpTraffic','true','--es','debugUdpHost',host,'--ei','debugUdpPort','40609',
        '--ei','debugUdpSourcePort','32000','--es','debugUdpNonce',nonce,'--ez','debugUdpExpectReply','true',
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
    assert int(queried['winnerAction'])==2,queried
    assert int(queried['logicalHits'])==int(before['logicalHits'])+1,queried
    assert int(queried['actualDrops'])==int(before['actualDrops'])+int(not delivered),queried
    endpoint=save(label+'-endpoint.txt',root('cat '+temporary+'/endpoint.log')) if host=='127.0.0.2' else None
    assert (nonce in (endpoint if endpoint is not None else lan_records))==delivered
    result['cases'].append(dict(phase=label,profile='root',family=4,nonce=nonce,delivered=delivered,
        rule_version=int(status[f'rule.{winner}.version']),revision=int(status['activeRevision']),
        saved_revision=int(status['savedRevision']),generation=result['lifetimes'][-1]['generation'],
        lifetime='root',query=label+'-query.properties',before=label+'-before-query.properties',mode=int(delivered),
        uid=uid,declared_action=2,probe=label+'-probe.properties',host=host,
        endpoint=label+'-endpoint.txt' if endpoint is not None else 'lan-endpoint.json',source_file=label+'-source.conf'))


def vpn_probe(label,status,delivered,winner=0,return_drop=False):
    before=query(label+'-before')
    nonce='t05-'+label+'-'+str(time.time_ns())
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
    query_winner=status['rule.2.version'] if return_drop else status[f'rule.{winner}.version']
    assert queried['winnerVersion']==query_winner and queried['winnerRevision']==status['activeRevision'],queried
    assert int(queried['winnerAction'])==2,queried
    assert int(queried['logicalHits'])==int(before['logicalHits'])+1+int(return_drop),queried
    assert int(queried['actualDrops'])==int(before['actualDrops'])+int(not delivered),queried
    assert (nonce+':0' in lan_records)==(delivered or return_drop)
    result['cases'].append(dict(phase=label,profile='vpn',family=4,nonce=nonce,delivered=delivered,
        rule_version=int(status[f'rule.{winner}.version']),revision=int(status['activeRevision']),saved_revision=int(status['savedRevision']),
        generation=result['lifetimes'][-1]['generation'],lifetime='vpn',query=label+'-query.properties',before=label+'-before-query.properties',mode=int(delivered or return_drop),uid=uid,declared_action=2,
        return_drop=return_drop,query_winner_version=int(query_winner),
        return_rule_version=int(status['rule.2.version']) if return_drop else 0,probe=label+'-probe.properties',host='192.168.4.5',source_file=label+'-source.conf'))

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
    status=start('root','root')
    status=submit('root-shared',status);assert status['result']=='0',status
    root_probe('root-shared',status,'192.168.4.5',True)
    status=toggle('root-disabled',status,'wifi',True)
    root_probe('root-disabled',status,'192.168.4.5',False,winner=2)
    source_file('root-outside')
    root_probe('root-outside',status,'127.0.0.2',True)
    status=toggle('root-enabled',status,'wifi',False)
    root_probe('root-enabled',status,'192.168.4.5',True)
    root_source=source_file('root-final');stop('root','root')
    status=start('vpn','vpn');assert source_file('vpn-read')==root_source
    status=submit('vpn-shared',status,profile='vpn');assert status['result']=='0',status
    vpn_probe('vpn-shared',status,True)
    status=toggle('vpn-wifi-return',status,'wifi',True)
    vpn_probe('vpn-wifi-return',status,False,return_drop=True)
    status=toggle('vpn-wifi-enabled',status,'wifi',False)
    status=toggle('vpn-outside',status,'mobile',True)
    vpn_probe('vpn-outside',status,True)
    status=toggle('vpn-outside-enabled',status,'mobile',False)
    status=toggle('vpn-disabled',status,'vpn',True)
    vpn_probe('vpn-disabled',status,False,winner=2)
    status=toggle('vpn-enabled',status,'vpn',False)
    vpn_probe('vpn-enabled',status,True)
    source_file('vpn-final');stop('vpn','vpn');result['process_absent']=True;result['status']='RAW_COMPLETE'

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
print('T05 Pixel existing switch/shared observe/scoped Root/VPN packets collected')
