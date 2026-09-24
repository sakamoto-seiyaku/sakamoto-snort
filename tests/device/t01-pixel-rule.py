#!/usr/bin/env python3
"""T01 Root: UI controls, real application UDP, API identities and native evidence."""
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
result = dict(status='HOLD', profile='root', source='NFQ_CAPTURED', serial=SERIAL,
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
    tree=capture(label+'-before')
    nodes=[n for n in tree.iter('node') if n.get('text')==text and n.get('enabled')=='true']
    assert len(nodes)==1,(text,len(nodes))
    numbers=list(map(int,re.findall(r'\d+',nodes[0].get('bounds'))))
    x,y=(numbers[0]+numbers[2])//2,(numbers[1]+numbers[3])//2
    adb('shell','input','tap',x,y)
def config(): return props(app('files/product-state/rule-config.properties'))
def wait_config(label, predicate):
    end=time.monotonic()+10
    while time.monotonic()<end:
        text=app('files/product-state/rule-config.properties',check=False);value=props(text)
        if predicate(value):save(label+'.properties',text);return value
        time.sleep(.1)
    raise RuntimeError('config deadline '+str(value))

# Reuse the audited prompt-before-command diagnostic transport, never a policy writer.
spec=importlib.util.spec_from_file_location('t01_target',ROOT/'tests/device/s233-fail-open.py')
target_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(target_module)
target=object.__new__(target_module.Target);target.pixel=True
def cli(label,*commands):return save(label+'.txt',target.cli(BASE+'/runtime',list(commands)))

endpoint_pid=None;temporary=None;started=False
previous_power=adb('shell','settings','get','global','stay_on_while_plugged_in').strip()
try:
    before=state();assert before.get('state')=='stopped' and before.get('mayBeActive')=='false',before
    assert digest(build['apk'])==build['apk_sha256']
    save('install.txt',adb('install','-r',build['apk'],timeout=60))
    package=save('package.txt',adb('shell','dumpsys','package',PKG))
    native=re.search(r'codePath=(\S+)',package)[1]+'/lib/arm64'
    installed=save('installed-native.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(build['native_sha256'])]))
    assert {Path(line.split()[1]).name:line.split()[0] for line in installed.splitlines()}==build['native_sha256']
    installed_apk=save('installed-apk.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk'))
    assert installed_apk.split()[0]==build['apk_sha256']
    uid=int(adb('shell','run-as',PKG,'id','-u').strip());result['uid']=uid
    save('device.txt',adb('shell','getprop','ro.product.device')+adb('shell','uname','-a'))
    save('before-source.conf',app('files/rule-configuration/rules.conf',check=False))
    compiler=Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang')
    helper_source=ROOT/'tests/device/helpers/s207-echo.c'
    subprocess.run([str(compiler),'-O2','-Wall','-Wextra','-Werror',str(helper_source),'-o',str(output/'echo')],check=True)
    save('echo.c',helper_source.read_text())
    result['endpoint_build']=dict(source_sha256=digest(helper_source),binary_sha256=digest(output/'echo'),compiler_sha256=digest(compiler))
    temporary=adb('shell','mktemp','-d','/data/local/tmp/t01.XXXXXX').strip()
    assert re.fullmatch(r'/data/local/tmp/t01\.[A-Za-z0-9]+',temporary)
    adb('push',output/'echo',temporary+'/echo');adb('shell','chmod','755',temporary+'/echo')
    endpoint_pid=root('nohup '+temporary+'/echo 40608 127.0.0.2 >'+temporary+'/endpoint.log 2>&1 </dev/null & echo $!').strip()
    assert endpoint_pid.isdigit()
    save('endpoint-start.txt',root('cat '+temporary+'/endpoint.log'))
    adb('shell','settings','put','global','stay_on_while_plugged_in','3')
    adb('shell','input','keyevent','224');adb('shell','wm','dismiss-keyguard')
    adb('shell','am','start','-n',PKG+'/.DebugControlActivity')
    tap('start','Start');started=True
    running=wait_state('running','running')
    assert running['profile']=='root' and running['protectionRunning']=='true'
    result['generation']=int(running['generation'])
    processes=save('processes-running.txt',root('ps -A -o PID,UID,ARGS'))
    candidates=[int(parts[0]) for line in processes.splitlines()
                if len(parts:=line.split(None,2))==3 and parts[0].isdigit()
                and parts[1]=='0' and Path(parts[2].split()[0]).name=='libvpp_runtime.so']
    assert len(candidates)==1,candidates
    pid=candidates[0];result['pid']=pid
    assert save('process-exe.txt',root('readlink /proc/'+str(pid)+'/exe')).strip()==native+'/libvpp_runtime.so'
    save('process-command.txt',root('cat /proc/'+str(pid)+'/cmdline'))
    save('owner.properties',app('files/profiles/root/vpp/owner.properties'))
    save('startup.conf',app('files/profiles/root/vpp/startup.conf'))
    save('hooks.txt',root('iptables-save -t mangle'))
    cli('startup','product packet-trace limit 4096','show product root lanes','show threads')
    initial=config();assert initial['transportCode']==initial['result']=='0',initial
    initial_revision=int(initial['savedRevision'])
    tap('empty','Clear')
    empty=wait_config('empty',lambda c:int(c.get('savedRevision','0'))>initial_revision and c.get('present')=='0')
    assert empty['savedRevision']==empty['activeRevision'] and empty['activeRuleVersion']=='0'
    revision=int(empty['savedRevision']);version=None
    for phase,button,action in [('allow','Allow UDP',1),('drop','Drop UDP',2),('recover','Allow UDP',1)]:
        tap(phase,button)
        status=wait_config(phase+'-apply',lambda c:int(c.get('savedRevision','0'))==revision+1)
        revision+=1
        assert status['savedRevision']==status['activeRevision'] and status['result']=='0',status
        assert int(status['uid'])==uid and int(status['action'])==action
        current=int(status['savedRuleVersion']);assert current>>16 and current&65535
        if version is not None:assert current==version+1
        version=current
        nonce='t01-'+phase+'-'+str(time.time_ns())
        adb('shell','am','start','-n',PKG+'/.DebugControlActivity',
            '--ez','debugUdpTraffic','true','--es','debugUdpHost','127.0.0.2',
            '--ei','debugUdpPort','40608','--ei','debugUdpSourcePort','32000',
            '--es','debugUdpNonce',nonce,'--ez','debugUdpExpectReply','true',
            '--ei','debugUdpTimeoutMillis','1000','--ez','debugTrafficBindToVpn','false')
        end=time.monotonic()+10
        while time.monotonic()<end:
            probe=app('files/debug/udp-traffic-probe.properties')
            if props(probe).get('nonce')==nonce:break
            time.sleep(.1)
        else:raise RuntimeError('UDP probe deadline')
        save(phase+'-probe.properties',probe)
        assert (props(probe)['result']=='udp_echo_matched')==(action==1),probe
        before_query=config()['queryElapsedMillis']
        tap(phase+'-query','Query')
        queried=wait_config(phase+'-query',lambda c:c.get('queryElapsedMillis')!=before_query)
        assert int(queried['winnerVersion'])==version and int(queried['winnerRevision'])==revision,queried
        assert int(queried['winnerAction'])==action,queried
        endpoint=save(phase+'-endpoint.txt',root('cat '+temporary+'/endpoint.log'))
        assert (nonce in endpoint)==(action==1)
        save(phase+'-source.conf',app('files/rule-configuration/rules.conf'))
        save(phase+'-vpp.log',app('files/profiles/root/vpp/logs/vpp-stdout.log'))
        capture(phase+'-result')
        result['cases'].append(dict(phase=phase,nonce=nonce,delivered=action==1,revision=revision,rule_version=version))
    save('source-owner.txt',adb('shell','run-as',PKG,'stat','-c','%u:%g:%a','files/rule-configuration/rules.conf'))
    cli('before-stop','show product completion','show product root lanes','show product flows')
    tap('stop','Stop');stopped=wait_state('stopped','stopped');started=False
    assert stopped['mayBeActive']=='false' and stopped['protectionRunning']=='false'
    save('stop-vpp.log',app('files/product-state/s242-last-stop.log'))
    save('hooks-after.txt',root('iptables-save -t mangle'))
    save('queues-after.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
    save('processes-after.txt',root('ps -A -o PID,UID,ARGS'))
    assert root('test ! -d /proc/'+str(pid)+' && echo absent').strip()=='absent'
    result['process_absent']=True
    result['status']='RAW_COMPLETE'
except Exception as error:
    result['error']=repr(error)
    raise
finally:
    if started:
        adb('shell','am','start','-n',PKG+'/.DebugControlActivity','--ez','runtimeStop','true',check=False)
        try:wait_state('cleanup-stopped','stopped')
        except Exception as error:result['cleanup_error']=repr(error)
    if endpoint_pid and temporary:
        root('test "$(readlink /proc/'+endpoint_pid+'/exe)" = '+temporary+'/echo && kill '+endpoint_pid,check=False)
        root('rm -f '+temporary+'/echo '+temporary+'/endpoint.log; rmdir '+temporary,check=False)
    adb('shell','settings','put','global','stay_on_while_plugged_in',previous_power,check=False)
    result['completed_ns']=time.time_ns()
    save('result.json',json.dumps(result,indent=2)+'\n')
print('T01 Pixel UI/API/UDP chain complete')
