#!/usr/bin/env python3
"""T29: QUIC domain and RTP protocol rules in one Root/VPN runtime."""
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
p.add_argument('--quic-fixtures',type=Path,required=True)
p.add_argument('--python',default='python3')
p.add_argument('--skip-install',action='store_true')
p.add_argument('--cost-extra-rules',type=int,default=0)
p.add_argument('--cost-extra-domains',type=int,default=0)

args = p.parse_args()
assert 0 <= args.cost_extra_rules <= 120
assert 0 <= args.cost_extra_domains <= 120

SERIAL = args.serial or (json.loads(args.serial_from.read_text())['serial'] if args.serial_from else None) or subprocess.check_output([str(ROOT/'dev/adb'),'get-serialno'],text=True).strip()
assert SERIAL and SERIAL != 'unknown'
build_path, output = args.build.resolve(), args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
build = json.loads(build_path.read_text())
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(name, text): (output/name).write_text(text); return text
def props(text): return dict(line.split('=',1) for line in text.splitlines() if '=' in line and not line.startswith('#'))
result = dict(status='HOLD', task='T29', profile='root', source='NFQ_CAPTURED+TUN_ORIGIN', serial=SERIAL,
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
def ordinary_hashes(label):
    values={}
    for path in ('files/observation/overall.sqlite3','files/observation/overall.json'):
        read=subprocess.run([str(ROOT/'dev/adb'),'-s',SERIAL,'exec-out','run-as',PKG,'cat',path],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,check=True)
        values[path]=hashlib.sha256(read.stdout).hexdigest()
    save(label+'-ordinary-hashes.json',json.dumps(values,indent=2)+'\n')
    return values
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
    for attempt in range(16):
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


endpoint=None;endpoint_log=None;quic_endpoint=None;quic_endpoint_log=None
started=False;current_profile=None;held=None;quic_held=None
capture_name='t29-combined-'+hashlib.sha256(str(output).encode()).hexdigest()[:12]
host_capture=None;device_capture_pid=None;capture_dir=None
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
def configure(label,prior,protocol,target_id,mode=1):
    expression='0d020f'+target_id.to_bytes(4,'little').hex()+'01'
    versions=[prior.get(f'rule.{i}.version','0') for i in range(4)]
    lines=[f'0 {versions[0]} 4294967295 4294967295 4294967295 10 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}',
           f'0 {versions[1]} 4294967295 4294967295 4294967295 20 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}03',
           f'0 {versions[2]} {uid} 4294967295 4294967295 100 0 {protocol} 0 1 * * 0 65535 0 65535',
           f'0 {versions[3]} 4294967295 4294967295 4294967295 5 0 17 0 2 * * 0 65535 0 65535 1100',
           'lists 1','domain 0 exact example.test',
           'group 10','edge 10 1 0','group 20','edge 20 1 1',
           f'bind 1 {uid} 2 10 {mode}',f'bind 2 {uid} 2 20 1',f'bind 3 {uid} 1 3 1']
    if args.cost_extra_rules:
        lines += ['group 30']
        for i in range(args.cost_extra_rules):
            version=prior.get(f'rule.{i+4}.version','0')
            port=60000+i
            lines += [f'0 {version} 4294967295 4294967295 4294967295 1 0 17 0 1 * * 0 65535 {port} {port}',
                      f'edge 30 1 {i+4}']
        lines += [f'bind 4 {uid} 2 30 1']
    for i in range(args.cost_extra_domains):
        lines += [f'domain 0 exact cost-{i:03d}.example.test']
    text='\n'.join(lines);save(label+'-request.txt',text+'\n')
    save(label+'-prefill.txt',action('--es','completeRuleText',shlex.quote(text)))
    old=config().get('queryElapsedMillis');begun=time.monotonic_ns();tap(label,'Replace all rules')
    status=wait_config(label+'-apply',lambda c:c.get('queryElapsedMillis') not in (None,old))
    with (output/'cost-operations.jsonl').open('a') as f:
        f.write(json.dumps(dict(label=label,operation='replace-all-ui',started_ns=begun,
                                completed_ns=time.monotonic_ns()))+'\n')
    assert status['result']=='0' and status['savedRevision']==status['activeRevision'],status
    expected=str(4+args.cost_extra_rules)
    assert status['effectiveRules']==expected and status['activeCount']==expected,status
    cli(label+'-resources','show product rule-budget','show product policy-index','show product flows')
    source_file(label)
    result.setdefault('configurations',[]).append(dict(label=label,profile=result['lifetimes'][-1]['profile'],
        revision=int(status['activeRevision']),source=label+'-source.conf',query=label+'-apply.properties',
        expression=expression,mode=mode,protocol=protocol,target=target_id,
        quic_domain='example.test',quic_rule_mode='observe'))
    return status

def clear_configuration(label,prior):
    nonce='t29-clear-'+str(time.time_ns())
    document=dict(format='sakamoto-config-v1',rules=[],groups=[],edges=[],bindings=[],lists=[])
    save(label+'-input.json',json.dumps(document,indent=2)+'\n')
    temporary='/data/local/tmp/'+nonce+'.json'
    destination='files/product-import/'+nonce+'.json'
    response='files/product-state/rule-import-'+nonce+'.json'
    try:
        adb('push',output/(label+'-input.json'),temporary)
        adb('shell','run-as',PKG,'mkdir','-p','files/product-import')
        adb('shell','run-as',PKG,'cp',temporary,destination)
        action('--es','ruleImportNonce',nonce,'--ei','ruleOperation',1,
               '--el','expectedSavedRevision',int(prior['savedRevision']))
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            text=app(response,check=False)
            try:value=json.loads(text)
            except json.JSONDecodeError:value=None
            if value is not None:break
            time.sleep(.1)
        else:raise RuntimeError('clear response deadline')
        save(label+'-reply.json',text)
        assert value['stage']=='vpp' and value['result']==0 and value['configuration']==document,value
        assert value['saved_revision']==value['active_revision'],value
        result.setdefault('cleared_profiles',[]).append(result['lifetimes'][-1]['profile'])
        return value
    finally:
        adb('shell','rm','-f',temporary,check=False)
        adb('shell','run-as',PKG,'rm','-f',destination,response,check=False)

def launch(label,profile,protocol,source):
    global held
    fixtures=json.loads(args.fixtures.read_text())
    fixture=next(f for f in fixtures['sessions'] if '-'+profile+'-' in f['nonce'])
    nonce=fixture['nonce']
    application='rtp_udp'
    helper_spec=importlib.util.spec_from_file_location('r4_peer',ROOT/'tests/device/helpers/r4_realtime_peer.py')
    helper=importlib.util.module_from_spec(helper_spec);helper_spec.loader.exec_module(helper)
    w=helper.workload(application,nonce)
    plan=dict(nonce=nonce,endpoint=args.endpoint,port=5004,source=source,mode=protocol,
              bindDefault=profile=='root',r4Protocol=application,
              realtime=dict(first=w['first'].hex(),firstReply=helper.stun(nonce,99,True).hex(),
                            requests=[x.hex() for x in w['requests']],replies=[x.hex() for x in w['replies']]))
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

def launch_quic(label,profile,source):
    global quic_held
    fixtures=json.loads(args.quic_fixtures.read_text())
    fixture=fixtures['cases']['named']
    nonce='t29-'+profile+'-quic-'+fixtures['nonce']
    plan=dict(nonce=nonce,endpoint=args.endpoint,port=40650,source=source,mode='udp',
              bindDefault=profile=='root',t16Sequence=fixture['sequence'],rawInitial=False,
              assemblyTimeout=False,initialBlocked=False,policyBlocked=False,domainChecks=False,
              preludeHex=fixtures['preludeHex'],preludeReplyHex=fixtures['preludeReplyHex'])
    assert re.fullmatch(r'[a-zA-Z0-9_-]{1,80}',nonce)
    check=('for f in files/product-state/t12-'+nonce+'.json '
           'files/product-state/t12-release-'+nonce+'-*; do '
           'if [ -e "$f" ]; then echo used; exit 0; fi; done; echo fresh')
    assert save(label+'-nonce-check.txt',adb('shell','run-as',PKG,'sh','-c',shlex.quote(check))).strip()=='fresh'
    save(label+'-launch.txt',action('--es','t12ProbePlan',shlex.quote(json.dumps(plan))))
    case=dict(label=label,profile=profile,nonce=nonce,port=source,protocol='udp',application='quic_named',
              plan=plan,generation=result['lifetimes'][-1]['generation'],started_ns=time.time_ns())
    result.setdefault('quic_sessions',[]).append(case);quic_held=case
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

def capacity_rejection(profile,source):
    nonce='t29-cap-'+profile+'-'+str(time.time_ns())
    plan=dict(nonce=nonce,endpoint=args.endpoint,port=5004,source=source,
              mode='udp',bindDefault=profile=='root')
    save(profile+'-capacity-request.txt',action('--es','t12ProbePlan',shlex.quote(json.dumps(plan))))
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        text=app('files/product-state/t12-'+nonce+'.json',check=False)
        try:value=json.loads(text)
        except json.JSONDecodeError:value={}
        if value.get('nonce')==nonce and value.get('phase')=='finished':
            save(profile+'-capacity-result.json',text)
            assert value.get('error')=='protocol_probe_capacity',value
            result.setdefault('capacity_rejections',[]).append(dict(profile=profile,nonce=nonce,
                error=value['error'],result=profile+'-capacity-result.json'))
            action()  # The rejected headless intent must not cache the two active probes.
            return
        time.sleep(.1)
    raise RuntimeError('third probe did not report bounded capacity')

def evidence(case,status,phase_name):
    label=case['label']+'-'+phase_name
    query(label);cli(label+'-flow','show product flows')
    result['cases'].append(dict(label=label,client=case['label'],profile=case['profile'],protocol=case['protocol'],
        port=case['port'],nonce=case['nonce'],phase=phase_name,application=case['application'],revision=int(status['activeRevision']),
        query=label+'-query.properties',flow=label+'-flow.txt',generation=case['generation']))

def sni_query(label,identity):
    nonce='t29-sni-'+str(time.time_ns())
    save(label+'-sni-action.txt',action('--es','sniNonce',nonce,'--ei','sniWorker',identity[0],
       '--ei','sniSlot',identity[1],'--el','sniIncarnation',int(identity[2])))
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        text=app('files/product-state/t13-sni-'+nonce+'.properties',check=False)
        value=props(text)
        if 'code' in value:
            save(label+'-sni.properties',text)
            assert value['code']=='0' and value['result']=='1' and value['name']=='example.test',value
            return value
        time.sleep(.1)
    raise RuntimeError('typed SNI query deadline')

def evidence_quic(case,status,phase_name):
    label=case['label']+'-'+phase_name
    query(label)
    text=cli(label+'-flow','show product flows')
    rows=[dict(item.split('=',1) for item in line.split()[1:] if '=' in item)
          for line in text.splitlines() if line.startswith('flow.entry ')]
    row=next(r for r in rows if str(case['port']) in (r['port_a'],r['port_b']))
    identity=[row['worker'],row['slot'],row['incarnation']]
    sni_query(label,identity)
    result.setdefault('quic_cases',[]).append(dict(label=label,profile=case['profile'],nonce=case['nonce'],
        port=case['port'],revision=int(status['activeRevision']),query=label+'-query.properties',
        flow=label+'-flow.txt',sni=label+'-sni.properties',identity=identity,generation=case['generation']))

def dashboard(label,worker,slot):
    def raw(suffix,cursor):
        nonce='t29-dash-'+str(time.time_ns())
        response='files/product-state/observation-'+nonce+'.json'
        action('--es','observationNonce',nonce,'--ei','observationOperation',0,
               '--ei','observationCursor',cursor)
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            text=app(response,check=False)
            try:value=json.loads(text)
            except json.JSONDecodeError:value=None
            if value is not None:break
            time.sleep(.1)
        else:raise RuntimeError('dashboard deadline')
        save(label+suffix+'-dashboard.json',text)
        adb('shell','run-as',PKG,'rm','-f',response,check=False)
        assert 'error' not in value and value['runtime']['profile']==current_profile,value
        assert value['vpp']['generation']==result['lifetimes'][-1]['generation']
        assert value['current_flows']['count']<=16 and value['current_flows']['scanned']<=256
        return value
    first=raw('',0)
    cursor=worker*first['current_flows']['capacity'][0]+slot
    selected=raw('-selected',cursor)
    entries=selected['current_flows']['entries']
    assert any(row['worker']==worker and row['slot']==slot for row in entries),entries
    action();tap(label+'-health','Query health and flows')
    deadline=time.monotonic()+20;projection='';xml=''
    while time.monotonic()<deadline:
        adb('shell','uiautomator','dump','/sdcard/t29-dashboard.xml',timeout=20)
        xml=adb('shell','cat','/sdcard/t29-dashboard.xml')
        for node in ET.fromstring(xml).iter('node'):
            if node.get('content-desc')=='Health and flow result':projection=node.get('text','')
        if projection.startswith('Runtime / VPP / Rust health'):break
        adb('shell','input','swipe','500','1600','500','900','240')
        time.sleep(.2)
    assert projection.startswith('Runtime / VPP / Rust health'),projection
    assert 'Current flows:' in projection and 'Rust store:' in projection
    assert current_profile in projection and str(selected['vpp']['policy_active_revision']) in projection
    save(label+'-ui.xml',xml)
    screenshot=subprocess.run([str(ROOT/'dev/adb'),'-s',SERIAL,'exec-out','screencap','-p'],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35,check=True)
    (output/(label+'-ui.png')).write_bytes(screenshot.stdout)
    result.setdefault('ui_dashboard',[]).append(dict(label=label,profile=current_profile,
        generation=result['lifetimes'][-1]['generation'],cursor=cursor,
        selected=label+'-selected-dashboard.json',xml=label+'-ui.xml',image=label+'-ui.png',
        projection=projection))
    return selected

try:
    before=state();assert before.get('state')=='stopped' and before.get('mayBeActive')=='false',before
    ordinary_before=ordinary_hashes('before')
    assert 'No such file' in app('files/observation/t27-test.enabled',check=False)
    assert digest(build['apk'])==build['apk_sha256']
    if not args.skip_install:save('install.txt',adb('install','-r',build['apk'],timeout=60))
    assert 'uid=0' in save('root-grant.txt',adb('shell','run-as',PKG,'su','-c','id',check=False))
    adb('shell','run-as',PKG,'rm','-rf','files/observation/t27-test')
    adb('shell','run-as',PKG,'mkdir','-p','files/observation/t27-test')
    adb('shell','run-as',PKG,'touch','files/observation/t27-test.enabled')
    package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package)[1]+'/lib/arm64'
    installed=save('installed-native.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(build['native_sha256'])]))
    assert {Path(line.split()[1]).name:line.split()[0] for line in installed.splitlines()}==build['native_sha256']
    assert save('installed-apk.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==build['apk_sha256']
    uid=int(adb('shell','run-as',PKG,'id','-u').strip());result['uid']=uid
    save('device.txt',adb('shell','getprop','ro.product.device')+adb('shell','uname','-a'))
    save('network.txt',adb('shell','ip','address'));source_file('before')
    peer=ROOT/'tests/device/helpers/r4_realtime_peer.py';save('protocol-peer.py',peer.read_text())
    result['peer_sha256']=digest(peer);result['endpoint']=args.endpoint
    quic_peer=ROOT/'tests/device/helpers/t16_quic_peer.py';save('quic-peer.py',quic_peer.read_text())
    result['quic_peer_sha256']=digest(quic_peer)
    save('fixtures.json',args.fixtures.read_text());result['fixtures_sha256']=digest(args.fixtures)
    save('quic-fixtures.json',args.quic_fixtures.read_text());result['quic_fixtures_sha256']=digest(args.quic_fixtures)
    endpoint_log=(output/'endpoint.jsonl').open('w')
    endpoint=subprocess.Popen([args.python,'-u',str(peer),'server','--host',args.endpoint,'--fixtures',str(args.fixtures.resolve()),'--applications','rtp_udp'],stdout=endpoint_log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+5
    while '"kind": "ready"' not in (output/'endpoint.jsonl').read_text():
        assert endpoint.poll() is None
        assert time.monotonic()<deadline
        time.sleep(.03)
    quic_endpoint_log=(output/'quic-endpoint.jsonl').open('w')
    quic_endpoint=subprocess.Popen([args.python,'-u',str(quic_peer),'server','--host',args.endpoint,
        '--directory',str(args.quic_fixtures.resolve().parent)],stdout=quic_endpoint_log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+5
    while '"kind": "ready"' not in (output/'quic-endpoint.jsonl').read_text():
        assert quic_endpoint.poll() is None
        assert time.monotonic()<deadline
        time.sleep(.03)
    host_capture=subprocess.Popen(['docker','run','--rm','--name',capture_name,'--network','host',
        '--cap-add','NET_RAW','--cap-add','NET_ADMIN',
        '--mount','type=bind,source='+str(output)+',target=/evidence',
        'sakamoto-vpp-nfq-poc:dev','tcpdump','-U','-i','any','-s','0','-w','/evidence/host.pcap',
        'udp port 5004 or udp port 40650'],stdout=(output/'host-capture.log').open('w'),stderr=subprocess.STDOUT)
    capture_dir=root('mktemp -d /data/local/tmp/t29-combined-capture.XXXXXX').strip()
    assert capture_dir.startswith('/data/local/tmp/t29-combined-capture.')
    device_capture_pid=int(root('/system/bin/tcpdump -U -i any -s 0 -w '+capture_dir+
        "/wire.pcap 'udp port 5004 or udp port 40650' >"+capture_dir+'/capture.log 2>&1 & echo $!').strip())
    time.sleep(.3);assert host_capture.poll() is None
    adb('shell','settings','put','global','stay_on_while_plugged_in','3')
    adb('shell','input','keyevent','224');adb('shell','wm','dismiss-keyguard')
    for profile,baseport in [('root',46310),('vpn',46410)]:
        status=start(profile,profile)
        status=configure(profile+'-combined-observe',status,17,1017)
        quic_case=launch_quic(profile+'-quic',profile,baseport+20)
        phase(quic_case,'quic_ready');evidence_quic(quic_case,status,'ready')
        # Keep the SNI/domain Flow alive while RTP facts publish and the first
        # later ruleset takes effect. Its next payload must use that revision.
        label=profile+'-rtp'
        case=launch(label,profile,'udp',baseport)
        action()  # Keep both gated diagnostic threads in a foreground app process.
        first='connected_ready';added='realtime_ready'
        phase(case,first);evidence(case,status,'first');release(case,first)
        phase(case,added);evidence(case,status,'added')
        capacity_rejection(profile,baseport+40)
        status=configure(label+'-enforce',status,17,1017,0)
        release(quic_case,'quic_ready');phase(quic_case,'budget_done')
        evidence_quic(quic_case,status,'budget')
        release(case,added);phase(case,'blocked');evidence(case,status,'blocked')
        status=configure(label+'-recover',status,17,1017)
        release(case,'blocked');phase(case,'budget_done');evidence(case,status,'budget')
        release(case,'budget_done');value=phase(case,'finished');assert not value.get('error'),value
        case['completed_ns']=time.time_ns();held=None
        release(quic_case,'budget_done');phase(quic_case,'finished')
        quic_case['completed_ns']=time.time_ns();quic_held=None
        flow_rows=[dict(word.split('=',1) for word in line.split()[1:] if '=' in word)
                   for line in (output/(label+'-budget-flow.txt')).read_text().splitlines()
                   if line.startswith('flow.entry ')]
        selected=next(row for row in flow_rows if str(baseport) in (row['port_a'],row['port_b']))
        dashboard(profile+'-combined',int(selected['worker']),int(selected['slot']))
        cli(profile+'-final','show product flows','show product completion')
        clear_configuration(profile+'-empty',status)
        stop(profile,profile)
    result['status']='RAW_COMPLETE';result['process_absent']=True
except Exception as error:
    result['error']=repr(error);raise
finally:
    if held:
        for gate in ('connected_ready','realtime_ready','blocked','budget_done'):release(held,gate)
    if quic_held:
        for gate in ('quic_ready','budget_done'):release(quic_held,gate)
    if started:
        try:
            if 'status' in locals() and status.get('savedRevision'):
                clear_configuration('failure-'+current_profile+'-empty',status)
        except Exception as error:result['cleanup_config_error']=repr(error)
        save('failure-vpp.log',app('files/profiles/'+current_profile+'/vpp/logs/vpp-stdout.log',check=False))
        action('--ez','runtimeStop','true')
        try:wait_state('cleanup-stopped','stopped')
        except Exception as error:result['cleanup_error']=repr(error)
    if endpoint:
        endpoint.terminate();endpoint.wait(timeout=3)
    if endpoint_log:endpoint_log.close()
    if quic_endpoint:
        quic_endpoint.terminate();quic_endpoint.wait(timeout=3)
    if quic_endpoint_log:quic_endpoint_log.close()
    if device_capture_pid is not None:
        root('kill -INT '+str(device_capture_pid),check=False);time.sleep(.3)
        save('device-capture.log',root('cat '+capture_dir+'/capture.log',check=False))
        root('chmod 644 '+capture_dir+'/wire.pcap; chmod 755 '+capture_dir)
        adb('pull',capture_dir+'/wire.pcap',output/'device.pcap')
        root('rm -f '+capture_dir+'/wire.pcap '+capture_dir+'/capture.log; rmdir '+capture_dir)
    if host_capture is not None:
        if host_capture.poll() is None:
            subprocess.run(['docker','kill','--signal','INT',capture_name],check=True,
                           stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        host_capture.wait(timeout=10)
    adb('shell','run-as',PKG,'rm','-f','files/observation/t27-test.enabled',check=False)
    if 'ordinary_before' in locals():
        try:result['ordinary_history_unchanged']=ordinary_hashes('after')==ordinary_before
        except Exception as error:result['ordinary_history_check_error']=repr(error)
    adb('shell','settings','put','global','stay_on_while_plugged_in',previous_power,check=False)
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
print('T29 Pixel combined QUIC domain and RTP facts collected')
