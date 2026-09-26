#!/usr/bin/env python3
"""Physical Android Product pipeline E01, isolated history and serial device work."""
import argparse,hashlib,importlib.util,json,re,shlex,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];PKG='com.sakamoto.snort.androidruntime'
p=argparse.ArgumentParser();p.add_argument('--serial-from',type=Path,required=True);p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--endpoint',default='192.168.4.5');p.add_argument('--arms',default='A,B,C,C,B,A,G,F,D');p.add_argument('--profile',choices=['root','vpn'],default='root');p.add_argument('--seed-baselines',type=int,default=0);p.add_argument('--skip-install',action='store_true');a=p.parse_args()
serial=json.loads(a.serial_from.read_text())['serial'];b=json.loads(a.build.read_text());out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);current=out
digest=lambda x:hashlib.sha256(Path(x).read_bytes()).hexdigest();tag=hashlib.sha256(str(out).encode()).hexdigest()[:7]
result={'status':'HOLD','kind':'android','serial':serial,'profile':a.profile,'build':str(a.build.resolve()),'build_sha256':digest(a.build),'source_sha256':b['source_sha256'],'started_ns':time.time_ns(),'arms':[]}
(out/'runner.py').write_bytes(Path(__file__).read_bytes())
(out/'e01_store_seed.py').write_bytes((ROOT/'tests/evidence/e01_store_seed.py').read_bytes())
def save(name,value):
    (current/name).write_text(value if isinstance(value,str) else json.dumps(value,indent=2)+'\n');return value
def adb(*args,check=True,timeout=45):
    start=time.time_ns();r=subprocess.run([str(ROOT/'dev/adb'),'-s',serial,*map(str,args)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    with (out/'operations.jsonl').open('a') as f:f.write(json.dumps({'start_ns':start,'end_ns':time.time_ns(),'argv':list(map(str,args)),'code':r.returncode})+'\n')
    if check and r.returncode:raise RuntimeError(r.stdout)
    return r.stdout.replace('\r','')
def root(command,check=True):return adb('shell','su','-c',shlex.quote(command),check=check)
def app(path,check=True):return adb('shell','run-as',PKG,'cat',path,check=check)
def props(t):return dict(l.split('=',1) for l in t.splitlines() if '=' in l and not l.startswith('#'))
def action(*args):return adb('shell','am','start','-n',PKG+'/.DebugControlActivity',*args)
def state(wanted):
    until=time.monotonic()+40
    while time.monotonic()<until:
        text=app('files/runtime-state/snapshot.properties');v=props(text)
        if v.get('state')==wanted:save(wanted+'.properties',text);return v
        assert v.get('errorCode')!='root_authorization_required','KernelSU grant required'
        time.sleep(.2)
    raise RuntimeError('state deadline: '+str(v))
def wait_json(path,label,predicate=lambda x:True,timeout=160):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        text=app(path,check=False)
        try:v=json.loads(text)
        except json.JSONDecodeError:v=None
        if v is not None and predicate(v):save(label+'.json',v);return v
        time.sleep(.15)
    raise RuntimeError('JSON deadline '+label)
def observation(label,operation=0):
    q='e01q-'+str(time.time_ns());action('--es','observationNonce',q,'--ei','observationOperation',operation)
    v=wait_json('files/product-state/observation-'+q+'.json',label)
    assert 'error' not in v and v['health']['generation']==generation,v
    return v
def phase(name):
    v=wait_json('files/product-state/t12-'+nonce+'.json',name,lambda x:x.get('phase')==name or bool(x.get('error')))
    assert not v.get('error'),v
    return v
def release(name):adb('shell','run-as',PKG,'touch','files/product-state/t12-release-'+nonce+'-'+name)
def write_app(local,dest):
    temporary='/data/local/tmp/e01-'+tag+'-'+local.name
    adb('push',local,temporary);adb('shell','run-as',PKG,'cp',temporary,dest);adb('shell','rm','-f',temporary)
spec=importlib.util.spec_from_file_location('e01target',ROOT/'tests/device/s233-fail-open.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.SERIAL=serial
target=object.__new__(module.Target);target.pixel=True
base='/data/user/0/'+PKG+'/files/profiles/'+a.profile+'/vpp'
def cli(label,*commands):return save(label+'.txt',target.cli(base+'/runtime',list(commands)))
def proc(pid,label):
    text=root('cat '+f'/proc/{pid}/stat /proc/{pid}/status /proc/{pid}/io /proc/{pid}/task/*/stat /proc/{pid}/task/*/status')
    save(label+'.txt',text)
    stats=[]
    for line in text.splitlines():
        m=re.match(r'^(\d+) \((.*?)\) (.*)$',line)
        if m:
            fields=m[3].split();stats.append({'tid':int(m[1]),'name':m[2],'cpu_ticks':int(fields[11])+int(fields[12])})
    first=text.split('Name:',1)[1].split('Name:',1)[0]
    fields={l.split(':',1)[0]:l.split(':',1)[1].strip() for l in first.splitlines() if ':' in l}
    threads={}
    for block in text.split('Name:')[2:]:
        values={l.split(':',1)[0]:l.split(':',1)[1].strip() for l in block.splitlines() if ':' in l}
        if 'Pid' in values:threads[values['Pid']]={'name':block.splitlines()[0].strip(),'voluntary':int(values['voluntary_ctxt_switches']),'involuntary':int(values['nonvoluntary_ctxt_switches'])}
    return {'pid':pid,'at_host_ns':time.time_ns(),'stats':stats,'fields':fields,'threads':threads}
def resources(label):return {'vpp':proc(vpp_pid,label+'-vpp'),'rust':proc(app_pid,label+'-rust'),'ticks_per_second':100}
endpoint=capture=None;device_capture=None;capture_dir=None;started=False;config_path='files/observation/overall.e01';created_stores=[]
capture_name='e01-cap-'+tag;previous_power=None
try:
    before=props(app('files/runtime-state/snapshot.properties'));assert before.get('state')=='stopped' and before.get('mayBeActive')=='false',before
    original=app('files/observation/overall.json');save('original-history.json',original);result['original_history_sha256']=hashlib.sha256(original.encode()).hexdigest()
    assert digest(b['apk'])==b['apk_sha256']
    if not a.skip_install:save('install.txt',adb('install','-r',b['apk'],timeout=90))
    assert 'uid=0' in save('root-grant.txt',adb('shell','run-as',PKG,'su','-c','id',check=False)),'restore KernelSU grant'
    package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package)[1]+'/lib/arm64'
    installed=save('installed-native.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(b['native_sha256'])]))
    assert {Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()}==b['native_sha256']
    assert save('installed-apk.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==b['apk_sha256']
    result['apk_sha256']=b['apk_sha256'];result['native_sha256']=b['native_sha256']
    save('environment.txt',adb('shell','getprop','ro.product.device')+adb('shell','uname','-a'))
    result['clock_ticks']=int(save('clock-ticks.txt',adb('shell','getconf','CLK_TCK')).strip());assert result['clock_ticks']==100
    save('battery-before.txt',adb('shell','dumpsys','battery'));save('thermal-before.txt',adb('shell','dumpsys','thermalservice'))
    previous_power=adb('shell','settings','get','global','stay_on_while_plugged_in').strip();adb('shell','settings','put','global','stay_on_while_plugged_in','3')
    peer=ROOT/'tests/device/helpers/e01_udp_peer.py';save('udp-peer.py',peer.read_text())
    endpoint=subprocess.Popen(['python3','-u',str(peer),'server','--host',a.endpoint],stdout=(out/'endpoint.jsonl').open('w'),stderr=(out/'endpoint.log').open('w'))
    time.sleep(.3);assert endpoint.poll() is None
    capture=subprocess.Popen(['docker','run','--rm','--name',capture_name,'--network','host','--cap-add','NET_RAW','--cap-add','NET_ADMIN','--mount','type=bind,source='+str(out)+',target=/evidence','sakamoto-vpp-nfq-poc:dev','tcpdump','-U','-i','any','-s','160','-w','/evidence/host.pcap','host '+a.endpoint],stdout=(out/'host-capture.log').open('w'),stderr=subprocess.STDOUT)
    capture_dir=root('mktemp -d /data/local/tmp/e01-cap.XXXXXX').strip();assert capture_dir.startswith('/data/local/tmp/e01-cap.')
    device_capture=int(root("/system/bin/tcpdump -U -i any -s 160 -w "+capture_dir+"/wire.pcap 'host "+a.endpoint+"' >"+capture_dir+'/capture.log 2>&1 & echo $!').strip());time.sleep(.3)
    for index,arm in enumerate(a.arms.split(',')):
        assert arm in ('A','B','C','G','F','D');current=out/f'{index:02d}-{arm}';current.mkdir()
        config={'arm':arm,'store':arm not in ('A','B'),'drain':16 if arm=='D' else 128,'name':f'pixel-{tag}-{index}','growth':128 if arm=='G' else 32,'flush':250000 if arm=='F' else 1000000,'export':arm!='A'}
        save('config.json',config);write_app(current/'config.json',config_path)
        experimental='files/observation/e01-'+config['name'];created_stores.append(experimental)
        if a.seed_baselines:
            seed_spec=importlib.util.spec_from_file_location('seed',ROOT/'tests/evidence/e01_store_seed.py');seed=importlib.util.module_from_spec(seed_spec);seed_spec.loader.exec_module(seed)
            seed.write(current/'synthetic-seed.json',a.seed_baselines)
            write_app(current/'synthetic-seed.json',experimental+'.json')
        started=True
        action(*(['--ez','debugVpnHevValidation','true'] if a.profile=='vpn' else ['--ez','runtimeStart','true','--es','runtimeProfile','root']))
        running=state('running');generation=int(running['generation']);assert running['profile']==a.profile
        text=save('processes.txt',root('ps -A -o PID,UID,ARGS'))
        pids=[int(parts[0]) for l in text.splitlines() if len(parts:=l.split(None,2))==3 and parts[0].isdigit() and Path(parts[2].split()[0]).name=='libvpp_runtime.so'];assert len(pids)==1
        vpp_pid=pids[0];app_pid=int(adb('shell','pidof',PKG+':runtime').strip())
        life={'capture_start_device_ns':int(adb('shell','date','+%s%N').strip()),'synthetic_seed_baselines':a.seed_baselines,'generation':generation,'config':config,'vpp_pid':vpp_pid,'app_pid':app_pid,'phases':[]};result['arms'].append(life)
        cli('configure',f"product e01 observation export {int(config['export'])} growth {config['growth']} flush {config['flush']}",'product packet-trace limit 0')
        baseline=observation('baseline');assert sum(c['basic_packets'][0] for c in baseline['health']['channels'])==0
        assert baseline['consumer']['store_error'] is None
        nonce='e01-'+tag+'-'+str(index)+'-'+str(time.time_ns());plan={'nonce':nonce,'endpoint':a.endpoint,'port':42141,'source':43000,'mode':'udp','bindDefault':a.profile=='root','e01':True};save('plan.json',plan)
        action('--es','t12ProbePlan',shlex.quote(json.dumps(plan)));phase('e01_ready')
        previous='e01_ready'
        for name in ('idle','low','burst','sustained','active','short','pause'):
            if name=='pause':observation('pause-control',1)
            observation(name+'-before')
            if name in ('idle','low','burst'):adb('shell','input','keyevent','HOME')
            save(name+'-activity-before.txt',adb('shell','dumpsys','activity','activities'))
            before_resources=resources(name+'-before');release(previous);row=phase('e01_'+name);after_resources=resources(name+'-after')
            save(name+'-resources.json',{'before':before_resources,'after':after_resources})
            save(name+'-activity-after.txt',adb('shell','dumpsys','activity','activities'))
            if config['store']:save(name+'-background-store.json',app(experimental+'.json'))
            immediate=observation(name+'-immediate')
            if name=='pause':observation('resume-control',2)
            time.sleep(1.3);settled=observation(name+'-settled')
            life['phases'].append({'name':name,'sent':row['e01']['sent'],'received':row['e01']['received'],'startedMonoNs':row['e01']['startedMonoNs'],'completedMonoNs':row['e01']['completedMonoNs']});previous='e01_'+name
        release(previous);phase('finished');observation('final')
        life['capture_end_device_ns']=int(adb('shell','date','+%s%N').strip())
        cli('runtime','show runtime','show product completion','show product observation')
        save('vpp.log',app('files/profiles/'+a.profile+'/vpp/logs/vpp-stdout.log'))
        action('--ez','runtimeStop','true');state('stopped');started=False
        assert root('test ! -d /proc/'+str(vpp_pid)+' && echo absent').strip()=='absent';life['process_absent']=True
        if config['store']:save('final-store.json',app(experimental+'.json'))
        adb('shell','am','force-stop',PKG);time.sleep(.3)
        life['status']='RAW_COMPLETE';print(json.dumps({'arm':arm,'index':index,'status':'RAW_COMPLETE','generation':generation}),flush=True)
    result['status']='RAW_COMPLETE'
except Exception as e:result['error']=repr(e);raise
finally:
    if started:
        action('--ez','runtimeStop','true')
        try:state('stopped')
        except Exception as e:result['cleanup_error']=repr(e)
    current=out
    if device_capture:
        root('kill -INT '+str(device_capture),check=False);time.sleep(.3)
        save('device-capture.log',root('cat '+capture_dir+'/capture.log',check=False));root('chmod 644 '+capture_dir+'/wire.pcap');root('chmod 755 '+capture_dir);adb('pull',capture_dir+'/wire.pcap',out/'device.pcap');root('rm -f '+capture_dir+'/wire.pcap '+capture_dir+'/capture.log; rmdir '+capture_dir)
    if capture:
        if capture.poll() is None:subprocess.run(['docker','kill','--signal','INT',capture_name],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=True)
        capture.wait(timeout=10)
    if endpoint:endpoint.terminate();endpoint.wait(timeout=5)
    adb('shell','am','force-stop',PKG,check=False)
    if previous_power is not None:adb('shell','settings','put','global','stay_on_while_plugged_in',previous_power)
    for path in created_stores:
        save(Path(path).name+'-cleanup-store.txt',app(path+'.json',check=False))
        adb('shell','run-as',PKG,'rm','-f',path+'.json',path+'.pending',path+'.lock',check=False)
    adb('shell','run-as',PKG,'rm','-f',config_path,check=False)
    final_history=save('final-history.json',app('files/observation/overall.json'));result['final_history_sha256']=hashlib.sha256(final_history.encode()).hexdigest()
    result['history_preserved']=result.get('original_history_sha256')==result['final_history_sha256']
    save('battery-after.txt',adb('shell','dumpsys','battery'));save('thermal-after.txt',adb('shell','dumpsys','thermalservice'))
    result['completed_ns']=time.time_ns();result['files']={str(f.relative_to(out)):digest(f) for f in out.rglob('*') if f.is_file()};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
