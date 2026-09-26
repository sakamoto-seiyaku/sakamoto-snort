#!/usr/bin/env python3
"""Real NFQUEUE/VPP pipeline cost experiment; no synthetic queue producer."""
import argparse,hashlib,importlib.util,json,os,select,sqlite3,subprocess,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--stage',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--arms',default='A,B,C,C,B,A,G,F,D');p.add_argument('--seed-baselines',type=int,default=0);p.add_argument('--phases',default='idle,low,burst,sustained,active,short,pause,recovery');p.add_argument('--fault',action='store_true');p.add_argument('--sqlite',action='store_true');a=p.parse_args()
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
b=json.loads(a.build.read_text());artifact=Path(b['artifact']);digest=lambda x:hashlib.sha256(Path(x).read_bytes()).hexdigest()
for n,h in b['artifact_hashes'].items():assert digest(artifact/n)==h,n
env=dict(os.environ,LD_LIBRARY_PATH=str(artifact/'lib'));tag=hashlib.sha256(str(out).encode()).hexdigest()[:7]
vppctl=a.stage.resolve()/'source/build-root/install-vpp-native/vpp/bin/vppctl';peer=ROOT/'tests/device/helpers/e01_udp_peer.py'
result={'status':'HOLD','storage_format':'sqlite' if a.sqlite else 'atomic_json_snapshot','kind':'linux','build':str(a.build.resolve()),'build_sha256':digest(a.build),'source_sha256':b['source_sha256'],'started_ns':time.time_ns(),'arms':[]}
for f in [Path(__file__),peer,ROOT/'tests/evidence/e01_store_seed.py',ROOT/'tests/evidence/e02_sqlite.py']: (out/f.name).write_bytes(f.read_bytes())
def save(name,value):
    target=current/name;target.write_text(value if isinstance(value,str) else json.dumps(value,indent=2)+'\n');return value
def cmd(*args,check=True):
    r=subprocess.run(list(map(str,args)),env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
    if check and r.returncode:raise RuntimeError(r.stdout)
    return r.stdout
buffers={}
def line(child,timeout=90):
    until=time.monotonic()+timeout
    data=buffers.pop(child.pid,b'')
    while time.monotonic()<until:
        if b'\n' in data:
            answer,remaining=data.split(b'\n',1);buffers[child.pid]=remaining;return answer.decode()
        if select.select([child.stdout],[],[],.05)[0]:
            x=os.read(child.stdout.fileno(),65536)
            if not x:raise RuntimeError('child closed: '+data.decode())
            data+=x
    raise RuntimeError('child deadline')
def cli(label,text):return save(label+'.txt',cmd(vppctl,'-s',runtime/'cli.sock',text))
def query(label=None):
    global query_clock
    started=time.monotonic_ns()
    observer.stdin.write(b'query\n');observer.stdin.flush();s=line(observer)
    assert s.startswith('observation.response='),s
    v=json.loads(s.split('=',1)[1]);assert 'error' not in v and v['health']['generation']==generation,v
    query_clock={'started_mono_ns':started,'completed_mono_ns':time.monotonic_ns()}
    if label:
        save(label+'.json',v)
        if a.sqlite:save(label+'-query-clock.json',query_clock)
    return v
def control(text):
    observer.stdin.write((text+'\n').encode());observer.stdin.flush();return line(observer)
def proc(pid):
    root=Path('/proc')/str(pid);stat=(root/'stat').read_text().rsplit(')',1)[1].split();status=(root/'status').read_text()
    def fields(text):return {l.split(':',1)[0]:l.split(':',1)[1].strip() for l in text.splitlines() if ':' in l}
    threads={}
    for task in (root/'task').iterdir():
        try:
            ts=(task/'stat').read_text().rsplit(')',1)[1].split();ss=fields((task/'status').read_text())
            threads[task.name]={'name':ss['Name'],'cpu_ticks':int(ts[11])+int(ts[12]),'voluntary':int(ss['voluntary_ctxt_switches']),'involuntary':int(ss['nonvoluntary_ctxt_switches'])}
        except FileNotFoundError:pass
    return {'at_mono_ns':time.monotonic_ns(),'pid':pid,'cpu_ticks':int(stat[11])+int(stat[12]),'status':fields(status),'io':fields((root/'io').read_text()),'threads':threads}
def sample():return {'vpp':proc(process.pid),'rust':proc(observer.pid),'clock_ticks':os.sysconf('SC_CLK_TCK')}
def stop(child):
    if child and child.poll() is None:
        child.terminate()
        try:child.wait(timeout=5)
        except subprocess.TimeoutExpired:child.kill();child.wait()
def snapshot_total(v):return sum(v['consumer']['overview']['packets'])
def settle(label):
    until=time.monotonic()+8
    while True:
        v=query();h=v['health'];normal=[h['channels'][i] for i in (0,2)]
        consumer=v['consumer']
        work_done=(not consumer['persistent'] or consumer['e01']['records']>=consumer['overview']['accepted'])
        if config['export'] and not any(c['full'] for c in normal):
            target=sum(c['basic_packets'][0] for c in normal)
            work_done=work_done and sum(consumer['overview']['packets'])==target
            if consumer['persistent'] and not consumer['store_error']:
                work_done=work_done and sum(consumer['persistent']['packets'])==target
        persistent=consumer['persistent']
        if a.sqlite and persistent and persistent['save_error'] is None:
            progress=persistent['persistence']
            work_done=work_done and not progress['pending'] and not progress['maintenance_pending'] and progress['packets']==persistent['packets']
        if all(c['occupancy']==0 for c in normal) and work_done:
            if not a.sqlite:time.sleep(.05);v=query()
            break
        if time.monotonic()>until:break
        time.sleep(.02)
    if a.sqlite:save(label+'-query-clock.json',query_clock)
    return save(label+'.json',v)
process=observer=client=server=capture=None;blocker=None;current=out;hooks=[];dummy_created=False;loopback_was_up=None
try:
    assert os.getuid()==0
    current_netns=os.readlink('/proc/self/ns/net')
    assert os.environ.get('E01_HOST_NETNS') and current_netns!=os.environ['E01_HOST_NETNS'],'explicit isolated network namespace required'
    links=json.loads(cmd('ip','-j','link','show'))
    assert [link['ifname'] for link in links]==['lo'],'isolated namespace must initially contain only loopback'
    loopback_was_up='UP' in links[0]['flags']
    result['network_namespace']={'host':os.environ['E01_HOST_NETNS'],'experiment':current_netns,'initial_links':links}
    save('environment.txt',cmd('uname','-a')+cmd('id')+'netns='+os.readlink('/proc/self/ns/net')+'\n')
    cmd('ip','link','set','lo','up');cmd('ip','link','add','e01dummy','type','dummy');dummy_created=True
    for addr in ('10.224.0.1/24','10.224.0.2/24'):cmd('ip','addr','add',addr,'dev','e01dummy')
    cmd('ip','link','set','e01dummy','up')
    server=subprocess.Popen(['python3','-u',str(peer),'server','--host','10.224.0.2'],stdout=(out/'endpoint.jsonl').open('w'),stderr=(out/'endpoint.log').open('w'),user=12002,group=12002,extra_groups=[])
    time.sleep(.2);assert server.poll() is None
    capture=subprocess.Popen(['tcpdump','-U','-i','any','-s','160','-w',str(out/'wire.pcap'),'udp port 42141'],stdout=(out/'capture.log').open('w'),stderr=subprocess.STDOUT)
    for index,arm in enumerate(a.arms.split(',')):
        assert arm in ('A','B','C','G','F','D')
        current=out/f'{index:02d}-{arm}';current.mkdir();generation=27400+index
        config={'arm':arm,'store':arm not in ('A','B'),'drain':16 if arm=='D' else 128,'name':f'linux-{tag}-{index}','growth':128 if arm=='G' else 32,'flush':250000 if arm=='F' else 1000000,'export':arm!='A'}
        life={'generation':generation,'config':config,'phases':[],'storage_fault':a.fault};result['arms'].append(life)
        runtime=ROOT/('build-output/product-vpp-runtime-e01-'+tag+'-'+str(index))
        store=current/'observation/overall.json';store.parent.mkdir();store.with_suffix('.e01').write_text(json.dumps(config))
        native_config=store.with_suffix('.e01-native');native_config.write_text(f"{int(config['export'])} {config['growth']} {config['flush']}\n")
        if a.seed_baselines:
            spec=importlib.util.spec_from_file_location('seed',ROOT/'tests/evidence/e01_store_seed.py');seed=importlib.util.module_from_spec(spec);spec.loader.exec_module(seed)
            seed_file=store.with_name('e01-'+config['name']+'.json')
            life['synthetic_seed_baselines']=a.seed_baselines;life['seed_bytes']=seed.write(seed_file,a.seed_baselines)
            life['seed_sha256']=digest(seed_file);life['expected_snapshot_guard']=not a.sqlite and life['seed_bytes']>32*1024*1024
            (current/'synthetic-seed.json').write_bytes(seed_file.read_bytes())
        launch=dict(env,SAKAMOTO_E01_CONFIG=str(native_config),PRODUCT_ARTIFACT_DIR=str(artifact),PRODUCT_RUNTIME_DIR=str(runtime),PRODUCT_RULE_CONFIG_DIR=str(current/'configuration'),PRODUCT_GENERATION=str(generation),PRODUCT_WORKER_COUNT='2',SAKAMOTO_RUNTIME_PROFILE='root',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',SAKAMOTO_LINUX_NETWORK_SOURCE='external')
        process=subprocess.Popen(['bash',str(ROOT/'tools/product/run-host-vpp.sh')],env=launch,stdout=(current/'vpp.log').open('w'),stderr=subprocess.STDOUT)
        until=time.monotonic()+30
        while not (runtime/'api.sock.obs').exists():
            assert process.poll() is None and time.monotonic()<until,'VPP startup';time.sleep(.05)
        configured=cli('configure','product e01 observation show')
        assert f"e01.export={int(config['export'])} growth={config['growth']} flush_us={config['flush']}" in configured,'applied E01 producer config'
        cli('trace','product packet-trace limit 0')
        save('configuration.txt',cmd(artifact/'bin/sakamoto-product-core-host','rule-export',runtime/'api.sock',generation))
        observer=subprocess.Popen([str(artifact/'bin/sakamoto-product-core-host'),'observation-serve',str(runtime/'api.sock'),str(generation),str(store)],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(current/'rust.log').open('w'),bufsize=0)
        open_started=time.monotonic_ns()
        while not line(observer).startswith('observation.ready='):pass
        life['consumer_ready_wait_ns']=time.monotonic_ns()-open_started
        life.update(vpp_pid=process.pid,rust_pid=observer.pid)
        baseline=query('baseline');assert sum(c['basic_packets'][0] for c in baseline['health']['channels'])==0
        if a.sqlite:
            spec=importlib.util.spec_from_file_location('sqlite_evidence',ROOT/'tests/evidence/e02_sqlite.py');sqlite_evidence=importlib.util.module_from_spec(spec);spec.loader.exec_module(sqlite_evidence)
            database=store.with_name('e01-'+config['name']+'.sqlite3')
            save('startup-resources.json',sample());save('startup-space.json',sqlite_evidence.footprint(database,store.with_name('e01-'+config['name']+'.json')))

        for flag in ('--dport','--sport'):
            hook=['iptables','-t','mangle','-A','OUTPUT','-p','udp',flag,'42141','-j','NFQUEUE','--queue-num','176'];cmd(*hook);hooks.append(hook)
        client=subprocess.Popen(['python3','-u',str(peer),'client','--host','10.224.0.1','--peer','10.224.0.2','--nonce',f'e01-{tag}-{index}'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(current/'client.log').open('w'),bufsize=0,user=12001,group=12001,extra_groups=[])
        assert json.loads(line(client))['ready']
        for name in a.phases.split(','):
            if name=='pause':save('pause-control.txt',control('pause'))
            fault_path=store.with_name('e01-'+config['name']+'.pending')
            if a.fault and name=='burst':
                if a.sqlite:
                    blocker=sqlite3.connect(database);blocker.execute('BEGIN IMMEDIATE')
                    save('lock-injected.json',{'collector_pid':os.getpid(),'at_mono_ns':time.monotonic_ns()})
                else:fault_path.mkdir()
            before=query(name+'-before');metrics_before=sample();start=time.monotonic_ns()
            client.stdin.write((name+'\n').encode());client.stdin.flush();traffic=json.loads(line(client,120));end=time.monotonic_ns()
            metrics_after=sample();save(name+'-traffic.json',traffic)
            measured=query(name+'-immediate');save(name+'-resources.json',{'before':metrics_before,'after':metrics_after})
            if name=='pause':save('resume-control.txt',control('resume'))
            time.sleep(1.2);after=settle(name+'-settled')
            save(name+'-resources-settled.json',sample())
            if a.sqlite:save(name+'-space.json',sqlite_evidence.footprint(database,store.with_name('e01-'+config['name']+'.json')))
            if a.fault and name=='burst':
                if a.sqlite:
                    blocker.rollback();blocker.close();blocker=None
                    save('lock-released.json',{'at_mono_ns':time.monotonic_ns()})
                else:fault_path.rmdir()
            life['phases'].append({'name':name,'started_ns':start,'completed_ns':end,'sent':traffic['sent'],'received':traffic['received']})
        # The ordinary API supplies visibility; polling overhead is retained.
        before=query('freshness-before');want=snapshot_total(before)+2
        client.stdin.write(b'freshness\n');client.stdin.flush();traffic=json.loads(line(client));save('freshness-traffic.json',traffic)
        polls=[];until=time.monotonic()+5
        if config['export']:
            while time.monotonic()<until:
                poll_label='freshness-poll-'+str(len(polls))
                v=query(poll_label if a.sqlite else None);now=time.monotonic_ns();visible=snapshot_total(v)
                persistent=v['consumer']['persistent']
                durable=sum(persistent['persistence']['packets'] if a.sqlite else persistent['packets']) if persistent else None
                polls.append({'query_completed_mono_ns':now,'overview_packets':visible,'persistent_packets':durable,**({'label':poll_label,'live_packets':sum(persistent['packets']),'pending':persistent['persistence']['pending'],'maintenance_pending':persistent['persistence']['maintenance_pending']} if a.sqlite and persistent else {})})
                if visible>=want and (not config['store'] or (durable is not None and durable>=want and (not a.sqlite or (not persistent['persistence']['pending'] and not persistent['persistence']['maintenance_pending'])))):break
                time.sleep(.02)
        save('freshness-polls.json',{'target':want,'poll_interval_seconds':.02,'polls':polls})
        cli('runtime','show runtime');cli('completion','show product completion');cli('observation','show product observation')
        query('final');save('final-resources.json',sample())
        observer.stdin.write(b'quit\n');observer.stdin.flush();observer.wait(timeout=10);observer=None
        for hook in hooks:hook[3]='-D';cmd(*hook)
        hooks=[];stop(client);client=None
        cli('stop','product root stop');stop(process);life['process_absent']=not Path('/proc',str(process.pid)).exists();process=None
        final=store.with_name('e01-'+config['name']+'.json')
        if a.sqlite:
            save('final-store.json',sqlite_evidence.closed_state(database))
            save('final-space.json',sqlite_evidence.footprint(database,final))
        elif final.exists():save('final-store.json',json.loads(final.read_text()))
        life['status']='RAW_COMPLETE'
        print(json.dumps({'arm':arm,'index':index,'status':'RAW_COMPLETE'}),flush=True)
    result['status']='RAW_COMPLETE'
except Exception as e:result['error']=repr(e);raise
finally:
    cleanup_errors=[]
    def cleanup(label, operation):
        try:return operation()
        except Exception as error:
            cleanup_errors.append({'step':label,'error':repr(error)})
            return None
    try:
        if blocker:
            cleanup('release-store-lock',blocker.rollback);cleanup('close-store-lock',blocker.close)
        for hook in hooks:
            hook[3]='-D';cleanup('remove-owned-hook',lambda hook=hook:cmd(*hook))
        cleanup('stop-client',lambda:stop(client));cleanup('stop-observer',lambda:stop(observer))
        if process and process.poll() is None:
            cleanup('stop-adapter',lambda:cli('cleanup-stop','product root stop'))
            cleanup('stop-vpp',lambda:stop(process))
        cleanup('stop-endpoint',lambda:stop(server))
        if capture and capture.poll() is None:
            cleanup('stop-capture',lambda:capture.send_signal(2))
            cleanup('await-capture',lambda:capture.wait(timeout=10))
        if dummy_created:cleanup('remove-owned-interface',lambda:cmd('ip','link','del','e01dummy'))
        if loopback_was_up is False:cleanup('restore-loopback',lambda:cmd('ip','link','set','lo','down'))
    finally:
        result['cleanup_errors']=cleanup_errors
        if cleanup_errors:result['status']='HOLD'
        result['completed_ns']=time.time_ns();result['files']={}
        for file in out.rglob('*'):
            if file.is_file():
                value=cleanup('seal-'+str(file.relative_to(out)),lambda file=file:digest(file))
                if value is not None:result['files'][str(file.relative_to(out))]=value
        if cleanup_errors:result['status']='HOLD'
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
