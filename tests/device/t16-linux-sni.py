#!/usr/bin/env python3
"""T16 QUIC v1 Initial facts through Product NFQUEUE rules and endpoint outcomes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import select
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0,str(ROOT/"tests/device/helpers"))
from t18_domain_policy import adapt as domain_policy
from t19_import_policy import document as import_document, roundtrip as import_roundtrip, failure_cases as import_failures
parser = argparse.ArgumentParser()
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--stage', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--fixtures',type=Path,required=True)
parser.add_argument('--python',default='python3')


parser.add_argument("--domain-policy",action="store_true")
parser.add_argument("--import-policy",action="store_true")
parser.add_argument("--domain-overlap",action="store_true",
                    help="hold a domain-bearing packet while two complete snapshots publish")
parser.add_argument("--persistent-helper",type=Path)
parser.add_argument("--persistent-build",type=Path)
args = parser.parse_args()
assert not args.domain_overlap or args.domain_policy
assert not args.domain_overlap or (args.persistent_helper and args.persistent_build)
assert not args.import_policy or (args.domain_policy and not args.domain_overlap)

artifact, stage, output = (p.resolve() for p in (args.artifact, args.stage, args.output))
output.mkdir(parents=True, exist_ok=False)
assert os.getuid() == 0
uid_map = Path('/proc/self/uid_map').read_text().split()
assert int(uid_map[2]) > 12002, 'two real mapped UIDs required'
env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'))
vppctl = stage/'source/build-root/install-vpp-native/vpp/bin/vppctl'
runtime_tag = hashlib.sha256(str(output).encode()).hexdigest()[:12]
runtime = ROOT/('build-output/product-vpp-runtime-'+runtime_tag)
generation = 26701
config_dir = output/'configuration'
result = dict(status='HOLD', generation=generation, profile='root', source='NFQ_CAPTURED',
              cases=[], started_ns=time.time_ns(), artifact=str(artifact),
              manifest_sha256=hashlib.sha256((artifact/'product-vpp-artifact.properties').read_bytes()).hexdigest())
build_path=args.build.resolve()
build=json.loads(build_path.read_text())
assert Path(build['artifact']) == artifact
for name, expected in build['artifact_hashes'].items():
    assert hashlib.sha256((artifact/name).read_bytes()).hexdigest()==expected,name
result.update(build=str(build_path),build_sha256=hashlib.sha256(build_path.read_bytes()).hexdigest(),
              source_sha256=build['source_sha256'],runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              policy_uids=[12001])
(output/'runner.py').write_bytes(Path(__file__).read_bytes())

def command(*argv, check=True):
    p = subprocess.run(list(map(str, argv)), env=env, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=30)
    if check and p.returncode: raise RuntimeError(p.stdout)
    return p.stdout

def save(name, text):
    (output/name).write_text(text)
    return text

def props(text):
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)

def cli(name, *commands):
    return save(name+'.txt', ''.join(command(vppctl, '-s', runtime/'cli.sock', c) for c in commands))

def api(name, operation, *values):
    text = save(name+'.txt', command(artifact/'bin/sakamoto-product-core-host', operation,
                                   runtime/'api.sock', generation, *values, check=False))
    return props(text)

def drain(name):
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        text = cli(name, 'show product completion')
        row = next(line for line in text.splitlines() if line.startswith('completion.status '))
        values = dict(item.split('=',1) for item in row.split()[1:] if '=' in item)
        if all(values[key] == '0' for key in ('pending','frames','buffers','obligations')): return
        time.sleep(.02)
    raise RuntimeError('completion drain timeout')

if args.domain_policy:
    result['domain_policy'] = True
    helper_path=ROOT/'tests/device/helpers/t18_domain_policy.py'
    result['domain_policy_sha256']=hashlib.sha256(helper_path.read_bytes()).hexdigest()
    save('domain-policy.py',helper_path.read_text())
if args.import_policy:
    result['import_policy'] = True
    helper_path=ROOT/'tests/device/helpers/t19_import_policy.py'
    result['import_policy_sha256']=hashlib.sha256(helper_path.read_bytes()).hexdigest()
    save('import-policy.py',helper_path.read_text())

save('environment.txt', command('uname','-a')+command('id')+'uid_map='+' '.join(uid_map)
     +'\nnetns='+os.readlink('/proc/self/ns/net')+'\n')
command('ip','link','set','lo','up')
launch = dict(env, PRODUCT_ARTIFACT_DIR=str(artifact), PRODUCT_RUNTIME_DIR=str(runtime),
              PRODUCT_RULE_CONFIG_DIR=str(config_dir), PRODUCT_GENERATION=str(generation),
              PRODUCT_WORKER_COUNT='2', SAKAMOTO_RUNTIME_PROFILE='root',
              SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
              SAKAMOTO_LINUX_NETWORK_SOURCE='external')

peer_source=ROOT/'tests/device/helpers/t16_quic_peer.py'
save('socket-peer.py',peer_source.read_text())
result['peer_sha256']=hashlib.sha256(peer_source.read_bytes()).hexdigest()
fixtures=json.loads(args.fixtures.read_text())
endpoint=None;endpoint_log=None
def start_endpoint():
    global endpoint,endpoint_log
    endpoint_log=(output/'endpoint.jsonl').open('w')
    endpoint=subprocess.Popen([args.python,'-u',str(peer_source),'server','--host','127.0.0.2','--directory',str(args.fixtures.resolve().parent)],
        env=env,user=12001,group=12001,extra_groups=[],stdout=endpoint_log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+5
    while '"kind": "ready"' not in (output/'endpoint.jsonl').read_text():
        assert endpoint.poll() is None
        assert time.monotonic()<deadline
        time.sleep(.02)
hooks = [['iptables','-t','mangle','-A','OUTPUT','-p',protocol,'-m','owner','--uid-owner','12001',
          flag,str(port),'-j','NFQUEUE','--queue-num','176']
         for protocol,port in [('udp',40650),('udp',40651)] for flag in ['--sport','--dport']]
clients=[]
process = None; log = None; hooked = []; persistent = None
def start(label):
    global process, log, runtime, generation
    generation = 26701 if label == "first" else 25602
    runtime = ROOT/("build-output/product-vpp-runtime-"+runtime_tag+"-"+label)
    launch.update(PRODUCT_RUNTIME_DIR=str(runtime), PRODUCT_GENERATION=str(generation))
    if args.import_policy and label == 'first':
        config_dir.mkdir(parents=True,exist_ok=False)
        invalid=b'T19 deliberately invalid source for online import repair\n'
        (config_dir/'rules.conf').write_bytes(invalid)
        (output/'startup-invalid-source.conf').write_bytes(invalid)
    log = (output/(label+'-vpp.log')).open('w')
    process = subprocess.Popen(['bash', str(ROOT/'tools/product/run-host-vpp.sh')], env=launch,
                               stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic()+20
    while not (runtime/'api.sock').exists():
        assert process.poll() is None, (output/(label+'-vpp.log')).read_text()
        assert time.monotonic() < deadline
        time.sleep(.05)
    while True:
        status = api(label+'-initial', 'rule-query')
        if status.get('query.adapter_available') == 'true': break
        if args.import_policy and status.get('config.saved_revision') == '0' and status.get('config.save_error') == '1':
            startup_import_repair()
            continue
        assert time.monotonic() < deadline, status
        time.sleep(.05)
    save(label+'-process.txt', 'pid='+str(process.pid)+'\nexe='+os.readlink(f'/proc/{process.pid}/exe')
         +'\ncmd='+Path(f'/proc/{process.pid}/cmdline').read_bytes().replace(b'\0',b' ').decode())
    cli(label+'-startup', 'product packet-trace limit 4096', 'show product root lanes', 'show threads')
    for hook in hooks: command(*hook); hooked.append(hook)
    return status

def stop(label):
    global process, log
    errors=[]
    for hook in hooked:
        removal=hook.copy();removal[3]='-D'
        try:command(*removal)
        except Exception as error:errors.append(repr(error))
    hooked.clear()
    if process is not None:
        try:
            if process.poll() is None and (runtime/'cli.sock').exists():
                drain(label+'-drain')
                assert 'root.stop=ok' in cli(label+'-stop','product root stop')
        except Exception as error:errors.append(repr(error))
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            assert not Path(f'/proc/{process.pid}').exists()
            save(label+'-stopped.txt',f'pid={process.pid}\nexit_code={process.returncode}\nabsent=True\n')
            if log is not None:log.close()
            process=None
    if errors:raise RuntimeError('runtime cleanup: '+repr(errors))

def import_call(label, document, expected):
    input_name = label+'-import-input.json' if document is not None else None
    if document is not None:
        save(input_name,json.dumps(document,ensure_ascii=False,indent=2)+'\n')
        response=api(label+'-import-transport','rule-import',expected,output/input_name)
    else:
        response=api(label+'-import-transport','rule-export')
    raw=response['import.response']; parsed=json.loads(raw)
    reply_name=label+'-import-reply.json';save(reply_name,raw+'\n')
    result.setdefault('imports',[]).append(dict(label=label,profile='root',generation=generation,
        expected_revision=expected,input=input_name,reply=reply_name,
        input_sha256=hashlib.sha256((output/input_name).read_bytes()).hexdigest() if input_name else None,
        reply_sha256=hashlib.sha256((output/reply_name).read_bytes()).hexdigest()))
    return parsed

def import_save_failure(call):
    held=config_dir.with_name(config_dir.name+'-t19-held')
    config_dir.rename(held)
    try:return call()
    finally:held.rename(config_dir)

def startup_import_repair():
    empty=dict(format='sakamoto-config-v1',rules=[],groups=[],edges=[],bindings=[],lists=[])
    queried=import_call('t19-startup-export',None,0)
    assert queried['stage']=='vpp' and queried['result']==0,queried
    assert queried['configuration'] is None and queried['export_error']
    bad=dict(empty,groups=[1],edges=[[1,1,0]])
    rejected=import_call('t19-startup-reference',bad,0)
    assert rejected['stage']=='vpp' and rejected['result']==10,rejected
    assert rejected['configuration'] is None and rejected['save_error']==1 and rejected['compile_error']==0
    failed=import_save_failure(lambda:import_call('t19-startup-save-failure',empty,0))
    assert failed['stage']=='vpp' and failed['result']==failed['save_error']==3,failed
    assert failed['compile_error']==0 and failed['saved_revision']==failed['active_revision']==0
    repaired=import_call('t19-startup-repair',empty,0)
    assert repaired['result']==repaired['save_error']==repaired['compile_error']==0
    assert repaired['saved_revision']==repaired['active_revision']==1
    assert repaired['configuration']==empty
    result['startup_import_repair']=True

def submit(label, prior, lines):
    request=output/(label+'-request.txt');request.write_text('\n'.join(lines)+'\n')
    if args.import_policy:
        imported=import_call(label,import_document(lines),int(prior['config.saved_revision']))
        assert imported['stage']=='vpp' and imported['result']==0,imported
        imported=import_roundtrip(import_call,label,imported)
        if not result.get('import_failures_checked'):
            imported=import_failures(import_call,'t19-root-failures',imported,import_save_failure)
            result['import_failures_checked']=True
        status=api(label+'-apply','rule-query')
        assert int(status['config.saved_revision'])==imported['saved_revision']
    else:
        status=api(label+'-apply','rule-replace-all',prior['config.saved_revision'],request)
    (output/(label+'-source.conf')).write_bytes((config_dir/'rules.conf').read_bytes())
    return status

def configure(label, prior, protocol, target, mode=1, variant="full"):
    expression='1001'
    versions=[prior.get(f'config.rule.{i}.version','0') for i in range(3)]
    lines=[f'0 {versions[0]} 4294967295 4294967295 4294967295 10 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}',
           f'0 {versions[1]} 4294967295 4294967295 4294967295 20 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}03',
           f'0 {versions[2]} 12001 4294967295 4294967295 100 0 {protocol} 0 1 * * 0 65535 0 65535',
           'group 10','edge 10 1 0','group 20','edge 20 1 1',
           f'bind 1 12001 2 10 {mode}',f'bind 2 12001 2 20 {mode}']
    if args.domain_policy: lines=domain_policy(lines,variant)
    status=submit(label,prior,lines)
    assert status['config.result']=='0' and status['config.saved_revision']==status['config.active_revision'],status
    result.setdefault('configurations',[]).append(dict(label=label,revision=int(status['config.active_revision']),
        source=label+'-source.conf',query=label+'-apply.txt',expression=expression,domain_variant=variant if args.domain_policy else None,mode=mode,protocol=protocol,target=target))
    return status

class Client:
    def __init__(self,label,mode,port):
        self.label,self.protocol,self.port=label,'udp',port
        self.mode=mode;self.nonce='t16-linux-'+mode+'-'+fixtures['nonce']
        self.process=subprocess.Popen([args.python,'-u',str(peer_source),'client','--host','127.0.0.2',
            '--mode',mode,'--source',str(port),'--nonce',self.nonce,'--directory',str(args.fixtures.resolve().parent)],
            env=env,user=12001,group=12001,extra_groups=[],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,text=True,bufsize=1)
        self.events=[];clients.append(self)
        assert self.read()['kind']=='quic_ready'
    def read(self):
        assert select.select([self.process.stdout],[],[],20)[0], 'client response deadline'
        line=self.process.stdout.readline();assert line,line
        value=json.loads(line);self.events.append(value)
        save(self.label+'-client.json',json.dumps(self.events,indent=2));return value
    def execute(self,operation,wanted):
        self.process.stdin.write(json.dumps(dict(op=operation,timeout=1 if wanted=='timeout' else 10))+'\n')
        self.process.stdin.flush();answer=self.read();assert answer['kind']==wanted,answer;return answer
    def capture(self,label,status,phase):
        drain(label+'-drain');api(label+'-query','rule-query')
        text=cli(label+'-flow','show product flows')
        rows=[dict(item.split('=',1) for item in line.split()[1:] if '=' in item)
              for line in text.splitlines() if line.startswith('flow.entry ')]
        row=next(r for r in rows if str(self.port) in (r['port_a'],r['port_b']))
        identity=[row['worker'],row['slot'],row['incarnation']]
        facts=api(label+'-sni','sni-query',*identity)
        assert facts.get('sni.code')=='0',facts
        fixture=fixtures['cases'][self.mode]
        assert facts['sni.result']==str(fixture['result']) and facts['sni.stop']==str(fixture['stop']),facts
        assert facts['sni.name']==fixture['name'],facts
        stale=api(label+'-stale','sni-query',identity[0],identity[1],int(identity[2])+100000)
        assert stale.get('sni.code')!='0'
        result['cases'].append(dict(label=label,client=self.label,protocol='udp',port=self.port,nonce=self.nonce,
            phase=phase,mode=self.mode,revision=int(status['config.active_revision']),query=label+'-query.txt',
            flow=label+'-flow.txt',sni=label+'-sni.txt',identity=identity,generation=generation))
    def close(self):
        if self.process.poll() is None:self.execute('close','closed');self.process.wait(timeout=5)
        assert self.process.returncode==0

try:
    start_endpoint()
    result['fixtures_sha256']=hashlib.sha256(args.fixtures.read_bytes()).hexdigest()
    save('fixtures.json',args.fixtures.read_text())
    status=start('first')
    if args.domain_overlap:
        modes=()
    elif args.domain_policy:
        modes=('named','named_child','named_boundary','named_suffix','named_alabel','absent','conflict','named_cutoff')
    else:
        modes=('named','absent','conflict','ranges','offset','timeout','packets','named_cutoff','absent_cutoff')
    for index,mode in enumerate(modes):
        cutoff=mode.endswith('_cutoff')
        status=configure(mode+'-initial-policy',status,17,1004,0 if cutoff else 1)
        client=Client(mode,mode,45620+index)
        client.capture(mode+'-ready',status,'ready')
        if not cutoff and (mode.startswith('named') or mode=='absent'):
            if args.domain_policy:
                status=configure(mode+'-list-only',status,17,1004,1,'without-exact')
                client.execute('echo','received');client.capture(mode+'-changed',status,'changed')
            status=configure(mode+'-enforce',status,17,1004,0)
            client.execute('blocked','timeout');client.capture(mode+'-blocked',status,'blocked')
            status=configure(mode+'-recover',status,17,1004,1)
        elif cutoff:status=configure(mode+'-recover',status,17,1004,1)
        client.execute('echo','received');client.capture(mode+'-recovered',status,'recovered')
        client.close()
    if args.domain_overlap:
        status=configure('overlap-initial',status,17,1004,1)
        old_revision=int(status['config.active_revision'])
        old_winner=int(status['config.rule.0.version'])
        client=Client('overlap','named',45620)
        client.capture('overlap-ready',status,'ready')
        owner=int(result['cases'][-1]['identity'][0])
        helper=args.persistent_helper.resolve()
        persistent_build=args.persistent_build.resolve()
        persistent_witness=json.loads(persistent_build.read_text())
        assert Path(persistent_witness['binary'])==helper
        assert Path(persistent_witness['artifact'])==artifact
        assert persistent_witness['binary_sha256']==hashlib.sha256(helper.read_bytes()).hexdigest()
        assert persistent_witness['artifact_manifest_sha256']==result['manifest_sha256']
        result['persistent_build']=str(persistent_build)
        result['persistent_build_sha256']=hashlib.sha256(persistent_build.read_bytes()).hexdigest()
        result['persistent_helper_sha256']=hashlib.sha256(helper.read_bytes()).hexdigest()
        result['persistent_helper_source_sha256']=hashlib.sha256(
            (ROOT/'tests/device/helpers/t18_persistent_config.c').read_bytes()).hexdigest()
        (output/'persistent-helper').write_bytes(helper.read_bytes())
        save('persistent-helper.c',(ROOT/'tests/device/helpers/t18_persistent_config.c').read_text())
        persistent=subprocess.Popen([str(helper),str(runtime/'api.sock'),str(generation)],
                                    env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,text=True,bufsize=1)
        def reply():
            assert select.select([persistent.stdout],[],[],5)[0], 'persistent reply deadline'
            line=persistent.stdout.readline();assert line,line
            return line
        assert reply().startswith('ready revision='+str(old_revision)+' ')
        def persistent_apply(command,label,variant):
            persistent.stdin.write(command+'\n');persistent.stdin.flush()
            line=reply()
            assert line.startswith('applied '),line
            values=dict(word.split('=',1) for word in line.split()[1:])
            assert values['result']=='0' and values['saved']==values['revision'],values
            save(label+'-apply.txt',line)
            (output/(label+'-source.conf')).write_bytes((config_dir/'rules.conf').read_bytes())
            revision=int(values['revision'])
            result['configurations'].append(dict(label=label,revision=revision,
                source=label+'-source.conf',query=label+'-apply.txt',expression='1001',
                domain_variant=variant,mode=1,protocol=17,target=1004,persistent=True))
            return revision
        log_path=output/'first-vpp.log'
        before=len(log_path.read_bytes())
        assert 'policy.hold=armed' in cli('overlap-arm',f'product policy hold-next {owner} 500000')
        errors=[]
        def held_packet():
            try: client.execute('echo','received')
            except Exception as error: errors.append(repr(error))
        held=threading.Thread(target=held_packet)
        held.start()
        deadline=time.monotonic()+4
        while 's209 event=hold_begin' not in log_path.read_bytes()[before:].decode(errors='replace'):
            assert time.monotonic()<deadline, 'domain packet did not reach the held reader'
            time.sleep(.001)
        answer={}
        def publish_changed_list():
            try: answer['middle']=persistent_apply('without-exact','overlap-without-exact','without-exact')
            except Exception as error: errors.append(repr(error))
        writer=threading.Thread(target=publish_changed_list)
        writer.start()
        writer.join(timeout=.35)
        assert not writer.is_alive() and not errors, 'changed list did not publish during held read'
        assert 's209 event=hold_end' not in log_path.read_bytes()[before:].decode(errors='replace')
        middle_revision=answer['middle']
        assert middle_revision==old_revision+1
        def reuse_bank():
            try: answer['final']=persistent_apply('full','overlap-restore','full')
            except Exception as error: errors.append(repr(error))
        reuse=threading.Thread(target=reuse_bank)
        reuse.start()
        time.sleep(.03)
        assert reuse.is_alive() and not errors, 'retired bank reused during held read'
        held.join(timeout=5);reuse.join(timeout=5)
        assert not held.is_alive() and not reuse.is_alive() and not errors,errors
        assert answer['final']==middle_revision+1
        status=api('overlap-final-query','rule-query')
        assert int(status['config.active_revision'])==answer['final']
        client.execute('echo','received')
        client.capture('overlap-restored',status,'recovered')
        client.close()
        result['overlap']=dict(owner=owner,old_revision=old_revision,
                               middle_revision=middle_revision,
                               final_revision=int(status['config.active_revision']),
                               old_winner=old_winner)
    cache=cli('final-counters','show product flows','show product completion')
    result['status']='RAW_COMPLETE'
except Exception as error:
    result['error']=repr(error);raise
finally:
    cleanup_errors=[]
    if persistent is not None:
        try:
            persistent.stdin.close()
            persistent.wait(timeout=3)
            if persistent.returncode:cleanup_errors.append('persistent client exit '+str(persistent.returncode))
        except Exception as error:
            persistent.kill();persistent.wait(timeout=3);cleanup_errors.append(repr(error))
    for client in clients:
        try:
            if client.process.poll() is None:
                client.process.terminate();client.process.wait(timeout=3)
        except Exception as error:cleanup_errors.append(repr(error))
    try:stop('final')
    except Exception as error:cleanup_errors.append(repr(error))
    try:
        if endpoint is not None:
            endpoint.terminate()
            try:endpoint.wait(timeout=3)
            except subprocess.TimeoutExpired:endpoint.kill();endpoint.wait(timeout=3)
    except Exception as error:cleanup_errors.append(repr(error))
    finally:
        if endpoint_log is not None:endpoint_log.close()
    try:save('hooks-after.txt',command('iptables-save','-t','mangle'))
    except Exception as error:cleanup_errors.append(repr(error))
    if cleanup_errors:result['cleanup_error']=cleanup_errors
    result['process_absent']=(process is None and (endpoint is None or endpoint.poll() is not None)
                              and all(client.process.poll() is not None for client in clients))
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
    if cleanup_errors:raise RuntimeError('cleanup: '+repr(cleanup_errors))
print('T16 Linux QUIC v1 Initial facts, typed queries and rule outcomes collected')
