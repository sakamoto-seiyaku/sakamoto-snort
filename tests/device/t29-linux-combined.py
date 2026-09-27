#!/usr/bin/env python3
"""T29 live QUIC domain and supplemental RTP rules in one Product runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import select
import subprocess
import time
from helpers.t25_observation_client import ObservationClient

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--stage', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--fixtures',type=Path,required=True)
parser.add_argument('--quic-fixtures',type=Path,required=True)
parser.add_argument('--python',default='python3')
parser.add_argument('--observation',action='store_true')
parser.add_argument('--cost-extra-rules',type=int,default=0)
parser.add_argument('--cost-extra-domains',type=int,default=0)
parser.add_argument('--cost-supplemental',action='store_true')


args = parser.parse_args()
assert 0 <= args.cost_extra_rules <= 120
assert 0 <= args.cost_extra_domains <= 120
assert not args.cost_supplemental or args.cost_extra_rules >= 2
assert not args.cost_supplemental or args.observation

artifact, stage, output = (p.resolve() for p in (args.artifact, args.stage, args.output))
output.mkdir(parents=True, exist_ok=False)
assert os.getuid() == 0
uid_map = Path('/proc/self/uid_map').read_text().split()
assert int(uid_map[2]) > 12002, 'two real mapped UIDs required'
env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/'lib'))
vppctl = stage/'source/build-root/install-vpp-native/vpp/bin/vppctl'
runtime_tag = hashlib.sha256(str(output).encode()).hexdigest()[:12]
runtime = ROOT/('build-output/product-vpp-runtime-'+runtime_tag)
generation = 28601
config_dir = output/'configuration'
result = dict(status='HOLD', task='T29', generation=generation, profile='root', source='NFQ_CAPTURED',
              cases=[], observation=args.observation, started_ns=time.time_ns(), artifact=str(artifact),
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
if args.observation:
    helper=ROOT/'tests/device/helpers/t25_observation_client.py'
    (output/'observation-helper.py').write_bytes(helper.read_bytes())
    result['observation_helper_sha256']=hashlib.sha256(helper.read_bytes()).hexdigest()

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
    begun=time.monotonic_ns()
    text = save(name+'.txt', command(artifact/'bin/sakamoto-product-core-host', operation,
                                   runtime/'api.sock', generation, *values, check=False))
    if operation in ('rule-replace-all','rule-query'):
        with (output/'cost-operations.jsonl').open('a') as f:
            f.write(json.dumps(dict(label=name,operation=operation,started_ns=begun,
                                    completed_ns=time.monotonic_ns()))+'\n')
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

save('environment.txt', command('uname','-a')+command('id')+'uid_map='+' '.join(uid_map)
     +'\nnetns='+os.readlink('/proc/self/ns/net')+'\n')
command('ip','link','set','lo','up')
launch = dict(env, PRODUCT_ARTIFACT_DIR=str(artifact), PRODUCT_RUNTIME_DIR=str(runtime),
              PRODUCT_RULE_CONFIG_DIR=str(config_dir), PRODUCT_GENERATION=str(generation),
              PRODUCT_WORKER_COUNT='2', SAKAMOTO_RUNTIME_PROFILE='root',
              SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
              SAKAMOTO_LINUX_NETWORK_SOURCE='external')

peer_source=ROOT/'tests/device/helpers/r4_realtime_peer.py'
quic_source=ROOT/'tests/device/helpers/t16_quic_peer.py'
save('socket-peer.py',peer_source.read_text())
result['peer_sha256']=hashlib.sha256(peer_source.read_bytes()).hexdigest()
save('quic-peer.py',quic_source.read_text())
result['quic_peer_sha256']=hashlib.sha256(quic_source.read_bytes()).hexdigest()
fixtures=json.loads(args.fixtures.read_text())
endpoint=None;endpoint_log=None;quic_endpoint=None;quic_endpoint_log=None
def start_endpoint():
    global endpoint,endpoint_log
    endpoint_log=(output/'endpoint.jsonl').open('w')
    endpoint=subprocess.Popen([args.python,'-u',str(peer_source),'server','--host','127.0.0.2','--fixtures',str(args.fixtures.resolve()),'--applications','rtp_udp'],
        env=env,user=12001,group=12001,extra_groups=[],stdout=endpoint_log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+5
    while '"kind": "ready"' not in (output/'endpoint.jsonl').read_text():
        assert endpoint.poll() is None
        assert time.monotonic()<deadline
        time.sleep(.02)
def start_quic_endpoint():
    global quic_endpoint,quic_endpoint_log
    quic_endpoint_log=(output/'quic-endpoint.jsonl').open('w')
    quic_endpoint=subprocess.Popen([args.python,'-u',str(quic_source),'server','--host','127.0.0.2',
        '--directory',str(args.quic_fixtures.resolve().parent)],env=env,user=12001,group=12001,
        extra_groups=[],stdout=quic_endpoint_log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+5
    while '"kind": "ready"' not in (output/'quic-endpoint.jsonl').read_text():
        assert quic_endpoint.poll() is None
        assert time.monotonic()<deadline
        time.sleep(.02)
hooks = [['iptables','-t','mangle','-A','OUTPUT','-p',protocol,'-m','owner','--uid-owner','12001',
          flag,str(port),'-j','NFQUEUE','--queue-num','176']
         for protocol,port in [('udp',5004),('udp',40650),('udp',40651)] for flag in ['--sport','--dport']]
if args.cost_supplemental:
    hooks += [['iptables','-t','mangle','-A','OUTPUT','-p',protocol,'-m','owner','--uid-owner','12001',
               flag,str(port),'-j','NFQUEUE','--queue-num','176']
              for protocol,port in [('tcp',2525),('udp',1195)] for flag in ['--sport','--dport']]
clients=[]
extra_endpoints=[]
process = None; log = None; hooked = []; observer = None
def start_supplemental_endpoints():
    peers=[('smtp','tests/device/helpers/r2_mail_peer.py',
            ['--directory',str(args.quic_fixtures.resolve().parent),'--applications','smtp']),
           ('openvpn','tests/device/helpers/r3_tunnel_peer.py',
            ['--fixtures',str(output/'r3-fixtures.json'),'--applications','openvpn_udp'])]
    save('r3-fixtures.json',json.dumps({'wireguard':[]})+'\n')
    for label,source,extra in peers:
        peer=ROOT/source;save(label+'-peer.py',peer.read_text())
        handle=(output/(label+'-endpoint.jsonl')).open('w')
        child=subprocess.Popen(['python3','-u',str(peer),'server','--host','127.0.0.2',*extra],
            env=env,user=12001,group=12001,extra_groups=[],stdout=handle,stderr=subprocess.STDOUT)
        extra_endpoints.append((child,handle))
        deadline=time.monotonic()+5
        while '"kind": "ready"' not in (output/(label+'-endpoint.jsonl')).read_text():
            assert child.poll() is None,(output/(label+'-endpoint.jsonl')).read_text()
            assert time.monotonic()<deadline
            time.sleep(.02)
def start(label):
    global process, log, runtime, generation, observer
    generation = 28601 if label == "first" else 25602
    runtime = ROOT/("build-output/product-vpp-runtime-"+runtime_tag+"-"+label)
    launch.update(PRODUCT_RUNTIME_DIR=str(runtime), PRODUCT_GENERATION=str(generation))
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
        assert time.monotonic() < deadline, status
        time.sleep(.05)
    save(label+'-process.txt', 'pid='+str(process.pid)+'\nexe='+os.readlink(f'/proc/{process.pid}/exe')
         +'\ncmd='+Path(f'/proc/{process.pid}/cmdline').read_bytes().replace(b'\0',b' ').decode())
    cli(label+'-startup', 'product packet-trace limit 4096', 'show product root lanes', 'show threads')
    if args.observation:
        observer=ObservationClient(artifact/'bin/sakamoto-product-core-host',runtime,generation,
            output/'observation/overall.json',output,env)
        observer.query('baseline')
    for hook in hooks: command(*hook); hooked.append(hook)
    return status

def stop(label):
    global process, log, observer
    errors=[]
    for hook in hooked:
        removal=hook.copy();removal[3]='-D'
        try:command(*removal)
        except Exception as error:errors.append(repr(error))
    hooked.clear()
    if observer is not None:observer.close();observer=None
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

def submit(label, prior, lines):
    request=output/(label+'-request.txt');request.write_text('\n'.join(lines)+'\n')
    status=api(label+'-apply','rule-replace-all',prior['config.saved_revision'],request)
    (output/(label+'-source.conf')).write_bytes((config_dir/'rules.conf').read_bytes())
    return status

def configure(label, prior, protocol, target, mode=1):
    expression='0d020f'+target.to_bytes(4,'little').hex()+'01'
    versions=[prior.get(f'config.rule.{i}.version','0') for i in range(4)]
    lines=[f'0 {versions[0]} 4294967295 4294967295 4294967295 10 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}',
           f'0 {versions[1]} 4294967295 4294967295 4294967295 20 0 {protocol} 0 2 * * 0 65535 0 65535 {expression}03',
           f'0 {versions[2]} 12001 4294967295 4294967295 100 0 {protocol} 0 1 * * 0 65535 0 65535',
           f'0 {versions[3]} 4294967295 4294967295 4294967295 5 0 17 0 2 * * 0 65535 0 65535 1100',
           'lists 1','domain 0 exact example.test',
           'group 10','edge 10 1 0','group 20','edge 20 1 1',
           f'bind 1 12001 2 10 {mode}','bind 2 12001 2 20 1','bind 3 12001 1 3 1']
    if args.cost_extra_rules:
        lines += ['group 30']
        for i in range(args.cost_extra_rules):
            version=prior.get(f'config.rule.{i+4}.version','0')
            port=60000+i
            if args.cost_supplemental and i < 2:
                protocol_id=1007 if i==0 else 1011
                transport=6 if i==0 else 17
                expression='0d020f'+protocol_id.to_bytes(4,'little').hex()+'01'
                lines.append(f'0 {version} 4294967295 4294967295 4294967295 1 0 {transport} 0 2 * * 0 65535 0 65535 {expression}')
            else:
                lines.append(f'0 {version} 4294967295 4294967295 4294967295 1 0 17 0 1 * * 0 65535 {port} {port}')
            lines.append(f'edge 30 1 {i+4}')
        lines += ['bind 4 12001 2 30 1']
    for i in range(args.cost_extra_domains):
        lines += [f'domain 0 exact cost-{i:03d}.example.test']
    status=submit(label,prior,lines)
    assert status['config.result']=='0' and status['config.saved_revision']==status['config.active_revision'],status
    cli(label+'-resources','show product rule-budget','show product policy-index','show product flows')
    result.setdefault('configurations',[]).append(dict(label=label,revision=int(status['config.active_revision']),
        source=label+'-source.conf',query=label+'-apply.txt',expression=expression,mode=mode,protocol=protocol,target=target,
        quic_domain='example.test',quic_rule_mode='observe'))
    return status

class Client:
    def __init__(self,label,application,port):
        self.label,self.protocol,self.port=label,("udp" if application.endswith("udp") else "tcp"),port
        self.application=application
        self.nonce=next(f['nonce'] for f in fixtures['sessions'] if f['application']==application and '-linux-' in f['nonce'])
        self.process=subprocess.Popen(['python3','-u',str(peer_source),'client','--host','127.0.0.2',
            '--application',application,'--source',str(port),'--nonce',self.nonce,'--fixtures',str(args.fixtures.resolve())],
            env=env,user=12001,group=12001,extra_groups=[],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,text=True,bufsize=1)
        self.events=[];clients.append(self)
        assert self.read()['kind']=='connected'
    def read(self):
        assert select.select([self.process.stdout],[],[],20)[0], 'client response deadline'
        line=self.process.stdout.readline();assert line,line
        value=json.loads(line);self.events.append(value)
        save(self.label+'-client.json',json.dumps(self.events,indent=2))
        return value
    def execute(self,operation,wanted):
        self.process.stdin.write(json.dumps(dict(op=operation,timeout=1 if wanted=='timeout' else 10))+'\n')
        self.process.stdin.flush();answer=self.read()
        assert answer['kind']==wanted,answer
        return answer
    def capture(self,label,status,phase):
        time.sleep(.1);drain(label+'-drain')
        api(label+'-query','rule-query');cli(label+'-flow','show product flows')
        if args.observation:observer.query(label)
        result['cases'].append(dict(label=label,client=self.label,protocol=self.protocol,port=self.port,nonce=self.nonce,
            phase=phase,application=self.application,revision=int(status['config.active_revision']),query=label+'-query.txt',flow=label+'-flow.txt',
            generation=generation,observation=(label+'-observation.json' if args.observation else None)))
    def close(self):
        if self.process.poll() is None:
            self.execute('close','closed');self.process.wait(timeout=5)
        assert self.process.returncode==0

class QuicClient:
    def __init__(self):
        self.label='quic_named'
        self.port=45620
        self.nonce='t29-linux-quic-'+str(time.time_ns())
        self.process=subprocess.Popen([args.python,'-u',str(quic_source),'client','--host','127.0.0.2',
            '--mode','named','--source',str(self.port),'--nonce',self.nonce,
            '--directory',str(args.quic_fixtures.resolve().parent)],env=env,user=12001,group=12001,
            extra_groups=[],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
            text=True,bufsize=1)
        self.events=[];clients.append(self)
        assert self.read()['kind']=='quic_ready'
    def read(self):
        assert select.select([self.process.stdout],[],[],20)[0], 'QUIC response deadline'
        line=self.process.stdout.readline();assert line,line
        value=json.loads(line);self.events.append(value)
        save(self.label+'-client.json',json.dumps(self.events,indent=2))
        return value
    def execute(self,operation,wanted):
        self.process.stdin.write(json.dumps(dict(op=operation,timeout=10))+'\n')
        self.process.stdin.flush();answer=self.read()
        assert answer['kind']==wanted,answer
        return answer
    def capture(self,label,status):
        drain(label+'-drain')
        api(label+'-query','rule-query')
        text=cli(label+'-flow','show product flows')
        rows=[dict(item.split('=',1) for item in line.split()[1:] if '=' in item)
              for line in text.splitlines() if line.startswith('flow.entry ')]
        row=next(r for r in rows if str(self.port) in (r['port_a'],r['port_b']))
        identity=[row['worker'],row['slot'],row['incarnation']]
        facts=api(label+'-sni','sni-query',*identity)
        assert facts['sni.code']=='0' and facts['sni.result']=='1' and facts['sni.name']=='example.test',facts
        if args.observation:observer.query(label)
        result.setdefault('quic_cases',[]).append(dict(label=label,port=self.port,nonce=self.nonce,
            revision=int(status['config.active_revision']),query=label+'-query.txt',flow=label+'-flow.txt',
            sni=label+'-sni.txt',identity=identity,generation=generation,
            observation=(label+'-observation.json' if args.observation else None)))
    def close(self):
        if self.process.poll() is None:
            self.execute('close','closed');self.process.wait(timeout=5)
        assert self.process.returncode==0

class SupplementalClient:
    def __init__(self,label,source,application,port):
        self.label=label
        peer=ROOT/source
        values=['python3','-u',str(peer),'client','--host','127.0.0.2',
                '--source',str(port),'--application',application,'--nonce','t30-'+label+'-'+str(time.time_ns())]
        if label=='openvpn':values += ['--fixtures',str(output/'r3-fixtures.json')]
        self.process=subprocess.Popen(values,env=env,user=12001,group=12001,extra_groups=[],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        self.events=[];clients.append(self)
        assert self.read()['kind']=='connected'
    def read(self):
        assert select.select([self.process.stdout],[],[],20)[0],self.label+' response deadline'
        line=self.process.stdout.readline();assert line,line
        value=json.loads(line);self.events.append(value)
        save(self.label+'-client.json',json.dumps(self.events,indent=2))
        return value
    def execute(self,operation,wanted):
        self.process.stdin.write(json.dumps(dict(op=operation,timeout=10))+'\n')
        self.process.stdin.flush();answer=self.read()
        assert answer['kind']==wanted,answer
        return answer
    def close(self):
        if self.process.poll() is None:
            self.execute('close','closed');self.process.wait(timeout=5)
        assert self.process.returncode==0

try:
    start_endpoint()
    start_quic_endpoint()
    if args.cost_supplemental:start_supplemental_endpoints()
    result['fixtures_sha256']=hashlib.sha256(args.fixtures.read_bytes()).hexdigest()
    save('fixtures.json',args.fixtures.read_text())
    result['quic_fixtures_sha256']=hashlib.sha256(args.quic_fixtures.read_bytes()).hexdigest()
    save('quic-fixtures.json',args.quic_fixtures.read_text())
    status=start('first')
    status=configure('combined-observe',status,17,1017)
    quic=QuicClient();quic.capture('quic-ready',status)
    rtp=Client('rtp_udp','rtp_udp',45302)
    rtp.execute('first','first_ready');rtp.capture('rtp-first',status,'first')
    rtp.execute('added','added_ready');rtp.capture('rtp-added',status,'added')
    quic.execute('echo','received');quic.capture('quic-allow',status)
    if args.cost_supplemental:
        smtp=SupplementalClient('smtp','tests/device/helpers/r2_mail_peer.py','smtp',45400)
        openvpn=SupplementalClient('openvpn','tests/device/helpers/r3_tunnel_peer.py','openvpn_udp',45410)
        for extra in (smtp,openvpn):
            extra.execute('first','first_ready');extra.execute('added','added_ready')
        cli('supplemental-all-live','show product flows','show product policy-index')
        observer.query('supplemental-all-live')
    status=configure('combined-enforce',status,17,1017,0)
    rtp.execute('send','timeout');rtp.capture('rtp-blocked',status,'blocked')
    quic.execute('echo','received');quic.capture('quic-during-rtp-drop',status)
    if args.cost_supplemental:
        for extra in (smtp,openvpn):extra.execute('send','received')
    status=configure('combined-recover',status,17,1017,1)
    rtp.execute('recv','received')
    rtp.execute('repeat','received');rtp.capture('rtp-recovered',status,'recovered')
    quic.execute('echo','received');quic.capture('quic-after-recover',status)
    if args.cost_supplemental:
        for extra in (smtp,openvpn):extra.execute('send','received')
        cli('supplemental-final-live','show product flows','show product policy-index')
        observer.query('supplemental-final-live')
        result['supplemental']=dict(labels=['smtp','openvpn'],
            flow='supplemental-final-live.txt',observation='supplemental-final-live-observation.json')
        smtp.close();openvpn.close()
    rtp.close();quic.close()
    cache=cli('final-counters','show product flows','show product completion')
    if args.observation:observer.query('final')
    result['status']='RAW_COMPLETE'
except Exception as error:
    result['error']=repr(error);raise
finally:
    cleanup_errors=[]
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
    try:
        if quic_endpoint is not None:
            quic_endpoint.terminate()
            try:quic_endpoint.wait(timeout=3)
            except subprocess.TimeoutExpired:quic_endpoint.kill();quic_endpoint.wait(timeout=3)
    except Exception as error:cleanup_errors.append(repr(error))
    finally:
        if quic_endpoint_log is not None:quic_endpoint_log.close()
    try:save('hooks-after.txt',command('iptables-save','-t','mangle'))
    except Exception as error:cleanup_errors.append(repr(error))
    for child,handle in extra_endpoints:
        try:
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=3)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
        except Exception as error:cleanup_errors.append(repr(error))
        finally:handle.close()
    if cleanup_errors:result['cleanup_error']=cleanup_errors
    result['process_absent']=(process is None and (endpoint is None or endpoint.poll() is not None)
                              and (quic_endpoint is None or quic_endpoint.poll() is not None)
                              and all(child.poll() is not None for child,_ in extra_endpoints)
                              and all(client.process.poll() is not None for client in clients))
    result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
    if cleanup_errors:raise RuntimeError('cleanup: '+repr(cleanup_errors))
print('T29 Linux combined QUIC/domain and RTP facts collected')
