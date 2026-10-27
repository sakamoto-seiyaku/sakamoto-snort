#!/usr/bin/env python3
"""Original Root/VPN TCP DNS on ordinary App sockets, wire and normal observation."""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s313_original_udp_support', ROOT / 'tests/device/s312-dns-response.py')
support = importlib.util.module_from_spec(spec); spec.loader.exec_module(support)
fixtures, digest, props, PKG, SERIAL = support.fixtures, support.digest, support.props, support.PKG, support.SERIAL


class Peer(support.Peer):
    def __init__(self, addresses, out, helper=None, deadline=None):
        self.out, self.rows, self.messages, self.responses = out, [], [], {}
        self.deadline = deadline
        self.start_timeout(12)
        self.lock, self.ready = threading.Lock(), threading.Event()
        self.plan, self.stop_path = out / 'peer-plan.json', out / 'peer.stop'
        self.publish()
        helper = helper or ROOT / 'tests/device/helpers/s313_dns_peer.ps1'
        quote = lambda value: "'" + value.replace("'", "''") + "'"
        command = ('& ' + quote(self.path(helper)) + ' -Addresses @('
            + ','.join(quote(a) for a in addresses) + ') -StopPath ' + quote(self.path(self.stop_path))
            + ' -PlanPath ' + quote(self.path(self.plan)))
        encoded = base64.b64encode(command.encode('utf-16le')).decode('ascii')
        self.encoded = encoded
        for attempt in range(3):
            self.start_timeout(12)
            self.process = subprocess.Popen(['/init', '/mnt/c/Windows/System32/cmd.exe', '/C', 'powershell.exe',
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
                cwd='/mnt/c', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace')
            self.thread = threading.Thread(target=self.read, daemon=True); self.thread.start()
            try:
                # A timed Event.wait returned False in 160ms on this WSL host
                # despite its 12s argument; the reader signalled at 1.16s.
                # Bound readiness with the monotonic deadline and actual flag.
                ready_deadline=time.monotonic()+self.budget_timeout(12)
                while not self.ready.is_set() and time.monotonic()<ready_deadline:
                    time.sleep(.05)
                if self.ready.is_set(): return
                self.process.wait(timeout=self.budget_timeout(15))
            except BaseException as error:
                try:self.cleanup_failed_start(attempt)
                except BaseException as cleanup:
                    error.add_note('peer constructor cleanup retained HOLD: '+repr(cleanup))
                    (self.out/f'peer-failed-{attempt}-unresolved.json').write_text(json.dumps(dict(
                        status='HOLD',primary_error=repr(error),cleanup_error=repr(cleanup),
                        local_pid=self.process.pid,local_returncode=self.process.poll(),
                        reader_alive=self.thread.is_alive()),indent=2)+'\n')
                raise error
            self.thread.join(timeout=self.budget_timeout(2))
            raw=(out/'peer.log').read_text()
            self.cleanup_failed_start(attempt)
            if self.messages or self.process.returncode==0 or 'UtilAcceptVsock' not in raw:
                raise RuntimeError('independent peer did not bind; inspect peer.log')
            (out/'peer.log').rename(out/f'peer-launch-{attempt}.log')
            self.stop_path.unlink()
            self.__dict__.pop('cleanup_deadline',None)
        raise RuntimeError('WSL peer launcher failed three times; no remote peer remained')

    def remote_read(self, label, command):
        encoded=base64.b64encode(("$ErrorActionPreference='Stop'; "+command).encode('utf-16le')).decode()
        for attempt in range(3):
            try:
                check=self.external(['/init','/mnt/c/Windows/System32/cmd.exe','/C','powershell.exe',
                    '-NoProfile','-NonInteractive','-EncodedCommand',encoded])
                (self.out/f'{label}-{attempt}.txt').write_text(check.stdout+check.stderr)
                if check.returncode==0: return json.loads(check.stdout)
            except subprocess.TimeoutExpired as error:
                (self.out/f'{label}-{attempt}.timeout.json').write_text(json.dumps(dict(
                    timeout_seconds=error.timeout,stdout_base64=base64.b64encode(error.stdout or b'').decode(),
                    stderr_base64=base64.b64encode(error.stderr or b'').decode()),indent=2)+'\n')
        raise RuntimeError('owned peer physical inspection unavailable: '+label)

    def cleanup_failed_start(self, attempt):
        try:self.cleanup_failed_remote_start(attempt)
        finally:self.reap_launcher()

    def cleanup_failed_remote_start(self, attempt):
        # Constructor owns the remote process even before the caller can assign
        # this object. Stop cooperatively first; PID alone is never kill authority.
        self.begin_cleanup()
        self.stop_path.touch()
        try: self.process.wait(timeout=self.budget_timeout(15))
        except subprocess.TimeoutExpired: pass
        self.thread.join(timeout=self.budget_timeout(2))
        selector=("Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'powershell.exe' "
            "-and $_.CommandLine.EndsWith('"+self.encoded+"')}")
        command=("@{process_ids=@("+selector+" | Select-Object -ExpandProperty ProcessId); "
            "tcp=@(Get-NetTCPConnection | Where-Object {$_.LocalPort -eq 53} | "
            "Select-Object LocalAddress,OwningProcess); udp=@(Get-NetUDPEndpoint | "
            "Where-Object {$_.LocalPort -eq 53} | Select-Object LocalAddress,OwningProcess)} | "
            "ConvertTo-Json -Depth 4 -Compress")
        remote=self.remote_read(f'peer-failed-{attempt}-before',command)
        if remote['process_ids']:
            # Recheck exact encoded command at mutation time. Never kill an
            # unrelated endpoint owner, even if it occupies the requested port.
            mutation=selector+" | ForEach-Object {Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop}"
            encoded=base64.b64encode(mutation.encode('utf-16le')).decode()
            check=self.external(['/init','/mnt/c/Windows/System32/cmd.exe','/C','powershell.exe',
                '-NoProfile','-NonInteractive','-EncodedCommand',encoded])
            (self.out/f'peer-failed-{attempt}-terminate.txt').write_text(check.stdout+check.stderr)
        after=self.remote_read(f'peer-failed-{attempt}-after',command)
        owned=set(remote['process_ids']) | {row['process_id'] for row in self.messages if row.get('kind')=='ready'}
        assert not after['process_ids'] and not any(row['OwningProcess'] in owned for row in after['tcp']+after['udp']),after
        if self.process.poll() is None:
            self.process.terminate(); self.process.wait(timeout=self.budget_timeout(5))
        self.thread.join(timeout=self.budget_timeout(2))
        assert not self.thread.is_alive(), 'old peer reader remains; no launch retry is safe'
        (self.out/f'peer-failed-{attempt}-cleanup.json').write_text(json.dumps(dict(before=remote,after=after,
            launcher_exit=self.process.returncode),indent=2)+'\n')

    def register(self, request, reply, gate=None, split=False, copies=1):
        self.responses[request.hex()] = dict(request_hex=request.hex(), reply_hex=reply.hex(),
            gate=self.path(gate) if gate else '', split_bytes=[1, 5] if split else [],
            split_delay_ms=40 if split else 0, frame_copies=copies)
        self.publish()

    def close(self):
        super().close()
        rows=self.messages
        received=[r for r in rows if r.get('kind')=='received']
        settled=[r for r in rows if r.get('kind') in ('exchange','cancelled')]
        identity=lambda r:(r['connection'],r['request'])
        assert len(set(map(identity,received)))==len(received)
        assert len(set(map(identity,settled)))==len(settled)
        assert set(map(identity,received))==set(map(identity,settled)), 'peer request settlement mismatch'
        stopped,=[r for r in rows if r.get('kind')=='stopped']
        assert stopped['pending']==stopped['connections']==0
        assert stopped['received']==stopped['exchanged']+stopped['cancelled']==len(received)
        connected=[r['connection'] for r in rows if r.get('kind')=='connected']
        closed=[r['connection'] for r in rows if r.get('kind')=='connection_closed']
        assert sorted(connected)==sorted(closed), 'peer connection close mismatch'
        ready,=[r for r in rows if r.get('kind')=='ready']
        process_id=ready['process_id']
        command=("$ErrorActionPreference='Stop'; @{endpoints=@(Get-NetTCPConnection | "
            "Where-Object {$_.LocalPort -eq 53} | Select-Object LocalAddress,"
            "@{n='State';e={$_.State.ToString()}},OwningProcess); process_present=[bool]"
            "(Get-Process -Id "+str(process_id)+" -ErrorAction SilentlyContinue)} | ConvertTo-Json -Depth 4 -Compress")
        for attempt in range(3):
            check=self.external(['/init','/mnt/c/Windows/System32/cmd.exe','/C','powershell.exe',
                '-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(command.encode('utf-16le')).decode()])
            (self.out/f'peer-remote-after-{attempt}.txt').write_text(check.stdout+check.stderr)
            if check.returncode==0: break
        assert check.returncode==0, 'actual peer endpoint inspection failed'
        remote=json.loads(check.stdout)
        assert not remote['process_present']
        assert not any(r['OwningProcess']==process_id for r in remote['endpoints'])
        (self.out/'peer-cleanup.json').write_text(json.dumps(dict(process_id=process_id,
            process_exit=self.process.returncode,stopped=stopped,actual_remote=remote,
            cancelled=[r for r in settled if r.get('kind')=='cancelled']),indent=2)+'\n')


class Device(support.Device):
    def __init__(self, args):
        super().__init__(args)
        self.adb_trace = None
        self.local_adb_recorder = self.transport_recorder()
        if getattr(args, 'trace', False) or os.environ.get('SAKAMOTO_ADB_TRACE') == '1':
            self.adb_trace = self.local_adb_recorder

    def transport_recorder(self):
        if not getattr(self,'local_adb_recorder',None):
            path=Path(__file__).resolve().parent/'helpers/s314_adb_trace.py'
            spec=importlib.util.spec_from_file_location('s314_adb_trace',path)
            module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            self.local_adb_recorder=module.AdbTrace(self.out,[str(ROOT/'dev/adb'),'-s',SERIAL])
        return self.local_adb_recorder

    def close_trace(self):
        errors=[]
        ui_path=getattr(self,'ui_capture_path',None)
        if ui_path:
            try:
                assert re.fullmatch(r'/data/local/tmp/s313-ui-\d+\.xml',ui_path)
                self.adb('shell','rm','-f',ui_path)
                self.ui_capture_path=None
                self.ui_capture_ready=False
                self.save('ui-capture-cleanup.json',json.dumps(dict(status='PASS_EXACT_OWNED_UI_XML_RETIRED',path=ui_path),indent=2)+'\n')
            except BaseException as error:errors.append(error)
        recorder=getattr(self,'adb_trace',None) or getattr(self,'local_adb_recorder',None)
        if recorder:
            # Closing already-owned work must survive an expired case clock,
            # while still honoring an explicit reserved cleanup phase.
            deadline=getattr(self,'cleanup_deadline',None)
            budget=deadline-time.monotonic() if deadline is not None else 30
            try:recorder.close(budget)
            except BaseException as error:errors.append(error)
        if len(errors)==1:raise errors[0]
        if errors:raise BaseExceptionGroup('owned UI capture and trace cleanup failed',errors)

    def budget_timeout(self, maximum):
        deadline=getattr(self,'capture_deadline',None)
        if deadline is None:return maximum
        remaining=deadline-time.monotonic()
        assert remaining>0,'lifecycle phase budget exhausted'
        return min(maximum,remaining)

    def reserve_source_port(self, label):
        # A deliberately dropped TCP connection can leave an orphaned kernel
        # FIN_WAIT1 tuple after its App socket and the VPN generation end.
        # Observe both families/protocols, then reserve once for this runner;
        # never kill an unrelated or orphaned socket to recycle a fixed port.
        raw = self.save(label+'-source-ports-before.txt', self.root(
            'cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6'))
        occupied = set()
        headers = 0
        for line in raw.splitlines():
            fields = line.split()
            if fields[:2] == ['sl', 'local_address']:
                headers += 1
            elif fields and fields[0].removesuffix(':').isdigit():
                assert len(fields) >= 10 and ':' in fields[1], 'invalid kernel socket table row'
                assert re.fullmatch(r'[0-9A-Fa-f]{8}(?:[0-9A-Fa-f]{24})?:[0-9A-Fa-f]{4}', fields[1]), 'invalid local socket endpoint'
                occupied.add(int(fields[1].rsplit(':', 1)[1], 16))
            elif fields:
                raise AssertionError('unexpected kernel socket table output: '+line)
        assert headers == 4, 'all four kernel socket tables must be observed'
        reserved = getattr(self, 'reserved_source_ports', set())
        selected = next((port for port in range(20000, 40000)
                         if port not in occupied and port not in reserved), None)
        assert selected is not None, 'bounded fixture source port range exhausted'
        self.save(label+'-source-port.json', json.dumps(dict(
            selected=selected, occupied=sorted(occupied), previously_reserved=sorted(reserved),
            tables_sha256=hashlib.sha256(raw.encode()).hexdigest(),
            scope='Observed free before bind, reserved only within this runner; no socket mutation or bind retry'), indent=2)+'\n')
        self.reserved_source_ports = reserved | {selected}
        return selected

    def adb(self, *command, check=True):
        ui_dump=command==('shell','uiautomator','dump','/sdcard/s312-ui.xml')
        if command==('shell','cat','/sdcard/s312-ui.xml'):
            assert getattr(self,'ui_capture_path',None)and getattr(self,'ui_capture_ready',False),'UI read requires this runner\'s acknowledged fresh capture'
            command=('shell','cat',self.ui_capture_path)
        if self.adb_trace and self.adb_trace.handles(command):
            return self.adb_trace.run(command, getattr(self, 'capture_deadline', None), check)
        # A WSL transport failure is not remote-operation completion. Only
        # side-effect-free reads may be retried, with each raw failed operation
        # retained by the common recorder. Only wake/dismiss UI operations are
        # additionally convergent; Product/runtime/rule mutations always surface.
        # File captures use the binary exec-out service, avoiding shell-v2's
        # interactive close handshake for large UI/JSON observations. This is
        # the same repository wrapper and existing server, with exact bytes.
        if ui_dump:
            # AOSP's normal idle wait alone permits ten seconds. Preserve a
            # separate bounded transport margin and never reuse an older XML.
            deadline=getattr(self,'capture_deadline',None)
            assert deadline and deadline-time.monotonic()>=18,'insufficient remaining UI capture/cleanup budget'
            if not getattr(self,'ui_capture_path',None):self.ui_capture_path='/data/local/tmp/s313-ui-'+str(time.monotonic_ns())+'.xml'
            self.ui_capture_ready=False
            self.adb('shell','rm','-f',self.ui_capture_path)
            command=('shell','timeout','15','uiautomator','dump',self.ui_capture_path)
        proc_tables_read = command == ('shell', 'su', '-c', shlex.quote(
            'cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6'))
        if proc_tables_read:
            # exec-out passes -c directly; shell service needs one additional
            # quote layer which would become a literal command name here.
            command = ('exec-out', 'su', '-c',
                       'cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6')
        elif command[:2]==('shell','cat'):
            command=('exec-out','cat',*command[2:])
        elif command[:4]==('shell','run-as',PKG,'cat'):
            command=('exec-out','run-as',PKG,'cat',*command[4:])
        read = (command[:2] in (('shell','dumpsys'), ('shell','sha256sum'),('exec-out','cat'))
            or command[:4] == ('exec-out','run-as',PKG,'cat')
            or command[:4] == ('shell','run-as',PKG,'cat')
            or command[:4] in (('shell','run-as',PKG,'sha256sum'),('shell','run-as',PKG,'id'))
            or command == ('shell','run-as',PKG,'su','-c','id')
            or command == ('shell','cmd','wifi','status') or proc_tables_read)
        ui_convergent=command in (('shell','input','keyevent','224'),('shell','wm','dismiss-keyguard'))
        for attempt in range(3):
            try:
                deadline=getattr(self,'capture_deadline',None)
                # A single stalled read must not consume the ordinary App's
                # 60s active-socket hold. Preserve every failed partial read;
                # only this side-effect-free capture may be retried.
                timeout=17 if ui_dump else 10
                if deadline:
                    remaining=deadline-time.monotonic()
                    if remaining<1:raise TimeoutError('insufficient remaining budget to start an external client')
                    timeout=min(timeout,remaining)
                recorder=self.transport_recorder()
                previous=getattr(recorder,'operation_deadline',None)
                recorder.operation_deadline=deadline
                try:
                    stdout,stderr,code,record=recorder.execute(command,command,timeout,check=False,kind='untraced-transport')
                finally:
                    if previous is None:recorder.__dict__.pop('operation_deadline',None)
                    else:recorder.operation_deadline=previous
                value=(stdout+stderr).decode(errors='replace').replace('\r','')
                if check and code:raise RuntimeError(value)
                if ui_dump and 'UI hierchary dumped to: '+self.ui_capture_path not in value:
                    raise RuntimeError('fresh owned UI capture was not acknowledged: '+value)
                if ui_dump:self.ui_capture_ready=True
                return value
            except subprocess.TimeoutExpired:
                if not read or attempt==2: raise
            except RuntimeError as error:
                if not (read or ui_convergent) or 'WSL' not in str(error) or attempt==2: raise
                self.save('transport-read-retry-'+str(time.time_ns())+'.txt',str(error))
            time.sleep(.2)

    def cli(self,label,*commands):
        deadline=getattr(self,'capture_deadline',None)
        timeout=30
        if deadline:
            remaining=deadline-time.monotonic()
            assert remaining>10,'capture budget reserves CLI cleanup and App release'
            timeout=min(10,remaining-10)
        return self.save(label+'.txt',self.target.cli(self.base+'runtime',list(commands),
            timeout=timeout,capture_output=self.out,deadline=deadline))

    def start(self, owners):
        self.owners, self.active = owners, True
        label = f'n{owners}'
        extras = ['--ez', 'runtimeStart', 'true', '--es', 'runtimeProfile', self.profile,
            '--es', 'runtimeWorkerCpuIds', '1' if owners == 1 else '1,2,1']
        if self.profile == 'vpn': extras += ['--es', 'runtimeTunIoCpuId', '2' if owners == 1 else '3']
        self.save(label + '-start.txt', self.action(*extras))
        state = self.wait(label + '-running', 'files/runtime-state/snapshot.properties',
            lambda c: c.get('state') == 'running' and c.get('protectionRunning') == 'true')
        self.generation = int(state['generation'])
        topology = self.cli(label + '-topology', 'show product topology', 'show product dns',
            'show product completion', 'product metadata check')
        assert 'dns.profile=original enabled=1' in topology and 'tcp=1' in topology
        assert 'root_tcp=1 vpn_tcp=1' in topology
        return dict(owners=owners, generation=self.generation, profile=self.profile)

    def verify_ui_state(self, label):
        power=self.save(label+'-power.txt',self.adb('shell','dumpsys','power'))
        policy=self.save(label+'-keyguard.txt',self.adb('shell','dumpsys','window','policy'))
        assert re.search(r'(?m)^\s*mWakefulness=Awake\s*$',power),'device is not awake'
        assert re.search(r'(?m)^\s*showing=false\s*$',policy),'keyguard is still showing'
        self.verify_ui_focus(label)

    def verify_ui_focus(self, label):
        windows=self.save(label+'-focus.txt',self.adb('shell','dumpsys','window','displays'))
        focus=[line for line in windows.splitlines()if line.strip().startswith('mCurrentFocus=')]
        assert len(focus)==1 and PKG in focus[0]and 'DebugControlActivity'in focus[0],('own debug UI is not focused',focus)

    def foreground_ui(self, label):
        previous=getattr(self,'capture_deadline',None)
        # One bounded UI-state read can consume most of the ordinary ten-second
        # transport window. Leave room for the existing retry loop without
        # relaxing the per-command or enclosing matrix deadline.
        self.capture_deadline=min(previous or float('inf'),time.monotonic()+30)
        try:
            self.save(label+'-wake.txt',self.adb('shell','input','keyevent','224'))
            self.save(label+'-dismiss.txt',self.adb('shell','wm','dismiss-keyguard'))
            self.save(label+'-foreground.txt',self.action())
            attempt=0
            while True:
                try:
                    self.verify_ui_state(label+f'-ready-{attempt}')
                    break
                except (AssertionError, subprocess.TimeoutExpired):
                    if self.capture_deadline-time.monotonic()<=.2:raise
                    time.sleep(.1);attempt+=1
        finally:self.capture_deadline=previous

    def validate_tap_ui(self, label, tree, text):
        nodes=list(tree.iter('node'))
        assert any(node.get('package')==PKG for node in nodes),'refusing to gesture outside the ordinary App UI'
        matches=[node for node in nodes if node.get('text')==text and node.get('enabled')=='true']
        assert len(matches)<=1 and all(node.get('package')==PKG for node in matches),'ambiguous or foreign UI action'
        self.verify_ui_state(label)

    def tap(self, label, text, *, click=True):
        previous=getattr(self,'capture_deadline',None)
        self.capture_deadline=min(previous or float('inf'),time.monotonic()+30)
        try:return super().tap(label,text,click=click)
        finally:self.capture_deadline=previous

    def release_probe(self, label, nonce):
        # Headless probe/observation activities finish. Android can freeze the
        # cached main process while its ordinary socket is held; a run-as file
        # touch alone does not wake that process. Bring only our normal UI
        # forward after captures, then release within the existing 10s budget.
        previous=getattr(self,'capture_deadline',None)
        self.capture_deadline=min(previous or float('inf'),time.monotonic()+10)
        errors=[]
        try:
            try:
                self.foreground_ui(label+'-release')
            except Exception as error:errors.append(error)
            try:
                self.save(label+'-release.txt',self.adb('shell','run-as',PKG,'touch',
                    'files/product-state/t12-release-'+nonce+'-dns_tcp_read_complete'))
            except Exception as error:errors.append(error)
        finally:
            self.capture_deadline=previous
        if errors:raise ExceptionGroup('ordinary App release failed',errors)

    def stop(self, label):
        errors=[]
        if getattr(self,'active_probe',None):
            try:
                self.release_probe(label+'-probe',self.active_probe)
            except Exception as error: errors.append(error)
        # Releasing the ordinary App and stopping Product are independent
        # obligations: a failed App transport operation must not skip native stop.
        try:
            result = super().stop(label)
            log = (self.out / (label + '-stop.log')).read_text()
            processes=(self.out/(label+'-processes-after.txt')).read_text()
            ui_path=getattr(self,'ui_capture_path',None)
            assert not any(ui_path and 'uiautomator'in line and ui_path in line for line in processes.splitlines()),'owned UI capture process remains'
            for owner in range(self.owners):
                assert re.search(rf'dns event=stop generation={self.generation} owner={owner} .*tcp_active=0 tcp_owned_bytes=0', log)
                if self.profile=='vpn':
                    settled=re.search(rf's237 event=owner_stopped generation={self.generation} owner={owner} .*sessions=0 inputs=0 pbufs=0 sockets_created=(\d+) sockets_closed=(\d+) timer_fd=-1 broker_fd=-1 buffers=0 obligations=0 frames=0',log)
                    assert settled and settled[1]==settled[2], 'native Direct owner did not settle all resources'
        except Exception as error: errors.append(error)
        if getattr(self,'active_probe',None):
            previous=getattr(self,'capture_deadline',None)
            self.capture_deadline=time.monotonic()+5
            try:
                self.wait(label+'-probe-finished','files/product-state/t12-'+self.active_probe+'.json',
                    lambda value:value.get('phase')=='finished',timeout=5,json_value=True)
                self.active_probe=None
            except Exception as error:errors.append(error)
            finally:self.capture_deadline=previous
        if errors: raise ExceptionGroup('App release / Product stop failures',errors)
        return result

    def configure(self, label, variant='allow', *, mode=0, prefill_only=False, direction=1, subject=None):
        path = 'files/product-state/complete-rule-config.properties'
        old = props(self.app(path)).get('queryElapsedMillis')
        self.foreground_ui(label+'-ready'); self.tap(label + '-query', 'Query all rules')
        self.wait(label + '-baseline', path, lambda c: c.get('queryElapsedMillis') not in (None, old))
        subject = self.uid if subject is None else subject
        protocol = 17 if getattr(self.args, 'protocol', 'tcp') == 'udp' else 6
        expressions = {'generic-drop':'', 'allow':'1102', 'alias-drop':'1101', 'alias-allow':'1101',
            'rank-qname':'1101', 'query-drop':'1100', 'and':'1100110101', 'or':'1100110102',
            'not':'110103', 'sni-or':'1001110102', 'business-port':'11010cbb01bb0101'}
        expression = expressions[variant] + f'06{direction:02x}' + ('' if variant=='generic-drop' else '01')
        rank0, rank1 = (20, 10) if variant == 'rank-qname' else (10, 20)
        alias_allow = variant in ('alias-allow', 'rank-qname')
        action0, action1 = (1, 2) if alias_allow else (2, 1)
        second = f'110006{direction:02x}01' if alias_allow else f'110206{direction:02x}01'
        lines = ['lists 3', 'domain 0 exact qname.test', 'domain 1 exact alias.test',
            f'0 0 4294967295 4294967295 4294967295 {rank0} 0 {protocol} 0 {action0} * * 0 65535 0 65535 {expression}',
            f'0 0 4294967295 4294967295 4294967295 {rank1} 0 {protocol} 0 {action1} * * 0 65535 0 65535 {second}',
            '0 0 4294967295 4294967295 4294967295 100 0 0 0 1 * * 0 65535 0 65535',
            'group 10', 'edge 10 1 0', 'group 20', 'edge 20 1 1', 'group 30', 'edge 30 1 2',
            f'bind 1 {subject} 2 10 {mode}', f'bind 2 {subject} 2 20 0', f'bind 3 {subject} 2 30 0']
        self.rule_expected=dict(expressions=[expression,second,''],ranks=[rank0,rank1,100],
            actions=[action0,action1,1],mode=mode,subject=subject)
        self.save(label+'-expected-config.json',json.dumps(self.rule_expected,indent=2)+'\n')
        request = self.out / (label + '-request.txt'); request.write_text('\n'.join(lines) + '\n')
        remote = '/data/local/tmp/s313-rules.txt'; self.adb('push', request, remote)
        command = f'am start -n {PKG}/.DebugControlActivity --es completeRuleText "$(cat {remote})"'
        self.save(label + '-prefill.txt', self.adb('shell', 'sh', '-c', shlex.quote(command)))
        self.adb('shell', 'rm', remote)
        if prefill_only: return self.tap(label + '-point', 'Replace all rules', click=False)
        old = props(self.app(path)).get('queryElapsedMillis')
        self.tap(label + '-replace', 'Replace all rules')
        status=self.applied(label, old)
        self.verify_config(label,status)
        return status

    def verify_config(self,label,status):
        expected=self.rule_expected
        assert status['result']=='0' and status['savedRevision']==status['activeRevision']
        assert status['count']==status['activeCount']=='3'
        for index,expression in enumerate(expected['expressions']):
            row=list(map(int,status[f'rule.{index}.wire'].split(',')))
            actual=b''.join(word.to_bytes(4,'big') for word in row[27:])[:row[26]].hex()
            assert actual==expression,(label,index,'compiled expression',actual,expression)
            assert row[5]==expected['ranks'][index] and row[10]==expected['actions'][index]
        assert status['binding.0']==f'1,{expected["subject"]},2,10,{expected["mode"]}'
        self.save(label+'-config-ack.json',json.dumps(dict(revision=int(status['activeRevision']),
            expected=expected,source_sha256=digest(self.out/(label+'-source.conf'))),indent=2)+'\n')

    def observation_matching(self,label,predicate,timeout=5):
        attempts=[];deadline=time.monotonic()+timeout
        previous=getattr(self,'capture_deadline',None)
        if previous is not None:self.capture_deadline=min(previous,deadline)
        try:
            while True:
                capture=label+'-capture-'+str(len(attempts))
                observed=self.observation(capture)
                attempts.append(capture+'-observation.json')
                if predicate(observed): break
                assert time.monotonic()<deadline,'normal decision did not arrive before bounded capture deadline'
        finally:
            if previous is not None:self.capture_deadline=previous
        # query_fresh acknowledges a real API query, not that asynchronous
        # producer export has caught up. Retain each result and copy the first
        # qualifying snapshot verbatim; never merge synthetic recent rows.
        (self.out/(label+'-observation.json')).write_bytes((self.out/attempts[-1]).read_bytes())
        self.save(label+'-observation-captures.json',json.dumps(attempts,indent=2)+'\n')
        return observed

    def launch_tcp(self, label, address, source, wires, *, split=False, pipeline=False, repeat=1,
                   timeout=1000, preserve_ui=False, hold=False):
        nonce = 's313-' + label + '-' + str(time.time_ns())
        # The first real VPN query warms only attribution on this socket.
        # A later pipeline write still contains the actual target and collateral
        # frames together; no fixture assigns or fabricates an App UID.
        warm_pipeline = self.profile=='vpn' and pipeline
        plan = dict(nonce=nonce, endpoint=address, port=53, source=source, bindDefault=True,
            dnsTcpQueries=[wire.hex() for wire in wires], dnsTcpRepeat=repeat, dnsTimeoutMs=timeout,
            dnsQueryDelayMs=0 if repeat > 1 else 150 if self.profile=='vpn' else 50, dnsTcpPipeline=pipeline,
            dnsTcpWriteSizes=[len(wires[0])+2] if warm_pipeline else [1, 8] if split else [],
            dnsTcpWriteDelayMs=200 if warm_pipeline else 40 if split else 0,
            dnsTcpHoldAfterReads=hold)
        self.save(label + '-plan.json', json.dumps(plan, indent=2) + '\n')
        if preserve_ui: self.adb('shell', 'input', 'keyevent', '3')
        flags = ['-f', '0x18000000'] if preserve_ui else []
        if hold: self.active_probe=nonce
        self.save(label + '-launch.txt', self.action(*flags, '--es', 't12ProbePlan', shlex.quote(json.dumps(plan))))
        if preserve_ui: self.save(label + '-return-ui.txt', self.action())
        return nonce

    def wire_start(self):
        source = ROOT / 'tests/device/helpers/s313_dns_wire.c'
        binary = self.out / 's313-wire'
        subprocess.run([str(self.args.cc), '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)], check=True)
        self.adb('push', binary, '/data/local/tmp/s313-wire'); self.adb('shell', 'chmod', '755', '/data/local/tmp/s313-wire')
        assert self.adb('shell', 'sha256sum', '/data/local/tmp/s313-wire').split()[0] == digest(binary)
        self.adb('shell', 'rm', '-f', '/data/local/tmp/s313-wire.stop', '/data/local/tmp/s313-wire.jsonl')
        command = ('/data/local/tmp/s313-wire wlan0 /data/local/tmp/s313-wire.stop '
            + ' '.join(map(shlex.quote, [self.args.endpoint4, self.args.endpoint6, '1.1.1.1', '2606:4700:4700::1111']))
            + ' > /data/local/tmp/s313-wire.jsonl 2>&1 < /dev/null & echo $!')
        self.witness_pid = int(self.save('witness-start.txt',self.root(command)).strip())
        for _ in range(30):
            if '"kind":"ready"' in self.adb('shell', 'cat', '/data/local/tmp/s313-wire.jsonl', check=False): return
            time.sleep(.1)
        raise RuntimeError('TCP underlay witness did not start')

    def wire(self, label):
        raw = self.save(label + '-underlay.jsonl', self.adb('shell', 'cat', '/data/local/tmp/s313-wire.jsonl'))
        return [json.loads(line) for line in raw.splitlines() if line.startswith('{')]

    def wire_stop(self):
        if not self.witness_pid: return
        self.adb('shell', 'touch', '/data/local/tmp/s313-wire.stop')
        for _ in range(30):
            rows = self.wire('final')
            if any(row.get('kind') == 'stopped' for row in rows): break
            time.sleep(.1)
        else: raise RuntimeError('TCP witness stop absent')
        processes=self.save('witness-process-after.txt', self.root('ps -A -o PID,UID,ARGS'))
        assert not any(line.split() and line.split()[0]==str(self.witness_pid) for line in processes.splitlines()), 'owned TCP witness PID remains after stop acknowledgement'
        self.adb('shell', 'rm', '-f', '/data/local/tmp/s313-wire', '/data/local/tmp/s313-wire.stop',
            '/data/local/tmp/s313-wire.jsonl', '/data/local/tmp/s313-rules.txt')
        self.witness_pid = None


def stream_frames(rows, source, outgoing):
    """Independent TCP byte positions; ignore identical retransmissions, reject conflicts."""
    selected = [r for r in rows if r.get('kind') == 'tcp'
        and r['source_port' if outgoing else 'destination_port'] == source
        and r['destination_port' if outgoing else 'source_port'] == 53]
    anchors = [r['sequence'] for r in selected if r['flags'] & 2]
    assert anchors, ('missing actual TCP handshake', source, outgoing)
    start = (anchors[0] + 1) & 0xffffffff
    positions = {}
    for row in selected:
        for offset, value in enumerate(bytes.fromhex(row['payload_hex'])):
            position = (row['sequence'] + bool(row['flags'] & 2) + offset - start) & 0xffffffff
            assert position < 2**31
            assert position not in positions or positions[position] == value, 'wire overlap conflict'
            positions[position] = value
    wire = bytearray(); cursor = 0
    while cursor in positions:
        wire.append(positions[cursor]); cursor += 1
    frames, at = [], 0
    while at + 2 <= len(wire):
        size = int.from_bytes(wire[at:at+2], 'big')
        if at + 2 + size > len(wire): break
        frames.append(bytes(wire[at+2:at+2+size]).hex()); at += 2 + size
    return dict(frames=frames, contiguous_bytes=len(wire), trailing_bytes=len(wire)-at,
        observed_bytes=len(positions), packets=len(selected))


class Qualification:
    def __init__(self, device, peer, result):
        self.d, self.peer, self.result = device, peer, result
        self.identifier = 24000

    def exchange(self, label, address, status, *, denied=False, query_drop=False,
                 winner=2, variant='alias', qtype=1, split=True, pipeline=False,
                 repeat=1, long_name=False, hot=False, coverage=1, aliases=1,
                 observe=False, collateral=False, chain_status=0, reply_copies=1, warm_name='allowed.test', padding=0):
        d = self.d
        if not self.wanted(label): return status
        source = d.reserve_source_port(label)
        target = ('.'.join(['a'*60]*3 + ['b'*50,'test'])) if long_name else 'qname.test'
        names = [warm_name, target, 'allowed.test'] if collateral else ([warm_name,target] if d.profile=='vpn' else [target])
        wires=[]; replies=[]
        early_history=aliases>=32
        gate = d.out / (label+'.gate') if hot or early_history else None
        warm_gate = d.out / (label+'.warm.gate') if d.profile=='vpn' and repeat>1 else None
        target_index = 1 if collateral or d.profile=='vpn' else 0
        for index,name in enumerate(names):
            self.identifier += 1
            request=fixtures.question(self.identifier,name,qtype if index==target_index else 1,
                edns=index==target_index and qtype==65,padding=padding if index==target_index else 0)
            reply,_=fixtures.answer(request,variant if index==target_index else 'ordinary',aliases=aliases)
            wires.append(request); replies.append(reply)
            self.peer.register(request,reply,gate if index==target_index else warm_gate if index==0 else None,split=split,copies=reply_copies if index==target_index else 1)
        target_id=0 if variant=='short' else int.from_bytes(wires[target_index][:2],'big')
        def normal_records(observed):
            return [row['record'] for row in observed['consumer']['persistent']['dns']['recent'].values()
                if row['record']['generation']==d.generation and row['record']['source_port']==source]
        def decision_ready(observed):
            rows=[r for r in normal_records(observed) if r['stage']==(1 if query_drop else 2)
                and r['id']==target_id and r['coverage']==coverage and not r['tcp_continuation']]
            if reply_copies==2: return {r['message_sequence'] for r in rows}=={target_index+1,target_index+2}
            if variant in ('alias','long') and coverage==1 and not query_drop:
                return any(r['name']=='alias.test' and r['name_index']==aliases for r in rows)
            return bool(rows)
        before = d.cli(label+'-before','show product dns','show product batch')
        with self.peer.lock:
            previous_connections = {r['connection'] for r in self.peer.messages if r.get('kind')=='connected'}
        old_status=status
        if hot:
            d.configure(label+'-hot-prefill','alias-drop',prefill_only=True)
            old_stamp=props(d.app('files/product-state/complete-rule-config.properties')).get('queryElapsedMillis')
        nonce=d.launch_tcp(label,address,source,wires,split=split,pipeline=pipeline,repeat=repeat,
            timeout=3000 if hot or early_history or warm_gate else 600,preserve_ui=hot,hold=True)
        early_observation=None;query_records=[]
        try:
            # The ordinary App holds its completed socket for 60s. Bound the
            # whole capture route, including failed reads, UI/CLI and snapshots,
            # to 40s, then reserve a separate bounded release attempt.
            d.capture_deadline=time.monotonic()+40
            if warm_gate:
                # Give the real asynchronous resolver its initial interval.
                # Packet history cannot expose enrichment until another packet
                # arrives, so do not make the reply depend on that history.
                deadline=time.monotonic()+2
                while not self.peer.received(wires[0]):
                    assert time.monotonic()<deadline,'initial warm query absent at peer'
                    time.sleep(.01)
                time.sleep(.2)
                warm_gate.touch()
            if hot or early_history:
                deadline=time.monotonic()+5
                while not self.peer.received(wires[target_index]):
                    assert time.monotonic()<deadline,'gated query absent at independent peer'
                    time.sleep(.01)
            if hot:
                d.tap(label+'-hot-current-ui','Replace all rules')
                status=d.applied(label+'-hot',old_stamp,previous_revision=int(old_status['activeRevision']))
                d.verify_config(label+'-hot',status)
                gate.touch()
            if early_history:
                query_observation=d.observation_matching(label+'-query',lambda observed:any(
                    r['stage']==1 and r['coverage']==1 and r['id']==target_id for r in normal_records(observed)))
                query_records=normal_records(query_observation)
                gate.touch()
                deadline=time.monotonic()+5
                while True:
                    with self.peer.lock:
                        answered=any(r.get('request_hex')==wires[target_index].hex() for r in self.peer.rows)
                    if answered: break
                    assert time.monotonic()<deadline,'gated answer absent at independent peer'
                    time.sleep(.01)
                # A 33-name reply and its retransmission continuations can fill
                # the normal 128-row recent view. Freeze the normal query and
                # first reply snapshots separately, preserving that real bound.
                early_observation=d.observation_matching(label,decision_ready)
            client=d.wait(label+'-client-open','files/product-state/t12-'+nonce+'.json',
                lambda c: c.get('phase') in ('dns_tcp_read_complete','finished'),
                timeout=max(35,min(120,repeat*.25)),json_value=True)
            assert client['phase']=='dns_tcp_read_complete' and not client.get('error'), (
                label, 'ordinary App failed before observation capture', client)
            native=d.cli(label+'-after','show product dns','show product batch','show product completion')
            wire=d.wire(label)
            observed=early_observation or d.observation_matching(label,decision_ready)
            # Freeze the independent peer alongside these active-socket inputs.
            with self.peer.lock:
                peer_messages=list(self.peer.messages); peer_rows=list(self.peer.rows)
                # Freeze the independent peer prefix before releasing the
                # ordinary App socket; retain its complete final log too.
                d.save(label+'-peer-active.jsonl',''.join(
                    json.dumps(row,separators=(',',':'))+'\n' for row in peer_messages))
            frozen_ns=time.time_ns()
        finally:
            d.capture_deadline=None
            d.release_probe(label,nonce)
        finished=d.client(label,nonce)
        d.active_probe=None
        assert finished['dnsExchanges']==client['dnsExchanges']
        expected=(wires*repeat); expected_replies=(replies*repeat)
        assert len(client['dnsExchanges'])==len(expected)
        for index,(row,request,reply) in enumerate(zip(client['dnsExchanges'],expected,expected_replies)):
            blocked=denied and index>=target_index
            assert row['sentHex']==request.hex()
            if blocked: assert row.get('timedOut') and 'replyHex' not in row,(label,index,row)
            else: assert row.get('replyHex')==reply.hex() and not row.get('timedOut'),(label,index,row)
        connections=[r for r in peer_messages if r.get('kind')=='connected' and r['connection'] not in previous_connections]
        assert len(connections)==1,(label,'one actual original Direct connection',connections)
        connection=connections[0]
        wire_source=int(connection['peer'].rsplit(':',1)[1])
        if d.profile=='root': assert wire_source==source
        outbound=stream_frames(wire,wire_source,True); inbound=stream_frames(wire,wire_source,False)
        accepted=target_index if query_drop else target_index+1 if denied else len(expected)
        received=[r for r in peer_messages if r.get('kind')=='received' and r['connection']==connection['connection']]
        sent=[r for r in peer_rows if r['connection']==connection['connection']]
        assert all(r['resolver']==[address,53] for r in received+sent),(label,'original resolver changed')
        assert [r['request_hex'] for r in received]==[w.hex() for w in expected[:accepted]],(label,received)
        assert [r['reply_hex'] for r in sent]==[w.hex() for w in expected_replies[:accepted]],(label,sent)
        assert outbound['frames']==[w.hex() for w in expected[:accepted]],(label,outbound)
        assert inbound['frames']==[w.hex() for index,w in enumerate(expected_replies[:accepted]) for _ in range(reply_copies if index%len(wires)==target_index else 1)],(label,inbound)
        records=[r['record'] for r in observed['consumer']['persistent']['dns']['recent'].values()
            if r['record']['generation']==d.generation and r['record']['source_port']==source]
        assert records,(label,'normal SQLite records absent')
        complete=[r for r in records if r['coverage']==coverage and not r['tcp_continuation']]
        for r in records:
            assert r['protocol']==6 and r['family']==(6 if ':' in address else 4)
            assert r['adapter_profile']==(1 if d.profile=='root' else 2) and 0<=r['owner']<d.owners
            assert r['incarnation']>0
            if r['coverage']==1:
                if d.profile=='vpn' and r['id']==int.from_bytes(wires[0][:2],'big') and r['caller']==0:
                    assert not r['domain_available'] and r['uid']==4294967295
                else: assert r['caller']==1 and r['uid']==d.uid
            if r['coverage']>=6: assert not r['domain_available'] and not r['name']
        target_rows=[r for r in complete if r['id']==target_id and r['stage']==(1 if query_drop else 2)]
        assert target_rows,(label,'target normal decision absent',records)
        if reply_copies==2:
            assert len(target_rows)==2 and {r['message_sequence'] for r in target_rows}=={target_index+1,target_index+2},(label,target_rows)
            assert len({r['token'] for r in target_rows})==1,(label,'malformed frames were not coalesced at Root')
            combined=(len(replies[target_index]).to_bytes(2,'big')+replies[target_index])*2
            assert any(r.get('kind')=='tcp' and r['destination_port']==wire_source
                and r['payload_hex']==combined.hex() for r in wire),(label,'actual one-packet coalescing absent')
        for r in target_rows:
            assert r['actual_action']==(2 if denied else 1),(label,r)
            expected_winner=int(status[f'rule.{winner}.version'])
            assert r['winner']==expected_winner,(label,'winner',expected_winner,r)
            assert r['policy_revision']==int(status['activeRevision']),(label,r)
            assert r['chain_status']==chain_status,(label,r)
            if observe: assert r['mode']==1 and r['declared_action']==2
            if r['stage']==2 and coverage==1:
                queries=[q for q in (query_records or records) if q['stage']==1 and q['coverage']==1 and not q['tcp_continuation']
                    and q['id']==target_id and q['message_sequence']==r['message_sequence']]
                if repeat==1:
                    assert len(queries)==1,(label,queries)
                    q=queries[0]
                    assert r['correlation']==1 and r['query_token']==q['token']
                    assert r['query_incarnation']==q['incarnation'] and r['query_policy_revision']==q['policy_revision']
                    assert q['policy_revision']==int(old_status['activeRevision'])
                    if d.profile=='vpn': assert r['transport_session'] and r['underlay_epoch']
        if denied and collateral:
            assert any(r['tcp_continuation'] and r['actual_action']==2 for r in records),label
        self.result['cases'].append(dict(label=label,profile=d.profile,generation=d.generation,owner_count=d.owners,
            wire_source_port=wire_source,peer_connection=connection,
            address=address,source_port=source,policy=status,query_policy=old_status,denied=denied,
            query_drop=query_drop,winner=winner,variant=variant,coverage=coverage,
            chain_status=chain_status,
            query_records=query_records,
            reply_copies=reply_copies,
            messages=len(expected),active_socket_frozen_ns=frozen_ns,peer_messages=received,peer_replies=sent,wire_out=outbound,wire_in=inbound,records=records,
            app_sha256=digest(d.out/(label+'-client.json'))))
        (d.out/'progress.json').write_text(json.dumps(self.result,indent=2)+'\n')
        print(label,'PASS',flush=True)
        return status

    def wanted(self, label):
        return re.search(self.d.args.case_filter,label) is not None

    def boundaries(self, owners):
        status=self.d.configure(f'n{owners}-boundaries','alias-drop')
        cases=[('long',32,1,0,0,True),('overflow',33,4,3,2,False),
            ('loop',1,2,1,2,False),('unrelated',1,1,0,2,False),
            ('tc',1,5,0,2,False),('malformed',1,2,0,2,False),
            ('short',1,2,0,2,False),('nxdomain',1,1,0,2,False)]
        if owners==3: cases=[cases[0],cases[6]]
        for variant,aliases,coverage,chain,winner,denied in cases:
            for family,address in ((4,self.d.args.endpoint4),(6,self.d.args.endpoint6)):
                self.exchange(f'n{owners}-boundary-{variant}-v{family}',address,status,
                    variant=variant,aliases=aliases,coverage=coverage,chain_status=chain,
                    winner=winner,denied=denied,collateral=variant in ('short','malformed'),
                    pipeline=variant in ('short','malformed'),split=False)

    def coalesced_errors(self, owners):
        status=self.d.configure(f'n{owners}-coalesced-errors','alias-drop')
        for family,address in ((4,self.d.args.endpoint4),(6,self.d.args.endpoint6)):
            self.exchange(f'n{owners}-coalesced-short-v{family}',address,status,
                variant='short',coverage=2,reply_copies=2,split=False)

    def full(self, owners):
        d=self.d
        addresses=((4,d.args.endpoint4),(6,d.args.endpoint6))
        groups=[('query-drop',True,0,'ordinary',3,0),('alias-drop',True,0,'alias',1,0),
            ('alias-allow',False,0,'alias',1,0),('rank-qname',True,1,'alias',1,0),
            ('and',False,2,'alias',1,0),('or',True,0,'alias',1,0),
            ('not',True,0,'ordinary',1,0),('sni-or',False,2,'alias',1,0),
            ('business-port',False,2,'alias',1,0),('alias-drop',False,0,'alias',1,1)]
        if owners==3: groups=[groups[0],groups[1],groups[4],groups[-1]]
        for index,(policy,denied,winner,variant,direction,mode) in enumerate(groups):
            label=f'n{owners}-g{index}-{policy}'+('-observe' if mode else '')
            if not any(self.wanted(label+f'-v{family}') for family,_ in addresses): continue
            status=d.configure(label,policy,direction=direction,mode=mode)
            for family,address in addresses:
                self.exchange(label+f'-v{family}',address,status,denied=denied,winner=winner,variant=variant,
                    query_drop=policy=='query-drop',observe=bool(mode),
                    collateral=policy in ('query-drop','alias-drop') and not mode,
                    warm_name='alias.test' if policy=='not' else 'allowed.test')
        if not any(self.wanted(f'n{owners}-'+kind+f'-v{family}') for family,_ in addresses
                for kind in ('rr1','rr28','rr16','rr15','rr33','rr65','rr65000','pipeline','continuous','hot')): return
        status=d.configure(f'n{owners}-compat','allow')
        kinds=(1,28,16,15,33,65,65000) if owners==1 else (65,)
        for kind in kinds:
            for family,address in addresses:
                self.exchange(f'n{owners}-rr{kind}-v{family}',address,status,qtype=kind,
                    variant='unrelated',split=False,pipeline=True)
        for family,address in addresses:
            self.exchange(f'n{owners}-pipeline-v{family}',address,status,variant='ordinary',split=False,
                pipeline=True,collateral=True)
            self.exchange(f'n{owners}-continuous-v{family}',address,status,variant='ordinary',split=False,
                repeat=64,long_name=True,padding=1024)
            self.exchange(f'n{owners}-hot-v{family}',address,status,hot=True,denied=True,winner=0)
            if self.wanted(f'n{owners}-hot-v{family}'):
                status=d.configure(f'n{owners}-after-hot-v{family}','allow')


def main(task='SAKAMOTO-313'):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('apk', 'stage', 'backup', 'output', 'cc'): parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--endpoint4', required=True); parser.add_argument('--endpoint6', required=True)
    parser.add_argument('--profile', choices=('root','vpn'), default='root')
    parser.add_argument('--owners', choices=('1','3','1,3'), default='1')
    parser.add_argument('--case-set', choices=('smoke','full','boundaries','coalesced-errors'), default='smoke')
    parser.add_argument('--installed', action='store_true')
    parser.add_argument('--case-filter',default='.*')
    args = parser.parse_args()
    for key in ('apk','stage','backup','output','cc'): setattr(args,key,getattr(args,key).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    assert json.loads((args.backup/'manifest.json').read_text())['generation'] >= 2603
    result = dict(status='HOLD', task=task, profile=args.profile, started_ns=time.time_ns(), cases=[], runs=[],
        apk_sha256=digest(args.apk), runner_sha256=digest(__file__), serial=SERIAL,
        adb_transport=dict(wrapper_sha256=digest(ROOT/'dev/adb'),override=os.environ.get('SAKAMOTO_ADB',''),
            override_sha256=digest(os.environ['SAKAMOTO_ADB']) if os.environ.get('SAKAMOTO_ADB') else ''),
        helpers_sha256={name:digest(ROOT/'tests/device/helpers'/name) for name in
            ('s313_dns_peer.ps1','s313_dns_wire.c','s312_dns_fixtures.py')})
    for path in (Path(__file__), ROOT/'tests/device/s312-dns-response.py',
                 ROOT/'tests/device/s233-fail-open.py',
                 ROOT/'tests/device/helpers/s313_dns_peer.ps1',ROOT/'tests/device/helpers/s313_dns_wire.c',
                 ROOT/'tests/device/helpers/s312_dns_fixtures.py'):
        (args.output/('source-'+path.name)).write_bytes(path.read_bytes())
    if task=='SAKAMOTO-314':
        (args.output/'source-s314-original-dns-tcp.py').write_bytes((ROOT/'tests/device/s314-original-dns-tcp.py').read_bytes())
    device, peer = Device(args), None
    try:
        result['native_sha256'] = device.install(); result['uid'] = device.uid
        peer = Peer([args.endpoint4,args.endpoint6], args.output)
        device.wire_start()
        qualification=Qualification(device,peer,result)
        for owners in map(int,args.owners.split(',')):
            run = device.start(owners); result['runs'].append(run)
            if args.case_set=='coalesced-errors':
                qualification.coalesced_errors(owners)
                run.update(device.stop(f'n{owners}'))
                continue
            if args.case_set=='boundaries':
                qualification.boundaries(owners)
                run.update(device.stop(f'n{owners}'))
                continue
            if args.case_set=='full':
                qualification.full(owners)
                run.update(device.stop(f'n{owners}'))
                continue
            status = device.configure(f'n{owners}-allow', 'allow')
            for family, address in ((4,args.endpoint4),(6,args.endpoint6)):
                label = f'n{owners}-v{family}-split'
                source = device.reserve_source_port(label)
                wires = [fixtures.question(21000+len(result['cases'])*3+i, name)
                    for i,name in enumerate(('allowed.test','qname.test','allowed.test'))]
                replies = [fixtures.answer(wire, 'ordinary')[0] for wire in wires]
                for request, reply in zip(wires,replies): peer.register(request,reply,split=True)
                nonce = device.launch_tcp(label,address,source,wires,split=True)
                client = device.client(label,nonce)
                assert [row.get('replyHex') for row in client['dnsExchanges']] == [r.hex() for r in replies], client
                observed = device.observation_matching(label,lambda observed:len([row for row in observed['consumer']['persistent']['dns']['recent'].values() if row['record']['generation']==device.generation and row['record']['source_port']==source and row['record']['coverage']==1 and not row['record']['tcp_continuation']])==6)
                records = [row['record'] for row in observed['consumer']['persistent']['dns']['recent'].values()
                    if row['record']['generation']==device.generation and row['record']['source_port']==source]
                complete = [row for row in records if row['coverage']==1 and not row['tcp_continuation']]
                assert len(complete)==6, complete
                assert all(row['protocol']==6 and row['actual_action']==1 for row in complete),complete
                first_id=int.from_bytes(wires[0][:2],'big')
                for row in complete:
                    assert row['caller']==1 or (args.profile=='vpn' and row['id']==first_id and row['caller']==0 and not row['domain_available']),row
                    if row['stage']==2:
                        query,=[q for q in complete if q['stage']==1 and q['id']==row['id']]
                        assert row['caller']==query['caller'] and row['query_token']==query['token'] and row['correlation']==1,row
                        if args.profile=='vpn': assert row['transport_session'] and row['underlay_epoch'],row
                assert observed['consumer']['malformed']==0,observed['consumer']['malformed']
                device.cli(label+'-after','show product dns','show product batch','show product completion')
                device.wire(label)
                result['cases'].append(dict(label=label,profile=args.profile,generation=device.generation,
                    owner_count=owners,address=address,source_port=source,policy=status,records=records))
            run.update(device.stop(f'n{owners}'))
        result['status']='PASS'
    except Exception as error:
        result['error']=repr(error)
        result['traceback']=traceback.format_exc()
        (args.output/'error.log').write_text(result['traceback'])
        raise
    finally:
        if device.active:
            try: device.stop('finally')
            except Exception as error: result['cleanup_error']=repr(error)
        try: device.wire_stop()
        except Exception as error: result['witness_cleanup_error']=repr(error)
        if peer:
            try: peer.close()
            except Exception as error: result['peer_cleanup_error']=repr(error)
        try: device.close_trace()
        except Exception as error: result['trace_cleanup_error']=repr(error)
        if any(key.endswith('cleanup_error') for key in result): result['status']='HOLD'
        result['completed_ns']=time.time_ns()
        (args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:result[key] for key in ('status','apk_sha256','runs')},indent=2))
    return 0 if result['status']=='PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
