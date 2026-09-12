#!/usr/bin/env python3
"""Real Root Q2/W2 lifecycle evidence; no graph injection or packet proxy.

Linux runs only in a disposable rootless user+network namespace. Pixel uses
exact private loopback rules while RuntimeService is stopped. The separate
RuntimeService acceptance exercises the Android supervisor, not this launcher.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s233_target', ROOT/'tests/device/s233-fail-open.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
digest, save, rows, props = base.digest, base.save, base.rows, base.props
PORTS = {'udp': 40642, 'tcp': 40643}


class Target(base.Target):
    def __init__(self, args, build, helper):
        self.owned_executables = {}
        super().__init__(args, build, helper)
        if self.pixel:
            for name in ('s222-tcp', 's242-stop', 's242-queue-holder', 's242-traffic'):
                self.adb('push', args.helpers.parent/name, self.temporary+'/'+name)
                self.run('chmod 755 '+shlex.quote(self.temporary+'/'+name))
                actual = save(args.output/(name+'-installed.txt'), self.run(
                    'sha256sum '+shlex.quote(self.temporary+'/'+name)).stdout)
                assert actual.split()[0] == helper['files'][name]

    def alive(self, pid):
        if not self.pixel:
            return self.children[pid].poll() is None
        return self.run('kill -0 '+str(pid), check=False).returncode == 0

    def spawn(self, argv, logfile, environment=None):
        pid = super().spawn(argv, logfile, environment)
        self.owned_executables[pid] = str(argv[0])
        return pid

    def stop_process(self, pid):
        if self.pixel:
            current = self.run('cat /proc/'+str(pid)+'/cmdline', check=False)
            if current.returncode and not self.alive(pid):
                return True
            executable = current.stdout.split('\0', 1)[0]
            if executable and executable != self.owned_executables[pid]:
                raise RuntimeError('refusing to signal a reused/unowned PID '+str(pid))
        return super().stop_process(pid)


class Campaign:
    def __init__(self, args, build, helper):
        self.args, self.build, self.helper = args, build, helper
        self.target = Target(args, build, helper)
        self.addresses, self.endpoints, self.generations, self.children = [], {}, [], []
        self.source_port = 32000
        self.result = dict(status='HOLD', platform=args.platform, source='NFQ_CAPTURED',
            build=str(args.build), build_sha256=digest(args.build),
            source_sha256=build['source_sha256'], helpers=str(args.helpers),
            helpers_sha256=digest(args.helpers), runner_sha256=digest(__file__),
            target_runner_sha256=digest(ROOT/'tests/device/s233-fail-open.py'),
            uid=self.target.uid, policy_uid=self.target.policy_uid,
            temporary=self.target.temporary, started_ns=time.time_ns(), generations=self.generations)
        save(args.output/'runner.py', Path(__file__).read_text())
        save(args.output/'target-runner.py', (ROOT/'tests/device/s233-fail-open.py').read_text())

    def hooks(self):
        return self.target.run('iptables-save -t mangle').stdout+self.target.run('ip6tables-save -t mangle').stdout

    def prepare(self):
        initial = save(self.args.output/'hooks-before.txt', self.hooks())
        assert 'SAKAMOTO_S242_' not in initial
        listeners = save(self.args.output/'listeners-before.txt', self.target.run('ss -lnut').stdout)
        assert not re.search(r':(?:40642|40643)\b', listeners), 'acceptance endpoint port already in use'
        save(self.args.output/'rcu-lazy.txt', self.target.run(
            'cat /sys/module/rcutree/parameters/enable_rcu_lazy', check=False).stdout)
        initial = save(self.args.output/'addresses-before.txt', self.target.run('ip -6 addr show dev lo').stdout)
        for number in range(2, 18):
            address = f'fd20:6242::{number:x}'
            if address+'/128' not in initial:
                self.target.run(f'ip -6 addr add {address}/128 dev lo nodad')
                self.addresses.append(address)

    def endpoint(self, protocol, family, host):
        key = (protocol, family, host)
        if key not in self.endpoints:
            path = self.target.temporary+'/endpoint-'+str(len(self.endpoints))+'.log'
            argv = ([self.target.helpers+'/s223-udp', 'server', self.target.uid, str(family), host, str(PORTS[protocol])]
                if protocol == 'udp' else [self.target.helpers+'/s222-tcp', 'server', str(PORTS[protocol]), host])
            pid = self.target.spawn(argv, path)
            self.endpoints[key] = (pid, path)
            deadline = time.monotonic()+5
            while 'listen ' not in self.target.read(path):
                assert time.monotonic() < deadline and self.target.alive(pid), 'endpoint did not listen'
                time.sleep(.02)
        return self.endpoints[key]

    def start(self, label, generation, partial=False):
        out = self.args.output/label
        out.mkdir()
        runtime = self.target.temporary+'/'+label if self.target.pixel else str(
            ROOT/'build-output'/f'product-vpp-runtime-s242-{self.args.output.name}-{len(self.generations)}')
        assert len((runtime+'/stats.sock').encode()) < 108, 'native Unix socket path too long'
        log = self.target.temporary+'/'+label+'-vpp.log'
        environment = dict(SAKAMOTO_PRODUCT_GENERATION=str(generation), SAKAMOTO_RUNTIME_PROFILE='root',
            SAKAMOTO_PRODUCT_ROOT_NFQUEUE_QUEUE='176', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4',
            SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID=self.target.uid)
        if self.target.pixel:
            # adb push is the shell UID; keep this test-owned staging
            # directory shell-writable before the Root VPP process starts.
            self.target.adb('shell', 'mkdir', '-p', runtime+'/shm')
            config = f'''plugin_path {self.target.native}
cpu {{ main-core 0 corelist-workers 1-2 }}
unix {{ nodaemon nobanner cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
api-segment {{ prefix sakamoto-s242-{generation} }}
statseg {{ socket-name {runtime}/statseg.sock }}
plugins {{ path {self.target.native} plugin default {{ disable }} plugin libproduct_core_plugin.so {{ enable }} }}
'''
            save(out/'startup.conf', config)
            self.target.adb('push', out/'startup.conf', runtime+'/startup.conf')
            environment.update(LD_LIBRARY_PATH=self.target.native, SAKAMOTO_VPP_SVM_DIR=runtime+'/shm',
                SAKAMOTO_VPP_RUNTIME_DIR=runtime, SAKAMOTO_VPP_OWNER_TOKEN=f's242-native-{generation}')
            argv = [self.target.native+'/libvpp_runtime.so', '-c', runtime+'/startup.conf']
        else:
            environment.update(PRODUCT_ARTIFACT_DIR=str(self.target.artifact), PRODUCT_RUNTIME_DIR=runtime,
                PRODUCT_GENERATION=str(generation), PRODUCT_WORKER_COUNT='2')
            argv = ['bash', str(ROOT/'tools/product/run-host-vpp.sh')]
        save(out/'launch.json', json.dumps(dict(argv=argv, environment=environment, runtime=runtime), indent=2)+'\n')
        pid = self.target.spawn(argv, log, environment)
        record = dict(label=label, generation=generation, pid=pid, runtime=runtime, logfile=log,
                      partial=partial, cases=[], rules=[], revision=0, clients=[])
        self.generations.append(record)
        deadline = time.monotonic()+30
        while time.monotonic() < deadline:
            assert self.target.alive(pid), self.target.read(log)
            if not self.target.run('test -S '+shlex.quote(runtime+'/cli.sock'), check=False).returncode:
                lanes = rows(self.cli(record, 'ready', 'show product root lanes'), 'root.lane ')
                if len(lanes) == 4 and all(r['ready'] == ('0' if partial else '1') for r in lanes):
                    if not partial or 'event=lane_open_failed' in self.target.read(log):
                        break
            time.sleep(.05)
        else:
            raise RuntimeError('native startup timeout '+self.target.read(log))
        self.cli(record, 'layout', 'product packet-trace limit 4096', 'show threads', 'show files')
        self.snapshot(record, 'initial')
        return record

    def cli(self, record, name, *commands):
        return save(self.args.output/record['label']/(name+'.txt'), self.target.cli(record['runtime'], commands))

    def snapshot(self, record, name):
        out = self.args.output/record['label']
        text = self.cli(record, name, 'show product root lanes', 'show product root receive',
                        'show product completion', 'show product primary', 'show product flows')
        save(out/(name+'-vpp.log'), self.target.read(record['logfile']))
        save(out/(name+'-fds.txt'), self.target.run('ls -l /proc/'+str(record['pid'])+'/fd').stdout)
        self.target.queue_witness(out, name)
        return text

    def install_rules(self, record):
        for tool, span in (('iptables', '176:177'), ('ip6tables', '178:179')):
            for protocol, port in PORTS.items():
                for hook in ('OUTPUT', 'INPUT'):
                    extra = ['--dport', str(port), '-m', 'owner', '--uid-owner', self.target.uid] if hook == 'OUTPUT' else ['--sport', str(port)]
                    rule = [tool, '-w', '5', '-t', 'mangle', '-A', hook,
                        '-o' if hook == 'OUTPUT' else '-i', 'lo', '-p', protocol, *extra,
                        '-m', 'comment', '--comment', 'SAKAMOTO_S242_'+record['label'],
                        '-j', 'NFQUEUE', '--queue-balance', span, '--queue-bypass']
                    self.target.run(shlex.join(rule))
                    record['rules'].append(rule)
        save(self.args.output/record['label']/'hooks.txt', self.hooks())

    def remove_rules(self, record):
        while record['rules']:
            rule = list(record['rules'][-1])
            rule[5] = '-D'
            self.target.run(shlex.join(rule))
            record['rules'].pop()

    def policy(self, record, mode):
        record['revision'] += 1
        argv = [self.target.helpers+'/s217-policy', record['runtime']+'/api.sock', str(record['generation']),
                record['runtime']+'/policy', str(record['revision']), str(mode), self.target.policy_uid, '0']
        answer = self.target.run('env '+shlex.quote('LD_LIBRARY_PATH='+self.target.native)+' '+shlex.join(argv))
        save(self.args.output/record['label']/f'policy-{record["revision"]}.txt', answer.stdout)
        assert 'policy rc=0 ' in answer.stdout

    def control(self, record, name, stop=False, expected=None):
        argv = [self.target.helpers+'/s242-stop', 'stop' if stop else 'query',
                record['runtime']+'/api.sock', str(record['generation'])]
        if stop:
            argv += [str(expected if expected is not None else record['generation']), '2000']
        answer = self.target.run('env '+shlex.quote('LD_LIBRARY_PATH='+self.target.native)+' '+shlex.join(argv),
                                 check=False, timeout=12)
        save(self.args.output/record['label']/(name+'.txt'), answer.stdout)
        return answer

    def probe(self, record, family, host, phase, expected=True, source_port=None):
        _, endpoint_log = self.endpoint('udp', family, host)
        if source_port is None:
            self.source_port += 1
            source_port = self.source_port
        nonce = f's242-{record["generation"]}-{len(record["cases"])}-{phase}-{time.time_ns()}'
        argv = [self.target.helpers+'/s223-udp', 'client', self.target.uid, str(family),
            '127.0.0.1' if family == 4 else '::1', str(source_port), host, str(PORTS['udp']),
            '1', nonce, '1', '3000' if expected else '150']
        answer = self.target.run(shlex.join(argv), check=False, timeout=8)
        case = dict(phase=phase, family=family, host=host, source_port=source_port,
                    nonce=nonce, expected=expected, returncode=answer.returncode)
        index = len(record['cases'])
        save(self.args.output/record['label']/f'client-{index}.txt', answer.stdout)
        endpoint = save(self.args.output/record['label']/f'endpoint-{index}.txt', self.target.read(endpoint_log))
        record['cases'].append(case)
        assert (answer.returncode == 0) == expected and ((nonce+'-0') in endpoint) == expected, case
        # Read-only log observation: no CLI barrier is used to rescue completion.
        log = self.target.read(record['logfile'])
        captured = [r for r in rows(log, 's231 ') if r.get('event') == 'nfq_payload'
                    and r.get('hook') == '3' and (nonce+'-0').encode().hex() in r['raw']]
        # Production hooks also capture an app-UID echo server's OUTPUT
        # reply. Select the actual client request tuple, not nonce alone.
        requests = []
        for capture in captured:
            wire = bytes.fromhex(capture['raw'])
            offset = (wire[0] & 15)*4 if family == 4 else 40
            if (int.from_bytes(wire[offset:offset+2], 'big') == source_port
                    and int.from_bytes(wire[offset+2:offset+4], 'big') == PORTS['udp']):
                requests.append(capture)
        captured = requests
        if phase != 'no-listener-bypass':
            assert len(captured) == 1, (case, captured)
            capture = captured[0]
            native = [r for r in rows(log, 's242 ') if r.get('event') == 'verdict_syscall'
                      and r['lane'] == capture['lane'] and r['packet'] == capture['packet']]
            verdict = [r for r in rows(log, 's203 ') if r.get('event') == 'verdict'
                       and r['lane'] == capture['lane'] and r['packet'] == capture['packet']]
            assert len(native) == len(verdict) == 1, (case, native, verdict)
            case.update(lane=int(capture['lane']), packet=int(capture['packet']), token=int(native[0]['token']),
                        owner=int(verdict[0]['owner']), origin_thread=int(native[0]['thread']),
                        syscall_result=int(native[0]['result']), syscall_errno=int(native[0]['errno']),
                        verdict=int(native[0]['verdict']))
            case['owner_path'] = 'local' if case['owner'] == case['origin_thread']-1 else 'remote'
        else:
            assert not captured, 'unbound bypass incorrectly claimed an NFQUEUE capture'
        return case

    def seeds(self, record):
        seeds = {}
        for family in (4, 6):
            for attempt in range(64):
                # Vary port parity while keeping each destination fixed for
                # two probes. Advancing both together correlated their hash
                # inputs and exercised only one final owner per family.
                number = 2+(attempt//2) % 16
                host = f'127.0.0.{number}' if family == 4 else f'fd20:6242::{number:x}'
                case = self.probe(record, family, host, 'seed')
                seeds.setdefault((case['lane'], case['owner_path']), case)
                if len([key for key in seeds if key[0]//2 == (family == 6)]) == 4:
                    break
        assert len(seeds) == 8, seeds
        record['seeds'] = list(seeds.values())
        return seeds

    def replay(self, record, old_generation=None):
        latest = {}
        for case in record['cases']:
            if 'lane' in case and case['syscall_result'] >= 0:
                latest[case['lane']] = case
        # A failed physical send has already consumed its identity too.
        # Replaying it must not deliver the old datagram by retrying verdict.
        for case in record['cases']:
            if case['phase'] == 'definite-failure':
                latest[case['lane']] = case
        old_record = None
        if old_generation is not None:
            old_record = next(r for r in self.generations if r['generation'] == old_generation)
            # Replay a real previous-generation completion identity, not a
            # made-up generation attached to an unrelated current packet.
            fields = ('lane', 'packet', 'token', 'owner', 'origin_thread', 'verdict')
            old = {tuple(c[f] for f in fields): c for c in old_record['cases']
                   if c['phase'] == 'seed' and c['syscall_result'] >= 0}
            latest = {}
            for case in record['cases']:
                if case['phase'] == 'seed' and tuple(case[f] for f in fields) in old:
                    latest.setdefault(case['lane'], case)
        assert set(latest) == set(range(4))
        record['replay_identities'] = []
        self.snapshot(record, 'before-replay')
        for lane, case in sorted(latest.items()):
            for mode in ('duplicate', 'stale'):
                command = f'product completion replay {case["packet"]} {mode} lane {lane}'
                if mode == 'stale' and old_generation is not None:
                    command += ' generation '+str(old_generation)
                text = self.cli(record, f'replay-{lane}-{mode}', command)
                assert 'completion.replay=accepted ' in text, text
                record['replay_identities'].append(dict(lane=lane, packet=case['packet'],
                    token=case['token'], owner=case['owner'], origin_thread=case['origin_thread'],
                    verdict=case['verdict'], mode=mode, old_generation=old_generation,
                    current_case=record['cases'].index(case)))
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            text = self.snapshot(record, 'after-replay')
            state = rows(text, 'completion.status ')[0]
            if state['duplicate'] == '4' and state['stale'] == '4' and state['frames'] == '0':
                return
            time.sleep(.02)
        raise RuntimeError('replayed completions did not retire')

    def traffic(self, record, gated_stop=False, gated_kill=False):
        gate = self.target.temporary+'/'+record['label']+'-traffic.go'
        tuples = [('udp', case['family'], case['host'], case['source_port']) for case in record['seeds']]
        for family in (4, 6):
            for number in range(2, 10):
                # New TCP connections are not the previous generation's
                # kernel TIME_WAIT tuple. UDP seeds deliberately retain their
                # tuples for captured old-generation identity replay.
                source_port = 35000+record.get('traffic_port_index', record['generation']-24210)*32+(family == 6)*8+number
                host = f'127.0.0.{number}' if family == 4 else f'fd20:6242::{number:x}'
                tuples.append(('tcp', family, host, source_port))
        # Prepare every listener before clients start their bounded gate wait.
        for protocol, family, host, _ in tuples:
            self.endpoint(protocol, family, host)
        if gated_stop or gated_kill:
            self.snapshot(record, 'before-gated-traffic')
            save(self.args.output/record['label']/'tcp-netstat-before.txt',
                 self.target.run('cat /proc/net/netstat').stdout)
        if gated_stop:
            stop_gate = gate+'.stop'
            path = self.target.temporary+'/'+record['label']+'-stop-client.log'
            argv = [self.target.helpers+'/s242-stop', 'stop', record['runtime']+'/api.sock',
                    str(record['generation']), str(record['generation']), '2000', stop_gate]
            pid = self.target.spawn(argv, path, {'LD_LIBRARY_PATH': self.target.native})
            record['stop_control'] = dict(pid=pid, logfile=path)
            deadline = time.monotonic()+5
            while 'stop_ready ' not in self.target.read(path):
                assert time.monotonic() < deadline and self.target.alive(pid)
                time.sleep(.02)
        if gated_stop or gated_kill:
            # Existing bounded policy delay creates real admitted backlog.
            # The stop client is already connected so its initial status
            # query cannot accidentally drain that backlog before stop.
            self.cli(record, 'hold-next', 'product policy hold-next 0 500000',
                     'product policy hold-next 1 500000')
        prime = set()
        if gated_stop or gated_kill:
            # Admit a known remote-owner datagram first. Its origin stays
            # available to enter the stop barrier while its other worker is
            # in the existing bounded policy hold. Waiting for two opposite
            # holds can serialize behind ingress on the first held owner.
            prime = {next(i for i, seed in enumerate(record['seeds'])
                          if seed['owner_path'] == 'remote' and seed['origin_thread'] == 1)}
            record['priming_clients'] = sorted(prime)
        for index, (protocol, family, host, source_port) in enumerate(tuples):
            nonce = f's242-active-{record["generation"]}-{index}'
            path = self.target.temporary+'/'+nonce+'.log'
            argv = [self.target.helpers+'/s242-traffic', self.target.uid, protocol, str(family),
                '127.0.0.1' if family == 4 else '::1', str(source_port), host, str(PORTS[protocol]),
                str(record.get('traffic_duration_ms', 15000)), '250000', nonce, gate+'.prime' if index in prime else gate]
            if gated_stop or gated_kill:
                # Kernel-owned unread SYNs can outlive queue-table removal
                # (RCU teardown), suppressing retransmit while still cloned.
                # Observe the old TCP socket separately from the unchanged
                # two-second Product drain budget; never retry an NFQ verdict.
                argv += ['20000']
            pid = self.target.spawn(argv, path)
            record['clients'].append(dict(pid=pid, logfile=path, nonce=nonce, protocol=protocol,
                family=family, host=host, source_port=source_port))
        # All endpoint processes already exist; one file releases this finite
        # kernel traffic cohort, not any Product packet or completion worker.
        command = 'touch '+shlex.quote(gate)
        if prime:
            command = 'touch '+shlex.quote(gate+'.prime')+'; s242_waits=0; '
            command += 'while [ "$(grep -c '+shlex.quote('s209 event=hold_begin ')+' '+shlex.quote(record['logfile'])+')" -lt 1 ]'
            command += ' && [ "$s242_waits" -lt 200 ]; do s242_waits=$((s242_waits+1)); sleep 0.003; done; '
            command += 'test "$s242_waits" -lt 200 && touch '+shlex.quote(gate)
        if gated_stop:
            command += ' && touch '+shlex.quote(stop_gate)
        if gated_kill:
            clock = 'env '+shlex.quote('LD_LIBRARY_PATH='+self.target.native)+' '+shlex.join(
                [self.target.helpers+'/s242-stop', 'clock'])
            command += ' && '+clock+' && kill -KILL '+str(record['pid'])+' && '+clock
        answer = self.target.run(command)
        if gated_kill:
            record['kill_sent'] = True
            save(self.args.output/record['label']/'kill-clock.txt', answer.stdout)
            save(self.args.output/record['label']/'after-kill-hooks.txt', self.hooks())
        deadline = time.monotonic()+(21 if gated_stop or gated_kill else 6)
        while time.monotonic() < deadline:
            text = self.target.run('cat '+shlex.join([c['logfile'] for c in record['clients']])).stdout
            # Steady-stop acceptance requires one actual successful echo per
            # client before stop, not merely a first attempted datagram.
            started = {r['nonce'] for r in rows(text, 'traffic ')
                       if (gated_stop or gated_kill or r['received'] == '1')}
            if all(c['nonce'] in started for c in record['clients']):
                break
            time.sleep(.02)
        else:
            out = self.args.output/record['label']
            for index, client in enumerate(record['clients']):
                save(out/f'traffic-failure-{index}.txt', self.target.read(client['logfile']))
            if record.get('stop_control'):
                save(out/'traffic-failure-stop.txt', self.target.read(record['stop_control']['logfile']))
            self.target.queue_witness(out, 'traffic-failure')
            save(out/'traffic-failure-tcp.txt', self.target.run(
                "ss -tan '( sport = :40643 or dport = :40643 )'", check=False).stdout)
            raise RuntimeError('continuous endpoints did not begin')
        if not gated_stop and not gated_kill:
            self.snapshot(record, 'active')

    def finish_traffic(self, record):
        deadline = time.monotonic()+max(20, record.get('traffic_duration_ms', 15000)/1000+5)
        for index, client in enumerate(record['clients']):
            while self.target.alive(client['pid']) and time.monotonic() < deadline:
                if 'traffic_end ' in self.target.read(client['logfile']):
                    break
                time.sleep(.05)
            text = save(self.args.output/record['label']/f'traffic-{index}.txt', self.target.read(client['logfile']))
            assert len(rows(text, 'traffic_end ')) == 1, text
            client['process_absent'] = self.target.stop_process(client['pid'])
            assert client['process_absent']
        if record.get('stop_control') or record.get('kill_sent'):
            save(self.args.output/record['label']/'tcp-netstat-after.txt',
                 self.target.run('cat /proc/net/netstat').stdout)

    def stop(self, record, abnormal=False):
        if abnormal:
            if not record.get('kill_sent'):
                self.target.run('kill -KILL '+str(record['pid']))
            record['termination'] = 'SIGKILL_OS_RECLAIM'
        else:
            if record.get('stop_control'):
                client = record['stop_control']
                deadline = time.monotonic()+8
                while time.monotonic() < deadline:
                    text = self.target.read(client['logfile'])
                    if 'client_close ' in text: break
                    time.sleep(.02)
                save(self.args.output/record['label']/'native-stop.txt', text)
                assert 'phase=stopped code=0 ' in text and 'disconnected=0 destroyed=0 ' in text, text
                assert self.target.stop_process(client['pid'])
            else:
                answer = self.control(record, 'native-stop', stop=True)
                assert answer.returncode == 0 and 'phase=stopped code=0 ' in answer.stdout, answer.stdout
            self.snapshot(record, 'native-closed')
            record['termination'] = 'DRAIN_THEN_TERM'
        self.remove_rules(record)
        absent = self.target.stop_process(record['pid'])
        record['process_absent'] = absent
        assert absent, record
        save(self.args.output/record['label']/'vpp.log', self.target.read(record['logfile']))
        self.target.queue_witness(self.args.output/record['label'], 'process-closed')

    def partial_start(self):
        path = self.target.temporary+'/foreign-queue.log'
        holder = self.target.spawn([self.target.helpers+'/s242-queue-holder', '179', '6'], path)
        self.children.append(holder)
        deadline = time.monotonic()+5
        while 'ack=0' not in self.target.read(path):
            assert time.monotonic() < deadline and self.target.alive(holder)
            time.sleep(.02)
        record = self.start('partial-start', 24200, partial=True)
        record['holder_pid'] = holder
        save(self.args.output/'partial-start'/'holder.txt', self.target.read(path))
        record['holder_survived_rollback'] = self.target.alive(holder)
        assert record['holder_survived_rollback']
        record['process_absent'] = self.target.stop_process(record['pid'])
        assert record['process_absent'] and self.target.alive(holder)
        save(self.args.output/'partial-start'/'vpp.log', self.target.read(record['logfile']))
        record['holder_process_absent'] = self.target.stop_process(holder)
        assert record['holder_process_absent']
        self.children.remove(holder)
        self.target.queue_witness(self.args.output/'partial-start', 'holder-closed')

    def run(self):
        self.prepare()
        self.partial_start()
        previous = None
        for index, label in enumerate(('faults-stop', 'restart', 'abnormal', 'recovery')):
            self.source_port = 32000
            record = self.start(label, 24210+index)
            self.install_rules(record)
            self.policy(record, 0)
            seeds = self.seeds(record)
            assert self.control(record, 'query-only').returncode == 0
            assert self.control(record, 'stale-stop', stop=True, expected=record['generation']-1).returncode == 5
            self.snapshot(record, 'after-query-and-stale-stop')
            if index == 0:
                self.policy(record, 1)
                for (lane, path), seed in sorted(seeds.items()):
                    if path == 'local':
                        case = self.probe(record, seed['family'], seed['host'], 'policy-drop', False, seed['source_port'])
                        assert case['lane'] == lane and case['verdict'] == 0
                self.policy(record, 0)
                for (lane, path), seed in sorted(seeds.items()):
                    if path == 'local':
                        text = self.cli(record, 'arm-'+str(lane), f'product root verdict-fault {lane}')
                        assert 'root.verdict_fault=armed ' in text
                        case = self.probe(record, seed['family'], seed['host'], 'definite-failure', False, seed['source_port'])
                        assert case['lane'] == lane and case['syscall_result'] == -1 and case['syscall_errno'] > 0
                        case = self.probe(record, seed['family'], seed['host'], 'verdict-recovery', True, seed['source_port'])
                        assert case['lane'] == lane and case['syscall_result'] >= 0
            if index != 2:
                self.replay(record, previous)
            self.traffic(record, gated_stop=index == 1, gated_kill=index == 2)
            self.stop(record, abnormal=index == 2)
            self.finish_traffic(record)
            for family in (4, 6):
                seed = next(case for case in record['seeds'] if case['family'] == family)
                self.probe(record, family, seed['host'], 'no-listener-bypass')
            previous = record['generation']
            print(self.args.platform, label, 'raw lifecycle complete', flush=True)
        self.result['status'] = 'RAW_COMPLETE'

    def cleanup(self):
        for record in reversed(self.generations):
            if record.get('stop_control') and self.target.alive(record['stop_control']['pid']):
                self.target.stop_process(record['stop_control']['pid'])
            for client in record['clients']:
                if self.target.alive(client['pid']):
                    self.target.stop_process(client['pid'])
            self.remove_rules(record)
            if self.target.alive(record['pid']):
                self.target.stop_process(record['pid'])
            save(self.args.output/record['label']/'vpp.log', self.target.read(record['logfile']))
        for pid in self.children:
            self.target.stop_process(pid)
        self.result['endpoint_cleanup'] = []
        for index, (key, (pid, path)) in enumerate(self.endpoints.items()):
            absent = self.target.stop_process(pid)
            self.result['endpoint_cleanup'].append(dict(protocol=key[0], family=key[1], host=key[2], pid=pid, process_absent=absent))
            save(self.args.output/f'endpoint-final-{index}.txt', self.target.read(path))
        for address in self.addresses:
            self.target.run(f'ip -6 addr del {address}/128 dev lo')
        save(self.args.output/'addresses-after.txt', self.target.run('ip -6 addr show dev lo').stdout)
        save(self.args.output/'hooks-after.txt', self.hooks())
        save(self.args.output/'processes-after.txt', self.target.run('ps -A -o PID,NAME,ARGS' if self.target.pixel else 'ps -eo pid,comm,args').stdout)
        self.result['completed_ns'] = time.time_ns()
        self.result['raw_hashes'] = {str(path.relative_to(self.args.output)): digest(path)
            for path in self.args.output.rglob('*') if path.is_file() and path.name != 'result.json'}
        save(self.args.output/'result.json', json.dumps(self.result, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('linux', 'pixel'), required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--helpers', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--vppctl', type=Path)
    args = parser.parse_args()
    for name in ('build', 'helpers', 'output'):
        setattr(args, name, getattr(args, name).resolve())
    if args.platform == 'linux':
        assert args.vppctl
        args.vppctl = args.vppctl.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert helper['build_sha256'] == digest(args.build) and helper['platform'] == args.platform
    for name, expected in helper['files'].items():
        assert digest(args.helpers.parent/name) == expected, name
    campaign = Campaign(args, build, helper)
    try:
        campaign.run()
    except Exception as error:
        campaign.result['error'] = repr(error)
        raise
    finally:
        campaign.cleanup()


if __name__ == '__main__':
    main()
