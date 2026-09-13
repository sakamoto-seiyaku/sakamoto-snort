#!/usr/bin/env python3
"""Ordered startup CPUs, real NFQUEUE endpoints and native cleanup; no idle soak."""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shlex
import time

ROOT = Path(__file__).resolve().parents[2]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


base = module('s220_lifecycle', 'tests/device/s242-root-lifecycle.py')
chain = module('s220_chain', 'tests/evidence/product_chain.py')
oracle = module('s220_oracle', 'tests/device/s207-owner-oracle.py')
save, digest, rows = base.save, base.digest, base.rows
PLAN = 'docs/testing/2026-09-13_S220_WORKER_CPU_PLACEMENT.md'


def cpus(text):
    result = set()
    for part in text.strip().split(','):
        if '-' in part:
            first, last = map(int, part.split('-')); result.update(range(first, last+1))
        else: result.add(int(part))
    return result


class Campaign(base.Campaign):
    def __init__(self, args, build, helper):
        super().__init__(args, build, helper)
        self.result.update(task='SAKAMOTO-220', s220_runner_sha256=digest(__file__),
            plan_sha256=digest(ROOT/PLAN), main_cpu=args.main_cpu, worker_cpus=args.worker_cpus,
            invalid_starts=[])
        save(args.output/'s220-runner.py', Path(__file__).read_text())
        save(args.output/'plan.md', (ROOT/PLAN).read_text())

    def platform(self):
        online = save(self.args.output/'cpu-online.txt', self.target.run('cat /sys/devices/system/cpu/online').stdout)
        present = save(self.args.output/'cpu-present.txt', self.target.run('cat /sys/devices/system/cpu/present').stdout)
        status = save(self.args.output/'launcher-status.txt', self.target.run('cat /proc/self/status').stdout)
        allowed = cpus(re.search(r'^Cpus_allowed_list:\s*(.+)$', status, re.M)[1])
        selected = {self.args.main_cpu, *self.args.worker_cpus}
        assert len(selected) == 3 and selected <= cpus(online) & allowed
        assert abs(self.args.worker_cpus[0]-self.args.worker_cpus[1]) > 1, 'noncontiguous precondition'
        self.result['present_offline_cpus'] = sorted(cpus(present)-cpus(online))
        self.absent_cpu = max(cpus(present))+1

    def config(self, label, cpu):
        out = self.args.output/label; out.mkdir()
        runtime = self.target.temporary+'/'+label
        if self.target.pixel: self.target.adb('shell', 'mkdir', '-p', runtime+'/shm')
        else: self.target.run('mkdir -p '+shlex.quote(runtime+'/shm'))
        prefix = 'plugin_path '+self.target.native+'\n' if self.target.pixel else ''
        plugins = (f'path {self.target.native} plugin default {{ disable }} plugin libproduct_core_plugin.so {{ enable }}'
            if self.target.pixel else f'path {self.target.artifact}/lib/vpp_plugins plugin default {{ disable }} plugin product_core_plugin.so {{ enable }}')
        text = prefix+f'''cpu {{ {cpu} }}
unix {{ nodaemon nobanner cli-no-pager runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
socksvr {{ socket-name {runtime}/api.sock }}
api-segment {{ prefix sakamoto-s220-{label} }}
statseg {{ socket-name {runtime}/stats.sock }}
plugins {{ {plugins} }}
'''
        local = out/'startup.conf'; save(local, text)
        if self.target.pixel:
            self.target.adb('push', local, runtime+'/startup.conf')
            argv = [self.target.native+'/libvpp_runtime.so', '-c', runtime+'/startup.conf']
        else: argv = [str(self.target.artifact/'bin/vpp'), '-c', str(local)]
        environment = dict(LD_LIBRARY_PATH=self.target.native, SAKAMOTO_VPP_SVM_DIR=runtime+'/shm',
            SAKAMOTO_VPP_RUNTIME_DIR=runtime, SAKAMOTO_VPP_OWNER_TOKEN='s220-'+label,
            SAKAMOTO_RUNTIME_PROFILE='root', SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID=self.target.uid,
            SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
        return out, runtime, argv, environment

    def invalid(self):
        main, (first, second) = self.args.main_cpu, self.args.worker_cpus
        common = f'main-core {main} workers 2 '
        good = common+f'ordered-workers {first},{second}'
        cases = [
            ('empty', common+'ordered-workers', 'CPU list required', None),
            ('duplicate', common+f'ordered-workers {first},{first}', 'duplicate CPU', None),
            ('count-one', common+f'ordered-workers {first}', 'CPU count must equal', None),
            ('count-three', common+f'ordered-workers {first},{second},{self.absent_cpu}', 'CPU count must equal', None),
            ('count-missing', f'main-core {main} ordered-workers {first},{second}', 'CPU count must equal', None),
            ('main-conflict', common+f'ordered-workers {main},{first}', 'conflicts with main-core', None),
            ('absent', common+f'ordered-workers {first},{self.absent_cpu}', 'absent or offline', None),
            ('overflow', common+f'ordered-workers 4294967297,{second}', 'out of range', None),
            ('range', common+f'ordered-workers {first}-{second}', 'expected comma', None),
            ('trailing-comma', common+f'ordered-workers {first},{second},', 'expected comma', None),
            ('negative', common+f'ordered-workers -1,{second}', 'expected decimal', None),
            ('unknown', good+' unknown-setting', 'unknown CPU input', None),
            ('relative', good+' relative', 'conflict', None),
            ('pthreads', good+' use-pthreads', 'conflict', None),
            ('skip', good+' skip-cores 1', 'conflict', None),
            ('corelist', f'main-core {main} corelist-workers {first},{second} ordered-workers {first},{second}', 'conflict', None),
            ('forbidden-worker', good, 'outside inherited allowed affinity', f'{main},{first}'),
            ('forbidden-main', good, 'outside inherited allowed affinity', f'{first},{second}'),
        ]
        if self.result['present_offline_cpus']:
            cases.append(('offline', common+f'ordered-workers {first},{self.result["present_offline_cpus"][0]}',
                          'absent or offline', None))
        for index, (name, config, error, allowed) in enumerate(cases):
            out, runtime, argv, environment = self.config('invalid-'+name, config)
            environment['SAKAMOTO_PRODUCT_GENERATION'] = str(22000+index)
            if allowed:
                # Hex masks are shared by Android Toybox and util-linux;
                # Toybox on this device does not implement taskset -c.
                mask = format(sum(1 << cpu for cpu in cpus(allowed)), 'x')
                argv = ['taskset', mask, *argv]
            # Android's env treats '=' anywhere as an assignment, including
            # the randomized APK path. Stop env parsing at a plain shell name.
            command = ['timeout', '5', 'env', *[key+'='+value for key, value in environment.items()],
                       'sh', '-c', 'exec "$@"', 's220-start', *argv]
            answer = self.target.run(shlex.join(command), check=False, timeout=12)
            save(out/'native.txt', answer.stdout)
            self.target.queue_witness(out, 'after')
            self.result['invalid_starts'].append(dict(case=name, config=config, argv=command,
                expected_error=error, allowed=allowed, returncode=answer.returncode))
            assert answer.returncode not in (0, 124, 137) and error in answer.stdout, (name, answer.stdout)
            assert 's231 event=nfq_payload' not in answer.stdout
        print(json.dumps(dict(event='invalid_starts_complete', count=len(cases))), flush=True)

    def start(self, label, generation, worker_cpus):
        cpu = f'main-core {self.args.main_cpu} workers 2 ordered-workers '+','.join(map(str, worker_cpus))
        out, runtime, argv, environment = self.config(label, cpu)
        environment['SAKAMOTO_PRODUCT_GENERATION'] = str(generation)
        log = runtime+'/vpp.log'; pid = self.target.spawn(argv, log, environment)
        record = dict(label=label, generation=generation, pid=pid, runtime=runtime, logfile=log,
            partial=False, cases=[], rules=[], revision=0, clients=[], worker_cpus=worker_cpus)
        self.generations.append(record)
        save(out/'launch.json', json.dumps(dict(argv=argv, environment=environment, pid=pid), indent=2)+'\n')
        deadline = time.monotonic()+25
        while time.monotonic() < deadline:
            assert self.target.alive(pid), self.target.read(log)
            if not self.target.run('test -S '+shlex.quote(runtime+'/cli.sock'), check=False).returncode:
                lanes = rows(self.cli(record, 'ready', 'show product root lanes'), 'root.lane ')
                if len(lanes) == 4 and all(e['ready'] == '1' for e in lanes): break
            time.sleep(.05)
        else: raise RuntimeError('native startup deadline')
        self.cli(record, 'layout', 'product packet-trace limit 4096', 'show threads', 'show files')
        self.snapshot(record, 'initial'); self.affinity(record, 'initial')
        return record

    def affinity(self, record, label):
        text = self.cli(record, label+'-threads', 'show threads')
        threads = re.findall(r'^\s*(\d+)\s+(vpp_main|vpp_wk_[01])\s+(?:workers\s+)?(\d+)\s+\S+\s+\([^)]*\)\s+(\d+)\s', text, re.M)
        assert len(threads) == 3, text
        expected = [self.args.main_cpu, *record['worker_cpus']]
        for index, name, tid, core in threads:
            root = f'/proc/{record["pid"]}/task/{tid}'
            status = self.target.run('cat '+root+'/status').stdout
            stat = self.target.run('cat '+root+'/stat').stdout
            save(self.args.output/record['label']/f'{label}-thread-{index}-status.txt', status)
            save(self.args.output/record['label']/f'{label}-thread-{index}-stat.txt', stat)
            allowed = cpus(re.search(r'^Cpus_allowed_list:\s*(.+)$', status, re.M)[1])
            processor = int(stat.rsplit(')', 1)[1].split()[36])
            assert allowed == {expected[int(index)]} and int(core) == processor == expected[int(index)]

    def snapshot(self, record, label):
        text = super().snapshot(record, label)
        self.cli(record, label+'-resources', 'show product expiry', 'show product flow-end', 'show buffers detail')
        return text

    def cohort(self, record):
        gate = record['runtime']+'/traffic.go'
        record['traffic_duration_ms'] = 8000
        for protocol in ('tcp', 'udp'):
            for family in (4, 6):
                local = '127.0.0.1' if family == 4 else '::1'
                host = '127.0.0.2' if family == 4 else 'fd20:6242::2'
                self.endpoint(protocol, family, host)
                for owner in (0, 1):
                    port = 42000+(record['generation']-22020)*1000+len(record['clients'])*50
                    packed = lambda ip: ipaddress.ip_address(ip).packed.rjust(16, b'\0').hex()
                    while True:
                        facts = dict(l3=1, l4=1, family=family, protocol=6 if protocol == 'tcp' else 17,
                            src=packed(local), dst=packed(host), src_port=port, dst_port=base.PORTS[protocol], icmp_known=0)
                        if oracle.assignment(facts)['owner'] == owner: break
                        port += 1
                    nonce = f's220-{record["generation"]}-{protocol}-{family}-{owner}-{time.time_ns()}'
                    path = record['runtime']+'/traffic-'+str(len(record['clients']))+'.log'
                    argv = [self.target.helpers+'/s242-traffic', self.target.uid, protocol, str(family), local,
                        str(port), host, str(base.PORTS[protocol]), '8000', '100000', nonce, gate]
                    pid = self.target.spawn(argv, path)
                    record['clients'].append(dict(protocol=protocol, family=family, host=host,
                        source_port=port, owner=owner, nonce=nonce, pid=pid, logfile=path))
        self.target.run('touch '+shlex.quote(gate))
        time.sleep(.5)
        self.affinity(record, 'active')
        self.snapshot(record, 'before-stop')

    def run(self):
        self.platform(); self.prepare(); self.invalid()
        first = None
        for index, mapping in enumerate((self.args.worker_cpus, list(reversed(self.args.worker_cpus)))):
            record = self.start('forward' if index == 0 else 'reverse', 22020+index, mapping)
            self.policy(record, 0); self.install_rules(record)
            assert self.control(record, 'stale-stop', stop=True,
                                expected=record['generation']-1).returncode == 5
            self.snapshot(record, 'after-stale-stop')
            if first is None:
                self.seeds(record); first = record
            else:
                record['seeds'] = []
                for old in first['seeds']:
                    new = self.probe(record, old['family'], old['host'], 'cpu-swap', source_port=old['source_port'])
                    assert new['owner'] == old['owner']
                    record['seeds'].append(new)
            self.cohort(record); self.stop(record); self.finish_traffic(record)
            print(json.dumps(dict(event='generation_collected', generation=record['generation'], cpus=mapping)), flush=True)
        self.result['status'] = 'RAW_COMPLETE'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('linux', 'pixel'), required=True)
    for name in ('build', 'helpers', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--vppctl', type=Path); parser.add_argument('--main-cpu', type=int, default=0)
    parser.add_argument('--worker-cpus', default='1,3')
    args = parser.parse_args(); args.worker_cpus = list(map(int, args.worker_cpus.split(',')))
    assert len(args.worker_cpus) == 2
    for name in ('build', 'helpers', 'output'): setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert chain.source_files() == build['files']
    campaign = Campaign(args, build, helper)
    try: campaign.run()
    except Exception as error:
        campaign.result['error'] = repr(error); raise
    finally:
        try:
            if campaign.target.pixel:
                save(args.output/'app-after.properties', campaign.target.adb('shell', 'run-as',
                    base.base.PKG, 'cat', 'files/runtime-state/snapshot.properties').stdout)
        except Exception as error:
            campaign.result.update(status='HOLD', error=repr(error)); raise
        finally: campaign.cleanup()
    print(json.dumps(dict(status=campaign.result['status'], output=str(args.output))))


if __name__ == '__main__': main()
