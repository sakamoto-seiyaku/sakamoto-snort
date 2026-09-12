#!/usr/bin/env python3
"""Real Root RuntimeService/JNI stop and external native-death acceptance.

Uses installed production hooks and independent kernel TCP/UDP endpoints.
The native-only S242 collector is a separate, complementary evidence scope.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s242_native', ROOT/'tests/device/s242-root-lifecycle.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
save, digest, rows, props = native.save, native.digest, native.rows, native.props
PKG = native.base.PKG
BASE = '/data/user/0/'+PKG+'/files/profiles/root/vpp'
STATE = 'files/runtime-state/snapshot.properties'


class Campaign(native.Campaign):
    def __init__(self, args, build, helper):
        super().__init__(args, build, helper)
        self.result.update(scope='Pixel-Root-RuntimeService-JNI-active-stop-and-native-death',
                           supervisor_runner_sha256=digest(__file__))
        save(args.output/'supervisor-runner.py', Path(__file__).read_text())

    def app(self, path):
        return self.target.adb('shell', 'run-as', PKG, 'cat', path, check=False).stdout

    def action(self, *extras):
        return self.target.adb('shell', 'am', 'start', '-n', PKG+'/.DebugControlActivity', *extras).stdout

    def policy(self, record, mode):
        record['revision'] += 1
        # The independent Root control helper must not create root-owned
        # subdirectories inside RuntimeService's app-owned profile tree.
        files = self.target.temporary+'/'+record['label']+'-policy'
        argv = [self.target.helpers+'/s217-policy', record['runtime']+'/api.sock', str(record['generation']),
                files, str(record['revision']), str(mode), self.target.policy_uid, '0']
        answer = self.target.run('env '+shlex.quote('LD_LIBRARY_PATH='+self.target.native)+' '+shlex.join(argv))
        save(self.args.output/record['label']/f'policy-{record["revision"]}.txt', answer.stdout)
        assert 'policy rc=0 ' in answer.stdout

    def wait_state(self, record, name, predicate):
        deadline = time.monotonic()+60
        while time.monotonic() < deadline:
            text = save(self.args.output/record['label']/(name+'.poll'), self.app(STATE))
            state = props(text)
            if predicate(state):
                save(self.args.output/record['label']/(name+'.properties'), text)
                return state
            if state.get('errorCode') == 'root_authorization_required':
                raise RuntimeError('KernelSU app grant needs restoring')
            time.sleep(.1)
        raise RuntimeError('RuntimeService state deadline '+str(state))

    def start_app(self, label, index):
        out = self.args.output/label
        out.mkdir()
        record = dict(label=label, runtime=BASE+'/runtime', logfile=BASE+'/logs/vpp-stdout.log',
                      partial=False, cases=[], rules=[], revision=100, clients=[], traffic_port_index=index,
                      traffic_duration_ms=30000)
        self.generations.append(record)
        # A prior idle query service must finish retiring before a new owner
        # starts; this is not a native packet-path wait or rescue query.
        deadline = time.monotonic()+10
        while True:
            services = self.target.adb('shell', 'dumpsys', 'activity', 'services', PKG).stdout
            if not any('ServiceRecord{' in line and '.RuntimeService' in line for line in services.splitlines()):
                break
            assert time.monotonic() < deadline, 'previous RuntimeService has not retired'
            time.sleep(.1)
        save(out/'start.txt', self.action('--ez', 'runtimeStart', 'true', '--es', 'runtimeProfile', 'root'))
        state = self.wait_state(record, 'running', lambda s: s.get('state') == 'running'
            and s.get('protectionRunning') == 'true' and not s.get('errorCode'))
        record.update(generation=int(state['generation']))
        owner = props(save(out/'owner.properties', self.target.read(BASE+'/owner.properties')))
        processes = save(out/'processes-before.txt', self.target.run('ps -A -o PID,UID,ARGS').stdout)
        candidates = [int(fields[0]) for line in processes.splitlines()
            if len(fields := line.split(None, 2)) == 3 and fields[0].isdigit() and fields[1] == '0'
            and Path(fields[2].split()[0]).name == 'libvpp_runtime.so']
        assert len(candidates) == 1, candidates
        record['pid'] = candidates[0]
        command = self.target.run('cat /proc/'+str(record['pid'])+'/cmdline').stdout
        executable = command.split('\0', 1)[0]
        assert Path(executable).name == 'libvpp_runtime.so', command
        actual_exe = save(out/'process-exe.txt', self.target.run('readlink /proc/'+str(record['pid'])+'/exe').stdout).strip()
        assert actual_exe == self.target.native+'/libvpp_runtime.so', actual_exe
        environment = save(out/'process-owner.properties', self.target.run(
            "tr '\\0' '\\n' </proc/"+str(record['pid'])+"/environ | grep -E '^SAKAMOTO_(VPP_OWNER_TOKEN|PRODUCT_GENERATION|VPP_RUNTIME_DIR|RUNTIME_PROFILE)='").stdout)
        expected = dict(SAKAMOTO_VPP_OWNER_TOKEN=owner['token'], SAKAMOTO_PRODUCT_GENERATION=str(record['generation']),
                        SAKAMOTO_VPP_RUNTIME_DIR=owner['runtimePath'], SAKAMOTO_RUNTIME_PROFILE='root')
        actual = props(environment)
        for values in (actual, expected):
            values['SAKAMOTO_VPP_RUNTIME_DIR'] = values['SAKAMOTO_VPP_RUNTIME_DIR'].replace('/data/data/', '/data/user/0/', 1)
        assert actual == expected, 'native process does not match durable generation owner'
        self.target.owned_executables[record['pid']] = executable
        save(out/'startup.conf', self.target.read(BASE+'/startup.conf'))
        self.cli(record, 'trace', 'product packet-trace limit 4096', 'show threads', 'show files')
        initial = self.snapshot(record, 'initial')
        record['revision'] = int(rows(initial, 'policy.snapshot ')[0]['revision'])
        save(out/'hooks.txt', self.hooks())
        self.policy(record, 0)
        self.source_port = 32000
        self.seeds(record)
        return record

    def app_stop(self, record, abnormal=False):
        out = self.args.output/record['label']
        clock = 'env '+shlex.quote('LD_LIBRARY_PATH='+self.target.native)+' '+shlex.join(
            [self.target.helpers+'/s242-stop', 'clock'])
        save(out/'before-stop-clock.txt', self.target.run(clock).stdout)
        if abnormal:
            self.cli(record, 'hold-next', 'product policy hold-next 0 500000', 'product policy hold-next 1 500000')
            deadline = time.monotonic()+2
            while 's209 event=hold_begin ' not in self.target.read(record['logfile']):
                assert time.monotonic() < deadline, 'no live policy work before native death'
                time.sleep(.01)
            # Freeze this exact owned native process before archiving its
            # last complete log. SIGKILL then proves OS reclamation, never
            # graceful zero or an assumed native syscall result.
            saved = self.target.temporary+'/'+record['label']+'-crash.log'
            command = 'kill -STOP '+str(record['pid'])+' && cp '+shlex.quote(record['logfile'])+' '+shlex.quote(saved)
            command += ' && '+clock+' && kill -KILL '+str(record['pid'])+' && '+clock
            save(out/'kill-clock.txt', self.target.run(command).stdout)
            record['termination'] = 'SIGKILL_OS_RECLAIM'
            record['native_log_source'] = 'frozen-before-sigkill'
            save(out/'vpp.log', self.target.read(saved))
            record['failed_state'] = self.wait_state(record, 'failed', lambda s: s.get('state') == 'error'
                and s.get('mayBeActive') == 'false' and s.get('errorCode') == 'unexpected_exit')
            save(out/'failed-service.log', self.app('files/logs/runtime-service.log'))
        else:
            record['termination'] = 'JNI_DRAIN_THEN_APP_STOP'
        save(out/'stop.txt', self.action('--ez', 'runtimeStop', 'true'))
        record['stopped_state'] = self.wait_state(record, 'stopped', lambda s: s.get('state') == 'stopped'
            and s.get('mayBeActive') == 'false' and not s.get('errorCode'))
        save(out/'after-stop-clock.txt', self.target.run(clock).stdout)
        if not abnormal:
            save(out/'vpp.log', self.app('files/product-state/s242-last-stop.log'))
            record['native_log_source'] = 'RuntimeService-stop-archive'
        save(out/'service.log', self.app('files/logs/runtime-service.log'))
        save(out/'cleanup.properties', self.app('files/product-state/s176-root-nfqueue-cleanup.properties'))
        record['process_absent'] = not self.target.alive(record['pid'])
        assert record['process_absent']
        save(out/'processes-after.txt', self.target.adb('shell', 'ps', '-A', '-o', 'PID,UID,ARGS').stdout)
        save(out/'hooks-after.txt', self.hooks())
        self.target.queue_witness(out, 'app-closed')
        save(out/'profile-after.txt', self.target.run('ls -la '+shlex.quote(BASE), check=False).stdout)
        self.finish_traffic(record)

    def run(self):
        self.prepare()
        for index, label in enumerate(('stop', 'restart-stop', 'crash', 'recovery-stop')):
            record = self.start_app(label, index)
            self.traffic(record)
            self.app_stop(record, abnormal=label == 'crash')
            print('pixel supervisor', label, 'raw lifecycle complete', flush=True)
        self.result['status'] = 'RAW_COMPLETE'

    def cleanup(self):
        # RuntimeService alone retires its production hooks/profile; do not
        # use the manual native launcher's cleanup on an app-owned runtime.
        state = props(self.app(STATE))
        if state.get('state') != 'stopped' or state.get('mayBeActive') != 'false':
            self.action('--ez', 'runtimeStop', 'true')
            deadline = time.monotonic()+15
            while time.monotonic() < deadline:
                state = props(self.app(STATE))
                if state.get('state') == 'stopped' and state.get('mayBeActive') == 'false':
                    break
                time.sleep(.1)
        for record in self.generations:
            for index, client in enumerate(record['clients']):
                if self.target.alive(client['pid']):
                    self.target.stop_process(client['pid'])
                save(self.args.output/record['label']/f'traffic-{index}.txt', self.target.read(client['logfile']))
        self.result['endpoint_cleanup'] = []
        for index, (key, (pid, path)) in enumerate(self.endpoints.items()):
            absent = self.target.stop_process(pid)
            self.result['endpoint_cleanup'].append(dict(protocol=key[0], family=key[1], host=key[2], pid=pid, process_absent=absent))
            save(self.args.output/f'endpoint-final-{index}.txt', self.target.read(path))
        for address in self.addresses:
            self.target.run(f'ip -6 addr del {address}/128 dev lo')
        save(self.args.output/'addresses-after.txt', self.target.run('ip -6 addr show dev lo').stdout)
        save(self.args.output/'hooks-after.txt', self.hooks())
        save(self.args.output/'app-after.properties', self.app(STATE))
        self.result['completed_ns'] = time.time_ns()
        self.result['raw_hashes'] = {str(p.relative_to(self.args.output)): digest(p)
            for p in self.args.output.rglob('*') if p.is_file() and p.name != 'result.json'}
        save(self.args.output/'result.json', json.dumps(self.result, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--helpers', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.platform = 'pixel'
    for name in ('build', 'helpers', 'output'):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert helper['build_sha256'] == digest(args.build) and helper['platform'] == 'pixel'
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
