#!/usr/bin/env python3
"""Pixel-only, independent NFQUEUE close/TCP observation; no Product runtime.

Leaves kernel RCU configuration unchanged. Only its private loopback rule,
queue holder, packet observer, and independent endpoints are operated.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s242', ROOT/'tests/device/s242-root-lifecycle.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
save, digest, props = module.save, module.digest, module.props


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--helpers', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    helper = json.loads(args.helpers.read_text())
    assert helper['platform'] == 'pixel'
    target = object.__new__(module.Target)
    target.pixel, target.children, target.owned_executables = True, {}, {}
    target.args = SimpleNamespace(output=args.output)
    pkg = module.base.PKG
    state = save(args.output/'app-before.txt', target.adb('shell', 'run-as', pkg,
        'cat', 'files/runtime-state/snapshot.properties').stdout)
    assert props(state)['state'] == 'stopped' and props(state)['mayBeActive'] == 'false'
    target.uid = target.adb('shell', 'run-as', pkg, 'id', '-u').stdout.strip()
    temporary = target.adb('shell', 'mktemp', '-d', '/data/local/tmp/s242-kernel.XXXXXX').stdout.strip()
    assert temporary.startswith('/data/local/tmp/s242-kernel.')
    pids, installed, rule_added = {}, {}, False
    rule = ['iptables', '-w', '5', '-t', 'mangle', '-A', 'OUTPUT', '-o', 'lo', '-p', 'tcp',
            '--dport', '40644', '-m', 'owner', '--uid-owner', target.uid, '-m', 'comment',
            '--comment', 'SAKAMOTO_S242_KERNEL_CLOSE', '-j', 'NFQUEUE', '--queue-num', '179', '--queue-bypass']
    result = dict(status='HOLD', helper_sha256=digest(args.helpers), helper=str(args.helpers.resolve()),
                  runner_sha256=digest(__file__), temporary=temporary, product_running=False)
    try:
        hooks = save(args.output/'hooks-before.txt', target.run('iptables-save -t mangle').stdout)
        assert 'SAKAMOTO_S242_' not in hooks
        assert not target.run('cat /proc/net/netfilter/nfnetlink_queue').stdout.strip()
        assert ':40644 ' not in target.run('ss -lnut').stdout
        save(args.output/'rcu-lazy.txt', target.run('cat /sys/module/rcutree/parameters/enable_rcu_lazy').stdout)
        save(args.output/'kernel.txt', target.run('uname -a').stdout)
        for name in ('s222-tcp', 's242-queue-holder', 's242-traffic'):
            assert digest(args.helpers.parent/name) == helper['files'][name]
            target.adb('push', args.helpers.parent/name, temporary+'/'+name)
            target.run('chmod 755 '+shlex.quote(temporary+'/'+name))
            installed[name] = target.run('sha256sum '+temporary+'/'+name).stdout.split()[0]
            assert installed[name] == helper['files'][name]
        def spawn(name, argv):
            pids[name] = target.spawn(argv, temporary+'/'+name+'.log')
        def wait_for(name, text, seconds):
            deadline = time.monotonic()+seconds
            while text not in target.read(temporary+'/'+name+'.log'):
                assert time.monotonic() < deadline and target.alive(pids[name]), name+' wait failed'
                time.sleep(.05)
        spawn('server', [temporary+'/s222-tcp', 'server', '40644', '127.0.0.9'])
        wait_for('server', 'listen ', 3)
        spawn('capture', ['/system/bin/tcpdump', '-nn', '-tt', '-l', '-i', 'lo', 'tcp', 'port', '40644'])
        spawn('holder', [temporary+'/s242-queue-holder', '179', '4', 'copy'])
        wait_for('holder', 'queue_copy queue=179 ack=0', 3)
        target.run(shlex.join(rule))
        rule_added = True
        def client(name, port):
            spawn(name, [temporary+'/s242-traffic', target.uid, 'tcp', '4', '127.0.0.1', str(port),
                '127.0.0.9', '40644', '1000', '250000', 's242-kernel-'+name, '-', '20000'])
        client('old', 36442)
        deadline = time.monotonic()+3
        while True:
            table = target.run('cat /proc/net/netfilter/nfnetlink_queue').stdout
            if any(line.split()[0] == '179' and int(line.split()[2]) > 0 for line in table.splitlines()):
                break
            assert time.monotonic() < deadline
            time.sleep(.02)
        save(args.output/'queue-pending.txt', table)
        save(args.output/'tcp-before-close.txt', target.run('cat /proc/net/netstat').stdout)
        result['holder_absent'] = target.stop_process(pids['holder'])
        assert result['holder_absent']
        save(args.output/'queue-closed.txt', target.run('cat /proc/net/netfilter/nfnetlink_queue').stdout)
        assert not (args.output/'queue-closed.txt').read_text().strip()
        client('fresh', 36443)
        wait_for('fresh', 'traffic_end ', 5)
        wait_for('old', 'traffic_end ', 24)
        save(args.output/'tcp-after-close.txt', target.run('cat /proc/net/netstat').stdout)
        result['status'] = 'OBSERVED'
    finally:
        if rule_added:
            rule[5] = '-D'
            target.run(shlex.join(rule))
        for name, pid in pids.items():
            result[name+'_absent'] = target.stop_process(pid)
            save(args.output/(name+'.txt'), target.read(temporary+'/'+name+'.log'))
        result['installed'] = installed
        save(args.output/'hooks-after.txt', target.run('iptables-save -t mangle').stdout)
        save(args.output/'queues-after.txt', target.run('cat /proc/net/netfilter/nfnetlink_queue').stdout)
        result['raw_hashes'] = {p.name: digest(p) for p in args.output.iterdir() if p.is_file()}
        save(args.output/'result.json', json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
