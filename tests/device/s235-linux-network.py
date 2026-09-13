#!/usr/bin/env python3
"""Linux kernel classification -> real dual-stack NFQUEUE policy -> endpoints.

Run inside unshare --user --map-root-user --net. A second disposable netns
provides actual WireGuard and unclassified veth paths. No host network changes.
External four-category projections run in a separately labelled generation.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import time
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

ROOT = Path(__file__).resolve().parents[2]
def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value
base = module('s235_lifecycle', 'tests/device/s242-root-lifecycle.py')
wireguard = module('s235_wireguard', 'tests/device/s235-wireguard.py')
chain = module('s235_chain', 'tests/evidence/product_chain.py')
save, digest, rows = base.save, base.digest, base.rows
ANY = 0xffffffff
LOCAL = {4: '10.235.1.1', 6: 'fd20:235:1::1'}
VPN = {4: '10.235.1.2', 6: 'fd20:235:1::2'}
DIRECT = {4: '10.235.0.2', 6: 'fd20:235:0::2'}


class Campaign(base.Campaign):
    def __init__(self, args, build, helper):
        super().__init__(args, build, helper)
        self.result.update(task='SAKAMOTO-235', scope='Linux-kernel-network-snapshot',
            network_runner_sha256=digest(__file__), setup_sha256=digest(ROOT/'tests/device/s235-wireguard.py'),
            actual_classes={'VPN': 'PENDING', 'Wired': 'UNVERIFIED_NO_HARDWARE',
                            'Wifi': 'UNVERIFIED_NO_HARDWARE', 'Mobile': 'UNVERIFIED_NO_HARDWARE'},
            transitions=[])
        save(args.output/'network-runner.py', Path(__file__).read_text())
        save(args.output/'wireguard-setup.py', (ROOT/'tests/device/s235-wireguard.py').read_text())
        self.remote_endpoints = []
        self.keeper = None
        self.configs = None

    def remote(self, argv):
        assert self.keeper and self.target.alive(self.keeper)
        return ['nsenter', '-t', str(self.keeper), '-n', *map(str, argv)]

    def configure(self, index):
        argv = ['python3', str(ROOT/'tests/device/s235-wireguard.py')]
        if index: argv = self.remote(argv)
        answer = base.base.invoke(argv, input=json.dumps(self.configs[index]), env=self.target.environment)
        save(self.args.output/f'wireguard-configured-{index}.json', answer.stdout)

    def network_setup(self):
        self.prepare()
        keeper_log = self.target.temporary+'/namespace.log'
        self.keeper = self.target.spawn(['unshare', '--net', 'python3',
            str(ROOT/'tests/device/s235-wireguard.py'), '--keeper'], keeper_log)
        for _ in range(100):
            text = self.target.read(keeper_log)
            if 'namespace_keeper' in text: break
            assert self.target.alive(self.keeper)
            time.sleep(.02)
        else: raise RuntimeError('private peer namespace deadline')
        save(self.args.output/'peer-namespace.json', text)
        assert json.loads(text)['namespace'] != os.readlink('/proc/self/ns/net')
        self.target.run('ip link add s235host type veth peer name s235peer')
        self.target.run('ip link set s235peer netns '+str(self.keeper))
        for index in (0, 1):
            def ip(*args):
                argv = ['ip', *args]
                if index: argv = self.remote(argv)
                return self.target.run(shlex.join(argv))
            number = index+1; iface = 's235peer' if index else 's235host'
            ip('link', 'set', 'lo', 'up'); ip('link', 'set', iface, 'up')
            ip('addr', 'add', f'10.235.0.{number}/24', 'dev', iface)
            ip('-6', 'addr', 'add', f'fd20:235:0::{number}/64', 'dev', iface, 'nodad')
            ip('link', 'add', 's235wg', 'type', 'wireguard')
            ip('addr', 'add', f'10.235.1.{number}/32', 'dev', 's235wg')
            ip('-6', 'addr', 'add', f'fd20:235:1::{number}/128', 'dev', 's235wg', 'nodad')
        keys = [X25519PrivateKey.generate(), X25519PrivateKey.generate()]
        self.configs = []
        for index, key in enumerate(keys):
            other = 1-index
            self.configs.append(dict(interface='s235wg',
                private=key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                peer_public=keys[other].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
                port=42350+index, peer_port=42350+other, peer_address=f'10.235.0.{other+1}',
                allowed=[f'10.235.1.{other+1}/32', f'fd20:235:1::{other+1}/128']))
            self.configure(index)
            def ip(*args):
                argv = ['ip', *args]
                if index: argv = self.remote(argv)
                return self.target.run(shlex.join(argv))
            ip('link', 'set', 's235wg', 'up')
            ip('route', 'add', f'10.235.1.{other+1}/32', 'dev', 's235wg')
            ip('-6', 'route', 'add', f'fd20:235:1::{other+1}/128', 'dev', 's235wg')
        self.wg_index = socket.if_nametoindex('s235wg')
        self.direct_index = socket.if_nametoindex('s235host')
        self.result.update(wireguard_ifindex=self.wg_index, direct_ifindex=self.direct_index)
        save(self.args.output/'links-initial.json', self.target.run('ip -j -d link show').stdout)
        save(self.args.output/'peer-links.json', self.target.run(shlex.join(self.remote(['ip', '-j', '-d', 'link', 'show']))).stdout)
        for family in (4, 6):
            path = self.target.temporary+f'/peer-udp{family}.log'
            argv = self.remote([self.target.helpers+'/s223-udp', 'server', '0', str(family),
                                '0.0.0.0' if family == 4 else '::', str(base.PORTS['udp'])])
            pid = self.target.spawn(argv, path)
            self.remote_endpoints.append(dict(family=family, pid=pid, path=path))
            for _ in range(100):
                if 'listen ' in self.target.read(path): break
                assert self.target.alive(pid); time.sleep(.02)
            else: raise RuntimeError('peer endpoint deadline')

    def start_network(self, label, generation, external=False):
        self.target.environment['SAKAMOTO_LINUX_NETWORK_SOURCE'] = 'external' if external else 'kernel'
        record = self.start(label, generation)
        record['network_source'] = 'controlled_external' if external else 'kernel'
        record['network_revision'] = 0
        return record

    def install_network_rules(self, record):
        for tool, span in (('iptables', '176:177'), ('ip6tables', '178:179')):
            for hook in ('OUTPUT', 'INPUT'):
                extra = ['--dport', str(base.PORTS['udp']), '-m', 'owner', '--uid-owner', '0'] if hook == 'OUTPUT' else ['--sport', str(base.PORTS['udp'])]
                rule = [tool, '-w', '5', '-t', 'mangle', '-A', hook, '-p', 'udp', *extra,
                    '-m', 'comment', '--comment', 'SAKAMOTO_S235_'+record['label'],
                    '-j', 'NFQUEUE', '--queue-balance', span, '--queue-bypass']
                self.target.run(shlex.join(rule)); record['rules'].append(rule)
        save(self.args.output/record['label']/'hooks.txt', self.hooks())

    def control_network(self, record, mode, context=ANY, ifindex=ANY, accepted=True):
        field = 'network_revision' if mode == 4 else 'revision'
        record[field] += 1
        # A deliberately high external revision also tests writer exclusion.
        revision = record[field] + (1000 if mode == 4 else 0)
        argv = [self.target.helpers+'/s235-policy', record['runtime']+'/api.sock', str(record['generation']),
            record['runtime']+'/policy', str(revision), str(mode), self.target.policy_uid, str(context), str(ifindex)]
        answer = self.target.run('env '+shlex.quote('LD_LIBRARY_PATH='+self.target.native)+' '+shlex.join(argv), check=False)
        save(self.args.output/record['label']/f'control-{mode}-{revision}.txt', answer.stdout)
        assert (answer.returncode == 0) == accepted, answer.stdout
        if mode != 4: record['policy'] = dict(mode=mode, context=context, ifindex=ifindex, revision=revision)
        return revision

    def platform(self, record, label, expected, after=0):
        deadline = time.monotonic()+8
        while time.monotonic() < deadline:
            text = self.target.read(record['logfile'])
            snapshots = rows(text, 's235 event=platform_snapshot ')
            if snapshots:
                latest = snapshots[-1]
                entries = {int(e['ifindex']): int(e['context']) for e in rows(text, 's235 event=platform_interface ')
                           if e['revision'] == latest['revision']}
                if int(latest['revision']) > after and int(latest['count']) == len(entries) and entries == expected and latest['reason'] in ('kernel_dump', 'map_overflow_unknown'):
                    save(self.args.output/record['label']/(label+'-platform.log'), text)
                    value = dict(label=label, revision=int(latest['revision']), reason=latest['reason'], entries=entries)
                    self.result['transitions'].append(value)
                    return value['revision']
            assert self.target.alive(record['pid']); time.sleep(.02)
        raise RuntimeError('platform snapshot deadline '+label+' '+str(snapshots[-1:] if snapshots else []))

    def network_probe(self, record, family, path, phase, expected=True, endpoint=True, context=None):
        self.source_port += 1
        host = VPN[family] if path == 'vpn' else DIRECT[family] if path == 'direct' else ('127.0.0.2' if family == 4 else 'fd20:6242::2')
        bind = LOCAL[family] if path == 'vpn' else ('10.235.0.1' if family == 4 else 'fd20:235:0::1') if path == 'direct' else ('127.0.0.1' if family == 4 else '::1')
        if path == 'loop': _, endpoint_log = self.endpoint('udp', family, host)
        else: endpoint_log = next(e['path'] for e in self.remote_endpoints if e['family'] == family)
        route = self.target.run(('ip' if family == 4 else 'ip -6')+' route get '+host+' from '+bind).stdout
        expected_device = 's235wg' if path == 'vpn' else 's235host' if path == 'direct' else 'lo'
        assert 'dev '+expected_device+' ' in route, 'test route does not use expected actual interface: '+route
        nonce = f's235-{record["generation"]}-{len(record["cases"])}-{phase}-{time.time_ns()}'
        argv = [self.target.helpers+'/s223-udp', 'client', '0', str(family), bind, str(self.source_port), host,
                str(base.PORTS['udp']), '1', nonce, '1', '2500' if expected else '160']
        answer = self.target.run(shlex.join(argv), check=False, timeout=6)
        case = dict(phase=phase, family=family, path=path, host=host, bind=bind, source_port=self.source_port,
            nonce=nonce, expected=expected, endpoint_expected=endpoint, returncode=answer.returncode,
            expected_context=context if context is not None else 4 if path == 'vpn' else 0,
            expected_ifindex=self.wg_index if path == 'vpn' else self.direct_index if path == 'direct' else 1,
            policy=dict(record['policy']))
        index = len(record['cases']); record['cases'].append(case)
        save(self.args.output/record['label']/f'route-{index}.txt', route)
        save(self.args.output/record['label']/f'client-{index}.txt', answer.stdout)
        endpoint_text = save(self.args.output/record['label']/f'endpoint-{index}.txt', self.target.read(endpoint_log))
        assert (answer.returncode == 0) == expected and ((nonce+'-0') in endpoint_text) == endpoint, case
        save(self.args.output/record['label']/f'case-{index}-vpp.log', self.target.read(record['logfile']))
        return case

    def both(self, record, path, phase, expected=True, endpoint=True, context=None):
        for family in (4, 6): self.network_probe(record, family, path, phase, expected, endpoint, context)

    def actual(self):
        record = self.start_network('kernel', 23510)
        revision = self.platform(record, 'initial', {self.wg_index: 4})
        self.install_network_rules(record)
        self.control_network(record, 0); self.both(record, 'vpn', 'vpn-allow'); self.both(record, 'direct', 'direct-allow')
        self.result['actual_classes']['VPN'] = 'REAL_KERNEL_ENDPOINT'
        self.control_network(record, 4, 1, self.wg_index, accepted=False)
        for mode, name in ((1, 'gate'), (2, 'l4-out'), (3, 'l4-in')):
            self.control_network(record, mode, 4)
            self.both(record, 'vpn', name+'-vpn-drop', False, mode == 3)
            self.both(record, 'direct', name+'-unknown-no-match')
        self.control_network(record, 2, ANY)
        self.both(record, 'direct', 'unknown-other-policy-drop', False, False)
        self.control_network(record, 1, 1)
        self.both(record, 'vpn', 'different-network-no-match')
        self.control_network(record, 1, ANY, self.direct_index)
        self.both(record, 'direct', 'exact-ifindex-drop', False, False)
        self.both(record, 'vpn', 'other-ifindex-allow')
        self.control_network(record, 1, 4)
        for default in ('s235wg', 's235host'):
            for family in (4, 6):
                tool = 'ip' if family == 4 else 'ip -6'
                self.target.run(tool+' route replace default dev '+default)
                save(self.args.output/record['label']/f'default-{default}-{family}.txt',
                     self.target.run(tool+' route show').stdout+
                     self.target.run(tool+' route get '+VPN[family]).stdout+
                     self.target.run(tool+' route get '+DIRECT[family]).stdout)
            self.both(record, 'vpn', 'default-'+default+'-vpn', False, False)
            self.both(record, 'direct', 'default-'+default+'-direct')
        self.target.run('ip addr add 10.235.2.1/32 dev s235wg')
        revision = self.platform(record, 'address-add', {self.wg_index: 4}, revision)
        self.target.run('ip addr del 10.235.2.1/32 dev s235wg')
        revision = self.platform(record, 'address-delete', {self.wg_index: 4}, revision)
        self.target.run('ip link set s235wg down')
        revision = self.platform(record, 'link-down', {}, revision)
        self.both(record, 'direct', 'disconnected-unknown-no-match')
        self.target.run('ip link set s235wg up')
        # Explicit scope-link routes are removed by this kernel on DOWN;
        # IPv6 addresses are also removed when keep_addr_on_down is off.
        # Restore test configuration before asserting tunnel recovery.
        self.target.run('ip -6 addr replace fd20:235:1::1/128 dev s235wg nodad')
        self.target.run('ip route replace 10.235.1.2/32 dev s235wg')
        self.target.run('ip -6 route replace fd20:235:1::2/128 dev s235wg')
        save(self.args.output/record['label']/'reconnected-addresses.json', self.target.run('ip -j addr show dev s235wg').stdout)
        revision = self.platform(record, 'link-up', {self.wg_index: 4}, revision)
        self.control_network(record, 0); self.both(record, 'vpn', 'link-recovered')
        self.target.run('ip link del s235wg')
        revision = self.platform(record, 'link-delete', {}, revision)
        self.target.run(f'ip link add name s235reuse index {self.wg_index} type dummy')
        self.target.run('ip link set s235reuse up')
        revision = self.platform(record, 'index-reused-unknown', {}, revision)
        save(self.args.output/record['label']/'index-reuse.json', self.target.run('ip -j -d link show dev s235reuse').stdout)
        self.target.run('ip link del s235reuse')
        self.target.run(f'ip link add name s235wg index {self.wg_index} type wireguard')
        self.target.run('ip addr add 10.235.1.1/32 dev s235wg')
        self.target.run('ip -6 addr add fd20:235:1::1/128 dev s235wg nodad')
        self.configure(0)
        self.target.run('ip link set s235wg up')
        self.target.run('ip route add 10.235.1.2/32 dev s235wg')
        self.target.run('ip -6 route add fd20:235:1::2/128 dev s235wg')
        revision = self.platform(record, 'vpn-recreated', {self.wg_index: 4}, revision)
        self.both(record, 'vpn', 'vpn-recreated-allow')
        for index in range(32):
            self.target.run(f'ip link add s235x{index} type wireguard')
            self.target.run(f'ip link set s235x{index} up')
        revision = self.platform(record, 'overflow-33-known', {}, revision)
        assert self.result['transitions'][-1]['reason'] == 'map_overflow_unknown'
        save(self.args.output/record['label']/'overflow-links.json', self.target.run('ip -j -d link show').stdout)
        self.control_network(record, 1, 4)
        self.both(record, 'vpn', 'overflow-unknown-no-match', context=0)
        for index in range(32): self.target.run(f'ip link del s235x{index}')
        revision = self.platform(record, 'overflow-recovered', {self.wg_index: 4}, revision)
        self.both(record, 'vpn', 'overflow-recovered-drop', False, False)
        # Actual receive-loss recovery: pause only this test-owned runtime,
        # overflow its route socket with link events, then delete/reuse the
        # classified ifindex. No packet traffic while the process is paused.
        self.target.run('kill -STOP '+str(record['pid']))
        try:
            batch = ''.join(f'link set s235wg mtu {1420+i%2}\n' for i in range(800))
            answer = base.base.invoke(['ip', '-batch', '-'], input=batch, env=self.target.environment)
            save(self.args.output/record['label']/'receive-loss-batch.txt',
                 'test_owned_interface=s235wg\nmtu_events=800\n'+answer.stdout)
            self.target.run('ip link del s235wg')
            self.target.run(f'ip link add name s235reuse index {self.wg_index} type dummy')
            self.target.run('ip link set s235reuse up')
            save(self.args.output/record['label']/'loss-netlink.txt', self.target.run('cat /proc/net/netlink').stdout)
        finally: self.target.run('kill -CONT '+str(record['pid']))
        self.platform(record, 'receive-loss-reused-unknown', {}, revision)
        self.both(record, 'direct', 'receive-loss-unknown-no-match')
        self.cli(record, 'loss-files', 'show files')
        assert 'reason=receive_loss ' in self.target.read(record['logfile']), 'real socket overflow not observed'
        self.stop(record)

    def projections(self):
        record = self.start_network('controlled', 23511, external=True)
        self.install_rules(record)
        for context, name in ((1, 'wifi'), (2, 'mobile'), (4, 'vpn'), (8, 'wired')):
            self.control_network(record, 4, context, 1)
            for mode, stage in ((1, 'gate'), (2, 'l4')):
                self.control_network(record, mode, context)
                self.both(record, 'loop', name+'-'+stage+'-projected-drop', False, False, context)
                self.control_network(record, mode, 8 if context != 8 else 1)
                self.both(record, 'loop', name+'-'+stage+'-other-no-match', context=context)
        self.control_network(record, 4, 0, 0)
        for mode, name in ((1, 'gate'), (2, 'l4')):
            self.control_network(record, mode, 15)
            self.both(record, 'loop', 'missing-'+name+'-no-match')
        self.control_network(record, 2, ANY)
        self.both(record, 'loop', 'missing-other-policy-drop', False, False)
        self.stop(record)

    def run(self):
        self.network_setup()
        self.actual()
        print('Linux actual kernel network matrix complete', flush=True)
        self.projections()
        self.result['status'] = 'RAW_COMPLETE'
        print('Linux controlled projections complete (separate evidence)', flush=True)

    def cleanup(self):
        self.result['peer_cleanup'] = []
        for entry in self.remote_endpoints:
            absent = self.target.stop_process(entry['pid'])
            self.result['peer_cleanup'].append(dict(family=entry['family'], pid=entry['pid'], absent=absent))
            save(self.args.output/f'peer-final-{entry["family"]}.txt', self.target.read(entry['path']))
        if self.keeper:
            self.result['peer_namespace_closed'] = self.target.stop_process(self.keeper)
        super().cleanup()


def main():
    parser = argparse.ArgumentParser()
    for name in ('build', 'helpers', 'output', 'vppctl'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args(); args.platform = 'linux'
    for name in ('build', 'helpers', 'output', 'vppctl'): setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert chain.source_files() == build['files'] and helper['build_sha256'] == digest(args.build)
    campaign = Campaign(args, build, helper)
    try: campaign.run()
    except Exception as error:
        campaign.result['error'] = repr(error); raise
    finally: campaign.cleanup()


if __name__ == '__main__': main()
