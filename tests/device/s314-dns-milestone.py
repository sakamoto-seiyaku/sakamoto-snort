#!/usr/bin/env python3
"""Current-artifact ordinary UDP and truthful shell-UID Unknown DNS fixtures."""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s314_tcp', Path(__file__).with_name('s313-root-dns-tcp.py'))
tcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tcp)
support, fixtures, PKG, SERIAL = tcp.support, tcp.fixtures, tcp.PKG, tcp.SERIAL


def windows_read(out, label, command):
    command = "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; " + command
    encoded = base64.b64encode(command.encode('utf-16le')).decode()
    for attempt in range(3):
        result = subprocess.run(['/init', '/mnt/c/Windows/System32/cmd.exe', '/C', 'powershell.exe',
            '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], cwd='/mnt/c',
            capture_output=True, timeout=25)
        (out / f'{label}-{attempt}.stdout').write_bytes(result.stdout)
        (out / f'{label}-{attempt}.stderr').write_bytes(result.stderr)
        if result.returncode == 0:
            return json.loads(result.stdout)
    raise RuntimeError('physical Windows process/endpoint read failed: ' + label)


def public_source_port(wire, address, requests, replies):
    packets = [row for row in wire if row.get('kind') == 'tcp' and (
        (row['destination'] == address and row['destination_port'] == 53)
        or (row['source'] == address and row['source_port'] == 53))]
    outgoing = [row for row in packets if row['destination'] == address and row['destination_port'] == 53]
    candidates = set()
    for source in {row['source_port'] for row in outgoing}:
        try:
            stream = tcp.stream_frames(packets, source, True)
        except AssertionError:
            continue
        if (stream['frames'] == requests and not stream['trailing_bytes']
                and stream['contiguous_bytes'] == stream['observed_bytes']):
            candidates.add(source)
    assert len(candidates) == 1, candidates
    source, = candidates
    returned = tcp.stream_frames(packets, source, False)
    assert returned['frames'] == replies and not returned['trailing_bytes']
    assert returned['contiguous_bytes'] == returned['observed_bytes']
    return source


class UdpPeer(tcp.Peer):
    def __init__(self, addresses, out):
        super().__init__(addresses, out, ROOT / 'tests/device/helpers/s312_dns_peer.ps1')

    def close(self):
        support.Peer.close(self)
        ready, = [row for row in self.messages if row.get('kind') == 'ready']
        stopped, = [row for row in self.messages if row.get('kind') == 'stopped']
        assert stopped['pending'] == 0
        process = ready['process_id']
        remote = windows_read(self.out, 'peer-physical-after',
            "@{process_present=[bool](Get-Process -Id " + str(process) + " -ErrorAction SilentlyContinue); "
            "endpoints=@(Get-NetUDPEndpoint | Where-Object {$_.LocalPort -eq 53} | "
            "Select-Object LocalAddress,OwningProcess)} | ConvertTo-Json -Depth 4 -Compress")
        assert not remote['process_present'] and not any(row['OwningProcess'] == process for row in remote['endpoints'])
        (self.out / 'peer-cleanup.json').write_text(json.dumps(dict(process_id=process,
            process_exit=self.process.returncode, stopped=stopped, actual_remote=remote), indent=2) + '\n')


class Device(tcp.Device):
    def helper_absence(self, label, *, cleanup=False):
        def owned(text):
            rows=[]
            for line in text.splitlines():
                fields=line.split()
                if len(fields)>=3 and fields[0].isdigit() and fields[1]=='2000' and fields[2]=='/data/local/tmp/s314-unknown':
                    rows.append(int(fields[0]))
            return rows
        before=self.save(label+'-helper-before.txt',self.root('ps -A -o PID,UID,ARGS'))
        pids=owned(before)
        if cleanup:
            for pid in pids:
                # Revalidate ownership and exact executable immediately before
                # terminating an overdue helper. Do not kill by bare PID/name.
                command=(f'if [ "$(stat -c %u /proc/{pid})" = 2000 ] && '
                    f'[ "$(readlink /proc/{pid}/exe)" = /data/local/tmp/s314-unknown ]; '
                    f'then kill -TERM {pid}; fi')
                self.save(label+f'-helper-terminate-{pid}.txt',self.root(command))
        after=self.save(label+'-helper-after.txt',self.root('ps -A -o PID,UID,ARGS'))
        assert not owned(after), 'owned shell socket helper remains'
        return dict(before_pids=pids,after_pids=owned(after))

    def wire_start(self):
        if self.args.protocol == 'tcp':
            return super().wire_start()
        support.Device.witness_start(self)

    def wire(self, label):
        if self.args.protocol == 'tcp':
            return super().wire(label)
        return support.Device.wire(self, label)

    def wire_stop(self):
        if self.args.protocol == 'tcp':
            return super().wire_stop()
        process = self.witness_pid
        support.Device.witness_stop(self)
        if process:
            rows = self.save('witness-process-after.txt', self.root('ps -A -o PID,UID,ARGS'))
            assert not any(line.split() and line.split()[0] == str(process) for line in rows.splitlines())


class Milestone:
    def __init__(self, device, peer, result):
        self.d, self.peer, self.result = device, peer, result
        self.identifier = 30000

    def question(self, name='qname.test', qtype=1):
        self.identifier += 1
        return fixtures.question(self.identifier, name, qtype)

    def add(self, case):
        self.result['cases'].append(case)
        (self.d.out / 'progress.json').write_text(json.dumps(self.result, indent=2) + '\n')
        print(case['label'], 'PASS', flush=True)

    def udp_query_drop(self, label, address, status):
        d = self.d
        source = d.reserve_source_port(label)
        requests = [self.question(name) for name in ('allowed.test', 'qname.test', 'allowed.test')]
        replies = [fixtures.answer(wire, 'ordinary')[0] for wire in requests]
        for query, reply in zip(requests, replies):
            self.peer.register(query, reply)
        before = d.cli(label + '-before', 'show product dns', 'show product batch', 'show product tun')
        nonce = d.launch(label, address, source, requests, timeout=1000)
        client = d.client(label, nonce)
        observed = d.observation_matching(label, lambda value: len([row for row in value['consumer']['persistent']['dns']['recent'].values()
            if row['record']['generation'] == d.generation and row['record']['source_port'] == source and row['record']['stage'] == 1]) == 3)
        wire = d.wire(label)
        after = d.cli(label + '-after', 'show product dns', 'show product batch', 'show product tun')
        records = [row['record'] for row in observed['consumer']['persistent']['dns']['recent'].values()
                   if row['record']['generation'] == d.generation and row['record']['source_port'] == source]
        for index, request in enumerate(requests):
            query, = [row for row in records if row['stage'] == 1 and row['id'] == int.from_bytes(request[:2], 'big')]
            denied = index == 1
            assert query['coverage'] == 1 and query['actual_action'] == (2 if denied else 1)
            if index:
                assert query['caller'] == 1 and query['uid'] == d.uid
            assert query['policy_revision'] == int(status['activeRevision'])
            if denied:
                assert query['winner'] == int(status['rule.0.version']) and query['domain_available']
            peer = [row for row in self.peer.rows if row['request_hex'] == request.hex()]
            transmitted = [row for row in wire if row.get('destination') == address and row.get('destination_port') == 53
                           and row.get('payload_hex') == request.hex()]
            exchange = client['dnsExchanges'][index]
            if denied:
                assert exchange.get('timedOut') and not exchange.get('replyHex') and not peer and not transmitted
                assert not any(row['stage'] == 2 and row['id'] == query['id'] for row in records)
            else:
                assert len(peer) == 1 and peer[0]['resolver'] == [address, 53] and transmitted
                assert exchange.get('replyHex') == replies[index].hex() == peer[0]['reply_hex']
                response, = [row for row in records if row['stage'] == 2 and row['id'] == query['id']]
                assert response['caller'] == query['caller'] and response['query_token'] == query['token'] and response['correlation'] == 1
        counter = 'policy_drops' if d.profile == 'vpn' else 'policy_qualified_matched_drop_succeeded'
        assert support.number(after, counter) > support.number(before, counter)
        self.add(dict(label=label, kind='udp-query-drop', profile=d.profile, protocol='udp', address=address,
                      generation=d.generation, owner_count=d.owners, source_port=source, policy=status, records=records))

    def public_tcp(self, label, address, status):
        d=self.d
        source=d.reserve_source_port(label)
        requests=[self.question('example.com',kind) for kind in (1,28,16)]
        before=d.cli(label+'-before','show product dns','show product batch','show product tun')
        nonce=d.launch_tcp(label,address,source,requests,timeout=1500)
        client=d.wait(label+'-client','files/product-state/t12-'+nonce+'.json',
            lambda value:value.get('phase')=='finished',timeout=20,json_value=True)
        wire=d.wire(label)
        after=d.cli(label+'-after','show product dns','show product batch','show product tun')
        counter='policy_drops' if d.profile=='vpn' else 'policy_qualified_matched_drop_succeeded'
        assert support.number(after,counter)==support.number(before,counter), 'public allowance unexpectedly produced policy DROP'
        completed=not client.get('error') and len(client.get('dnsExchanges',[]))==3 and all(
            row.get('replyHex') and not row.get('timedOut') for row in client['dnsExchanges'])
        observed=d.observation_matching(label,lambda value:len([row for row in value['consumer']['persistent']['dns']['recent'].values()
            if row['record']['generation']==d.generation and row['record']['source_port']==source
            and row['record']['coverage']==1 and not row['record']['tcp_continuation']])==6) if completed else d.observation(label)
        records=[row['record'] for row in observed['consumer']['persistent']['dns']['recent'].values()
            if row['record']['generation']==d.generation and row['record']['source_port']==source]
        assert all(row['actual_action']==1 for row in records),records
        outgoing=[row for row in wire if row.get('destination')==address and row.get('destination_port')==53]
        if completed:
            request_hex=[query.hex()for query in requests]
            first_id=int.from_bytes(requests[0][:2],'big')
            for record in records:
                if record['coverage']==1:
                    assert record['caller']==1 or (d.profile=='vpn' and record['id']==first_id and record['caller']==0),record
            direct_source=public_source_port(wire,address,request_hex,
                [row['replyHex']for row in client['dnsExchanges']])
            assert d.profile!='root'or direct_source==source
        else:
            self.result.setdefault('limits',[]).append(label+': permitted public TCP transport did not complete; not classified as policy DROP')
        self.add(dict(label=label,kind='public-tcp',profile=d.profile,protocol='tcp',generation=d.generation,
            owner_count=d.owners,address=address,source_port=source,policy=status,records=records,
            transport_complete=completed,wire_packets=len(outgoing),policy_drop_delta=0,
            identity_limit='original public destination wire is not resolver-provider authentication'))

    def unknown(self, label, address, denied):
        d = self.d
        status = d.configure(label, 'generic-drop' if denied else 'query-drop', direction=3, subject=2000)
        source = d.reserve_source_port(label)
        requests = [self.question(), self.question()]
        replies = [fixtures.answer(query, 'ordinary')[0] for query in requests]
        for query, reply in zip(requests, replies):
            self.peer.register(query, reply)
        tool = 'ip6tables' if ':' in address else 'iptables'
        rule = (f'-d {address} -p {d.args.protocol} --dport 53 --sport {source} '
                '-m owner --uid-owner 2000 -m comment --comment S314_UNKNOWN_FIXTURE '
                '-j NFQUEUE --queue-num 176 --queue-bypass')
        d.save(label + '-source.json', json.dumps(dict(source='real shell UID2000 socket; not Android resolver IPC',
            root_capture='explicit exact UID/peer/protocol/port fixture outside ordinary debug-App capture' if d.profile == 'root' else None,
            protocol=d.args.protocol, address=address, source_port=source, expected_dns_caller='Unknown'), indent=2) + '\n')
        d.helper_absence(label+'-preflight')
        capture_owned=False
        try:
            if d.profile == 'root':
                preflight=d.save(label + '-capture-before.txt', d.root(tool + '-save -c -t mangle'))
                assert 'S314_UNKNOWN_FIXTURE' not in preflight, 'preexisting fixture capture contamination'
                # Ownership starts before the possibly ambiguous insertion.
                # Never retry a mutation because its acknowledgement is missing.
                capture_owned=True
                d.root(tool + ' -w -t mangle -I OUTPUT 1 ' + rule)
                d.save(label + '-capture-active.txt', d.root(tool + '-save -c -t mangle'))
            before = d.cli(label + '-before', 'show product dns', 'show product batch', 'show product tun')
            raw=d.save(label + '-client.jsonl', d.adb('shell', '/data/local/tmp/s314-unknown',
                d.args.protocol, address, source, *(query.hex() for query in requests)))
            ready,client=[json.loads(line) for line in raw.splitlines() if line.startswith('{')]
            assert ready['phase']=='ready' and client['phase']=='finished' and ready['pid']==client['pid']
            d.save(label+'-client.json',json.dumps(client,indent=2)+'\n')
            assert client['uid'] == 2000 and client['source_port'] == source
            observed = d.observation(label) if denied else d.observation_matching(label, lambda value: len([
                row for row in value['consumer']['persistent']['dns']['recent'].values()
                if row['record']['generation'] == d.generation and row['record']['source_port'] == source
                and row['record']['coverage'] == 1 and not row['record']['tcp_continuation']]) == 4)
            records = [row['record'] for row in observed['consumer']['persistent']['dns']['recent'].values()
                       if row['record']['generation'] == d.generation and row['record']['source_port'] == source]
            wire = d.wire(label)
            after = d.cli(label + '-after', 'show product dns', 'show product batch', 'show product tun')
            peer = [row for row in self.peer.rows if row['request_hex'] in [query.hex() for query in requests]]
            if not denied:
                assert client['connect_errno'] == 0 and len(peer) == 2
                assert [row['reply_hex'] for row in client['exchanges']] == [reply.hex() for reply in replies]
                queries = [row for row in records if row['stage'] == 1 and row['coverage'] == 1 and not row['tcp_continuation']]
                assert len(queries) == 2 and any(row['uid'] == 2000 for row in queries), queries
                for query in queries:
                    assert query['caller'] == 0 and not query['domain_available'] and query['actual_action'] == 1
                    answers = [row for row in records if row['stage'] == 2 and row['id'] == query['id']
                               and row['coverage'] == 1 and not row['tcp_continuation']]
                    assert len(answers) == 1 and answers[0]['caller'] == 0
                    assert answers[0]['correlation'] == 1 and answers[0]['query_token'] == query['token']
                if d.args.protocol == 'tcp':
                    connection, = {row['connection'] for row in peer}
                    connected, = [row for row in self.peer.messages if row.get('kind') == 'connected' and row['connection'] == connection]
                    direct_source = int(connected['peer'].rsplit(':', 1)[1])
                    assert tcp.stream_frames(wire, direct_source, True)['frames'] == [query.hex() for query in requests]
                    assert tcp.stream_frames(wire, direct_source, False)['frames'] == [reply.hex() for reply in replies]
                else:
                    assert all(any(row.get('payload_hex') == query.hex() and row.get('destination') == address for row in wire) for query in requests)
                    assert all(any(row.get('payload_hex') == reply.hex() and row.get('source') == address for row in wire) for reply in replies)
            else:
                assert client['exchanges'][1]['timed_out'] and not client['exchanges'][1]['reply_hex']
                assert not any(row['request_hex'] == requests[1].hex() for row in peer)
                counter = 'policy_drops' if d.profile == 'vpn' else 'policy_qualified_matched_drop_succeeded'
                assert support.number(after, counter) > support.number(before, counter)
                for record in records:
                    if record['coverage'] == 1:
                        assert record['caller'] == 0 and not record['domain_available']
            if d.profile == 'root':
                d.save(label + '-capture-counters.txt', d.root(tool + '-save -c -t mangle'))
            processes = d.save(label + '-helper-processes-after.txt', d.root('ps -A -o PID,UID,ARGS'))
            assert not any(line.split() and line.split()[0] == str(client['pid']) for line in processes.splitlines()), 'owned shell socket helper PID remains'
            self.add(dict(label=label, kind='unknown-generic-drop' if denied else 'unknown-domain-drop-allows',
                          profile=d.profile, protocol=d.args.protocol, generation=d.generation, owner_count=d.owners,
                          address=address, source_port=source, policy=status, records=records, source='real UID2000 socket, caller Unknown'))
        finally:
            try:
                d.helper_absence(label+'-finally',cleanup=True)
            finally:
                if capture_owned:
                    current=d.save(label+'-capture-cleanup-before.txt',d.root(tool+'-save -c -t mangle'))
                    tagged=[line for line in current.splitlines() if 'S314_UNKNOWN_FIXTURE' in line]
                    if tagged:
                        assert len(tagged)==1 and all(value in tagged[0] for value in (
                            '-A OUTPUT ',address,f'--sport {source}',f'-p {d.args.protocol}',
                            '--uid-owner 2000','--queue-num 176')), tagged
                        d.root(tool + ' -w -t mangle -D OUTPUT ' + rule)
                    after = d.save(label + '-capture-after.txt', d.root(tool + '-save -c -t mangle'))
                    assert 'S314_UNKNOWN_FIXTURE' not in after


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('apk', 'stage', 'backup', 'output', 'cc'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--profile', choices=('root', 'vpn'), required=True)
    parser.add_argument('--protocol', choices=('udp', 'tcp'), required=True)
    parser.add_argument('--case-set', choices=('udp', 'tcp', 'unknown', 'public'), required=True)
    parser.add_argument('--case-filter', default='.*')
    parser.add_argument('--owners', choices=('1', '3', '1,3'), default='1,3')
    parser.add_argument('--endpoint4', required=True)
    parser.add_argument('--endpoint6', required=True)
    parser.add_argument('--public4', default='1.1.1.1')
    parser.add_argument('--public6', default='2606:4700:4700::1111')
    parser.add_argument('--installed', action='store_true')
    args = parser.parse_args()
    for key in ('apk', 'stage', 'backup', 'output', 'cc'):
        setattr(args, key, getattr(args, key).resolve())
    assert args.case_set != 'udp' or args.protocol == 'udp'
    assert args.case_set != 'tcp' or args.protocol == 'tcp'
    assert args.case_set != 'public' or args.protocol == 'tcp'
    args.output.mkdir(parents=True, exist_ok=False)
    result = dict(status='HOLD', task='SAKAMOTO-314', profile=args.profile, protocol=args.protocol,
        case_set=args.case_set, apk_sha256=tcp.digest(args.apk), started_ns=time.time_ns(), cases=[], runs=[])
    for source in (Path(__file__), Path(tcp.__file__), Path(support.__file__),
                   ROOT / 'tests/device/s233-fail-open.py',
                   ROOT / 'tests/device/helpers/s314_dns_unknown.c', ROOT / 'tests/device/helpers/s312_dns_peer.ps1',
                   ROOT / 'tests/device/helpers/s313_dns_peer.ps1', ROOT / 'tests/device/helpers/s312_dns_wire.c',
                   ROOT / 'tests/device/helpers/s313_dns_wire.c', ROOT / 'tests/device/helpers/s312_dns_fixtures.py'):
        (args.output / ('source-' + source.name)).write_bytes(source.read_bytes())
    d, peer = Device(args), None
    try:
        result['native_sha256'] = d.install()
        result['uid'] = d.uid
        if args.case_set!='public': peer = (UdpPeer if args.protocol == 'udp' else tcp.Peer)([args.endpoint4, args.endpoint6], args.output)
        d.wire_start()
        if args.case_set == 'unknown':
            source = ROOT / 'tests/device/helpers/s314_dns_unknown.c'
            binary = args.output / 's314-unknown'
            subprocess.run([str(args.cc), '-O2', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)], check=True)
            d.adb('push', binary, '/data/local/tmp/s314-unknown')
            d.adb('shell', 'chmod', '755', '/data/local/tmp/s314-unknown')
            assert d.adb('shell', 'sha256sum', '/data/local/tmp/s314-unknown').split()[0] == tcp.digest(binary)
        q = Milestone(d, peer, result)
        ordinary = support.Qualification(d, peer, result)
        tcp_cases = tcp.Qualification(d, peer, result)
        for owners in map(int, args.owners.split(',')):
            result['runs'].append(d.start(owners))
            if args.case_set=='tcp':
                for policy,denied,winner,variant in (
                        ('query-drop',True,0,'ordinary'),('alias-drop',True,0,'alias'),
                        ('alias-allow',False,0,'alias'),('allow',False,2,'unrelated')):
                    prefix=f'n{owners}-milestone-{policy}'
                    if not any(tcp_cases.wanted(prefix+f'-v{family}')for family in (4,6)):continue
                    status=d.configure(prefix,policy,direction=3 if policy=='query-drop'else 1)
                    for family,address in ((4,args.endpoint4),(6,args.endpoint6)):
                        tcp_cases.exchange(prefix+f'-v{family}',address,status,denied=denied,winner=winner,
                            variant=variant,qtype=65 if policy=='allow'else 1,
                            query_drop=policy=='query-drop',collateral=policy in ('query-drop','alias-drop'))
                result['runs'][-1].update(d.stop(f'n{owners}'))
                continue
            if args.case_set=='public':
                status=d.configure(f'n{owners}-public-allow','allow',direction=3)
                for family,address in ((4,args.public4),(6,args.public6)):
                    label=f'n{owners}-v{family}-public'
                    if tcp_cases.wanted(label):q.public_tcp(label,address,status)
                result['runs'][-1].update(d.stop(f'n{owners}'))
                continue
            for family, address in ((4, args.endpoint4), (6, args.endpoint6)):
                if args.case_set == 'unknown':
                    for denied in (False, True):
                        label=f'n{owners}-v{family}-unknown-' + ('generic-drop' if denied else 'domain-allows')
                        if tcp_cases.wanted(label):q.unknown(label,address,denied)
                else:
                    label=f'n{owners}-v{family}-query-drop'
                    if tcp_cases.wanted(label):
                        status=d.configure(label,'query-drop',direction=3)
                        q.udp_query_drop(label,address,status)
                    for policy, variant, denied, winner, kind in (
                            ('allow', 'ordinary', False, 2, 1), ('alias-drop', 'alias', True, 0, 28 if family == 6 else 1),
                            ('alias-allow', 'alias', False, 0, 16), ('allow', 'unrelated', False, 2, 65000 if owners == 3 else 16)):
                        label = f'n{owners}-v{family}-{policy}-{kind}-{variant}'
                        if not tcp_cases.wanted(label):continue
                        status = d.configure(label, policy)
                        ordinary.exchange(label, address, status, variant=variant, denied=denied, winner=winner, qtype=kind, edns=kind == 65000)
                        (args.output / 'progress.json').write_text(json.dumps(result, indent=2) + '\n')
                        print(label, 'PASS', flush=True)
            result['runs'][-1].update(d.stop(f'n{owners}'))
        result['status'] = 'PASS_WITH_EXPLICIT_LIMITS' if result.get('limits') else 'PASS'
    except Exception as error:
        result['error'] = repr(error)
        result['traceback'] = traceback.format_exc()
        (args.output / 'error.log').write_text(result['traceback'])
        raise
    finally:
        if d.active:
            try:
                d.stop('finally')
            except Exception as error:
                result['cleanup_error'] = repr(error)
        try:
            d.wire_stop()
        except Exception as error:
            result['witness_cleanup_error'] = repr(error)
        if peer:
            try:
                peer.close()
            except Exception as error:
                result['peer_cleanup_error'] = repr(error)
        try:
            d.helper_absence('final',cleanup=True)
            d.adb('shell', 'rm', '-f', '/data/local/tmp/s314-unknown')
        except Exception as error:
            result['helper_cleanup_error'] = repr(error)
        try:
            d.close_trace()
        except Exception as error:
            result['trace_cleanup_error'] = repr(error)
        if any(key.endswith('cleanup_error') for key in result):
            result['status'] = 'HOLD'
        result['completed_ns'] = time.time_ns()
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(status=result['status'], cases=len(result['cases']))))


if __name__ == '__main__':
    main()
