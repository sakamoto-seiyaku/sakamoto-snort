#!/usr/bin/env python3
"""Independently verify S303 Pixel Root N=1/N=3 traffic, policy and cleanup."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def props(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def rows(text, prefix):
    return [dict(re.findall(r'(\w+)=([^\s]+)', line))
            for line in text.splitlines() if line.startswith(prefix)]


def one(values, **expected):
    selected = [row for row in values
                if all(row.get(key) == str(value) for key, value in expected.items())]
    assert len(selected) == 1, (expected, selected)
    return selected[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--apk', type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve()
    result = json.loads((run / 'result.json').read_text())
    assert result['status'] == 'RAW_COMPLETE' and result['task'] == 'SAKAMOTO-303'
    assert result['runner_sha256'] == digest(ROOT / 'tests/device/s303-pixel-root-topology.py')
    assert result['apk_sha256'] == digest(args.apk)
    assert result['apk_sha256'] == (run / 'installed-apk.txt').read_text().split()[0]
    with zipfile.ZipFile(args.apk) as archive:
        native = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                  for name in archive.namelist()
                  if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
    installed = {Path(line.split()[1]).name: line.split()[0]
                 for line in (run / 'installed-native.txt').read_text().splitlines()}
    assert native == installed == result['apk_native_sha256']
    assert result['helper_source_sha256'] == digest(ROOT / 'tests/device/helpers/s206-udp-echo.c')
    assert result['helper_sha256'] == digest(run / 'udp-endpoint')
    assert result['device_helper_source_sha256'] == digest(ROOT / 'tests/device/helpers/s207-echo.c')
    assert result['device_helper_sha256'] == digest(run / 'device-echo')
    assert [case['cpus'] for case in result['runs']] == [[1], [1, 2, 1]]
    generations = [int(case['generation']) for case in result['runs']]
    assert generations == sorted(set(generations))
    packets = 0
    for index, case in enumerate(result['runs']):
        label = f'run{index}'
        generation = case['generation']
        cpus = case['cpus']
        running = props(run / (label + '-running.properties'))
        stopped = props(run / (label + '-stopped.properties'))
        status = props(run / (label + '-worker-status.properties'))
        assert running['generation'] == generation and running['state'] == 'running'
        assert running['profile'] == 'root' and running['protectionRunning'] == 'true'
        assert stopped['generation'] == generation and stopped['state'] == 'stopped'
        assert stopped['mayBeActive'] == 'false' and stopped['errorCode'] == ''
        assert status['generation'] == generation
        assert status['vpp_owner_cores'] == ','.join(map(str, cpus))
        assert status['worker_core_config_match'] == 'true'
        route = (run / (label + '-network.txt')).read_text()
        assert re.search(r'\bsrc 192\.168\.4\.\d+\b', route)
        topology = (run / (label + '-topology.txt')).read_bytes().replace(b'\0', b'').decode(errors='replace')
        actual = one(rows(topology, 'topology.profile='), profile='root')
        assert int(actual['owner_count']) == int(actual['vpp_worker_count']) == len(cpus)
        assert 'topology.tun_io_lane=none' in topology
        assert len(rows(topology, 'root.lane ')) == 4
        for role, cpu in [('main', 0), *((f'wk_{i}', value)
                        for i, value in enumerate(cpus))]:
            affinity = (run / (label + '-affinity-' + role + '.txt')).read_text()
            assert re.search(r'^Cpus_allowed_list:\s*' + str(cpu) + r'\s*$',
                             affinity, re.MULTILINE), (role, cpu)
        trace = (run / (label + '-trace.log')).read_text()
        captured = rows(trace, 's203 event=capture ')
        admitted = [row for row in rows(trace, 's216 ')
                    if row.get('stage') == 'admit']
        verdicts = rows(trace, 's242 event=verdict_syscall ')
        freed = rows(trace, 's203 event=buffer_free ')
        covered = set()
        for probe in case['probes']:
            origins = [row for row in admitted
                       if probe['nonce'].encode().hex() in row.get('raw', '')]
            assert len(origins) == 2
            assert {row['direction'] for row in origins} == {'1', '3'}
            assert {row['owner'] for row in origins} == {str(probe['owner'])}
            covered.add(probe['owner'])
            for origin in origins:
                token, buffer = origin['token'], origin['buffer']
                assert origin['generation'] == generation
                assert one(captured, obligation=token)['buffer'] == buffer
                verdict = one(verdicts, token=token)
                assert verdict['generation'] == generation and verdict['verdict'] == '1'
                assert verdict['outcome'] == '0'
                assert one(freed, obligation=token)['buffer'] == buffer
                packets += 1
            assert probe['nonce'] in (run / 'endpoint.log').read_text()
        assert covered == set(range(len(cpus))) == set(case['covered'])
        lifecycle_before = (run / (label + '-owner-lifecycle-before.txt')).read_text()
        lifecycle_after = (run / (label + '-owner-lifecycle-after.txt')).read_text()
        entries_before = rows(lifecycle_before, 'flow.entry ')
        entries_after = rows(lifecycle_after, 'flow.entry ')
        ends_before = rows(lifecycle_before, 'flow-end.owner=')
        ends_after = rows(lifecycle_after, 'flow-end.owner=')
        assert {int(row['owner']) for row in ends_before} == set(range(len(cpus)))
        assert {int(row['owner']) for row in rows(lifecycle_before, 'expiry.owner=')} == \
            set(range(len(cpus)))
        assert {int(row['owner']) for row in rows(lifecycle_before, 'primary.owner=')} == \
            set(range(len(cpus)))
        assert {int(row['channel']) for row in rows(lifecycle_before,
                                                   'observation.channel=')} == \
            set(range(2 * len(cpus)))
        assert {flow['owner'] for flow in case['closed_flows']} == set(range(len(cpus)))
        for flow in case['closed_flows']:
            owner = flow['owner']
            selected = one(entries_before, worker=owner, slot=flow['slot'],
                           incarnation=flow['incarnation'])
            assert {selected['port_a'], selected['port_b']} == \
                {str(flow['source_port']), str(result['endpoint_port'])}
            assert int(selected['orig_packets']) >= 1
            assert int(selected['reply_packets']) >= 1
            assert not [row for row in entries_after
                        if row['worker'] == str(owner)
                        and row['slot'] == flow['slot']
                        and row['incarnation'] == flow['incarnation']]
            assert int(one(ends_after, owner=owner)['released']) > \
                int(one(ends_before, owner=owner)['released'])
            assert f'flow-end.close=queued owner={owner}' in \
                (run / (label + f'-flowend-close-{owner}.txt')).read_text()
        drop_nonce = case['policy_drop_nonce']
        drop_trace = (run / (label + '-drop-trace.log')).read_text()
        drop_origin = one([row for row in rows(drop_trace, 's216 ')
                           if row.get('stage') == 'admit'
                          if drop_nonce.encode().hex() in row.get('raw', '')])
        drop_token = drop_origin['token']
        assert one([row for row in rows(drop_trace, 's216 ')
                    if row.get('stage') == 'policy'], token=drop_token)['intent'] == '2'
        assert one(rows(drop_trace, 's242 event=verdict_syscall '),
                   token=drop_token)['verdict'] == '0'
        assert one(rows(drop_trace, 's203 event=buffer_free '),
                   obligation=drop_token)['buffer'] == drop_origin['buffer']
        assert drop_nonce not in (run / (label + '-policy-endpoint-before.txt')).read_text()
        drop_state = props(run / (label + '-policy-drop.properties'))
        allow_state = props(run / (label + '-policy-allow.properties'))
        assert drop_state['action'] == '2' and allow_state['action'] == '1'
        assert int(allow_state['savedRevision']) > int(drop_state['savedRevision'])
        assert case['policy_recovery_nonce'] in \
            (run / (label + '-policy-endpoint-after.txt')).read_text()
        if len(cpus) == 1:
            assert case['capacity_fault'] is None
        else:
            fault = case['capacity_fault']
            assert fault and fault['rejected_before'] == 0
            pressure = (run / (label + '-capacity-trace.log')).read_text()
            fault_packets = [row for row in rows(pressure, 's216 ')
                             if row.get('stage') == 'admit'
                             and fault['nonce'].encode().hex() in row.get('raw', '')]
            assert fault_packets
            rejected = rows(pressure, 's210 event=primary_rejected ')
            pressure_verdicts = rows(pressure, 's242 event=verdict_syscall ')
            pressure_frees = rows(pressure, 's203 event=buffer_free ')
            for packet in fault_packets:
                token = packet['token']
                rejection = one(rejected, token=token)
                assert rejection['buffer'] == packet['buffer']
                assert rejection['owner'] == packet['owner']
                assert rejection['retained'] == '1' and rejection['policy_evaluated'] == '0'
                assert int(packet['worker']) != int(packet['owner'])
                verdict = one(pressure_verdicts, token=token)
                assert verdict['verdict'] == '1' and verdict['outcome'] == '0'
                assert one(pressure_frees, obligation=token)['buffer'] == packet['buffer']
            recovered = (run / (label + '-capacity-recovery-trace.log')).read_text()
            recovery_packets = [row for row in rows(recovered, 's216 ')
                                if row.get('stage') == 'admit'
                                and (fault['nonce'] + '-recovery').encode().hex()
                                in row.get('raw', '')]
            assert recovery_packets
            for packet in recovery_packets:
                accepted = one(rows(recovered, 's205 event=primary_accepted '),
                               token=packet['token'])
                delivered = one(rows(recovered, 's205 event=owner_delivery '),
                                token=packet['token'])
                assert accepted['buffer'] == delivered['buffer'] == packet['buffer']
                assert delivered['match'] == '1'
        before = (run / (label + '-before-stop.txt')).read_bytes().replace(b'\0', b'').decode(errors='replace')
        completion = one(rows(before, 'completion.status '))
        assert all(completion[key] == '0' for key in
                   ('pending', 'frames', 'buffers', 'obligations', 'duplicate', 'stale'))
        assert 'productRootNfqueueResidueClean=true' in \
            (run / (label + '-cleanup.properties')).read_text()
        assert not (run / (label + '-queues-after.txt')).read_text().strip()
        assert 'SAKAMOTO' not in (run / (label + '-hooks-after.txt')).read_text()
        processes = (run / (label + '-processes-after.txt')).read_text()
        assert not [line for line in processes.splitlines()
                    if len(parts := line.split(None, 3)) >= 3
                    and Path(parts[2]).name == 'libvpp_runtime.so']
    print(f'S303 Root N=1/N=3, {packets} LAN packet completions, '
          'bidirectional canonical owners, DROP/ALLOW, affinity and zero residue: PASS')


if __name__ == '__main__':
    main()
