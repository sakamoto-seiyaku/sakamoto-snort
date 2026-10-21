#!/usr/bin/env python3
"""Independently check S302 Pixel TUN stop/restart raw event identities."""
import argparse
import json
from pathlib import Path
import re
import hashlib
import zipfile


def rows(lines, prefix):
    return [(index, dict(re.findall(r'(\w+)=([^\s]+)', line)))
            for index, line in enumerate(lines) if line.startswith(prefix)]


def exactly_one(lines, prefix):
    found = rows(lines, prefix)
    assert len(found) == 1, (prefix, len(found))
    return found[0]


def verify(path, expected_count, expected_outcome, apk):
    result = json.loads((path / 'result.json').read_text())
    generation = str(result['generation'])
    assert result['status'] in ('QUIESCE_HELD_RETURN_COMPLETE', 'RAW_COMPLETE')
    installed_apk = (result.get('installed_apk_sha256') or
                     (path / 'installed-apk.txt').read_text().split()[0])
    assert result['apk_sha256'] == installed_apk
    expected_native = result.get('apk_native_sha256', result.get('native_sha256'))
    if expected_native is None:
        with zipfile.ZipFile(apk) as archive:
            expected_native = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                               for name in archive.namelist()
                               if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
    installed_native = result.get('installed_native_sha256')
    if installed_native is None:
        installed_native = {Path(line.split()[1]).name: line.split()[0]
                            for line in (path / 'installed-native.txt').read_text().splitlines()}
    assert expected_native == installed_native
    log_path = path / ('native-stop.log' if expected_outcome else 'vpp.log')
    lines = log_path.read_text().splitlines()
    packet_prefixes = ('s203 ', 's204 ', 's205 ', 's210 ', 's213 ',
                       's216 ', 's237 ', 's239 ', 's298 ', 's302 ')
    for line in lines:
        if line.startswith(packet_prefixes) and (match := re.search(
                r'(?<!\w)generation=(\d+)', line)):
            assert match.group(1) == generation, line
    cutoff_line, cutoff = exactly_one(lines, 's302 event=tun_read_quiesced ')
    graph_line, graph = exactly_one(lines, 's302 event=graph_quiesced ')
    stop_line, stop = exactly_one(lines, 's213 event=stop ')
    assert cutoff_line < graph_line < stop_line
    assert all(item['generation'] == generation for item in (cutoff, graph, stop))
    assert all(stop[key] == '0' for key in ('pending', 'buffers', 'frames', 'obligations'))
    assert stop['tun_fd'] == '-1'

    captures = rows(lines, 's213 event=capture source=TUN_CAPTURED ')
    completions = rows(lines, 's213 event=completion source=TUN_CAPTURED ')
    returns = rows(lines, 's237 event=return_copy ')
    return_completions = rows(lines, 's213 event=completion source=FLOW_STACK_RETURN ')
    frees = rows(lines, 's203 event=buffer_free source=TUN_CAPTURED ')
    released = rows(lines, 's239 event=return_credit_released ')
    assert captures and len(captures) == len(completions)
    assert all(line < cutoff_line for line, _ in captures)
    assert all(item['generation'] == generation for _, item in
               captures + completions + returns + return_completions + released)
    capture_identity = [(item['token'], item['buffer']) for _, item in captures]
    completion_identity = [(item['token'], item['buffer']) for _, item in completions]
    return_identity = [(item['token'], item['buffer']) for _, item in returns]
    return_completion_identity = [(item['token'], item['buffer'])
                                  for _, item in return_completions]
    free_identity = [(item['obligation'], item['buffer']) for _, item in frees]
    assert len(set(capture_identity)) == len(capture_identity)
    assert len(set(return_identity)) == len(return_identity)
    assert sorted(capture_identity) == sorted(completion_identity)
    assert sorted(return_identity) == sorted(return_completion_identity)
    assert sorted(capture_identity + return_identity) == sorted(free_identity)
    assert sorted(item['token'] for _, item in released) == \
        sorted(item['token'] for _, item in returns)
    assert all(line > cutoff_line for line, _ in return_completions)
    assert all(line < graph_line for line, _ in completions)
    owners = rows(lines, 's237 event=owner_stopped ')
    assert len(owners) == expected_count
    assert {int(item['owner']) for _, item in owners} == set(range(expected_count))
    assert all(item['generation'] == generation and
               all(item[key] == '0' for key in
                   ('sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'))
               for _, item in owners)

    if expected_outcome:
        assert len(return_completions) == 1
        assert return_completions[0][1]['transport_outcome'] == expected_outcome
        assert result['held_return_writes_after_cutoff'] == 1
    else:
        deferred = rows(lines, 's210 event=completion_deferred ')
        assert deferred and len(deferred) == result['congestion']['deferred']
        assert int(cutoff['pending']) == result['congestion']['pending_at_cutoff'] > 0
        assert sum(line > cutoff_line for line, _ in completions) == \
            result['congestion']['completion_after_cutoff'] > 0
        assert len(captures) == result['congestion']['captures']
    return result


def verify_review_cases(prestop_path, stale_path, apk):
    prestop = json.loads((prestop_path / 'result.json').read_text())
    stale = json.loads((stale_path / 'result.json').read_text())
    digest = hashlib.sha256(apk.read_bytes()).hexdigest()
    assert prestop['status'] == 'RAW_COMPLETE'
    assert stale['status'] == 'STALE_RETURN_REJECTED'
    assert prestop['apk_sha256'] == stale['apk_sha256'] == digest
    assert int(stale['generation']) == int(prestop['generation']) + 1
    assert stale['stale_supplied_generation'] == int(prestop['generation'])
    assert prestop['completed_ns'] < stale['started_ns']
    assert ('tun.fault armed=pre-stop-draining generation=' + str(prestop['generation'])) \
        in (prestop_path / 'prestop-draining.txt').read_text()
    before = (prestop_path / 'vpp.log').read_text().splitlines()
    markers = ('s301 event=tun_read_pause ', 's302 event=tun_read_quiesced ',
               's302 event=graph_quiesced ',
               's213 event=stop ')
    positions = [next(i for i, line in enumerate(before) if marker in line)
                 for marker in markers]
    assert positions == sorted(positions), positions
    stop_pre = exactly_one(before, 's213 event=stop ')[1]
    assert all(stop_pre[key] == '0' for key in ('pending', 'buffers', 'frames', 'obligations'))
    assert stop_pre['tun_fd'] == '-1'
    after = (stale_path / 'native-stop.log').read_text().splitlines()
    fault = rows(after, 's237 event=fault_stale_output ')
    assert len(fault) == 1
    assert fault[0][1]['current_generation'] == str(stale['generation'])
    assert fault[0][1]['supplied_generation'] == str(prestop['generation'])
    assert not rows(after, 's237 event=return_copy ')
    assert not rows(after, 's213 event=completion source=FLOW_STACK_RETURN ')
    stop = exactly_one(after, 's213 event=stop ')[1]
    assert stop['generation'] == str(stale['generation'])
    assert all(stop[key] == '0' for key in ('pending', 'buffers', 'frames', 'obligations'))
    return prestop, stale


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--n3-short', type=Path, required=True)
    parser.add_argument('--n1-eagain', type=Path, required=True)
    parser.add_argument('--n3-success', type=Path, required=True)
    parser.add_argument('--congestion', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--prestop-draining', type=Path, required=True)
    parser.add_argument('--stale-return', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.apk.read_bytes()).hexdigest() == \
        json.loads((args.n3_short / 'result.json').read_text())['apk_sha256']
    cases = [verify(args.n3_short, 3, 'TUN_WRITE_SHORT', args.apk),
             verify(args.n1_eagain, 1, 'TUN_WRITE_EAGAIN', args.apk),
             verify(args.n3_success, 3, 'TUN_WRITE_SUCCEEDED', args.apk),
             verify(args.congestion, 3, None, args.apk)]
    assert len({case['apk_sha256'] for case in cases}) == 1
    assert [int(case['generation']) for case in cases] == sorted(
        {int(case['generation']) for case in cases})
    assert all(a['completed_ns'] < b['started_ns']
               for a, b in zip(cases, cases[1:]))
    prestop, stale = verify_review_cases(args.prestop_draining, args.stale_return, args.apk)
    assert stale['completed_ns'] < cases[0]['started_ns']
    print('S302 Pixel fatal-draining stop, stale-generation return rejection, '
          'N=3/1/3 restart, held return writes, congestion, '
          'exact buffer/token/credit settlement: PASS')


if __name__ == '__main__':
    main()
