#!/usr/bin/env python3
"""Independent raw Product TUN fault and settlement witness check."""
import argparse
import json
from pathlib import Path
import re


def require(value, message):
    if not value: raise AssertionError(message)


def events(log, prefix):
    return [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in log.splitlines()
            if line.startswith(prefix)]


def one(rows, token):
    found = [row for row in rows if row.get('token') == str(token)]
    require(len(found) == 1, f'token {token}: expected exactly one {len(found)}')
    return found[0]


def check(directory):
    result = json.loads((directory / 'result.json').read_text())
    require(result['status'] == 'RAW_COMPLETE', 'device run incomplete')
    owner_count = len(result.get('requested_owner_cpus', '1,2,1').split(','))
    origin_thread = str(owner_count + 1)
    require(result['installed_apk_sha256'] == result['apk_sha256'] and
            len(result['apk_native_sha256']) >= 12 and
            result['installed_native_sha256'] == result['apk_native_sha256'],
            'installed Product APK/native bytes differ from published artifact')
    require(result['restored_sha256'] == result['restore_sha256'], 'APK not restored')
    if result.get('completion_fault_mode') == 'held-original':
        held_text = (directory / 'completion-held.txt').read_bytes().replace(b'\0', b'').decode(errors='replace')
        held_tun = events(held_text, 'tun.status ')
        held_primary = events(held_text, 'primary.status ')
        require(len(held_tun) == len(held_primary) == 1
                and int(held_tun[0]['pending']) > 0 and int(held_primary[0]['deferred']) > 0,
                'held completion fixture did not create actual bounded debt')
        require('tun.original_hold milliseconds=0' in
                (directory / 'completion-release.txt').read_text(), 'held completion not released')
    if result.get('requested_capture_batch') is not None:
        configured = events((directory / 'capture-batch-configured.txt').read_text(),
                            'tun.capture_batch_configured ')
        require(len(configured) == 1 and configured[0]['generation'] == str(result['generation'])
                and int(configured[0]['limit']) == result['requested_capture_batch'],
                'capture batching differs from requested configuration')
        batches = events((directory / 'fragmented.txt').read_text(), 'tun.capture_batch ')
        require(len(batches) == 1 and int(batches[0]['limit']) == result['requested_capture_batch'],
                'capture batching changed during fault matrix')
    require(result['final_route'] == result['initial_route'], 'device route changed')
    stopped = (directory / 'stopped.properties').read_text()
    require('state=stopped' in stopped and 'mayBeActive=false' in stopped,
            'supervisor did not cleanly stop')
    require(not any('libvpp_runtime.so' in line for line in
                    (directory / 'processes-after-stop.txt').read_text().splitlines()),
            'VPP process remained after stop')
    before, failed, rejected, recovered, congested, fragmented = (
        result[key] for key in ('before', 'after_capture_alloc', 'handoff_rejected',
                                'recovered', 'completion_congested', 'fragmented'))
    for step in (failed, rejected, recovered, congested, fragmented):
        require(all(step[0][key] == '0' for key in
                    ('pending', 'frames', 'buffers', 'obligations')), 'native debt remains')
        require(step[2]['handoff_debt'] == step[2]['pending_returns'] == '0',
                'queue debt remains')
        require(step[2]['owner_failures'] == '0', 'owner mismatch')
    if result.get('ordinary_product'):
        require(result['running_state']['protectionRunning'] == 'true',
                'ordinary VPN Product mode was not running')
        require(int(failed[1]['alloc_failures']) - int(before[1]['alloc_failures']) == 1 and
                int(failed[1]['read_pauses']) - int(before[1]['read_pauses']) == 1 and
                int(failed[1]['read_resumes']) - int(before[1]['read_resumes']) == 1 and
                failed[1]['read_paused'] == '0',
                'ordinary Product pre-read allocation fault did not pause/recover')
        require(int(failed[0]['captured']) > int(before[0]['captured']) and
                int(failed[0]['runtime_drops']) > int(before[0]['runtime_drops']),
                'ordinary Product invalid ingress did not reach origin fault')
        require(int(rejected[2]['rejected']) > int(failed[2]['rejected']) and
                int(recovered[2]['published']) > int(rejected[2]['published']) and
                int(recovered[2]['received']) > int(rejected[2]['received']),
                'ordinary Product primary reject/recovery absent')
        require(int(congested[2]['deferred']) > int(recovered[2]['deferred']) and
                int(congested[2]['retries']) > int(recovered[2]['retries']),
                'ordinary Product completion congestion/recovery absent')
        require(int(fragmented[0]['captured']) - int(congested[0]['captured']) >= 2 and
                int(result['fragment_after']['completed']) >
                int(result['fragment_before']['completed']) and
                all(result['fragment_after'][key] == '0' for key in
                    ('contexts', 'originals', 'retained')),
                'ordinary Product fragments did not settle')
        print(f'S301 ordinary VPN Product status witness PASS: generation '
              f'{result["generation"]}, rejected={rejected[2]["rejected"]}, '
              f'deferred={congested[2]["deferred"]}')
        return
    log = (directory / 'vpp.log').read_text()
    unavailable_events = events(log, 's301 event=tun_buffer_unavailable ')
    require(len(unavailable_events) == 1, 'expected one bounded allocation fault event')
    unavailable = unavailable_events[0]
    first = int(unavailable['captured']) + 1
    last = int(fragmented[0]['captured'])
    require(int(fragmented[0]['completed']) - int(before[0]['completed']) >= last - first + 1,
            'capture/completion count mismatch')
    require(int(failed[1]['alloc_failures']) - int(before[1]['alloc_failures']) == 1,
            'one pre-read allocation failure required')
    require(int(failed[1]['read_pauses']) - int(before[1]['read_pauses']) == 1 and
            int(failed[1]['read_resumes']) - int(before[1]['read_resumes']) == 1,
            'read subscription did not pause/resume once')
    require(int(rejected[2]['rejected']) - int(failed[2]['rejected']) == 1,
            'primary rejection missing')
    require(int(recovered[2]['published']) - int(rejected[2]['published']) == 1 and
            int(recovered[2]['received']) - int(rejected[2]['received']) == 1,
            'normal owner handoff did not recover')
    require(int(congested[2]['deferred']) > int(recovered[2]['deferred']) and
            int(congested[2]['retries']) > int(recovered[2]['retries']),
            'bounded completion return path did not congest and recover')
    require(int(fragmented[0]['captured']) - int(congested[0]['captured']) >= 2 and
            int(result['fragment_after']['completed']) -
            int(result['fragment_before']['completed']) >= 1 and
            all(result['fragment_after'][key] == '0' for key in
                ('contexts', 'originals', 'retained')), 'fragment reassembly/debt mismatch')
    capture = events(log, 's213 event=capture ')
    completion = events(log, 's213 event=completion ')
    freed = events(log, 's203 event=buffer_free ')
    for token in range(first, last + 1):
        c, d = one(capture, token), one(completion, token)
        f = [row for row in freed if row.get('obligation') == str(token)]
        require(len(f) == 1, f'token {token}: missing/duplicate native free')
        require(c['generation'] == d['generation'] == result['generation'],
                f'token {token}: generation mismatch')
        require(c['buffer'] == d['buffer'] == f[0]['buffer'],
                f'token {token}: original buffer index changed')
        require(c['thread'] == d['thread'] == origin_thread,
                f'token {token}: TUN origin lane changed')
    require(unavailable['injected'] == '1' and
            int(before[0]['captured']) <= int(unavailable['captured']) <
            int(failed[0]['captured']),
            'fault did not precede read/capture')
    invalid = one(completion, first)
    require(invalid['intent'] == '2' and invalid['producer'] == origin_thread and
            invalid['policy_verdict'] == 'NOT_EVALUATED',
            'invalid packet did not settle on origin without owner policy')
    primary = one(events(log, 's210 event=primary_rejected '), first + 1)
    require(primary['buffer'] == one(capture, first + 1)['buffer'] and
            primary['retained'] == '1' and primary['policy_evaluated'] == '0' and
            primary['thread'] == origin_thread and primary['owner'] != str(owner_count),
            'primary rejection rerouted owner or changed original buffer')
    require(one(completion, first + 1)['producer'] == origin_thread,
            'rejected primary packet left origin lane')
    accepted = one(events(log, 's205 event=primary_accepted '), first + 2)
    delivered = one(events(log, 's205 event=owner_delivery '), first + 2)
    require(accepted['buffer'] == delivered['buffer'] == one(capture, first + 2)['buffer'] and
            delivered['match'] == '1' and accepted['owner'] == delivered['owner'],
            'recovered packet did not reach selected owner with original index')
    deferred = events(log, 's210 event=completion_deferred ')
    retries = events(log, 's205 event=completion_return_retry ')
    for item in deferred:
        token = int(item['token'])
        require(int(recovered[0]['captured']) < token <= int(congested[0]['captured']),
                'completion defer outside burst')
        require(any(row.get('token') == item['token'] and
                    row.get('buffer') == item['buffer'] for row in retries),
                f'token {token}: deferred index was not retried')
    pieces = [row for row in events(log, 's212 event=fragment_ingress ')
              if int(row['token']) > int(congested[0]['captured'])]
    require(len(pieces) == 2 and
            {(row['offset'], row['more']) for row in pieces} == {('0', '1'), ('16', '0')},
            'two real fragment offsets missing')
    initial_piece = next(row for row in pieces if row['offset'] == '0')
    final_piece = next(row for row in pieces if row['offset'] == '16')
    merged = [row for row in events(log, 's229 event=product_reassembled ')
              if row.get('token') == initial_piece['token']]
    require(len(merged) == 1 and merged[0]['originals'] == '2' and
            merged[0]['survivor'] == one(capture, initial_piece['token'])['buffer'],
            'fragment survivor/original count mismatch')
    require(one(completion, initial_piece['token'])['buffer'] ==
            one(capture, initial_piece['token'])['buffer'] and
            one(completion, final_piece['token'])['buffer'] ==
            one(capture, final_piece['token'])['buffer'],
            'fragment originals not individually returned')
    print(f'S301 Pixel Product TUN fault witness PASS: generation {result["generation"]}, '
          f'{last-first+1} original indexes, {len(deferred)} deferred returns')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    check(parser.parse_args().directory)
