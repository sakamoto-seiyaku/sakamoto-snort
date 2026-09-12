#!/usr/bin/env python3
"""Mutate actual Echo raw evidence, rehash it, and require semantic rejection."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('icmp_oracle', ROOT/'tests/device/verify-s224-icmp-tracker.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def change(text, prefix, field, value, condition=lambda line: True):
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.startswith(prefix) and condition(line):
            lines[i] = re.sub(r'\b'+re.escape(field)+r'=\S+', field+'='+value, line, count=1)
            break
    return ''.join(lines)


def remove(text, prefix):
    return re.sub(r'^'+re.escape(prefix)+r'[^\n]*\n', '', text, count=1, flags=re.M)


def corrupt_packet(text):
    match = re.search(r'^s231 event=nfq_payload [^\n]*\braw=([0-9a-f]+)', text, re.M)
    if not match:
        return text
    raw = bytearray.fromhex(match[1])
    raw[-1] ^= 1
    return text[:match.start(1)]+raw.hex()+text[match.end(1):]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    source = args.run.resolve()
    assert verifier.verify(source)['status'] == 'PASS'
    original_result = json.loads((source/'result.json').read_text())
    cases = [
        ('missing_tracker_update', 'trace', lambda t: remove(t, 's224 event=icmp_update ')),
        ('tracker_wrong_owner', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'owner', '1')),
        ('tracker_wrong_thread', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'thread', '2')),
        ('tracker_stale_generation', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'generation', '22409')),
        ('first_faked_established', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'phase', '2')),
        ('reply_first_invented_request', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'seen_request', '1',
            lambda line: 'created=1 ' in line and 'seen_request=0 ' in line and 'seen_reply=1 ' in line)),
        ('request_invented_reply', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'seen_reply', '1')),
        ('wrong_ct_state', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'ct_state', '0')),
        ('wrong_update_result', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'update', '2')),
        ('wrong_timeout_class', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'timeout', '1')),
        ('valid_update_lost_refresh', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'refresh', '0')),
        ('wrong_sequence_fact', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'sequence', '11')),
        ('wrong_identifier_fact', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'identifier', '1')),
        ('fake_recreated_sequence', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'created', '1', lambda line: 'created=0 ' in line)),
        ('incarnation_changed_on_hit', 'trace', lambda t: change(t, 's224 event=icmp_update ', 'incarnation', '999', lambda line: 'created=0 ' in line)),
        ('origin_redefined', 'trace', lambda t: change(t, 's208 event=observe ', 'origin_is_a', '0')),
        ('wrong_typed_hash', 'trace', lambda t: change(t, 's208 event=observe ', 'stored_hash', '1')),
        ('wrong_observed_bytes', 'trace', lambda t: change(t, 's208 event=observe ', 'bytes', '1')),
        ('raw_checksum_corrupted', 'trace', corrupt_packet),
        ('missing_original_free', 'trace', lambda t: remove(t, 's203 event=buffer_free ')),
        ('missing_shared_consumer', 'trace', lambda t: remove(t, 's225 event=consumer_packet ')),
        ('wrong_original_verdict', 'trace', lambda t: change(t, 's242 event=verdict_syscall ', 'verdict', '0')),
        ('wrong_original_fd', 'trace', lambda t: change(t, 's242 event=verdict_syscall ', 'fd', '999')),
        ('wrong_original_lane', 'trace', lambda t: change(t, 's204 event=completion_consume ', 'lane', '1')),
        ('fake_automatic_end', 'output/vpp.log', lambda t: t+'\ns225 event=unlink_allocate\n'),
        ('fake_ports_in_snapshot', 'output/final.txt', lambda t: change(t, 'flow.entry ', 'port_a', '24001')),
        ('snapshot_identifier_changed', 'output/final.txt', lambda t: change(t, 'flow.entry ', 'identifier', '1')),
        ('snapshot_state_lost_reply', 'output/final.txt', lambda t: change(t, 'flow.icmp ', 'seen_reply', '0')),
        ('snapshot_separate_capacity', 'output/final.txt', lambda t: change(t, 'flow.runtime ', 'capacity', '64')),
        ('premature_icmp_timer', 'output/final.txt', lambda t: change(t, 'expiry.owner=', 'timers', '1')),
        ('endpoint_nonce_changed', 'output/case-0-first-client.txt', lambda t: change(t, 'endpoint ', 'nonce', 'wrong')),
        ('endpoint_sequence_changed', 'output/case-0-repeat-client.txt', lambda t: change(t, 'endpoint ', 'sequence', '2')),
        ('endpoint_reply_missing', 'output/case-0-first-client.txt', lambda t: change(t, 'endpoint ', 'reply_ns', '0')),
        ('receiver_missing', 'echo-4-1.log', lambda t: remove(t, 'received ')),
        ('receiver_bad_checksum', 'echo-4-1.log', lambda t: change(t, 'received ', 'checksum_valid', '0')),
        ('receiver_duplicate', 'echo-4-1.log', lambda t: t+next(line for line in t.splitlines() if line.startswith('received '))+'\n'),
        ('wrong_hook_queue', 'output/case-0-first-hooks.txt', lambda t: t.replace('--queue-num 176', '--queue-num 177', 1)),
        ('missing_system_ping', 'output/ping-4-client.txt', lambda t: t.replace('3 received', '0 received').replace('3 packets received', '0 packets received')),
        ('management_entry_residue', 'output/closed.txt', lambda t: change(t, 'flow.pool ', 'entries', '1')),
        ('management_release_missing', 'output/closed.txt', lambda t: change(t, 'flow-end.owner=', 'administrative_releases', '0')),
        ('fake_handoff_zero', 'output/closed.txt', lambda t: change(t, 'primary.status ', 'published', '0')),
        ('fake_completion_count', 'output/closed.txt', lambda t: change(t, 'completion.status ', 'verdicts', '1')),
        ('end_buffer_residue', 'output/closed.txt', lambda t: t.replace('flow-end.buffers=0', 'flow-end.buffers=1', 1)),
        ('periodic_timer', 'output/timer-0.txt', lambda t: re.sub(r'it_interval:\s*\(0,\s*0\)', 'it_interval: (1, 0)', t)),
        ('timer_fd_survived', 'output/fds-closed.txt', lambda t: t+'99 -> anon_inode:[timerfd]\n'),
        ('missing_orderly_stop', 'output/vpp.log', lambda t: remove(t, 's242 event=stop_native_zero ')),
        ('private_hook_survived', 'hooks-after.txt', lambda t: t+'\n-A OUTPUT -m comment --comment SAKAMOTO_S224_output -j ACCEPT\n'),
    ]
    if original_result['platform'] == 'linux':
        cases.append(('queue_survived', 'output/closed-queue-bind.json', lambda t: t.replace('"176": 0', '"176": -16', 1)))
    else:
        cases.append(('queue_survived', 'output/closed-queues.txt', lambda t: t+'176 12345 1 2 65531 0 0 0 1\n'))
    rejected = []
    # Keep immutable hardlinks on the evidence filesystem (/tmp may differ).
    with tempfile.TemporaryDirectory(prefix='s224-semantic-negatives-', dir=source.parent) as temporary:
        for name, target, mutate in cases:
            run = Path(temporary)/name
            shutil.copytree(source, run, copy_function=os.link)
            result = json.loads((run/'result.json').read_text())
            paths = [run/n for n in result['raw_hashes'] if n.startswith('output/') and n.endswith('vpp.log')] if target == 'trace' else [run/target]
            changed = 0
            for path in paths:
                before = path.read_text()
                after = mutate(before)
                if before != after:
                    path.unlink()  # Never write through a hardlink into original evidence.
                    path.write_text(after)
                    result['raw_hashes'][str(path.relative_to(run))] = verifier.digest(path)
                    changed += 1
            assert changed, 'no-op semantic mutation '+name
            (run/'result.json').unlink()
            (run/'result.json').write_text(json.dumps(result, indent=2)+'\n')
            try:
                verifier.verify(run)
            except AssertionError as error:
                assert 'raw evidence changed' not in str(error), 'hash-only rejection '+name
                rejected.append(dict(case=name, reason=str(error)))
            else:
                raise AssertionError('semantic corruption accepted '+name)
    answer = json.dumps(dict(status='PASS', semantic_negatives=len(rejected), rejected=rejected), indent=2)+'\n'
    if args.output:
        args.output.write_text(answer)
    print(answer, end='')


if __name__ == '__main__':
    main()
