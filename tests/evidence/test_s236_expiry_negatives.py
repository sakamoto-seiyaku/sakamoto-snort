#!/usr/bin/env python3
"""Rehash corruptions of real S236 evidence and demand semantic rejection."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def change(text, prefix, field, value, condition=lambda line: True):
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(prefix) and condition(line):
            lines[index] = re.sub(r'\b'+re.escape(field)+r'=\S+', field+'='+str(value), line, count=1)
            break
    return ''.join(lines)


def remove(text, prefix, condition=lambda line: True):
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(prefix) and condition(line):
            del lines[index]; break
    return ''.join(lines)


def duplicate(text, prefix):
    return text+'\n'+next(line for line in text.splitlines() if line.startswith(prefix))+'\n'


def corrupt_wire(text, prefix):
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if not line.startswith(prefix): continue
        match = re.search(r'\braw=([0-9a-f]+)', line)
        data = bytearray.fromhex(match[1]); data[-1] ^= 1
        lines[index] = line[:match.start(1)]+data.hex()+line[match.end(1):]
        break
    return ''.join(lines)


def replace(path, text):
    path.unlink()  # Never modify original evidence through a private hardlink.
    path.write_text(text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--ovs', type=Path, required=True)
    parser.add_argument('--suite', choices=('protocols', 'mixed'), required=True)
    parser.add_argument('--cases'); parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    source = args.run.resolve()
    filename = 'verify-s236-protocol-expiry.py' if args.suite == 'protocols' else 'verify-s236-mixed-expiry.py'
    spec = importlib.util.spec_from_file_location('s236_mutation_verifier', ROOT/'tests/device'/filename)
    verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
    selected = args.cases.split(',') if args.cases else None
    baseline = verifier.verify(source, args.ovs, selected)
    assert baseline['status'] == 'VALID_PARTIAL'
    chosen = [e['case'] for e in baseline['cases']]
    first = chosen[0]
    mutations = []

    def add(name, case, path, mutate):
        if case in chosen: mutations.append((name, case, path, mutate))

    def field(name, case, file, prefix, key, value, condition=lambda line: True):
        add(name, case, case+'/'+file, lambda t: change(t, prefix, key, value, condition))

    release = verifier.rows((source/first/'vpp.log').read_text(), 's227 event=release ')[0]
    common = [
        ('wrong_deadline', 'seeded.txt', 'flow.timer ', 'deadline_us', '1'),
        ('wrong_timeout_class', 'seeded.txt', 'flow.timer ', 'timeout', '255'),
        ('lost_heap_membership', 'seeded.txt', 'flow.timer ', 'heap_position', '4294967295'),
        ('heap_count_mismatch', 'seeded.txt', 'expiry.owner=', 'timers', '99999'),
        ('wrong_owner', 'vpp.log', 's208 event=observe ', 'owner', '9'),
        ('wrong_stored_hash', 'vpp.log', 's208 event=observe ', 'stored_hash', '1'),
        ('wrong_observed_bytes', 'vpp.log', 's208 event=observe ', 'bytes', '1'),
        ('early_release', 'vpp.log', 's227 event=release ', 'release_us', int(release['deadline_us'])-1),
        ('late_release', 'vpp.log', 's227 event=release ', 'release_us', int(release['deadline_us'])+1600000),
        ('wrong_release_owner', 'vpp.log', 's227 event=release ', 'owner', '9'),
        ('wrong_release_generation', 'vpp.log', 's227 event=release ', 'generation', '1'),
        ('wrong_release_incarnation', 'vpp.log', 's227 event=release ', 'incarnation', '999999'),
        ('oversized_batch', 'vpp.log', 's227 event=batch ', 'closed', '101'),
        ('wrong_batch_minimum', 'vpp.log', 's227 event=batch ', 'oldest_us', '1'),
        ('wrong_native_verdict', 'vpp.log', 's242 event=verdict_syscall ', 'verdict', '0'),
        ('wrong_native_fd', 'vpp.log', 's242 event=verdict_syscall ', 'fd', '999999'),
        ('retained_END_obligation', 'vpp.log', 's225 event=unlink_allocate ', 'obligation', '1'),
        ('changed_END_carrier', 'vpp.log', 's225 event=consumer_end ', 'buffer', '1'),
        ('changed_END_protocol', 'vpp.log', 's225 event=consumer_end ', 'protocol', '255'),
        ('separate_protocol_pool', 'closed.txt', 'flow.runtime ', 'capacity', '1'),
        ('packet_debt', 'closed.txt', 'completion.status ', 'pending', '1'),
        ('administrative_substitute', 'completed.txt', 'flow-end.owner=', 'administrative_releases', '999999'),
        ('flow_capacity_bypass', 'closed.txt', 'flow.pool ', 'capacity_drops', '1'),
        ('queue_fd_survived', 'closed.txt', 'root.lane ', 'fd', '999999'),
        ('experimental_driver', 'initial.txt', 'expiry.owner=', 'experiment', '1'),
        ('driver_not_default', 'initial.txt', 'expiry.owner=', 'mode', '0'),
    ]
    for name, file, prefix, key, value in common: field(name, first, file, prefix, key, value)
    for name, prefix in [('missing_release', 's227 event=release '), ('missing_consumer', 's225 event=consumer_end '),
                         ('missing_END_free', 's225 event=free_callback '), ('missing_packet_free', 's203 event=buffer_free '),
                         ('missing_orderly_stop', 's242 event=stop_native_zero ')]:
        add(name, first, first+'/vpp.log', lambda t, p=prefix: remove(t, p))
    add('duplicate_release', first, first+'/vpp.log', lambda t: duplicate(t, 's227 event=release '))
    add('duplicate_END_free', first, first+'/vpp.log', lambda t: duplicate(t, 's225 event=free_callback '))
    add('native_checksum_corrupted', first, first+'/vpp.log', lambda t: corrupt_wire(t, 's231 event=nfq_payload '))
    add('periodic_timer', first, first+'/armed-fdinfo-0.txt', lambda t: re.sub(r'it_interval:.*', 'it_interval: (1, 0)', t))
    add('timer_not_monotonic', first, first+'/armed-fdinfo-0.txt', lambda t: re.sub(r'clockid:.*', 'clockid: 0', t))
    add('timer_survived_stop', first, first+'/closed-fds.txt', lambda t: t+'\n999 -> anon_inode:[timerfd]\n')
    add('private_hook_survived', first, 'hooks-after.txt', lambda t: t+'\nSAKAMOTO_S236_leftover\n')
    add('END_buffer_residue', first, first+'/closed.txt', lambda t: t.replace('flow-end.buffers=0', 'flow-end.buffers=1', 1))
    if args.suite == 'protocols':
        field('tcp_peer_drift', 'tcp-first', 'vpp.log', 's222 event=tcp_update ', 'orig_seqlo', '1')
        field('tcp_snapshot_peer_drift', 'tcp-first', 'seeded.txt', 'flow.tcp ', 'orig_seqlo', '1')
        field('INVALID_renewal', 'tcp-invalid', 'vpp.log', 's222 event=tcp_update ', 'refresh', '1', lambda line: 'update=3 ' in line)
        field('icmp_wrong_sequence', 'icmp-first', 'vpp.log', 's224 event=icmp_update ', 'sequence', '999')
        field('icmp_wrong_identifier', 'icmp-first', 'vpp.log', 's224 event=icmp_update ', 'identifier', '999')
        field('icmp_reply_fabricated', 'icmp-first', 'vpp.log', 's224 event=icmp_update ', 'seen_reply', '1')
        field('icmp_phase_drift', 'icmp-reply', 'seeded.txt', 'flow.icmp ', 'phase', '1')
        field('lost_renewal', 'icmp-renew', 'refreshed.txt', 'flow.timer ', 'deadline_us', '1')
        field('lost_shortening', 'icmp-shorten', 'refreshed.txt', 'flow.timer ', 'deadline_us', '1')
        field('Echo_no_reply', 'icmp-first', 'flow-0-seed-client.txt', 'endpoint ', 'reply_ns', '0')
        add('duplicate_Echo_server_receipt', 'icmp-first', 's224-icmp-4.log', lambda t: duplicate(t, 'received '))
    else:
        field('handoff_credit_not_returned', first, 'closed.txt', 'primary.status ', 'credit0', '0')
        field('handoff_rejected_hidden', first, 'closed.txt', 'primary.status ', 'rejected', '1')
        field('mixed_renewal_lost', 'mixed-renew', 'refreshed.txt', 'flow.timer ', 'deadline_us', '1')
        lookup = 'mixed-lookup'
        field('logical_before_deadline', lookup, 'vpp.log', 's227 event=logical_expiry ', 'now_us', '1')
        field('logical_stale_instance', lookup, 'vpp.log', 's227 event=logical_expiry ', 'old_incarnation', '999999')
        field('logical_false_deadline', lookup, 'vpp.log', 's227 event=logical_expiry ', 'old_deadline_us', '1')
        field('logical_wrong_new_instance', lookup, 'vpp.log', 's227 event=logical_expiry ', 'new_incarnation', '999999')
        field('large_backlog_erased', lookup, 'vpp.log', 's227 event=batch ', 'timers', '0')
        field('large_peer_drift', lookup, 'seeded.txt', 'flow.tcp ', 'orig_seqlo', '1')
        field('wire_outside_private_selection', lookup, 'wire-final.txt', 'wire ', 'value', '999')
        field('wire_fake_capture_window', lookup, 'wire-final.txt', 'window ', 'full', '0')
        add('independent_wire_checksum', lookup, lookup+'/wire-final.txt', lambda t: corrupt_wire(t, 'wire '))
        add('logical_missing', lookup, lookup+'/vpp.log', lambda t: remove(t, 's227 event=logical_expiry '))
        add('large_missing_entry', lookup, lookup+'/seeded.txt', lambda t: remove(t, 'flow.entry '))
        add('large_lost_native_sample', lookup, lookup+'/vpp.log', lambda t: remove(t, 's231 event=nfq_payload '))

    rejected = []
    with tempfile.TemporaryDirectory(prefix='s236-semantic-negatives-', dir=source.parent) as temporary:
        for name, case, relative, mutate in mutations:
            run = Path(temporary)/name
            shutil.copytree(source, run, copy_function=os.link)
            path = run/relative; before = path.read_text(); after = mutate(before)
            assert after != before, 'no-op semantic mutation '+name
            replace(path, after)
            result = json.loads((run/'result.json').read_text())
            result['raw_hashes'][relative] = verifier.digest(path)
            replace(run/'result.json', json.dumps(result, indent=2)+'\n')
            try: verifier.verify(run, args.ovs, [case])
            except AssertionError as error:
                assert not str(error).startswith('raw file '), 'hash-only rejection '+name
                rejected.append(dict(case=name, reason=str(error)))
            else: raise AssertionError('semantic corruption accepted '+name)
            if len(rejected) % 10 == 0: print(json.dumps(dict(event='negatives', rejected=len(rejected), suite=args.suite)), flush=True)
    answer = dict(status='PASS', suite=args.suite, platform=json.loads((source/'result.json').read_text())['platform'],
        source_result_sha256=verifier.digest(source/'result.json'), script_sha256=verifier.digest(__file__),
        verifier_files=baseline['verifier_files'],
        semantic_negatives=len(rejected), rejected=rejected)
    if args.output: args.output.write_text(json.dumps(answer, indent=2)+'\n')
    print(json.dumps(answer, indent=2))


if __name__ == '__main__': main()
