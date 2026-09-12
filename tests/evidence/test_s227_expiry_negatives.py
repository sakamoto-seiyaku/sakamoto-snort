#!/usr/bin/env python3
"""Rehash semantic corruptions of actual S227 data; never accept hash-only tests."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s227_verify', ROOT/'tests/device/verify-s227-udp-expiry.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def change(text, prefix, field, value):
    return re.sub(r'^('+re.escape(prefix)+r'[^\n]*?\b'+re.escape(field)+r'=)\S+',
                  lambda match: match[1]+str(value), text, count=1, flags=re.M)


def replace(path, value):
    path.unlink()  # Break the private hard link before changing any bytes.
    path.write_text(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    source = args.run.resolve()
    baseline = verifier.verify(source)
    assert baseline['status'] == 'PASS' and baseline['matrix_complete']
    release = verifier.rows((source/'first/vpp.log').read_text(), 's227 event=release ')[0]
    mutations = [
        ('missing_release', 'first/vpp.log', lambda t: re.sub(r'^s227 event=release [^\n]*\n', '', t, count=1, flags=re.M)),
        ('early_release', 'first/vpp.log', lambda t: change(t, 's227 event=release ', 'release_us', int(release['deadline_us'])-1)),
        ('late_release', 'first/vpp.log', lambda t: change(t, 's227 event=release ', 'release_us', int(release['deadline_us'])+1600000)),
        ('wrong_release_owner', 'first/vpp.log', lambda t: change(t, 's227 event=release ', 'owner', '7')),
        ('wrong_release_thread', 'first/vpp.log', lambda t: change(t, 's227 event=release ', 'thread', '0')),
        ('wrong_release_generation', 'first/vpp.log', lambda t: change(t, 's227 event=release ', 'generation', '1')),
        ('wrong_release_instance', 'first/vpp.log', lambda t: change(t, 's227 event=release ', 'incarnation', '999999')),
        ('changed_timeout', 'first/seeded.txt', lambda t: change(t, 'flow.timer ', 'deadline_us', '1')),
        ('wrong_timeout_class', 'shorten/refreshed.txt', lambda t: change(t, 'flow.timer ', 'timeout', '1')),
        ('lost_renewal', 'renew-first/refreshed.txt', lambda t: change(t, 'flow.timer ', 'deadline_us', '1')),
        ('old_timer_woke_after_renewal', 'renew-bidir/past-original-deadline.txt', lambda t: change(t, 'expiry.owner=', 'wakes', '1')),
        ('endpoint_reply_missing', 's227-server-4.log', lambda t: re.sub(r'^received [^\n]*\n', '', t, count=1, flags=re.M)),
        ('same_socket_not_retained', 'first/client-closed.txt', lambda t: change(t, 'prepared ', 'retained_fds', '0')),
        ('oversized_batch', 'bulk/vpp.log', lambda t: change(t, 's227 event=batch ', 'closed', '101')),
        ('changed_batch_minimum', 'bulk/vpp.log', lambda t: change(t, 's227 event=batch ', 'oldest_us', '1')),
        ('erased_backlog', 'bulk/vpp.log', lambda t: change(t, 's227 event=batch ', 'timers', '0')),
        ('erased_budget_exhaustion', 'bulk/completed.txt', lambda t: change(t, 'expiry.owner=', 'budget_exhausted', '999999')),
        ('logical_old_slot_overwritten', 'lookup/vpp.log', lambda t: change(t, 's227 event=logical_expiry ', 'new_slot',
            verifier.rows(t, 's227 event=logical_expiry ')[0]['old_slot'])),
        ('logical_before_deadline', 'lookup/vpp.log', lambda t: change(t, 's227 event=logical_expiry ', 'now_us', '1')),
        ('logical_old_instance_changed', 'lookup/vpp.log', lambda t: change(t, 's227 event=logical_expiry ', 'old_incarnation', '999999')),
        ('logical_old_deadline_changed', 'lookup/vpp.log', lambda t: change(t, 's227 event=logical_expiry ', 'old_deadline_us', '1')),
        ('stale_wake_accepted', 'stop/vpp.log', lambda t: change(t, 's227 event=stale_wake ', 'accepted', '1')),
        ('stale_wake_was_current', 'stop/vpp.log', lambda t: change(t, 's227 event=stale_wake ', 'received_generation',
            verifier.rows(t, 's227 event=stale_wake ')[0]['generation'])),
        ('driver_still_experimental', 'first/initial.txt', lambda t: change(t, 'expiry.owner=', 'experiment', '1')),
        ('driver_not_default_on', 'first/initial.txt', lambda t: change(t, 'expiry.owner=', 'mode', '0')),
        ('shared_owner_timerfd', 'first/initial.txt', lambda t: change(t, 'expiry.owner=1 ', 'timer_fd',
            verifier.rows(t, 'expiry.owner=')[0]['timer_fd'])),
        ('timerfd_periodic', 'first/armed-fdinfo-0.txt', lambda t: re.sub(r'it_interval:.*', 'it_interval: (1, 0)', t)),
        ('timerfd_not_disarmed', 'first/disarmed-fdinfo-0.txt', lambda t: re.sub(r'it_value:.*', 'it_value: (1, 0)', t)),
        ('timerfd_residue', 'first/closed-fds.txt', lambda t: t+'\n999 -> anon_inode:[timerfd998:vpp_main]\n'),
        ('missing_consumer', 'first/vpp.log', lambda t: re.sub(r'^s225 event=consumer_end [^\n]*\n', '', t, count=1, flags=re.M)),
        ('changed_END_buffer', 'first/vpp.log', lambda t: change(t, 's225 event=consumer_end ', 'buffer', '1')),
        ('retained_packet_obligation', 'first/vpp.log', lambda t: change(t, 's225 event=unlink_allocate ', 'obligation', '1')),
        ('changed_native_verdict', 'first/vpp.log', lambda t: change(t, 's242 event=verdict_syscall ', 'verdict', '0')),
        ('missing_packet_return', 'first/vpp.log', lambda t: re.sub(r'^s203 event=buffer_free [^\n]*\n', '', t, count=1, flags=re.M)),
        ('administrative_substitute', 'first/completed.txt', lambda t: change(t, 'flow-end.owner=', 'administrative_releases', '1')),
        ('flow_capacity_bypass', 'first/completed.txt', lambda t: change(t, 'flow.pool ', 'capacity_drops', '1')),
        ('packet_debt', 'first/completed.txt', lambda t: change(t, 'completion.status ', 'pending', '1')),
        ('lost_capture', 'first/completed.txt', lambda t: change(t, 'root.lane ', 'captured', '999999')),
        ('missing_stop', 'first/stop.txt', lambda t: t.replace('root.stop=ok', 'root.stop=failed')),
        ('hook_residue', 'first/hooks-after.txt', lambda t: t+'\nSAKAMOTO_S227_leftover\n'),
    ]
    rejected = []
    with tempfile.TemporaryDirectory(prefix='s227-negatives-', dir=source.parent) as temporary:
        for name, relative, mutate in mutations:
            run = Path(temporary)/name
            shutil.copytree(source, run, copy_function=os.link)
            path = run/relative
            original = path.read_text()
            altered = mutate(original)
            assert altered != original, 'no-op mutation '+name
            replace(path, altered)
            result = json.loads((run/'result.json').read_text())
            result['raw_hashes'][relative] = verifier.digest(path)
            replace(run/'result.json', json.dumps(result, indent=2)+'\n')
            try: verifier.verify(run)
            except AssertionError as error:
                assert 'raw hash mismatch' not in str(error), 'hash-only rejection '+name
                rejected.append(dict(case=name, reason=str(error)))
            else: raise AssertionError('semantic corruption accepted '+name)
    answer = dict(status='PASS', semantic_negatives=len(rejected), rejected=rejected)
    if args.output: args.output.write_text(json.dumps(answer, indent=2)+'\n')
    print(json.dumps(answer, indent=2))


if __name__ == '__main__':
    main()
