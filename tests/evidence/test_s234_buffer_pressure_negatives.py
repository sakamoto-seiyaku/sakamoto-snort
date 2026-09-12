#!/usr/bin/env python3
"""Corrupt raw pressure evidence and refresh hashes: semantic checks must fail."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('pressure', ROOT/'tests/device/verify-s234-buffer-pressure.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def change(text, prefix, field, value):
    pattern = r'^('+re.escape(prefix)+r'[^\n]*?\b'+re.escape(field)+r'=)\S+'
    return re.sub(pattern, lambda m: m[1]+value, text, count=1, flags=re.M)


def early_free(text):
    line = next(line for line in text.splitlines() if line.startswith('s225 event=unlink_allocate '))
    return text+'\n'+line.replace('event=unlink_allocate', 'event=free_callback')+'\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    source = args.run.resolve()
    assert verifier.verify(source)['status'] == 'PASS'
    record = json.loads((source/'result.json').read_text())
    fatal = (source/'fatal/vpp.log').read_text()
    stamp = int(verifier.rows(fatal, 's234 event=allocator_returned_zero ')[0]['monotonic_ns'])
    cases = [
        ('missing_allocator_result', 'fatal/vpp.log', lambda t: t.replace('event=allocator_returned_zero', 'event=synthetic_exception', 1)),
        ('allocator_still_available', 'fatal/vpp.log', lambda t: change(t, 's234 event=allocator_returned_zero ', 'available', '1')),
        ('owner_cache_not_exhausted', 'fatal/vpp.log', lambda t: change(t, 's234 event=allocator_returned_zero ', 'owner_cached', '1')),
        ('fake_exit_code', 'fatal/vpp.log', lambda t: change(t, 's225 event=fatal_allocation_failure ', 'exit_code', '0')),
        ('abort_dump_path', 'fatal/vpp.log', lambda t: t+'received signal SIGABRT\n'),
        ('false_orderly_free_after_fatal', 'fatal/vpp.log', early_free),
        ('pending_entries_faked_zero', 'fatal/vpp.log', lambda t: change(t, 's234 event=allocator_returned_zero ', 'ending', '0')),
        ('wrong_owner_pressure', 'fatal/vpp.log', lambda t: change(t, 's234 event=batch_begin ', 'owner', '1')),
        ('wrong_generation_pressure', 'fatal/vpp.log', lambda t: change(t, 's234 event=batch_begin ', 'generation', '1')),
        ('near_boundary_not_reached', 'near/vpp.log', lambda t: change(t, 's234 event=batch_end ', 'owner_cached', '2')),
        ('missing_normal_consumer', 'normal/vpp.log', lambda t: re.sub(r'^s225 event=consumer_end [^\n]*\n', '', t, count=1, flags=re.M)),
        ('changed_final_entry', 'normal/vpp.log', lambda t: change(t, 's225 event=free_callback ', 'orig_bytes', '9999')),
        ('retained_first_packet', 'normal/vpp.log', lambda t: change(t, 's225 event=unlink_allocate ', 'obligation', '1')),
        ('wrong_end_buffer', 'normal/vpp.log', lambda t: change(t, 's225 event=consumer_end ', 'buffer', '1')),
        ('missing_orderly_stop', 'normal/vpp.log', lambda t: re.sub(r'^s242 event=stop_native_zero [^\n]*\n', '', t, count=1, flags=re.M)),
        ('capture_verdict_became_drop', 'normal/vpp.log', lambda t: change(t, 's242 event=verdict_syscall ', 'verdict', '0')),
        ('entry_from_old_runtime', 'normal/initial.txt', lambda t: change(t, 'flow.runtime ', 'generation', '1')),
        ('missing_endpoint_echo', 'udp-4.log', lambda t: re.sub(r'^received [^\n]*\n', '', t, count=1, flags=re.M)),
        ('request_not_after_fatal', 'fatal/trigger-and-recovery.txt', lambda t: change(t, 'traffic ', 'begin_ns', '1')),
        ('new_request_recovery_too_late', 'fatal/trigger-and-recovery.txt', lambda t: re.sub(r'\bend_ns=\d+', 'end_ns='+str(stamp+3_000_000_000), t)),
        ('platform_cleanup_too_late', 'fatal/cleanup-clock.txt', lambda t: change(t, 'clock ', 'mono_ns', str(stamp+6_000_000_000))),
        ('private_hook_survived', 'normal/hooks-after.txt', lambda t: t+'\n-A OUTPUT -m comment --comment SAKAMOTO_S234_normal -j ACCEPT\n'),
    ]
    if record['platform'] == 'linux':
        cases.append(('queue_still_owned', 'fatal/fatal-closed-queue-bind.json', lambda t: t.replace('"176": 0', '"176": -16', 1)))
    else:
        cases.append(('queue_still_owned', 'fatal/fatal-closed-queues.txt', lambda t: t+'176 12345 1 2 65531 0 0 0 1\n'))
        if record['mode'] == 'supervisor':
            cases.append(('protection_not_stopped', 'fatal/failed.properties', lambda t: t.replace('protectionRunning=false', 'protectionRunning=true', 1)))
    rejected = []
    with tempfile.TemporaryDirectory(prefix='s234-negatives-') as temporary:
        for name, relative, mutate in cases:
            run = Path(temporary)/name
            shutil.copytree(source, run)
            path = run/relative
            original = path.read_text()
            altered = mutate(original)
            assert altered != original, 'no-op mutation '+name
            path.write_text(altered)
            result = json.loads((run/'result.json').read_text())
            result['raw_hashes'][relative] = verifier.digest(path)
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
