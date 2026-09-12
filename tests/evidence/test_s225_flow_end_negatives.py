#!/usr/bin/env python3
"""Corrupt semantic evidence, updating file hashes so rejection is behavioral."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s225_verify', ROOT/'tests/device/verify-s225-flow-end.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def line_change(text, event, key, value):
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith('s225 event='+event+' '):
            replacement, count = re.subn(r'\b'+key+r'=[^\s]+', key+'='+value, line, count=1)
            assert count and replacement != line
            lines[index] = replacement
            return ''.join(lines)
    raise AssertionError('mutation event absent '+event)


def event_remove(text):
    return re.sub(r'^s225 event=consumer_end .*\n', '', text, count=1, flags=re.M)


def duplicate_free(text):
    return re.sub(r'^(s225 event=free_callback .*\n)', r'\1\1', text, count=1, flags=re.M)


def early_release(text):
    lines = text.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith('s225 event=unlink_allocate '))
    free = next(i for i in range(start, len(lines)) if lines[i].startswith('s225 event=free_callback '))
    line = lines.pop(free)
    lines.insert(start+1, line)
    return ''.join(lines)


def extra_packet_stage(text):
    match = re.search(r'^s225 event=unlink_allocate .*$', text, re.M)
    row = verifier.fields(match[0])
    return text[:match.end()]+f'\ns216 stage=policy buffer={row["buffer"]} thread={row["thread"]} generation={row["generation"]} token=999999'+text[match.end():]


def overwrite_slot(text):
    events = [verifier.fields(line) for line in text.splitlines() if line.startswith('s225 event=unlink_allocate ')]
    # The first replacement follows normal and early cases.
    old = events[2]
    lines = text.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith('s225 event=unlink_allocate ') and
                 verifier.fields(line)['incarnation'] == old['incarnation'] and verifier.fields(line)['owner'] == old['owner'])
    for index in range(start+1, len(lines)):
        line = lines[index]
        if line.startswith('s208 ') and 'created=1 ' in line and verifier.fields(line).get('hash') == old['hash']:
            replacement, count = re.subn(r'\bslot=\d+', 'slot='+old['slot'], line, count=1)
            assert count and replacement != line
            lines[index] = replacement
            return ''.join(lines)
    raise AssertionError('replacement vector absent')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    source = args.run.resolve()
    assert verifier.verify(source)['status'] == 'PASS'
    first = json.loads((source/'result.json').read_text())['generations'][0]['label']
    log = first+'/vpp.log'
    mutations = [
        ('missing_consumer', log, event_remove),
        ('duplicate_free', log, duplicate_free),
        ('release_before_consumer', log, early_release),
        ('wrong_owner', log, lambda t: line_change(t, 'consumer_end', 'owner', '7')),
        ('wrong_thread', log, lambda t: line_change(t, 'consumer_end', 'thread', '0')),
        ('stale_generation', log, lambda t: line_change(t, 'consumer_end', 'generation', '1')),
        ('cloned_signal', log, lambda t: line_change(t, 'consumer_end', 'buffer', '1')),
        ('entry_relinked', log, lambda t: line_change(t, 'consumer_end', 'linked', '1')),
        ('entry_freed_early', log, lambda t: line_change(t, 'consumer_end', 'allocated', '0')),
        ('payload_signal', log, lambda t: line_change(t, 'consumer_end', 'length', '64')),
        ('adapter_obligation', log, lambda t: line_change(t, 'consumer_end', 'obligation', '123')),
        ('immutable_counters_changed', log, lambda t: line_change(t, 'free_callback', 'orig_bytes', '999999')),
        ('end_reason_changed', log, lambda t: line_change(t, 'consumer_end', 'reason', '0')),
        ('packet_policy_on_end', log, extra_packet_stage),
        ('old_slot_overwritten', log, overwrite_slot),
        ('stale_close_accepted', log, lambda t: re.sub(r'(s225 event=controlled_close [^\n]*status=)12', r'\g<1>0', t, count=1)),
        ('end_residue', first+'/closed.txt', lambda t: t.replace('flow-end.buffers=0', 'flow-end.buffers=1', 1)),
        ('entry_residue', first+'/closed.txt', lambda t: t.replace('active_entries=0', 'active_entries=1', 1)),
        ('release_accounting', first+'/closed.txt', lambda t: re.sub(r'^(flow-end.owner=[^\n]*\breleased=)\d+', r'\g<1>999', t, count=1, flags=re.M)),
        ('native_vector_count', first+'/runtime.txt', lambda t: re.sub(r'(product-flow-consumer\s+active\s+\d+\s+)\d+', r'\g<1>999', t, count=1)),
        ('endpoint_not_received', 's225-endpoint-4.log', lambda t: re.sub(r'^received .*\n', '', t, count=1, flags=re.M)),
        ('policy_verdict_changed', log, lambda t: re.sub(r'(s242 event=verdict_syscall [^\n]*\bverdict=)1', r'\g<1>0', t, count=1)),
    ]
    rejected = []
    with tempfile.TemporaryDirectory(prefix='s225-negatives-') as temporary:
        for name, relative, mutate in mutations:
            run = Path(temporary)/name
            shutil.copytree(source, run)
            path = run/relative
            before = path.read_text()
            after = mutate(before)
            assert before != after, 'mutation was a no-op: '+name
            path.write_text(after)
            result = json.loads((run/'result.json').read_text())
            result['raw_hashes'][relative] = verifier.digest(path)
            (run/'result.json').write_text(json.dumps(result, indent=2)+'\n')
            try:
                verifier.verify(run)
            except AssertionError as error:
                assert 'raw evidence changed' not in str(error), 'only hash rejection: '+name
                rejected.append(dict(case=name, reason=str(error)))
            else:
                raise AssertionError('semantic corruption accepted: '+name)
    answer = json.dumps(dict(status='PASS', semantic_negatives=len(rejected), rejected=rejected), indent=2)+'\n'
    if args.output:
        args.output.write_text(answer)
    print(answer, end='')


if __name__ == '__main__':
    main()
