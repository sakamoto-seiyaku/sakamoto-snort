#!/usr/bin/env python3
"""Rehash semantic corruptions of actual S226 evidence; never trust hashes alone."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('expiry', ROOT/'tests/device/verify-s226-expiry-ab.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def change(text, prefix, field, value):
    pattern = r'^('+re.escape(prefix)+r'[^\n]*?\b'+re.escape(field)+r'=)\S+'
    return re.sub(pattern, lambda m: m[1]+str(value), text, count=1, flags=re.M)


def replace_private(path, value):
    # The private tree uses hard links only to avoid copying immutable large
    # logs for every mutation. Break the link BEFORE touching its bytes.
    path.unlink()
    path.write_text(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--retry-run', type=Path, action='append', default=[])
    args = parser.parse_args()
    source, build = args.run.resolve(), args.build.resolve()
    baseline = verifier.verify(source, build)
    retry_outcomes = [verifier.verify(path.resolve(), build) for path in args.retry_run]
    if retry_outcomes: baseline = verifier.combine_retries(baseline, retry_outcomes)
    assert baseline['matrix_complete'] and baseline['status'] == 'FUNCTIONAL_PASS'
    result = json.loads((source/'result.json').read_text())
    pixel = result['platform'] == 'pixel'
    if pixel: assert baseline['comparison']['selected'], 'decision negatives require an otherwise valid candidate'
    stem = 'bulk100-0-deadline/'
    empty = 'empty-0-deadline/'
    log = (source/stem/'vpp.log').read_text()
    release = verifier.records(log, 's226 event=release ')[0]
    mutations = [
        ('missing_release', stem+'vpp.log', lambda t: re.sub(r'^s226 event=release [^\n]*\n', '', t, count=1, flags=re.M)),
        ('early_release', stem+'vpp.log', lambda t: change(t, 's226 event=release ', 'release_us', int(release['deadline_us'])-1)),
        ('late_release', stem+'vpp.log', lambda t: change(t, 's226 event=release ', 'release_us', int(release['deadline_us'])+1600000)),
        ('wrong_owner', stem+'vpp.log', lambda t: change(t, 's226 event=release ', 'owner', '7')),
        ('wrong_thread', stem+'vpp.log', lambda t: change(t, 's226 event=release ', 'thread', '0')),
        ('wrong_generation', stem+'vpp.log', lambda t: change(t, 's226 event=release ', 'generation', '1')),
        ('wrong_incarnation', stem+'vpp.log', lambda t: change(t, 's226 event=release ', 'incarnation', '0')),
        ('timeout_extended', stem+'vpp.log', lambda t: change(t, 's226 event=release ', 'deadline_us', int(release['deadline_us'])+1000000)),
        ('entry_still_indexed', stem+'vpp.log', lambda t: change(t, 's226 event=release ', 'linked', '1')),
        ('timer_still_indexed', stem+'vpp.log', lambda t: change(t, 's226 event=release ', 'heap_position', '0')),
        ('wrong_timeout_class', stem+'vpp.log', lambda t: change(t, 's226 event=release ', 'timeout', '1')),
        ('oversized_batch', stem+'vpp.log', lambda t: change(t, 's226 event=batch ', 'closed', '101')),
        ('wrong_batch_minimum', stem+'vpp.log', lambda t: change(t, 's226 event=batch ', 'oldest_us', '1')),
        ('backlog_erased', 'maximum-0-deadline/vpp.log', lambda t: change(t, 's226 event=batch ', 'timers', '0')),
        ('missing_consumer', stem+'vpp.log', lambda t: re.sub(r'^s225 event=consumer_end [^\n]*\n', '', t, count=1, flags=re.M)),
        ('changed_end_buffer', stem+'vpp.log', lambda t: change(t, 's225 event=consumer_end ', 'buffer', '1')),
        ('retained_packet_obligation', stem+'vpp.log', lambda t: change(t, 's225 event=unlink_allocate ', 'obligation', '1')),
        ('changed_snapshot', stem+'vpp.log', lambda t: change(t, 's225 event=free_callback ', 'orig_bytes', '999999')),
        ('changed_verdict', stem+'vpp.log', lambda t: change(t, 's242 event=verdict_syscall ', 'verdict', '0')),
        ('missing_buffer_return', stem+'vpp.log', lambda t: re.sub(r'^s203 event=buffer_free [^\n]*\n', '', t, count=1, flags=re.M)),
        ('admin_substitute_release', stem+'expired.txt', lambda t: change(t, 'flow-end.owner=', 'administrative_releases', '1')),
        ('flow_capacity_bypass', stem+'expired.txt', lambda t: change(t, 'flow.pool ', 'capacity_drops', '1')),
        ('pending_packet_debt', stem+'expired.txt', lambda t: change(t, 'completion.status ', 'pending', '1')),
        ('lost_captured_packet', stem+'expired.txt', lambda t: change(t, 'root.lane ', 'captured', '999999')),
        ('missing_stop', stem+'stop.txt', lambda t: t.replace('root.stop=ok', 'root.stop=failed')),
        ('timer_fd_residue', stem+'fds-closed.txt', lambda t: t+'\n999 -> anon_inode:[timerfd]\n'),
        ('named_timer_fd_residue', stem+'fds-closed.txt', lambda t: t+'\n999 -> anon_inode:[timerfd598:vpp_main]\n'),
        ('owner_timer_fd_missing', stem+'initialized.txt', lambda t: change(t, 'expiry.owner=', 'timer_fd', '999')),
        ('default_off_timer_backing', stem+'fds-before.txt', lambda t: t+'\n999 -> anon_inode:[timerfd598:vpp_main]\n'),
        ('hook_residue', stem+'hooks-after.txt', lambda t: t+'\nSAKAMOTO_S226_leftover\n'),
        ('not_default_off', stem+'initial.txt', lambda t: change(t, 'expiry.owner=', 'mode', '2')),
        ('empty_deadline_polling', empty+'main-after.txt', lambda t: change(t, 'expiry.owner=', 'calls', '999999999999')),
        ('endpoint_reply_missing', 's226-server-4.log', lambda t: re.sub(r'^received [^\n]*\n', '', t, count=1, flags=re.M)),
        ('rss_peak_over_budget', empty+'main-monitor.txt', lambda t: re.sub(r'^VmHWM:\s+\d+ kB', 'VmHWM: 300000 kB', t, count=1, flags=re.M)),
    ]
    if pixel:
        mutations.extend([
            ('energy_regression', empty+'main-monitor.txt', lambda t: re.sub(r'^(CH3\(T=\d+\)\[S2M_VDD_CPUCL2\], )\d+', r'\g<1>999999999999999', t, count=1, flags=re.M)),
            ('energy_rail_renamed', empty+'main-monitor.txt', lambda t: t.replace('S4M_VDD_CPUCL0', 'UNRELATED_RAIL', 1)),
        ])
    rejected = []
    with tempfile.TemporaryDirectory(prefix='s226-negatives-', dir=source.parent) as temporary:
        for name, relative, mutate in mutations:
            run = Path(temporary)/name
            shutil.copytree(source, run, copy_function=os.link)
            path = run/relative
            original = path.read_text()
            altered = mutate(original)
            assert altered != original, 'no-op mutation '+name
            replace_private(path, altered)
            current = json.loads((run/'result.json').read_text())
            current['raw_hashes'][relative] = verifier.digest(path)
            replace_private(run/'result.json', json.dumps(current, indent=2)+'\n')
            try:
                checked = verifier.verify(run, build)
                if retry_outcomes: verifier.combine_retries(checked, retry_outcomes)
            except AssertionError as error:
                assert 'raw hash mismatch' not in str(error), 'hash-only rejection '+name
                rejected.append(dict(case=name, reason=str(error)))
            else: raise AssertionError('semantic corruption accepted '+name)
        if pixel:
            # Corrupt an actual selected screen-state witness, including a
            # retry's witness when present. Rehash it and require HOLD, so
            # environment acceptance is not tested only on synthetic rows.
            selected = next(r for r in baseline['outcomes'] if r['label'] == 'screen-off-0-deadline')
            selected_source = Path(selected.get('evidence_run', source)).resolve()
            invalid_run = Path(temporary)/'raw_screen_environment'
            shutil.copytree(selected_source, invalid_run, copy_function=os.link)
            relative = 'screen-off-0-deadline-main-before-deviceidle.txt'
            path = invalid_run/relative
            original = path.read_text()
            altered = original.replace('mScreenOn=false', 'mScreenOn=true', 1)
            assert altered != original, 'selected screen witness was not screen-off'
            replace_private(path, altered)
            altered_result = json.loads((invalid_run/'result.json').read_text())
            altered_result['raw_hashes'][relative] = verifier.digest(path)
            replace_private(invalid_run/'result.json', json.dumps(altered_result, indent=2)+'\n')
            checked_original = verifier.verify(invalid_run if selected_source == source else source, build)
            checked_retries = [verifier.verify(invalid_run if p.resolve() == selected_source else p.resolve(), build)
                               for p in args.retry_run]
            checked = verifier.combine_retries(checked_original, checked_retries) if checked_retries else checked_original
            assert checked['comparison']['selected'] is None, 'invalid raw screen witness selected a winner'
            assert any('before_screen' in row['errors'] for row in checked['comparison']['environment_errors'])
            rejected.append(dict(case='raw_screen_environment', reason='HOLD: before_screen'))

            # Bad measurement conditions must yield HOLD, not disappear from
            # the paired comparison. These are decision negatives, not a
            # claim that correct packet processing became incorrect.
            for name, mutate in (
                ('thermal_invalid', lambda rows: rows[0]['environment'].update(valid=False, errors=['thermal'])),
                ('missing_energy_advantage', lambda rows: [r['interval'].update(cpu_rails_mw=100) for r in rows]),
                ('candidate_idle_cpu_failure', lambda rows: [r['idle_failures'].append('process_cpu') for r in rows if r['arm'] == 'deadline' and r['case'] == 'empty']),
            ):
                rows = json.loads(json.dumps(baseline['outcomes']))
                mutate(rows)
                assert verifier.decision(rows)['selected'] is None, 'invalid comparison selected winner '+name
                rejected.append(dict(case=name, reason='HOLD'))
    answer = json.dumps(dict(status='PASS', semantic_negatives=len(rejected), rejected=rejected), indent=2)+'\n'
    if args.output: args.output.write_text(answer)
    print(answer, end='')


if __name__ == '__main__':
    main()
