#!/usr/bin/env python3
"""Evaluate the fixed gate without changing its thresholds after measurement."""
import argparse
import importlib.util
import json
from pathlib import Path
import tarfile
ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True, help='new report path; frozen inputs are never overwritten')
args = parser.parse_args()
run_dir = OUT / 'run-balanced'
if args.output.resolve() == (run_dir / 'gate-result.json').resolve():
    parser.error('output must differ from the frozen gate result')
spec = importlib.util.spec_from_file_location('quick', ROOT / 'tests/benchmark/pixel_quick.py')
quick = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quick)
raw = json.loads((run_dir / 'result.json').read_text())
gate = json.loads((OUT / 'pre-registered-balanced-cohort.json').read_text())
structural = gate['structural_gate']
effective = gate['effectiveness_gate']
validity = gate['workload_validity']

def read_cli(profile, mode, name):
    relative = Path('run-balanced') / (profile + '-' + mode) / name
    with tarfile.open(OUT / 'run-balanced-raw.tar.gz', 'r:gz') as archive:
        stream = archive.extractfile(str(relative))
        if stream is None: raise RuntimeError('missing archived CLI: ' + str(relative))
        return stream.read().decode()

checks = []
def check(name, passed, observed=None, bound=None):
    checks.append({'name': name, 'passed': bool(passed), 'observed': observed, 'bound': bound})
check('complete four windows within 120 seconds', raw['status'] == 'COMPLETE' and len(raw['cases']) == 4 and raw['elapsed_seconds'] <= 120 and not raw['errors'], raw['elapsed_seconds'], 120)
check('ordinary lifetimes and final cleanup', len(raw['lifetimes']) == 2 and raw['final_runtime'].get('state') == 'stopped' and raw['final_runtime'].get('mayBeActive') == 'false' and not raw['final_processes'] and raw['rules_unchanged'])
comparisons = {}
if len(raw['cases']) == 4:
    successful_profiles = []
    for profile in ('root', 'vpn'):
        cells = {v['mode']: v for v in raw['cases'] if v['profile'] == profile}
        old, new = (cells[m]['mechanism'] for m in ('baseline', 'batch'))
        changes = {key: (new[key] / old[key] - 1) * 100 for key in
                   ('admit_clocks_per_vector', 'vpp_cpu_seconds_per_admitted_packet', 'admitted_pps')}
        changes['remote_share_difference_pp'] = abs(new['remote_share'] - old['remote_share']) * 100
        changes['rejection_share_increase_pp'] = (new['rejection_share'] - old['rejection_share']) * 100
        changes['root_bypass_share_increase_pp'] = (new['root_bypass_share'] - old['root_bypass_share']) * 100 if profile == 'root' else None
        comparisons[profile] = changes
        check(profile + ' batch vectors per call', new['vectors_per_call'] >= structural['batch_admit_vectors_per_call_min'], new['vectors_per_call'], '>=4')
        check(profile + ' batch remote packets per actual queue publication', new['remote_packets_per_publication'] >= structural['batch_remote_packets_per_physical_queue_publication_min'], new['remote_packets_per_publication'], '>=4')
        check(profile + ' lookahead four-packet preparation exercised', new['quads'] > 0, new['quads'], '>0')
        for mode, cell in cells.items():
            m = cell['mechanism']
            check(profile + ' ' + mode + ' workload actually exercises primary handoff', validity['primary_remote_share_min'] <= m['remote_share'] <= validity['primary_remote_share_max'], m['remote_share'], '[.1,.9]')
            check(profile + ' ' + mode + ' no Flow capacity miss', cell['score']['flow_capacity_misses'] == 0, cell['score']['flow_capacity_misses'], 0)
            before = read_cli(profile, mode, 'before-cli.txt')
            after = read_cli(profile, mode, 'after-cli.txt')
            for field in ('node_calls', 'node_vectors', 'node_clocks', 'primary_calls', 'primary_packets', 'transferred', 'quads'):
                delta = sum(int(v.get(field, 0)) for v in quick.rows(after, 'admit.experiment.thread ')) - sum(int(v.get(field, 0)) for v in quick.rows(before, 'admit.experiment.thread '))
                check(profile + ' ' + mode + ' raw ' + field + ' matches summary', delta == m[field], delta, m[field])
            publications = sum(int(v['tail']) for v in quick.rows(after, 'admit.experiment.queue ')) - sum(int(v['tail']) for v in quick.rows(before, 'admit.experiment.queue '))
            check(profile + ' ' + mode + ' actual native queue publications match summary', publications == m['physical_queue_publications'], publications, m['physical_queue_publications'])
            cpu = quick.monitor_summary(read_cli(profile, mode, 'cpu.jsonl'), cell['client'])
            check(profile + ' ' + mode + ' raw simultaneous CPU samples match summary', cpu == cell['cpu'])
            failures = sum(int(v['owner_failures']) for v in quick.rows(after, 'primary.status ')) - sum(int(v['owner_failures']) for v in quick.rows(before, 'primary.status '))
            check(profile + ' ' + mode + ' no owner failure', failures == 0, failures, 0)
        check(profile + ' whole VPP CPU per packet regression', changes['vpp_cpu_seconds_per_admitted_packet'] <= effective['other_profile_cpu_per_packet_regression_percent_max'], changes['vpp_cpu_seconds_per_admitted_packet'], '<=+5%')
        check(profile + ' admission rate regression', changes['admitted_pps'] >= -effective['admitted_pps_regression_percent_max'], changes['admitted_pps'], '>=-5%')
        check(profile + ' remote share comparability', changes['remote_share_difference_pp'] <= effective['remote_packet_share_difference_percentage_points_max'], changes['remote_share_difference_pp'], '<=5pp')
        check(profile + ' primary rejection regression', changes['rejection_share_increase_pp'] <= effective['bypass_or_rejection_share_regression_percentage_points_max'], changes['rejection_share_increase_pp'], '<=3pp')
        if profile == 'root': check('Root ingress bypass regression', changes['root_bypass_share_increase_pp'] <= effective['bypass_or_rejection_share_regression_percentage_points_max'], changes['root_bypass_share_increase_pp'], '<=3pp')
        minima = effective['require_at_least_one_profile']
        successful_profiles.append(changes['admit_clocks_per_vector'] <= -minima['admit_clocks_per_vector_reduction_percent_min'] and changes['vpp_cpu_seconds_per_admitted_packet'] <= -minima['vpp_cpu_seconds_per_admitted_packet_reduction_percent_min'])
    check('at least one profile improves BOTH admit clocks and whole VPP CPU per packet by 10%', any(successful_profiles), comparisons, 'both <=-10% in the same profile')
result = {'decision': 'PASS' if all(v['passed'] for v in checks) else 'FAIL',
          'threshold_source': str(OUT / 'pre-registered-balanced-cohort.json'), 'comparisons': comparisons,
          'checks': checks, 'failed_checks': [v for v in checks if not v['passed']]}
args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'decision': result['decision'], 'comparisons': comparisons, 'failed_checks': result['failed_checks']}, indent=2))
