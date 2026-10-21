#!/usr/bin/env python3
"""Recheck and summarize the raw S304 Product VPN topology campaigns."""
import argparse
import json
from pathlib import Path

import pixel_quick as quick


def read(path):
    return json.loads(path.read_text())


def evidence_path(value, root):
    path = Path(value)
    if path.is_absolute():
        parts = path.parts
        if 'build-output' not in parts:
            raise RuntimeError('absolute evidence path is outside build-output: ' + value)
        return root.joinpath(*parts[parts.index('build-output'):])
    return root / path


def counter_delta(before, after, prefix, key):
    def total(text):
        rows = quick.rows(text, prefix)
        if not rows or any(key not in row for row in rows):
            raise RuntimeError(f'missing required counter {prefix}{key}')
        return sum(int(row[key]) for row in rows)
    return total(after) - total(before)


def check_campaign(path, snapshots, evidence_root):
    campaign = read(path / 'campaign.json')
    assert campaign['status'] == 'COMPLETE' and not campaign['errors']
    assert len(campaign['runs']) == 6
    assert [r['label'] for r in campaign['runs']] == [
        'A1-local-n2', 'B1-io-n2', 'B2-io-n2', 'A2-local-n2', 'C1-io-n1', 'C3-io-n3']
    prepared = read(evidence_path(campaign['prepared'], evidence_root))
    assert prepared['serial'] == quick.SERIAL and prepared['model'] == 'Pixel 6a'
    assert prepared['peer_host'] == '192.168.4.5' and prepared['peer_port'] == 41723
    assert quick.digest(quick.SOURCE) == prepared['source_sha256']
    assert quick.digest(evidence_path(prepared['android_binary'], evidence_root)) == prepared['android_sha256']
    assert quick.digest(evidence_path(prepared['host_binary'], evidence_root)) == prepared['host_sha256']
    source_hash = prepared['collector_sha256']
    assert source_hash in snapshots, source_hash
    assert quick.digest(snapshots[source_hash]) == source_hash
    installs = {}
    for file in path.glob('install-*/identity.json'):
        value = read(file)
        assert quick.digest(evidence_path(value['apk'], evidence_root)) == value['apk_sha256']
        installs[value['apk_sha256']] = value
    rows = []
    for scheduled, campaign_run in zip(campaign['schedule'], campaign['runs']):
        label = scheduled['label']
        assert campaign_run['label'] == label and campaign_run['status'] == 'COMPLETE'
        assert campaign_run['returncode'] == 0
        run = path / ('run-' + label)
        result = read(run / 'result.json')
        assert result['status'] == 'COMPLETE' and not result['errors']
        assert result['runner_sha256'] == source_hash
        assert len(result['cases']) == 1
        manifest = result['manifest']
        assert manifest['collector_sha256'] == source_hash
        assert manifest['apk_sha256'] in installs
        assert manifest['android_sha256'] == prepared['android_sha256']
        assert manifest['rules_sha256'] == prepared['rules_sha256']
        assert manifest['worker_cpu_ids'] == scheduled['owner_cpus']
        assert manifest.get('tun_io_cpu_id') == scheduled['tun_io_cpu']
        assert manifest['client_cpu_mask'] == '10'
        assert manifest['peer_host'] == prepared['peer_host'] and manifest['peer_port'] == prepared['peer_port']
        assert manifest['cell_ms'] == prepared['cell_ms']
        assert result['rules_unchanged'] is True and not result['final_processes']
        assert result['final_runtime']['state'] == 'stopped'
        case = result['cases'][0]
        assert case['profile'] == 'vpn'
        assert case['case'] == prepared['cases'][0]
        cell = run / ('vpn-' + case['case'])
        before = (cell / 'before-cli.txt').read_text(errors='replace')
        after = (cell / 'after-cli.txt').read_text(errors='replace')
        native = (cell / 'native-stop.txt').read_text(errors='replace')
        owner_count = len(scheduled['owner_cpus'])
        quick.validate_vpn_window(case['generation'], case['client'], before, after, owner_count)
        quick.validate_vpn_stop(native, case['generation'], owner_count)
        quick.validate_vpn_layout(case['worker_layout'], scheduled['owner_cpus'],
                                  scheduled['tun_io_cpu'], before)
        assert case['client']['uid'] == 2000
        assert case['score']['flow_capacity'] == [1024] * owner_count
        assert case['score']['elapsed_seconds'] >= prepared['cell_ms'] / 1000
        elapsed = case['score']['elapsed_seconds']
        delivered = case['client']['bytes'] if case['case'] == 'tcp-fixed' else case['peer']['udp_received_bytes']
        assert abs(case['score']['delivered_mbps'] - delivered * 8 / elapsed / 1e6) < 1e-6
        assert case['score']['p99_upper_us'] == case['client']['p99_upper_us']
        assert case['score']['latency_samples'] == case['client']['latency_samples']
        thread_cpu = {thread['name']: next((value['cpu_seconds'] for value in case['cpu']['threads']
                                             if value['tid'] == thread['tid']), None)
                      for thread in case['worker_layout']}
        assert all(value is not None for value in thread_cpu.values())
        assert abs(sum(thread_cpu.values()) - case['score']['vpp_cpu_seconds']) < 1e-6
        capture = (None if scheduled['artifact'] == 'old' else {
            'tun_alloc_failed': counter_delta(before, after, 'tun.capture_capacity ', 'alloc_failures'),
            'tun_read_pauses': counter_delta(before, after, 'tun.capture_capacity ', 'read_pauses'),
            'tun_read_resumes': counter_delta(before, after, 'tun.capture_capacity ', 'read_resumes'),
        })
        faults = {
            'primary_credit_rejected': counter_delta(before, after, 'primary.rejection ', 'credit'),
            'primary_enqueue_rejected': counter_delta(before, after, 'primary.rejection ', 'enqueue'),
            'tun_alloc_failed': capture['tun_alloc_failed'] if capture is not None else None,
            'tun_read_pauses': capture['tun_read_pauses'] if capture is not None else None,
            'tun_read_resumes': capture['tun_read_resumes'] if capture is not None else None,
            'tun_write_failed': counter_delta(before, after, 'tun.flow_stack ', 'write_failed'),
            'tun_original_rejected': counter_delta(before, after, 'tun.flow_stack ', 'rejected_originals'),
            'return_no_credit': counter_delta(before, after, 'tun.return_detail ', 'no_credit'),
            'return_no_stamp': counter_delta(before, after, 'tun.return_detail ', 'no_stamp'),
            'return_no_buffer': counter_delta(before, after, 'tun.return_detail ', 'no_buffer'),
            'flow_capacity_misses': counter_delta(before, after, 'flow.runtime ', 'capacity_misses'),
        }
        assert all(value >= 0 for value in faults.values() if value is not None)
        assert faults['flow_capacity_misses'] == case['score']['flow_capacity_misses']
        row = dict(label=label, artifact=scheduled['artifact'], apk_sha256=manifest['apk_sha256'],
                   generation=case['generation'], owner_count=owner_count,
                   owner_cpus=scheduled['owner_cpus'], tun_io_cpu=scheduled['tun_io_cpu'],
                   client_cpu=4, source_port=manifest.get('tcp_fixed_source_port_base')
                   or manifest.get('udp_fixed_source_port_base'),
                   delivered_mbps=case['score']['delivered_mbps'],
                   vpp_cpu_seconds=case['score']['vpp_cpu_seconds'],
                   cpu_seconds_per_delivered_gib=case['score']['cpu_seconds_per_delivered_gib'],
                   thread_cpu_seconds=thread_cpu,
                   p99_upper_us=case['score']['p99_upper_us'],
                   latency_samples=case['score']['latency_samples'],
                   client_errors=case['client']['errors'], client_timeouts=case['client']['timeouts'],
                   udp_loss_packets=case['score']['udp_loss_packets'],
                   udp_duplicate_packets=case['score']['udp_duplicate_packets'],
                   udp_offered_packets=case['client'].get('offered_packets'),
                   udp_pacing_missed=case['client'].get('pacing_missed'),
                   faults=faults, raw_result=str(run / 'result.json'))
        rows.append(row)
    old = [row for row in rows if row['label'] in ('A1-local-n2', 'A2-local-n2')]
    new = [row for row in rows if row['label'] in ('B1-io-n2', 'B2-io-n2')]
    def mean(group, key):
        return sum(row[key] for row in group) / len(group)
    pair = {key: {'old_mean': mean(old, key), 'new_mean': mean(new, key),
                  'new_vs_old_percent': (mean(new, key) / mean(old, key) - 1) * 100}
            for key in ('delivered_mbps', 'vpp_cpu_seconds', 'cpu_seconds_per_delivered_gib')}
    return dict(campaign=str(path), suite=prepared['suite'], collector_sha256=source_hash,
                helper_sha256=prepared['android_sha256'], rows=rows, n2_descriptive_means=pair)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tcp', type=Path, required=True)
    parser.add_argument('--udp-stress', type=Path, required=True)
    parser.add_argument('--udp-paced', type=Path, required=True)
    parser.add_argument('--snapshots', type=Path, required=True)
    parser.add_argument('--evidence-root', type=Path, default=Path.cwd())
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    snapshot_paths = list(args.snapshots.glob('*-pixel_quick.py'))
    snapshots = {quick.digest(path): path for path in snapshot_paths}
    root = args.evidence_root.resolve()
    report = dict(schema='s304-vpn-topology-summary/v1', status='VERIFIED_RAW',
                  scope='Pixel 6a ordinary Product VPN; descriptive cohorts; no adoption threshold',
                  cohorts=[check_campaign(path, snapshots, root) for path in
                           (args.tcp, args.udp_stress, args.udp_paced)])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
