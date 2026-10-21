#!/usr/bin/env python3
"""Attribute retained sched_switch intervals within the actual load window."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys


def category(names):
    if any('FwmarkClient::send' in name for name in names):
        return 'android_fwmark'
    # FP chains omit inlined helpers: the actual outer scheduler distinguishes
    # HEV's poll from VPP's file poll without inventing missing inline frames.
    if any('hev_task_system_io_poll' in name for name in names) or (
            'do_epoll_wait' in names and 'hev_task_system_schedule' in names):
        return 'hev_io_poll'
    if 'do_epoll_wait' in names and any(name in names for name in
            ('vlib_file_poll', 'vlib_worker_thread_fn', 'vlib_main')):
        return 'vpp_file_poll'
    if any('futex' in name for name in names):
        return 'futex'
    if any('preempt_schedule' in name for name in names):
        return 'preempted_work'
    return 'other'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path)
    parser.add_argument('--record', required=True, type=Path)
    parser.add_argument('--symfs', required=True, type=Path)
    parser.add_argument('--sdk', type=Path, default=Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865/simpleperf'))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.sdk))
    from simpleperf_report_lib import ReportLib

    run = json.loads(args.run.read_text())
    if run['status'] != 'COMPLETE':
        raise ValueError('complete diagnostic window required')
    case, = run['cases']
    begin, end = [case['client'][key] for key in ('start_monotonic_ns', 'end_monotonic_ns')]
    receiver_tids = case['client'].get('worker_tids')
    lib = ReportLib()
    lib.SetRecordFile(str(args.record))
    lib.SetSymfs(str(args.symfs))
    metadata = lib.MetaInfo()
    if metadata.get('trace_offcpu') != 'true':
        raise ValueError('record has no off-CPU scheduler tracing')
    record_stats = {key: int(value) for key, value in
                    (part.split('=', 1) for part in metadata['record_stat'].split(','))}
    lossy = any(value for key, value in record_stats.items() if 'lost' in key)
    lib.SetTraceOffCpuMode('off-cpu')
    threads = defaultdict(lambda: dict(states=Counter(), categories=Counter(), stacks=Counter(), next_threads=Counter(), next_tasks=Counter(), tun_next_tasks=Counter(), intervals=0))
    while (sample := lib.GetNextSample()) is not None:
        if sample.pid != case['vpp_pid']:
            continue
        duration = max(0, min(end, sample.time + sample.period) - max(begin, sample.time))
        if not duration:
            continue
        event = lib.GetEventOfCurrentSample().name
        if 'sched_switch' not in event:
            raise ValueError(f'unexpected off-CPU event: {event}')
        raw = lib.GetTracingDataOfCurrentSample()
        state = int(raw['prev_state'])
        chain = lib.GetCallChainOfCurrentSample()
        names = [lib.GetSymbolOfCurrentSample().symbol_name]
        names.extend(chain.entries[i].symbol.symbol_name for i in range(chain.nr))
        row = threads[(sample.tid, sample.thread_comm)]
        row['intervals'] += 1
        row['states'][state] += duration
        row['categories'][category(names)] += duration
        row['next_threads'][str(raw['next_comm'])] += duration
        row['stacks'][(state, tuple(names))] += duration
        # Count switch events only when the event itself is inside the load
        # window, independently of the clipped interval accounting above.
        if begin <= sample.time < end:
            next_task = (str(raw['next_comm']), int(raw['next_pid']))
            row['next_tasks'][next_task] += 1
            if 'tun_rx_batched' in names:
                row['tun_next_tasks'][next_task] += 1
    lib.Close()
    output = []
    def task_counts(counts):
        return [dict(name=name, tid=tid, switches=count,
                     is_client_receive_thread=tid in receiver_tids if receiver_tids is not None else None)
                for (name, tid), count in counts.most_common()]

    for (tid, name), row in sorted(threads.items()):
        duration = sum(row['states'].values())
        if duration > (end - begin) * 1.01:
            raise ValueError(f'overlapping scheduler accounting for {tid}')
        output.append(dict(
            tid=tid, name=name, offcpu_seconds=duration / 1e9,
            offcpu_fraction=duration / (end - begin), intervals=row['intervals'],
            raw_prev_state_seconds={str(k): v / 1e9 for k, v in row['states'].items()},
            category_seconds={k: v / 1e9 for k, v in row['categories'].items()},
            next_thread_on_switch_seconds={k: v / 1e9 for k, v in row['next_threads'].most_common(12)},
            next_task_switches=task_counts(row['next_tasks']),
            tun_rx_batched_next_task_switches=task_counts(row['tun_next_tasks']),
            top_stacks=[dict(raw_prev_state=k[0], stack=k[1], seconds=v / 1e9)
                        for k, v in row['stacks'].most_common(12)],
        ))
    report = dict(
        schema='vpn-waits/v2', generation=case['generation'], window_seconds=(end - begin) / 1e9,
        client_pid=case['client']['pid'], client_receive_tids=receiver_tids,
        profile_integrity='LOSSY' if lossy else 'NO_REPORTED_LOSS',
        complete_wait_accounting=False, record_stats=record_stats,
        record_sha256=hashlib.sha256(args.record.read_bytes()).hexdigest(), threads=output,
        limits=[
            'Separate tracing window; do not pair throughput with CPU-only windows.',
            'Intervals are clipped to the load window; terminal intervals absent from the record cannot be recovered.',
            'Lost scheduler records can bias interval attribution; retained intervals are not a complete or unbiased wait-time budget.',
            'Stack categories describe where a thread switched out, not what caused its wakeup or all end-to-end latency.',
            'next_thread_on_switch names only the immediate successor; interval duration is not that successor thread CPU time.',
            'Switch counts use events starting inside the load window; receiver membership requires gettid() identities in the client result, not a process-name or PID-offset guess.',
            'Raw prev_state is retained; a preempted stack is not proof of lock contention or a blocking syscall.',
            'Build ID and symbol identity must be verified separately against the same record.',
        ],
    )
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    for row in output:
        print(row['name'], row['offcpu_seconds'], row['category_seconds'])


if __name__ == '__main__':
    main()
