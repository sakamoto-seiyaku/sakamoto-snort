#!/usr/bin/env python3
"""Offline, exclusive sampled CPU attribution for one Android VPN workload.

Rules use exact names (only compiler clone suffixes are removed). Scan leaf to
root and select the first phase anchor; outer dispatch frames never override
inner work. A mixed callback such as tun_read_ready is a barrier: its body and
unrecognized children stay unknown instead of becoming outer dispatch overhead.
Syscall read/write anchors require the corresponding TUN ancestor. Kernel-only
chains cannot establish which fd was used and stay unknown. Every complete
observed chain and its selected anchor is emitted for auditing.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys

SDK = Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865/simpleperf')
# Anchors from src/product/vpp/{product_packet*,product_vpn_tun_adapter,
# product_vpn_flow_stack*}.c and pinned VPP src/vlib/{main,buffer*,file*}.
# A missing/inlined anchor reduces coverage; it is never inferred from timing.
PHASES = {
    'read_readiness': {'tun_pause_reads', 'tun_resume_reads', 'product_vpn_tun_buffer_retry_node_fn'},
    'buffer_parse_selector': {'vlib_buffer_alloc', 'vlib_buffer_alloc_inline',
        'vlib_buffer_alloc_from_pool', 'vlib_buffer_alloc_to_ring',
        'product_packet_parse_ingress', 'product_owner_assign', 'parse_transport',
        'parse_ipv4', 'parse_ipv6', 'product_packet_admit', 'product_packet_admit_selected'},
    'admission_publication_wakeup': {'tun_submit_captured',
        'product_packet_graph_submit_external', 'product_packet_graph_submit_external_batch',
        'product_packet_graph_submit_external_batch_internal', 'product_primary_handoff',
        'product_packet_admit_node_fn', 'product_packet_owner_guard_node_fn'},
    'completion_write_free': {'product_vpn_tun_complete_from_graph',
        'product_vpn_tun_return_freed', 'product_vpn_tun_submit_return',
        'product_packet_origin_completion_node_fn', 'product_packet_completion_retry_node_fn',
        'product_packet_terminal_node_fn', 'product_origin_reclaim_flush',
        'product_completion_return_try', 'product_completion_return',
        'vlib_buffer_free', 'vlib_buffer_free_inline', 'vlib_buffer_free_no_next'},
    'owner_transport': {'product_vpn_flow_stack_driver_input',
        'product_vpn_flow_stack_input_copy', 'product_vpn_flow_stack_step',
        'product_vpn_flow_stack_input_node_fn', 'product_vpn_egress_node_fn'},
    'dispatch_runtime': {'dispatch_node', 'dispatch_pending_node',
        'vlib_main_or_worker_loop', 'vlib_worker_thread_fn', 'vlib_main', 'vlib_file_poll',
        'vlib_frame_queue_dequeue_fn'},
}
MIXED = {'tun_read_ready', 'product_packet_policy_node_fn', 'product_flow_consumer_node_fn'}
READ = {'read', '__read', '__read_chk', '__arm64_sys_read', 'ksys_read', 'vfs_read',
        'new_sync_read', 'tun_chr_read_iter', 'tun_do_read', 'tun_ring_recv'}
WRITE = {'write', '__write', '__write_chk', '__arm64_sys_write', 'ksys_write',
         'vfs_write', 'new_sync_write', 'tun_chr_write_iter', 'tun_get_user'}
KERNEL_GROUPS = (
    ('eventfd_write_publication', {'eventfd_write'}),
    ('eventfd_ack_read', {'eventfd_read', 'eventfd_ctx_read'}),
    ('tun_read', {'tun_chr_read_iter', 'tun_do_read', 'tun_ring_recv'}),
    ('tun_write_return', {'tun_chr_write_iter', 'tun_get_user'}),
    ('epoll_syscall_on_cpu', {'do_epoll_wait'}),
    ('socket_send', {'udp_sendmsg', 'udp_send_skb', 'udp_sendmsg_locked',
                     'sock_sendmsg', 'tcp_sendmsg', 'tcp_sendmsg_locked'}),
    ('socket_receive', {'udp_recvmsg', 'tcp_recvmsg', 'tcp_recvmsg_locked', 'sock_recvmsg'}),
)


def kernel_group(frames):
    if frames[0][0] != '[kernel.kallsyms]':
        return None
    names = {normalized(name) for _, name in frames}
    return next((group for group, anchors in KERNEL_GROUPS if names & anchors), 'other_kernel')


def normalized(name):
    return re.sub(r'\.(?:llvm\.[0-9A-Fa-f]+|isra\.\d+|constprop\.\d+|part\.\d+)$', '', name)


def unresolved(name):
    return name in ('', 'unknown', '[unknown]') or '[+' in name or bool(re.fullmatch(r'0x[0-9a-fA-F]+', name))


def classify(frames):
    names = [normalized(symbol) for _, symbol in frames]
    for index, name in enumerate(names):
        phase = None
        if name in READ and 'tun_read_ready' in names[index + 1:]:
            phase = 'read_readiness'
        elif name in WRITE and any(n in names[index + 1:] for n in
                ('product_vpn_tun_complete_from_graph', 'product_vpn_tun_submit_return')):
            phase = 'completion_write_free'
        else:
            phase = next((p for p, anchors in PHASES.items() if name in anchors), None)
        if phase == 'dispatch_runtime' and index != 0:
            # An outer poll/loop cannot explain an unrecognized child syscall
            # or work hidden by incomplete FP unwinding.
            return 'other_unknown', index, 'outer_runtime_only:' + name
        if phase:
            return phase, index, name
        if name in MIXED:
            return 'other_unknown', index, 'mixed_callback:' + name
    return 'other_unknown', None, 'no_exact_anchor'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def rows(counter, total, limit=None):
    return [dict(dso=dso, symbol=symbol, samples=values[0], period_ns=values[1],
                 sampled_cpu_seconds=values[1] / 1e9,
                 period_fraction=values[1] / total if total else None)
            for (dso, symbol), values in sorted(counter.items(), key=lambda item: (-item[1][1], item[0]))[:limit]]


def increment(counter, key, period):
    counter[key][0] += 1
    counter[key][1] += period


def analyze(lib, case):
    begin, end = (case['client'][k] for k in ('start_monotonic_ns', 'end_monotonic_ns'))
    if end <= begin:
        raise ValueError('invalid monotonic workload window')
    threads = {}
    exclusions = Counter()
    while (sample := lib.GetNextSample()) is not None:
        if sample.pid != case['vpp_pid']:
            exclusions['different_pid'] += 1
            continue
        if not begin <= sample.time < end:
            exclusions['outside_window'] += 1
            continue
        event = lib.GetEventOfCurrentSample().name
        if event != 'cpu-clock':
            raise ValueError('unexpected in-window event: ' + event)
        leaf = lib.GetSymbolOfCurrentSample()
        chain = lib.GetCallChainOfCurrentSample()
        frames = [(leaf.dso_name, leaf.symbol_name)]
        frames.extend((chain.entries[i].symbol.dso_name, chain.entries[i].symbol.symbol_name)
                      for i in range(chain.nr))
        period = int(sample.period)
        if period < 0:
            raise ValueError('negative cpu-clock period')
        key = (int(sample.tid), sample.thread_comm)
        if key not in threads:
            threads[key] = dict(samples=0, period=0, self=defaultdict(lambda: [0, 0]),
                inclusive=defaultdict(lambda: [0, 0]), phases=defaultdict(lambda: [0, 0]),
                kernel_groups=defaultdict(lambda: [0, 0]),
                stacks=defaultdict(lambda: [0, 0]), depths=Counter(), unknown_leaf=0,
                unknown_chain=0, unknown_leaf_period=0, unknown_chain_period=0, unresolved_frames=0, frames=0, first=sample.time, last=sample.time)
        row = threads[key]
        phase, index, anchor = classify(frames)
        row['samples'] += 1
        row['period'] += period
        row['first'] = min(row['first'], sample.time)
        row['last'] = max(row['last'], sample.time)
        increment(row['self'], frames[0], period)
        for frame in set(frames):  # recursion contributes once per inclusive sample
            increment(row['inclusive'], frame, period)
        increment(row['phases'], phase, period)
        kernel = kernel_group(frames)
        if kernel:
            increment(row['kernel_groups'], kernel, period)
        increment(row['stacks'], (phase, index, anchor, tuple(frames)), period)
        row['depths'][len(frames)] += 1
        unknown = sum(unresolved(name) for _, name in frames)
        row['unknown_leaf'] += unresolved(frames[0][1])
        row['unknown_chain'] += bool(unknown)
        row['unknown_leaf_period'] += period if unresolved(frames[0][1]) else 0
        row['unknown_chain_period'] += period if unknown else 0
        row['unresolved_frames'] += unknown
        row['frames'] += len(frames)
    output = []
    for (tid, name), row in sorted(threads.items()):
        output.append(dict(tid=tid, name=name, samples=row['samples'], period_ns=row['period'],
            sampled_cpu_seconds=row['period'] / 1e9,
            first_sample_monotonic_ns=row['first'], last_sample_monotonic_ns=row['last'],
            phases={phase: dict(samples=values[0], period_ns=values[1], sampled_cpu_seconds=values[1]/1e9,
                                period_fraction=values[1]/row['period'] if row['period'] else None)
                    for phase, values in row['phases'].items()},
            kernel_leaf_groups={group: dict(samples=values[0], period_ns=values[1],
                sampled_cpu_seconds=values[1]/1e9,
                total_thread_period_fraction=values[1]/row['period'] if row['period'] else None)
                for group, values in row['kernel_groups'].items()},
            diagnostics=dict(unknown_leaf_samples=row['unknown_leaf'],
                unknown_leaf_period_ns=row['unknown_leaf_period'],
                samples_with_unresolved_frame_period_ns=row['unknown_chain_period'],
                samples_with_unresolved_frame=row['unknown_chain'], unresolved_frames=row['unresolved_frames'],
                observed_frames=row['frames'], observed_chain_depth_samples=dict(sorted(row['depths'].items())),
                leaf_only_samples=row['depths'][1]),
            top_self=rows(row['self'], row['period'], 50),
            top_inclusive=rows(row['inclusive'], row['period'], 50),
            symbol_chains=[dict(phase=phase, matched_frame_index=index, matched_anchor=anchor,
                frames=[dict(dso=dso, symbol=symbol) for dso, symbol in frames],
                samples=values[0], period_ns=values[1])
                for (phase, index, anchor, frames), values in sorted(row['stacks'].items(),
                    key=lambda item: (-item[1][1], str(item[0])))]))
    if not output:
        raise ValueError('no target cpu-clock samples in exact workload window')
    return dict(pid=case['vpp_pid'], begin_monotonic_ns=begin, end_monotonic_ns=end,
                window_seconds=(end-begin)/1e9, excluded_samples=dict(exclusions), threads=output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('run', 'record', 'symfs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--sdk', type=Path, default=SDK)
    args = parser.parse_args()
    run = json.loads(args.run.read_text())
    if run.get('status') != 'COMPLETE':
        raise ValueError('complete run required')
    case, = run['cases']
    sys.path.insert(0, str(args.sdk))
    from simpleperf_report_lib import ReportLib
    from simpleperf_utils import get_host_binary_path
    lib = ReportLib()
    try:
        lib.SetRecordFile(str(args.record.resolve()))
        lib.SetSymfs(str(args.symfs.resolve()))
        metadata = lib.MetaInfo()
        if metadata.get('trace_offcpu') == 'true':
            lib.SetTraceOffCpuMode('on-cpu')
        report = analyze(lib, case)
        report.update(metadata=metadata, record_command=lib.GetRecordCmd(),
                      arch=lib.GetArch(), recorded_build_ids=lib.GetAllBuildIds())
    finally:
        lib.Close()
    stats = {}
    for part in metadata.get('record_stat', '').split(','):
        if '=' in part:
            key, value = part.split('=', 1)
            stats[key] = int(value) if value.strip().isdigit() else value
    identities = {}
    for name, path in [('analyzer', Path(__file__)), ('run', args.run), ('record', args.record),
                       ('report_lib', args.sdk / 'simpleperf_report_lib.py'),
                       ('native_report_lib', Path(get_host_binary_path('libsimpleperf_report.so')))]:
        identities[name] = dict(path=str(path.resolve()), sha256=digest(path) if path.is_file() else None)
    report.update(schema='s308-cpu-profile/v1', profile_mode='on-cpu', event='cpu-clock',
        record_stats=stats,
        profile_integrity=('LOSS_REPORTED' if any(value for key, value in stats.items() if 'lost' in key)
                           else 'NO_REPORTED_LOSS' if stats else 'UNKNOWN'),
        identities=identities, symfs=str(args.symfs.resolve()),
        classification=dict(rule='nearest exact anchor from leaf; mixed callbacks stop attribution; runtime requires exact leaf',
            phase_anchors={p: sorted(s) for p, s in PHASES.items()}, mixed_barriers=sorted(MIXED),
            tun_read_anchors=sorted(READ), tun_write_anchors=sorted(WRITE)),
        limits=['Sample counts are observations, not a CPU-time metric. cpu-clock periods approximate sampled CPU nanoseconds.',
            'Period sums are not scheduler accounting or wall time; periods crossing window edges are not clipped.',
            'FP chains may omit inlined, kernel or interrupted frames. Unknown attribution and observed depth are retained; stack completeness is not asserted.',
            'Inclusive rows overlap and must not be summed; phase rows are exclusive.',
            'Recorded build IDs identify expected binaries; this report does not establish complete symfs coverage or verify every supplied binary.',
            'Read/write syscall attribution requires observed TUN ancestry; isolated kernel frames stay unknown.',
            'Mixed callback bodies and missing exact anchors stay other_unknown. Classification is conservative, not a complete pipeline CPU budget.'])
    report['classification']['kernel_groups_in_precedence_order'] = [
        dict(group=group, exact_chain_anchors=sorted(anchors)) for group, anchors in KERNEL_GROUPS]
    report['limits'].append('Kernel leaf groups are exclusive observed-chain subsets of CPU periods, not off-CPU waits; missing ancestry remains other_kernel.')
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
