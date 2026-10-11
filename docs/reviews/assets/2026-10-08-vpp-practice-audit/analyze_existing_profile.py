#!/usr/bin/env python3
"""Read an existing, source-bound profile; never run a workload or modify inputs."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ndk', type=Path,
                        default=Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[4]
    base = root / 'build-output/vpn-mode-fix-20260928'
    sender = json.loads((base / 'vpn/tcp25-sender.json').read_text())
    pids = json.loads((base / 'vpn/pids.json').read_text())['pids']
    mapping = json.loads((base / 'symbol-cache-manifest.json').read_text())
    plugin_mapping = next(row for row in mapping
                          if row['mapped_path'].endswith('/libproduct_core_plugin.so'))
    plugin = base / plugin_mapping['source']
    assert digest(plugin) == plugin_mapping['sha256'], 'matching symbol ELF identity'
    sys.path.insert(0, str(args.ndk / 'simpleperf'))
    from simpleperf_report_lib import ReportLib

    start = sender['start_monotonic_ns']
    end = start + 20_000_000_000
    lib = ReportLib()
    lib.SetSymfs(str(base / 'binary_cache'))
    lib.SetRecordFile(str(base / 'vpn/tcp25.perf.data'))
    leaves, inclusive = collections.Counter(), collections.Counter()
    pc_counts = collections.Counter()
    parents = collections.defaultdict(collections.Counter)
    callchain_lengths = collections.Counter()
    targets = {'[linker]tlsdesc_resolver_dynamic', '__memmove_aarch64_simd', 'memset'}
    policy_set = {'product_packet_policy_node_fn', 'product_packet_graph_l4_view_evaluate'}
    preparation_set = {'product_l4_policy_match_cached',
                       'product_packet_graph_l4_match_evidence_key',
                       'product_packet_graph_l4_match_policy_key',
                       'product_packet_graph_l4_packet_projection'}
    total = period = kernel = fnv_samples = fnv_period = policy_union = preparation_union = 0
    loop_pcs = set(range(0x7599C, 0x759B1, 4))
    try:
        while (sample := lib.GetNextSample()) is not None:
            if sample.pid != int(pids['vpp']) or not start <= sample.time < end:
                continue
            leaf = lib.GetSymbolOfCurrentSample()
            chain = lib.GetCallChainOfCurrentSample()
            frames = [(leaf.dso_name, leaf.symbol_name, leaf.vaddr_in_file)]
            frames += [(entry.symbol.dso_name, entry.symbol.symbol_name,
                        entry.symbol.vaddr_in_file) for entry in chain.entries[:chain.nr]]
            names = set(name for _, name, _ in frames)
            leaves[(frames[0][0], frames[0][1])] += 1
            for dso, name in set((dso, name) for dso, name, _ in frames):
                inclusive[(dso, name)] += 1
            if leaf.symbol_name in targets:
                parents[leaf.symbol_name][tuple(name for _, name, _ in frames[1:8])] += 1
            if leaf.symbol_name == 'product_l4_policy_match_cached':
                pc_counts[leaf.vaddr_in_file] += 1
                if leaf.vaddr_in_file in loop_pcs:
                    fnv_samples += 1
                    fnv_period += sample.period
            if 'product_packet_graph_l4_view_evaluate' in names:
                callchain_lengths[len(frames)] += 1
            policy_union += bool(names & policy_set)
            preparation_union += bool(names & preparation_set)
            total += 1
            period += sample.period
            kernel += bool(sample.in_kernel)
    finally:
        lib.Close()

    def rows(counter):
        return [{'dso': dso, 'symbol': name, 'samples': count,
                 'fraction_of_vpp_samples': count / total}
                for (dso, name), count in counter.most_common()]

    warmup = base / 'flows/vpn-tcp25-warmup/attempt0-page0.json'
    facts = json.loads(warmup.read_text())
    output = {
        'scope': 'Offline existing TCP first-20s samples; inclusive values overlap; no new workload.',
        'record': str((base / 'vpn/tcp25.perf.data').relative_to(root)),
        'record_sha256': digest(base / 'vpn/tcp25.perf.data'),
        'plugin_sha256': digest(plugin),
        'window_start_ns': start, 'window_end_ns': end,
        'vpp_pid': int(pids['vpp']), 'vpp_samples': total,
        'period_ns': period, 'kernel_samples': kernel,
        'active_rule_count': facts['policy_source']['active_rule_count'],
        'vpp_policy_rule_count': facts['vpp']['policy_rule_count'],
        'warmup_record': str(warmup.relative_to(root)), 'warmup_sha256': digest(warmup),
        'cache_fnv_loop_samples': fnv_samples, 'cache_fnv_loop_period_ns': fnv_period,
        'cache_fnv_loop_pcs': [hex(pc) for pc in sorted(loop_pcs)],
        'cache_self_pcs': {hex(pc): count for pc, count in pc_counts.most_common()},
        'self': rows(leaves), 'inclusive': rows(inclusive),
        'policy_and_l4_sample_union': policy_union,
        'cache_evidence_projection_sample_union': preparation_union,
        'l4_view_callchain_lengths': dict(callchain_lengths),
        'selected_self_callchains': {
            name: [{'callchain': list(stack), 'samples': count}
                   for stack, count in counts.most_common()]
            for name, counts in parents.items()},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(output, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: output[key] for key in (
        'vpp_samples', 'period_ns', 'active_rule_count', 'cache_fnv_loop_samples',
        'policy_and_l4_sample_union', 'cache_evidence_projection_sample_union')}))


if __name__ == '__main__':
    main()
