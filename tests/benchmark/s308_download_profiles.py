#!/usr/bin/env python3
"""Audit and render only the four frozen S308 TCP download CPU profiles.

All input is retained offline evidence. SVG widths and folded stack weights are
cpu-clock sample periods in nanoseconds; each thread has its own scale. These
are sampled on-CPU stacks, never an energy or scheduler wait-time measurement.
"""
import argparse
from collections import Counter
import hashlib
import html
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

import s308_profile as profile

ROOT = Path(__file__).resolve().parents[2]
POOL = ROOT / 'build-output/s308-symbols-20261022'
CANDIDATE = ROOT / 'build-output/s308-final-unified64-20261022/symbols/product_core_plugin.so'
STRIP = Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip')


def read(path):
    return json.loads(path.read_text())


def command(argv):
    return subprocess.check_output(['rtk', 'proxy', *map(str, argv)], text=True)


def build_id(path):
    found = re.findall(r'Build ID:\s*([0-9a-fA-F]+)', command(['readelf', '-n', path]))
    if len(set(found)) != 1:
        raise ValueError('missing or ambiguous ELF build ID: ' + str(path))
    return found[0].lower()


def matches_recorded_id(elf, recorded):
    # ReportLib stores 20 bytes, right-padding shorter ELF build IDs with zeroes.
    return len(elf) <= 40 and recorded.lower().removeprefix('0x') == elf.ljust(40, '0')


def folded_frame(frame):
    # Frame delimiters/newlines are escaped, preserving exact original names in
    # attribution.json. DSO basename distinguishes otherwise identical symbols.
    return (Path(frame['dso']).name + '!' + frame['symbol']).replace('%', '%25').replace(';', '%3B').replace('\n', '%0A').replace('\r', '%0D')


def folded_stacks(thread):
    stacks = Counter()
    for chain in thread['symbol_chains']:
        stacks[tuple(folded_frame(f) for f in reversed(chain['frames']))] += chain['period_ns']
    assert sum(stacks.values()) == thread['period_ns']
    return stacks


def flame_svg(stacks, title):
    """Deterministic standalone SVG of a weighted prefix tree, root at bottom."""
    root = dict(weight=0, children={})
    maximum = 0
    for stack, weight in stacks.items():
        if weight < 0:
            raise ValueError('negative folded period')
        node = root
        node['weight'] += weight
        for label in stack:
            node = node['children'].setdefault(label, dict(weight=0, children={}))
            node['weight'] += weight
        maximum = max(maximum, len(stack))
    total = root['weight']
    width, row, margin, header = 1440, 19, 12, 76
    height = header + (maximum + 1) * row + 28
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
             '<style>text{font:12px monospace;fill:#17202b}rect{stroke:white;stroke-width:.4}g:hover rect{stroke:#111;stroke-width:1.2}</style>',
             '<rect width="100%" height="100%" fill="#fff"/>',
             f'<text x="12" y="22" font-weight="bold">{html.escape(title)}</text>',
             f'<text x="12" y="42">Width = sampled cpu-clock periods: {total / 1e9:.6f} CPU s; each thread uses its own scale.</text>',
             '<text x="12" y="61">Root at bottom, leaf at top. Hover for exact frame and period. Complete stacks retained in .folded.</text>']
    def draw(label, node, x, span, depth):
        y = header + (maximum - depth) * row
        if span >= .25:
            fraction = node['weight'] / total if total else 0
            tooltip = f"{label}\n{node['weight']} period ns ({node['weight']/1e9:.6f} sampled CPU s), {fraction:.3%} of thread"
            hue = int(hashlib.sha256(label.encode()).hexdigest()[:6], 16) % 65
            parts.append(f'<g><title>{html.escape(tooltip)}</title><rect x="{x:.3f}" y="{y}" width="{span:.3f}" height="{row-1}" fill="hsl({hue},78%,73%)"/>')
            length = int((span - 6) / 7.3)
            if length > 2:
                text = label if len(label) <= length else label[:max(0, length-2)] + '..'
                parts.append(f'<text x="{x+3:.3f}" y="{y+13}">{html.escape(text)}</text>')
            parts.append('</g>')
        offset = x
        for child_label, child in sorted(node['children'].items()):
            child_span = span * child['weight'] / node['weight'] if node['weight'] else 0
            draw(child_label, child, offset, child_span, depth + 1)
            offset += child_span
    draw('all observed stacks', root, margin, width - margin * 2, 0)
    parts.append('</svg>')
    return '\n'.join(parts) + '\n'


def monitored_cpu_svg(threads, label, interval):
    """One-core CPU percentages use each recorded monitor interval, not samples."""
    width, left, chart_width = 1360, 220, 900
    height = 110 + len(threads) * 36
    largest = max((t.get('monitored_cpu') or {}).get('cpu_percent_one_core', 0) for t in threads)
    scale = max(100, math.ceil(largest / 25) * 25)
    result = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        '<style>text{font:14px monospace;fill:#17202b}</style><rect width="100%" height="100%" fill="white"/>',
        f'<text x="16" y="23">{html.escape(label)} | observed per-thread CPU (% of one core)</text>',
        f'<text x="16" y="45">Monitor interval: {interval.get("sample_coverage_seconds")} s; CPU tick deltas, no whole-window extrapolation.</text>']
    for tick in range(0, scale + 1, 25):
        x = left + chart_width * tick / scale
        result.append(f'<line x1="{x}" x2="{x}" y1="68" y2="{height-15}" stroke="#e4e7eb"/><text x="{x}" y="64">{tick}%</text>')
    for index, thread in enumerate(threads):
        y = 78 + index * 36
        cpu = thread.get('monitored_cpu')
        result.append(f'<text x="16" y="{y+17}">{html.escape(thread["role"])} / {thread["tid"]}</text>')
        if cpu is None:
            result.append(f'<text x="{left}" y="{y+17}">No matched monitor thread</text>')
            continue
        percent = cpu['cpu_percent_one_core']
        span = chart_width * percent / scale
        color = '#eea34b' if thread['role']=='io' else '#679bc7' if thread['role'].startswith('owner') else '#9ca5ae'
        result.append(f'<rect x="{left}" y="{y}" width="{span}" height="24" fill="{color}"/><text x="{left+chart_width+12}" y="{y+17}">{percent:.2f}% / {cpu["cpu_seconds"]:.3f} CPU s</text>')
    result.append('</svg>')
    return '\n'.join(result)+'\n'


def symbol_source(name, arm):
    if name == 'libproduct_core_plugin.so' and arm == 'B':
        return CANDIDATE
    for directory in (POOL / 'unstripped', POOL):
        source = directory / name
        if source.is_file():
            return source
    return None


def prepare_symfs(record, manifest, apk, arm, destination, sdk):
    sys.path.insert(0, str(sdk))
    from simpleperf_report_lib import ReportLib
    lib = ReportLib()
    try:
        lib.SetRecordFile(str(record))
        recorded_ids = lib.GetAllBuildIds()
    finally:
        lib.Close()
    symfs = destination / 'symfs'
    symfs.mkdir(parents=True, exist_ok=True)
    install_root = str(Path(manifest['apk']).parent) + '/'
    audit = []
    with zipfile.ZipFile(apk) as archive:
        native = {Path(n).name: hashlib.sha256(archive.read(n)).hexdigest()
                  for n in archive.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
        if profile.digest(apk) != manifest['apk_sha256']:
            raise ValueError('manifest/frozen APK identity mismatch')
        for dso, recorded in sorted(recorded_ids.items()):
            row = dict(dso=dso, recorded_build_id=recorded)
            if dso.startswith('[') or dso.endswith('.ko'):
                row['verification'] = 'recorded device kernel/module/vDSO only; not independently rebuilt'
                audit.append(row)
                continue
            name = Path(dso).name
            source = symbol_source(name, arm)
            if source is None:
                row['verification'] = 'MISSING_ELF'
                audit.append(row)
                continue
            if name in native and not dso.startswith(install_root):
                raise ValueError('native DSO is outside actual manifest install root: ' + dso)
            elf_id = build_id(source)
            if not matches_recorded_id(elf_id, recorded):
                raise ValueError('ELF/record build ID mismatch: ' + dso)
            row.update(elf_build_id=elf_id, source=str(source), sha256=profile.digest(source), verification='MATCHED_ELF_BUILD_ID')
            if name in native:
                stripped = destination / ('strip-check-' + name)
                subprocess.run(['rtk', 'proxy', str(STRIP), '--strip-unneeded', '-o', str(stripped), str(source)], check=True)
                row.update(apk_member_sha256=native[name], stripped_sha256=profile.digest(stripped))
                if row['stripped_sha256'] != native[name]:
                    raise ValueError('symbol ELF stripped bytes differ from frozen APK: ' + name)
                row['apk_strip_match'] = True
            target = symfs / dso.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                target.unlink()
            if target.exists():
                raise ValueError('refusing to replace non-symlink in symfs: ' + str(target))
            target.symlink_to(source.resolve())
            audit.append(row)
    result = dict(status='MISSING_USERSPACE_ELF' if any(r['verification']=='MISSING_ELF' for r in audit) else 'ALL_SUPPLIED_USERSPACE_IDS_MATCH',
        manifest_installed_apk=manifest['apk'], frozen_apk=str(apk), apk_sha256=profile.digest(apk),
        comparison='Exact ELF build IDs, right-padded only to ReportLib fixed 20-byte storage.', records=audit)
    (destination / 'dso-identities.json').write_text(json.dumps(result, indent=2) + '\n')
    return symfs, result


def role(thread, case):
    match = next((worker for worker in case['worker_layout'] if int(worker['tid']) == thread['tid']), None)
    if match is None:
        return 'other'
    index = int(match['id'])
    owners = len(case.get('_owners', [1, 2]))
    return 'main' if index == 0 else f'owner{index-1}' if index <= owners else 'io' if index == owners+1 else 'other'


def analyze_one(campaign, plan, protocol, output, sdk):
    label = plan['label']
    run_path = campaign / label / 'result.json'
    record = campaign / label / 'vpn-tcp-fixed/perf.data'
    if not run_path.is_file() or not record.is_file():
        return dict(label=label, status='PENDING')
    run = read(run_path)
    if run.get('status') != 'COMPLETE':
        return dict(label=label, status='PENDING')
    manifest = run['manifest']
    case, = run['cases']
    if (manifest.get('threads') != 1 or manifest.get('flows_per_thread') != plan['flows']
            or manifest.get('tcp_latency_probes') is not False
            or case['client'].get('tcp_probe_connections') != 0
            or case['client'].get('tcp_download_connections') != plan['flows']):
        raise ValueError('profile connection counts differ from frozen download workload')
    if not manifest['profiling'] or manifest.get('profiler_callgraph') != 'dwarf':
        raise ValueError('frozen row is not a DWARF CPU record')
    destination = output / label
    destination.mkdir(parents=True, exist_ok=True)
    apk = Path(protocol['baseline'] if plan['arm']=='A' else protocol['candidate'])
    apk = apk if apk.is_absolute() else ROOT / apk
    symfs, audit = prepare_symfs(record.resolve(), manifest, apk.resolve(),
        plan['arm'], destination, sdk)
    attribution = destination / 'attribution.json'
    argv = [sys.executable, str(Path(profile.__file__)), '--run', str(run_path.resolve()),
            '--record', str(record.resolve()), '--symfs', str(symfs), '--sdk', str(sdk), '--output', str(attribution)]
    command(argv)
    data = read(attribution)
    case['_owners'] = manifest['worker_cpu_ids']
    rows = []
    observed = {int(t['tid']): t for t in case['cpu']['threads']}
    for thread in data['threads']:
        name = f"{role(thread, case)}-tid{thread['tid']}"
        stacks = folded_stacks(thread)
        folded = destination / (name + '.folded')
        folded.write_text(''.join(';'.join(stack) + ' ' + str(weight) + '\n'
                                  for stack, weight in sorted(stacks.items())))
        svg = destination / (name + '.svg')
        svg.write_text(flame_svg(stacks, label + ' | ' + name + ' | ' + thread['name']))
        cpu = observed.get(thread['tid'])
        diag = thread['diagnostics']
        total_period = thread['period_ns']
        leaf_dsos = Counter()
        for chain in thread['symbol_chains']:
            leaf_dsos[chain['frames'][0]['dso']] += chain['period_ns']
        coverage = dict(
            resolved_leaf_sample_fraction=1-diag['unknown_leaf_samples']/thread['samples'],
            resolved_leaf_period_fraction=1-diag['unknown_leaf_period_ns']/total_period if total_period else None,
            observed_chains_without_unresolved_frame_sample_fraction=1-diag['samples_with_unresolved_frame']/thread['samples'],
            observed_chains_without_unresolved_frame_period_fraction=1-diag['samples_with_unresolved_frame_period_ns']/total_period if total_period else None,
            unclassified_phase_period_fraction=thread['phases'].get('other_unknown',{}).get('period_ns',0)/total_period if total_period else None,
            first_to_last_sample_span_seconds=(thread['last_sample_monotonic_ns']-thread['first_sample_monotonic_ns'])/1e9,
            stack_completeness_asserted=False)
        rows.append(dict(status='SAMPLED', tid=thread['tid'], name=thread['name'], role=role(thread, case),
            samples=thread['samples'], period_ns=thread['period_ns'],
            sampled_cpu_seconds=thread['sampled_cpu_seconds'],
            first_sample_monotonic_ns=thread['first_sample_monotonic_ns'],
            last_sample_monotonic_ns=thread['last_sample_monotonic_ns'],
            diagnostics=thread['diagnostics'], coverage=coverage, leaf_dso_period_ns=dict(leaf_dsos.most_common()),
            phases=thread['phases'], kernel_leaf_groups=thread.get('kernel_leaf_groups',{}),
            monitored_cpu=cpu, svg=svg.name, folded=folded.name))
    sampled_tids = {row['tid'] for row in rows}
    for worker in case['worker_layout']:
        tid = int(worker['tid'])
        if tid not in sampled_tids:
            rows.append(dict(status='NO_RECORDED_SAMPLES', tid=tid, name=worker['name'],
                role=role(dict(tid=tid), case), samples=0, period_ns=0,
                sampled_cpu_seconds=0, monitored_cpu=observed.get(tid), svg=None, folded=None))
    row = dict(label=label, status='ANALYZED', arm=plan['arm'], flows=plan['flows'],
        run=str(run_path), run_sha256=profile.digest(run_path), record=str(record), record_sha256=profile.digest(record),
        attribution_command=argv, profile_integrity=data['profile_integrity'], record_stats=data['record_stats'],
        symbol_audit_status=audit['status'], window_seconds=data['window_seconds'],
        monitored_cpu_interval={k:case['cpu'].get(k) for k in ('begin_monotonic_ns','end_monotonic_ns','sample_coverage_seconds')},
        threads=rows)
    row['thread_cpu_svg'] = 'thread-cpu.svg'
    (destination/'thread-cpu.svg').write_text(monitored_cpu_svg(rows,label,row['monitored_cpu_interval']))
    (destination/'summary.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, default=profile.SDK)
    args=parser.parse_args()
    campaign=args.campaign.resolve();output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    protocol=read(campaign/'frozen-protocol.json')
    plans=[p for p in protocol['plan'] if p['profile']=='dwarf']
    if len(plans)!=4:
        raise ValueError('expected exactly the four frozen profile windows')
    accepted={r['label']:r for r in read(campaign/'campaign.json').get('runs',[])}
    rows=[analyze_one(campaign,p,protocol,output,args.sdk)
          if accepted.get(p['label'],{}).get('status')=='PASS' else dict(label=p['label'],status='PENDING')
          for p in plans]
    index=dict(schema='s308-download-profile-analysis/v1',status='COMPLETE' if all(r['status']=='ANALYZED' for r in rows) else 'PENDING',
        campaign=str(campaign),frozen_protocol_sha256=profile.digest(campaign/'frozen-protocol.json'),
        protocol_document_sha256=protocol['protocol_sha256'],
        analyzer_sha256=profile.digest(Path(__file__)),profiles=rows,
        tools=dict(python_executable=sys.executable,python_version=sys.version,
                   readelf_path=shutil.which('readelf'),readelf_sha256=profile.digest(Path(shutil.which('readelf'))),
                   strip_path=str(STRIP),strip_sha256=profile.digest(STRIP),
                   attribution_analyzer_sha256=profile.digest(Path(profile.__file__))),
        limits=['Separate profiled windows; no CPU/throughput gain inferred from these records.',
                'Flame widths use sample periods, not event counts, energy, wall time or off-CPU intervals.',
                'Per-thread SVGs use independent scales; compare totals and monitor CPU separately.',
                'All observed chains retained; incomplete/unresolved frames and unknown classification stay explicit.',
                'Kernel/module/vDSO build IDs are retained device identities, not independent symbol/source verification.'])
    (output/'index.json').write_text(json.dumps(index,indent=2)+'\n')
    links=[]
    for row in rows:
        links.append(f"<h2>{html.escape(row['label'])}: {row['status']}</h2>")
        if row['status']=='ANALYZED':
            links.append(f'<img src="{row["label"]}/{row["thread_cpu_svg"]}" style="width:100%;height:auto" alt="Observed thread CPU percentages">')
            for thread in row['threads']:
                if not thread['svg']:
                    links.append(f'<p>{thread["role"]} / {thread["name"]}: no recorded CPU samples; monitor accounting is separate.</p>')
                    continue
                links.append(f'<p><a href="{row["label"]}/{thread["svg"]}">{thread["role"]} / {thread["name"]}: {thread["sampled_cpu_seconds"]:.3f} sampled CPU s, {thread["samples"]} samples</a></p>')
    (output/'index.html').write_text('<!doctype html><meta charset="utf-8"><title>S308 TCP download CPU flames</title><style>body{font:16px system-ui;margin:24px;max-width:1200px}</style><h1>S308 TCP download CPU flames</h1><p>Period-weighted on-CPU samples; separate profiling windows. Each thread has its own SVG scale.</p>'+''.join(links))
    print(output/'index.json')


if __name__=='__main__':
    main()
