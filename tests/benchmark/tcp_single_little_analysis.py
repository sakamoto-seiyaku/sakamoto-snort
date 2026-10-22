#!/usr/bin/env python3
"""Recompute existing little-core campaign graph and system-CPU observations.

Offline only. CLI/system brackets differ from the client byte interval. Counter
ratios describe those brackets, not packet delivery rates or waiting time.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

LABELS = ('single-little-1', 'single-little-2', 'single-little-3', 'profile-single-little')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rows(raw, prefix):
    return [dict(v.split('=', 1) for v in line[len(prefix):].split() if '=' in v)
            for line in raw.splitlines() if line.startswith(prefix)]


def only(raw, prefix):
    found = rows(raw, prefix)
    if len(found) != 1:
        raise ValueError(f'expected exactly one {prefix}: {len(found)}')
    return found[0]


def sections(raw):
    parts = re.split(r'^PATH ', raw, flags=re.M)
    return {part.splitlines()[0]: '\n'.join(part.splitlines()[1:]) for part in parts[1:]}


def system_cpu(before, after):
    b, a = sections(before), sections(after)
    def cpus(raw):
        return {line.split()[0]: [int(v) for v in line.split()[1:9]]
                for line in raw.splitlines() if re.match(r'^cpu[0-7] ', line)}
    first, last = cpus(b['/proc/stat']), cpus(a['/proc/stat'])
    required = {f'cpu{i}' for i in range(8)}
    if first.keys() != required or last.keys() != required:
        raise ValueError('missing per-core CPU accounting')
    output = []
    for key in sorted(first):
        delta = [y-x for x, y in zip(first[key], last[key])]
        if any(v < 0 for v in delta) or not sum(delta):
            raise ValueError('nonmonotonic or empty CPU bracket')
        total = sum(delta)
        output.append(dict(cpu=int(key[3:]), ticks=delta,
            total_ticks=total, busy_percent=100*(total-delta[3]-delta[4])/total,
            irq_percent=100*delta[5]/total, softirq_percent=100*delta[6]/total,
            iowait_percent=100*delta[4]/total))
    path = '/sys/devices/system/cpu/cpu0/cpufreq/stats/time_in_state'
    def residency(raw):
        # A trailing uptime line has a decimal value and is deliberately excluded.
        return {int(m[1]): int(m[2]) for line in raw.splitlines()
                if (m := re.fullmatch(r'(\d+) (\d+)', line))}
    f, l = residency(b[path]), residency(a[path])
    if f.keys() != l.keys():
        raise ValueError('frequency-state sets changed')
    states = {k: l[k]-f[k] for k in f}
    if any(v < 0 for v in states.values()) or not sum(states.values()):
        raise ValueError('invalid frequency residency delta')
    units = sum(states.values())
    return dict(core_cpu=output, policy0_residency_delta_units=states,
        policy0_residency_share_percent={k:100*v/units for k,v in states.items()},
        policy0_residency_weighted_khz=sum(k*v for k,v in states.items())/units,
        outer_uptime_seconds=[float(b['/proc/uptime'].splitlines()[0].split()[0]),
                              float(after.splitlines()[-1].split()[0])])


def analyze(campaign, label):
    run = campaign/label
    result = json.loads((run/'result.json').read_text())
    if result['status'] != 'COMPLETE':
        raise ValueError('incomplete raw window')
    case, = result['cases']
    client = case['client']; cell = run/'vpn-tcp-fixed'
    before = (cell/'before-cli.txt').read_text()
    after = (cell/'after-cli.txt').read_text()
    def delta(prefix, keys):
        actual = prefix + 'owner=0 ' if prefix.startswith('flow_stack.') else prefix
        b, a = only(before, actual), only(after, actual)
        return {k:int(a[k])-int(b[k]) for k in keys}
    counters = {}
    for prefix, keys in (
        ('tun.capture_batch ', ('calls','packets')),
        ('tun.capture_io ', ('callbacks','budget_exits','callback_ns')),
        ('tun.write_size ', ('bytes','large_packets')),
        ('flow_stack.tcp_progress ', ('idle_rounds','ring_full','sndbuf_full','window_full','cwnd_full','pending_rounds')),
        ('flow_stack.tcp_receive ', ('rounds','read_calls','read_blocked','commits','bytes','write_blocked','output_calls','eagain','eintr','eof')),
        ('flow_stack.driver ', ('schedules','ready_wakes','timer_wakes','nodes','empty_steps','ready_samples','ready_delay_ns','ready_over_1ms'))):
        counters[prefix.strip()] = delta(prefix, keys)
    batch = {}
    owner_count = len(result['manifest']['worker_cpu_ids'])
    io_index = str(owner_count + 1)
    for tid in range(1, owner_count + 2):
        prefix = f'batch.thread={tid} '
        b, a = only(before,prefix), only(after,prefix)
        batch[str(tid)] = {k:int(a[k])-int(b[k]) for k in a if not k.endswith('_max_ns')}
    matched = [f for f in rows(after,'flow.entry ') if f.get('port_a')=='31000' and f.get('port_b')=='41723' and f.get('uid')=='2000']
    if len(matched) != 1:
        raise ValueError('missing or ambiguous workload flow')
    f = matched[0]
    flow = {k:int(f[k]) for k in ('orig_packets','reply_packets','orig_bytes','reply_bytes','first_seen','last_seen')}
    if any(x.get('port_a')=='31000' and x.get('port_b')=='41723' for x in rows(before,'flow.entry ')):
        raise ValueError('workload flow existed before measurement')
    ratios = {}
    def ratio(name, numerator, denominator):
        ratios[name] = numerator/denominator if denominator else None
    capture = counters['tun.capture_batch']; receive = counters['flow_stack.tcp_receive']
    ratio('capture_packets_per_call',capture['packets'],capture['calls'])
    ratio('return_admit_vectors_per_frame',batch['1']['admit_vectors'],batch['1']['admit_frames'])
    ratio('completion_vectors_per_publication',batch['1']['completion_vectors'],batch['1']['completion_publications'])
    ratio('origin_vectors_per_frame',batch[io_index]['origin_vectors'],batch[io_index]['origin_frames'])
    ratio('primary_vectors_per_publication',batch[io_index]['primary_vectors'],batch[io_index]['primary_publications'])
    ratio('receive_commits_per_round',receive['commits'],receive['rounds'])
    ratio('receive_bytes_per_commit',receive['bytes'],receive['commits'])
    ratio('read_eagain_per_call',receive['eagain'],receive['read_calls'])
    ratio('ring_full_observations_per_round',counters['flow_stack.tcp_progress']['ring_full'],receive['rounds'])
    ratio('sndbuf_full_observations_per_round',counters['flow_stack.tcp_progress']['sndbuf_full'],receive['rounds'])
    ratio('orig_ip_bytes_per_packet',flow['orig_bytes'],flow['orig_packets'])
    ratio('reply_ip_bytes_per_packet',flow['reply_bytes'],flow['reply_packets'])
    ratio('data_reply_packets_per_orig_control_packet',flow['reply_packets'],flow['orig_packets'])
    cpu = case['cpu']; duration = (client['end_monotonic_ns']-client['start_monotonic_ns'])/1e9
    ratio('stationary_estimated_vpp_cpu_s_per_gib',cpu['cpu_seconds']*duration/cpu['sample_coverage_seconds'],client['bytes']/2**30)
    # Deliberate mixed-bracket proxy; never presented as exact per-packet CPU.
    ratio('mixed_bracket_vpp_cpu_us_per_graph_vector_proxy',cpu['cpu_seconds']*1e6,counters['tun.capture_batch']['packets']+flow['reply_packets'])
    ratio('32k_at_delivered_rate_ms',32768*8*1000,client['bytes']*8/duration)
    system_before=(cell/'system-cpu-before.txt').read_text()
    system_after=(cell/'system-cpu-after.txt').read_text()
    section_before,section_after=sections(system_before),sections(system_after)
    schedstat=[]
    for worker in case['worker_layout']:
        path=f"/proc/{case['vpp_pid']}/task/{worker['tid']}/schedstat"
        b=[int(v) for v in section_before[path].splitlines()[0].split()]
        a=[int(v) for v in section_after[path].splitlines()[0].split()]
        schedstat.append(dict(tid=worker['tid'],name=worker['name'],core=worker['lcore'],runtime_ns=a[0]-b[0],runqueue_wait_ns=a[1]-b[1],timeslices=a[2]-b[2]))
    conditions = []
    for line in (campaign/f'conditions-{label}.jsonl').read_text().splitlines():
        row = json.loads(line)
        if 'error' in row:
            raise ValueError('condition sampler error')
        raw = row['raw']; paths = sections(raw)
        start = float(raw.splitlines()[0].split()[0]); end = float(raw.splitlines()[-1].split()[0])
        conditions.append(dict(offset_seconds=start-client['start_monotonic_ns']/1e9,
            duration_seconds=end-start,
            wholly_inside_client=(client['start_monotonic_ns']/1e9<=start<=end<=client['end_monotonic_ns']/1e9),
            policy0_khz=int(paths['/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq'].splitlines()[0]),
            little_millicelsius=int(paths['/sys/class/thermal/thermal_zone11/temp'].splitlines()[0])))
    return dict(label=label,owner_count=owner_count,owner_cpu_ids=result['manifest']['worker_cpu_ids'],io_cpu=result['manifest']['tun_io_cpu_id'],client_cpu_mask=result['manifest']['client_cpu_mask'],profile=result['manifest']['profiling'],client_bytes=client['bytes'],client_seconds=duration,
        raw_sha256={str(p.relative_to(campaign)):digest(p) for p in (run/'result.json',cell/'before-cli.txt',cell/'after-cli.txt',cell/'system-cpu-before.txt',cell/'system-cpu-after.txt',campaign/f'conditions-{label}.jsonl')},
        graph_delta=counters,batch_delta=batch,workload_flow_lifetime=flow,ratios=ratios,
        lifetime_tcp_progress=only(after,'flow_stack.tcp_progress owner=0 '),
        tcp_wait_diagnostic_rows=rows(after,'flow_stack.tcp_wait '),
        schedstat=schedstat,system=system_cpu(system_before,system_after),
        conditions=conditions)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--historical-campaign',type=Path)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    result=dict(schema='single-little-offline-analysis/v1',analyzer_sha256=digest(Path(__file__)),
        rows=[analyze(args.campaign,label) for label in LABELS],
        limits=['CLI/system/condition brackets differ from client byte interval.',
                'Batch/pressure/wakeup counters count observations or calls, not independent events or wait duration.',
                'Product packets are IP buffers, not Wi-Fi wire segments.',
                'Shared policy residency includes idle/other work; not per-thread executed-cycle frequency.'])
    if args.historical_campaign:
        result['historical_context_only']=[analyze(args.historical_campaign,label) for label in ('download1-A1','download1-B2','download1-B3','download1-A4')]
    (args.output/'graph-system.json').write_text(json.dumps(result,indent=2)+'\n')
    print(args.output/'graph-system.json')


if __name__=='__main__':
    main()
