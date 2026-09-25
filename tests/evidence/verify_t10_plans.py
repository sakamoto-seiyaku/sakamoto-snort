#!/usr/bin/env python3
"""Join T10 saved/active source, complete packet winners and bounded plans."""
import argparse
import json
from pathlib import Path
import statistics
import verify_t06_expressions as v


def one(text, prefix):
    rows = v.rows(text, prefix)
    assert len(rows) == 1, ('unique resource record', prefix)
    return rows[0]


def verify(directory):
    d = Path(directory)
    run = json.loads((d/'result.json').read_text())
    pixel = 'serial' in run
    assert run['status'] == 'RAW_COMPLETE' and run['process_absent']
    assert not run.get('error') and not run.get('cleanup_error')
    build = v.chain.verify_product_build(run['build'])
    assert v.digest(run['build']) == run['build_sha256'] and build['source_sha256'] == run['source_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    assert v.digest(d/'runner.py') == run['runner_sha256']
    if pixel:
        assert v.digest(build['apk']) == build['apk_sha256'] == (d/'installed-apk.txt').read_text().split()[0]
        assert {Path(l.split()[1]).name:l.split()[0] for l in (d/'installed-native.txt').read_text().splitlines()} == build['native_sha256']
        assert v.digest(d/'echo') == run['endpoint_build']['binary_sha256']
        assert v.digest(d/'echo.c') == run['endpoint_build']['source_sha256']
        assert {life['profile'] for life in run['lifetimes']} == {'root','vpn'}
        for life in run['lifetimes']:
            label = life['label']
            running = v.props(d/(label+'-running.properties'))
            stopped = v.props(d/(label+'-stopped.properties'))
            assert running['generation'] == str(life['generation']) and running['profile'] == label
            assert running['state'] == 'running' and running['protectionRunning'] == ('true' if label == 'root' else 'false')
            assert stopped['state'] == 'stopped' and stopped['mayBeActive'] == stopped['protectionRunning'] == 'false'
            assert life['process_absent'] and not (d/(label+'-queues-after.txt')).read_text().strip()
            assert 'SAKAMOTO' not in (d/(label+'-hooks-after.txt')).read_text()
        for owner in d.glob('*-owner.txt'):
            assert owner.read_text().strip() == f"{run['uid']}:{run['uid']}:600"
        profiles = ['root', 'vpn']
        failures = run['failures']
    else:
        for name, value in build['artifact_hashes'].items():
            assert v.digest(Path(run['artifact'])/name) == value
        assert v.digest(Path(run['artifact'])/'product-vpp-artifact.properties') == run['manifest_sha256']
        assert run['policy_uids'] == [12001] and 'NFQUEUE' not in (d/'hooks-after.txt').read_text()
        assert v.props(d/'first-stopped.txt')['absent'] == 'True'
        assert 'root.stop=ok' in (d/'first-stop.txt').read_text()
        profiles = ['linux']
        failures = [run['failure']]

    def keys(java, native):
        return java if pixel else 'config.'+native

    def source_query(saved, query, active, result):
        assert int(query[keys('activeRevision','active_revision')]) == active
        assert query[keys('result','result')] == str(result)
        # Reuse the source-field decoder only, after independently checking the
        # actual active revision/result. Its normal-success preconditions do not
        # apply to saved edits whose compilation failed.
        projected = dict(query)
        projected[keys('activeRevision','active_revision')] = str(saved['revision'])
        projected[keys('result','result')] = '0'
        v.query_source(saved, projected, pixel)

    snapshots = {}
    rss = []
    for profile in profiles:
        prefix = profile+'-' if pixel else ''
        for phase in ['direct','factorized','over-limit','residual','observe']:
            label = prefix+phase
            active_label = prefix+'factorized' if phase == 'over-limit' else label
            source_path = d/(active_label+'-source.conf')
            config = v.source(source_path)
            saved = v.source(d/(label+'-source.conf'))
            resource = (d/(label+'-resources.txt')).read_text()
            index, plan, budget = (one(resource, p) for p in ['policy.index ', 'policy.plan ', 'rule.budget '])
            identity = tuple(int(index[k]) for k in ['generation','revision','hash'])
            generation = next(l['generation'] for l in run['lifetimes'] if l['profile'] == profile) if pixel else run['generation']
            assert identity == (generation, config['revision'], v.snapshot_hash(source_path)), 'snapshot resource identity'
            assert tuple(int(plan[k]) for k in ['generation','revision','hash']) == identity
            expected = {'direct':(2,0,0), 'factorized':(1,1,0), 'over-limit':(1,1,0),
                        'residual':(1,0,1), 'observe':(1,1,0)}[phase]
            assert tuple(int(plan[k]) for k in ['direct','factorized','residual']) == expected, 'actual plan selection'
            assert int(plan['conditions']) == (20 if phase == 'residual' else 21)
            expected_entries = (31 if pixel else 17) if phase == 'direct' else 2
            # 1..65534 has pairs of equal-length prefixes sharing 15 masks;
            # 1..65535 has one prefix of each of 16 lengths. Add the fallback.
            expected_masks = (16 if pixel else 17) if phase == 'direct' else 1
            # VPN's 42001..65534 source range retains the high bit; the
            # Root/Linux range crosses 32768 and shares the fallback mask.
            if profile == 'vpn' and phase in ('factorized','over-limit','observe'):
                expected_masks = 2
            assert int(index['entries']) == expected_entries
            assert int(index['masks']) == expected_masks
            assert int(index['view_bytes']) == 55320, 'native view storage'
            assert int(index['max_query_work']) == 16 + int(index['masks']) + int(index['entries']) + 2
            for field, value in dict(query_state_bytes=916, compile_scratch_bytes=21376,
                                     publication_peak_bytes=321396, direct_limit=32, entries_limit=256,
                                     conditions_limit=9344, publication_limit_bytes=393216).items():
                assert int(plan[field]) == value, ('compiler resource bound',field)
            assert int(budget['saved']) == saved['revision'] and int(budget['active']) == config['revision']
            assert int(budget['peak_bytes']) == 868684 and int(budget['limit_bytes']) == 1048576
            assert int(budget['compile_error']) == (5 if phase == 'over-limit' else 0)
            assert int(budget['compiler_status']) == (2 if phase == 'over-limit' else 0)
            assert budget['source_rules_limit'] == '256' and budget['effective_rules_limit'] == '128'
            assert budget['expression_bytes_limit'] == '64' and budget['expression_depth_limit'] == '8'
            q = v.props(d/(label+('-apply.properties' if pixel else '-apply.txt')))
            source_query(saved, q, config['revision'], 5 if phase == 'over-limit' else 0)
            assert q[keys('saveError','save_error')] == '0'
            if identity in snapshots:
                assert snapshots[identity] == index, 'failed publication changed old index'
            snapshots[identity] = index
            memory = (d/(label+'-memory.txt')).read_text()
            hwm = int(next(line.split()[1] for line in memory.splitlines() if line.startswith('VmHWM:')))
            current = int(next(line.split()[1] for line in memory.splitlines() if line.startswith('VmRSS:')))
            assert hwm >= current > 0
            rss.append(dict(profile=profile, phase=phase, maxrss_kib=hwm, rss_kib=current))
            # Verify each selected source shape independently of collector flags.
            first = 32000 if profile == 'root' else 42000 if profile == 'vpn' else 65534
            if phase != 'over-limit':
                expr = v.expression(config['rules'][0]['expression'])
                exact = first+1 if pixel else first
                lower = first+1 if pixel else 1
                dst_last = 65534 if pixel else 65535
                expected_expr = (('and',('sport',exact,exact),('dport',1,dst_last)) if phase == 'direct'
                    else ('not',('sport',first if pixel else 65535,first if pixel else 65535)) if phase == 'residual'
                    else ('and',('sport',lower,65534),('dport',1,dst_last)))
                assert expr == expected_expr
                assert len(config['rules']) == 2 and config['rules'][0]['action'] == 2 and config['rules'][1]['action'] == 1

    assert len(failures) == len(profiles)
    for failure in failures:
        active = v.source(d/failure['active_source'])
        saved = v.source(d/failure['saved_source'])
        q = v.props(d/failure['apply'])
        assert len(saved['rules']) == 129 and len(active['rules']) == 2
        assert saved['revision'] == active['revision']+1
        assert saved['rules'][0]['version'] == active['rules'][0]['version']+1
        assert saved['rules'][0]['action'] == 1 and active['rules'][0]['action'] == 2
        assert q[keys('compileError','compile_error')] == '5' and q[keys('compilerStatus','compiler_status')] == '2'
        assert q[keys('activeCount','active_count')] == '2'
        for i, rule in enumerate(active['rules']):
            key = f'activeVersion.{i}' if pixel else f'config.active_version.{i}'
            assert int(q[key]) == rule['version'], 'failure changed active rule versions'

    phases = ['direct','factorized','over-limit','residual','observe']
    expected_cases = [(profile, phase, port) for profile in profiles for phase in phases
                      for port in ([32000,32001] if profile == 'root' else [42000,42001] if profile == 'vpn' else [65534,65535])]
    observed_cases = [(c.get('profile','linux'), c['phase'].removeprefix(c.get('profile','')+'-').rsplit('-',1)[0]
                       if pixel else c['phase'], c['source_port']) for c in run['cases']]
    assert observed_cases == expected_cases, 'complete representative matrix'
    durations = []
    drops = 0
    claimed_tokens = set()
    for case in run['cases']:
        assert int(case['nonce'].rsplit('-',1)[1]) > run['started_ns']
        config_path = d/case['source_file']; active = v.source(config_path)
        query, before = v.props(d/case['query']), v.props(d/case['before'])
        failed = 'over-limit' in case['phase']
        saved_path = d/((case['profile']+'-' if pixel else '')+'over-limit-source.conf') if failed else config_path
        saved = v.source(saved_path)
        source_query(saved, query, active['revision'], 0)
        assert int(query[keys('compileError','compile_error')]) == (5 if failed else 0)
        assert case['saved_revision'] == saved['revision']
        key = lambda java,native: java if pixel else 'query.'+native
        assert int(query[key('winnerVersion','winner_version')]) == case['rule_version']
        assert int(query[key('winnerRevision','winner_revision')]) == case['revision'] == active['revision']
        assert int(query[key('winnerAction','winner_action')]) == case['declared_action']
        assert int(query[key('logicalHits','logical_hits')]) == int(before[key('logicalHits','logical_hits')])+1
        assert int(query[key('actualDrops','actual_drops')]) == int(before[key('actualDrops','actual_drops')])+int(not case['delivered'])
        probe = v.props(d/case['probe']) if pixel else json.loads((d/case['probe']).read_text())
        assert str(probe['uid']) == str(case['uid']) and probe['nonce'] == case['nonce']
        vpn = case.get('profile') == 'vpn'
        endpoint = (json.loads((d/'lan-endpoint.json').read_text()) if vpn else
                    (d/case['endpoint']).read_text()) if pixel else json.loads((d/'endpoint.json').read_text())
        delivered = (probe.get('packet.0') == 'echo' if vpn else probe.get('result') == 'udp_echo_matched') if pixel else probe['received'] == case['nonce']
        assert delivered == case['delivered'] == ((case['nonce']+(':0' if vpn else '')) in endpoint)
        trace = (d/(case['lifetime']+('-stop.log' if pixel else '-vpp.log'))).read_text()
        v.packet_evidence(trace, case, active, config_path)
        payload = (case['nonce']+(':0' if vpn else '')).encode()
        packet = next(p for p in v.rows(trace,'s216 stage=admit ') if p.get('uid') == str(case['uid'])
                      and p.get('direction') == '3' and bytes.fromhex(p.get('raw',''))[28:] == payload)
        identity = (case['generation'], active['revision'], v.snapshot_hash(config_path))
        token = (case['generation'], packet['token'])
        assert token not in claimed_tokens; claimed_tokens.add(token)
        queries = [q for q in v.rows(trace,'t09 event=query ') if q['token'] == packet['token'] and int(q['generation']) == case['generation']]
        assert len(queries) == 1 and queries[0]['position'] == '1', 'whole static rule executes once'
        q = queries[0]
        assert q['status'] == '0' and int(q['rule']) == case['rule_version']
        expected = v.reference.ordered_reference(v.logical_rules(active,case['uid']),v.packet_facts(packet))
        assert int(q['rank']) == expected['winner_rank']
        assert (int(q['generation']),int(q['revision']),int(q['snapshot_hash'])) == identity
        index = snapshots[identity]
        assert 0 <= int(q['residuals']) <= 2 and int(q['residuals']) <= int(q['keys']) <= int(index['entries'])
        assert 0 <= int(q['masks']) <= int(index['masks']) and 0 <= int(q['subject_probes']) <= 16
        assert sum(int(q[k]) for k in ['residuals','keys','masks','subject_probes']) <= int(index['max_query_work'])
        assert int(q['query_ns']) >= 0; durations.append(int(q['query_ns']))
        drops += int(not delivered)
    root_trace = (d/('root-stop.log' if pixel else 'first-vpp.log')).read_text()
    zero = v.rows(root_trace,'s242 event=stop_native_zero ')
    assert zero and all(zero[-1][k] == '0' for k in ['pending','buffers','obligations','handoffs','completion_frames'])
    if pixel:
        stops = v.rows((d/'vpn-stop.log').read_text(),'s237 event=owner_stopped ')
        assert len(stops) == 2 and {s['owner'] for s in stops} == {'0','1'}
        for stop in stops:
            assert all(stop[k] == '0' for k in ['sessions','inputs','pbufs','buffers','obligations','frames'])
            assert stop['sockets_created'] == stop['sockets_closed'] and stop['timer_fd'] == stop['broker_fd'] == '-1'
    return dict(status='PASS', platform='pixel' if pixel else 'linux', packets=len(run['cases']),
                logical_hits=len(run['cases']), actual_drops=drops, compile_failures=len(failures),
                snapshot_resources=len(snapshots), query_ns_median=statistics.median(durations),
                query_ns_max=max(durations), process_memory=rss, source_sha256=run['source_sha256'],
                verifier_sha256=v.digest(__file__))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('directory',type=Path)
    parser.add_argument('--output',type=Path); args = parser.parse_args()
    result = verify(args.directory); text = json.dumps(result,indent=2)+'\n'
    if args.output: args.output.write_text(text)
    print(text)
