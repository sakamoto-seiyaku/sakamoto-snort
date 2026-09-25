#!/usr/bin/env python3
"""Source-bound native plan/scale/budget experiment; no alternative product engine."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
FILES = ['src/product/vpp/product_l4_policy.c', 'src/product/vpp/product_l4_policy.h',
         'src/product/vpp/product_rule_config.c', 'src/product/vpp/product_rule_config.h',
         'src/product/include/sakamoto_product_rule_config.h', 'tests/device/helpers/t10_policy_cost.c']


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def configurations():
    rows = [(shape, count, path, 32, 256)
            for shape in range(5) for count in (1,8,32,64,128) for path in range(3)]
    rows += [(shape,count,0,32,count) for shape in range(5) for count in (1,8,32,64,128)]
    rows += [(shape,count,0,direct,256) for shape in (1,2,3) for count in (1,32,128)
             for direct in (1,8,16)]
    return rows


def build(directory, compiler):
    directory.mkdir(parents=True,exist_ok=False)
    manifest = dict(started_ns=time.time_ns(),compiler=compiler,
                    compiler_version=subprocess.check_output([compiler,'--version'],text=True),files={})
    for name in FILES:
        path = directory/'source'/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes((ROOT/name).read_bytes())
        manifest['files'][name] = digest(path)
    source = directory/'source'
    command = [compiler,'-std=c11','-O2','-Wall','-Wextra','-Werror','-fstack-usage',
               '-I'+str(source/'src/product/vpp'),'-I'+str(source/'src/product/include'),
               str(source/'tests/device/helpers/t10_policy_cost.c'),
               str(source/'src/product/vpp/product_l4_policy.c'),
               str(source/'src/product/vpp/product_rule_config.c'),'-o',str(directory/'cost')]
    subprocess.run(command,check=True)
    manifest.update(command=command,binary_sha256=digest(directory/'cost'),completed_ns=time.time_ns())
    (directory/'build.json').write_text(json.dumps(manifest,indent=2)+'\n')


def run(directory, repetitions, serial=None):
    manifest = json.loads((directory/'build.json').read_text())
    assert digest(directory/'cost') == manifest['binary_sha256']
    result = dict(started_ns=time.time_ns(),repetitions=repetitions,binary_sha256=manifest['binary_sha256'],
                  configurations=configurations(),platform='android-arm64' if serial else 'linux-x86_64')
    remote = None
    adb = [str(ROOT/'dev/adb'),'-s',serial] if serial else None
    try:
        if serial:
            # The caller serializes this operation with every other phone runner.
            remote = subprocess.check_output(adb+['shell','mktemp','-d','/data/local/tmp/t10-cost.XXXXXX'],text=True).strip()
            assert remote.startswith('/data/local/tmp/t10-cost.') and '/' not in remote.removeprefix('/data/local/tmp/')
            subprocess.run(adb+['push',str(directory/'cost'),remote+'/cost'],check=True,stdout=subprocess.DEVNULL)
            subprocess.run(adb+['shell','chmod','755',remote+'/cost'],check=True)
            observed = subprocess.check_output(adb+['shell','sha256sum',remote+'/cost'],text=True).split()[0]
            assert observed == manifest['binary_sha256']
            result['executed_binary_sha256'] = observed
            result['environment'] = subprocess.check_output(adb+['shell','uname','-a'],text=True)
        else:
            result['executed_binary_sha256'] = digest(directory/'cost')
            result['environment'] = subprocess.check_output(['uname','-a'],text=True)
        for repetition in range(repetitions):
            configs = configurations()
            if repetition % 2: configs.reverse()
            with (directory/f'run-{repetition}.jsonl').open('w') as output:
                for values in configs:
                    command = (adb+['shell',remote+'/cost'] if serial else [str(directory/'cost')])+list(map(str,values))
                    row = json.loads(subprocess.check_output(command,text=True))
                    output.write(json.dumps(row)+'\n');output.flush()
            print(f'{result["platform"]} repetition {repetition+1}/{repetitions} complete',flush=True)
    finally:
        if remote:
            subprocess.run(adb+['shell','rm',remote+'/cost'],check=True)
            subprocess.run(adb+['shell','rmdir',remote],check=True)
        result['completed_ns'] = time.time_ns()
        (directory/'run.json').write_text(json.dumps(result,indent=2)+'\n')


def summary(directory):
    build = json.loads((directory/'build.json').read_text())
    run = json.loads((directory/'run.json').read_text())
    assert digest(directory/'cost') == build['binary_sha256'] == run['executed_binary_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    for name, expected in build['files'].items():
        assert digest(directory/'source'/name) == expected == digest(ROOT/name), 'current compiler/helper source identity'
    groups = {}
    for repetition in range(run['repetitions']):
        raw = [json.loads(line) for line in (directory/f'run-{repetition}.jsonl').read_text().splitlines()]
        expected = configurations()
        if repetition % 2: expected.reverse()
        assert [tuple(row[k] for k in ['shape','rules','path','direct_limit','entry_budget']) for row in raw] == expected
        for row in raw:
            assert row['direct']+row['factorized']+row['residual'] == row['rules']
            assert row['rules'] <= row['entries'] <= row['entry_budget'] <= 256
            assert 1 <= row['masks'] <= row['entries']
            assert row['view_bytes'] == 55320 and row['materialized_view_bytes'] == 221280
            assert row['publication_peak_bytes'] == 321396 and row['management_peak_bytes'] == 868684
            assert row['query_state_bytes'] == 916 and row['compile_scratch_bytes'] == 21376
            assert row['process_maxrss_kib'] > 0 and row['query_ns'] > 0 and row['compile_ns'] > 0
            key = tuple(row[k] for k in ['shape','rules','path','direct_limit','entry_budget'])
            groups.setdefault(key,[]).append(row)
    rows = []
    signatures = {}
    for key, samples in groups.items():
        assert len(samples) == run['repetitions']
        sigs = {s['signature'] for s in samples}; assert len(sigs) == 1
        logical = key[:2]
        if logical in signatures: assert signatures[logical] == next(iter(sigs)), 'full winner/mode/action signature differs by legal plan/budget'
        signatures[logical] = next(iter(sigs))
        row = dict(samples[0])
        row['query_ns_each'] = statistics.median(s['query_ns']/s['queries'] for s in samples)
        row['compile_ns_each'] = statistics.median(s['compile_ns']/s['compiles'] for s in samples)
        row['query_ns_each_min'] = min(s['query_ns']/s['queries'] for s in samples)
        row['query_ns_each_max'] = max(s['query_ns']/s['queries'] for s in samples)
        row['process_maxrss_kib'] = max(s['process_maxrss_kib'] for s in samples)
        rows.append(row)
    return dict(status='PASS complete-result equivalence across plans and budgets',platform=run['platform'],
                repetitions=run['repetitions'],configurations=len(groups),rows=sorted(rows,key=lambda r:tuple(r[k] for k in ['shape','rules','path','direct_limit','entry_budget'])),
                build_sha256=digest(directory/'build.json'),run_sha256=digest(directory/'run.json'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest='op',required=True)
    p = sub.add_parser('build');p.add_argument('directory',type=Path);p.add_argument('--compiler',default='cc')
    p = sub.add_parser('run');p.add_argument('directory',type=Path);p.add_argument('--serial');p.add_argument('--repetitions',type=int,default=3)
    p = sub.add_parser('summary');p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
    args = parser.parse_args(); directory = args.directory.resolve()
    if args.op == 'build': build(directory,args.compiler)
    elif args.op == 'run': run(directory,args.repetitions,args.serial)
    else:
        result = summary(directory); text = json.dumps(result,indent=2)+'\n'
        if args.output: args.output.write_text(text)
        print(json.dumps({k:v for k,v in result.items() if k != 'rows'},indent=2))
