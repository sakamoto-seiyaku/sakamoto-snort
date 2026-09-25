#!/usr/bin/env python3
"""Source-bound worker cache/guard/capacity experiment; no alternative product engine."""
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
         'src/product/include/sakamoto_product_rule_config.h', 'tests/device/helpers/t11_cache_cost.c']


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def configurations():
    rows = [(shape,count,flows,capacity,0) for shape in (0,1,2)
            for count in (1,32,128) for flows in (1,64,256) for capacity in (16,64,128)]
    rows += [(1,128,8,64,period) for period in (1,2,16)]
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
               str(source/'tests/device/helpers/t11_cache_cost.c'),
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
            remote = subprocess.check_output(adb+['shell','mktemp','-d','/data/local/tmp/t11-cost.XXXXXX'],text=True).strip()
            assert remote.startswith('/data/local/tmp/t11-cost.') and '/' not in remote.removeprefix('/data/local/tmp/')
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
                    command = (adb+['shell',remote+'/cost'] if serial else [str(directory/'cost')])+list(map(str,values))+[str(repetition%2)]
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
        assert digest(directory/'source'/name) == expected == digest(ROOT/name)
    groups = {}
    keys = ['shape','rules','flows','capacity','fact_period']
    for repetition in range(run['repetitions']):
        raw = [json.loads(line) for line in (directory/f'run-{repetition}.jsonl').read_text().splitlines()]
        expected = configurations()
        if repetition % 2: expected.reverse()
        assert [tuple(row[k] for k in keys) for row in raw] == expected
        for row in raw:
            assert row['first_arm']==repetition%2
            assert row['hits']+row['misses']==row['queries']
            assert row['occupied']<=row['capacity']<=128
            assert row['misses']==row['occupied']+row['replacements']
            assert row['guard_bytes']>0 and row['entry_bytes']>row['guard_bytes']
            assert row['cache_bytes']>=128*row['entry_bytes']
            assert 0<row['management_peak_bytes']<=1024*1024 and row['process_hwm_kib']>0
            groups.setdefault(tuple(row[k] for k in keys),[]).append(row)
    rows=[];signatures={}
    for key,samples in groups.items():
        assert len(samples)==run['repetitions']
        assert len({s['signature'] for s in samples})==1
        logical=key[:3]+key[4:]
        sig=samples[0]['signature']
        if logical in signatures: assert signatures[logical]==sig
        signatures[logical]=sig
        row=dict(samples[0])
        for field in ('direct','cached'):
            row[field+'_ns_each']=statistics.median(s[field+'_ns']/s['queries'] for s in samples)
        row['cached_over_direct']=row['cached_ns_each']/row['direct_ns_each']
        row['hit_rate']=row['hits']/row['queries']
        rows.append(row)
    return dict(status='PASS complete-result equivalence; timings are measurements, not a performance gate',
                platform=run['platform'],repetitions=run['repetitions'],configurations=len(groups),
                rows=sorted(rows,key=lambda row:tuple(row[k] for k in keys)),
                build_sha256=digest(directory/'build.json'),run_sha256=digest(directory/'run.json'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest='op',required=True)
    p = sub.add_parser('build');p.add_argument('directory',type=Path);p.add_argument('--compiler',default='cc')
    p = sub.add_parser('run');p.add_argument('directory',type=Path);p.add_argument('--serial');p.add_argument('--repetitions',type=int,default=4)
    p = sub.add_parser('summary');p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
    args = parser.parse_args(); directory = args.directory.resolve()
    if args.op == 'build': build(directory,args.compiler)
    elif args.op == 'run': run(directory,args.repetitions,args.serial)
    else:
        result = summary(directory); text = json.dumps(result,indent=2)+'\n'
        if args.output: args.output.write_text(text)
        print(json.dumps({k:v for k,v in result.items() if k != 'rows'},indent=2))
