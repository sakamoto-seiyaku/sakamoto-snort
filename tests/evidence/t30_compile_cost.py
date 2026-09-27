#!/usr/bin/env python3
"""Build and time current Product C source activation on Host and ARM64."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
SOURCES=('tests/device/helpers/t30_compile_cost.c',
         'src/product/vpp/product_rule_config.c',
         'src/product/vpp/product_l4_policy.c',
         'src/product/vpp/product_domains.c',
         'src/product/vpp/product_domains_memory.c',
         'src/product/vpp/product_domains_rax.c')
INPUTS=SOURCES+tuple(str(x.relative_to(ROOT)) for base in
    ('src/product/vpp','src/product/include','third_party/rax')
    for x in sorted((ROOT/base).glob('*.h')))+('third_party/rax/rax.c',)
CONFIGS=('linux-baseline-c','linux-scaled-c','linux-supplement-f')
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):Path(path).write_text(json.dumps(value,indent=2)+'\n')

def build(args):
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    product=json.loads(args.product_build.read_text())
    copied={}
    for name in INPUTS:
        src=ROOT/name;target=out/'source'/name
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(src,target)
        copied[name]=digest(target)
        if name in product['files']:
            assert copied[name]==product['files'][name],name
    source=out/'source';compiler=args.compiler
    command=[compiler,'-std=c11','-O2','-Wall','-Wextra','-Werror',
        '-I'+str(source/'src/product/vpp'),'-I'+str(source/'src/product/include'),
        *[str(source/name) for name in SOURCES],'-lm','-o',str(out/'cost')]
    with (out/'build.log').open('w') as log:
        subprocess.run(command,check=True,stdout=log,stderr=subprocess.STDOUT)
    result=dict(platform=args.platform,compiler=compiler,
        compiler_version=subprocess.check_output([compiler,'--version'],text=True),
        product_build=str(args.product_build.resolve()),product_source_sha256=product['source_sha256'],
        product_build_sha256=digest(args.product_build),command=command,source_hashes=copied,
        binary_sha256=digest(out/'cost'),built_ns=time.time_ns())
    write(out/'build.json',result)
    print(json.dumps({k:result[k] for k in ('platform','binary_sha256','product_source_sha256')},indent=2))

def parse(raw):
    lines=raw.splitlines()
    assert lines[0].startswith('source_rules=') and lines[1].startswith('repetition,activate_ns,')
    head=dict(item.split('=',1) for item in lines[0].split())
    rows=[]
    assert lines[-1].startswith('query,')
    for line in lines[2:-1]:
        values=[int(x) for x in line.split(',')]
        assert len(values)==5 and values[1]>=values[2]+values[3]
        rows.append(dict(zip(('repetition','activate_ns','publish_compile_ns',
                              'old_destroy_ns','publications'),values)))
    query=[int(x) for x in lines[-1].split(',')[1:]]
    assert len(query)==4 and query[2]==100000 and query[3]>0
    return head,rows,dict(domain_ns_each=query[0]/query[2],
                          match_ns_each=query[1]/query[2],signature=query[3])

def run(args):
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    build_dir=args.build.resolve();build=json.loads((build_dir/'build.json').read_text())
    assert digest(build_dir/'cost')==build['binary_sha256']
    configs={}
    for name in CONFIGS:
        source=args.evidence.resolve()/name/'combined-observe-source.conf'
        parent=json.loads((args.evidence.resolve()/name/'result.json').read_text())
        parent_build=json.loads(Path(parent['build']).read_text())
        assert parent['status']=='RAW_COMPLETE' and parent['source_sha256']==parent_build['source_sha256']
        assert parent['build_sha256']==digest(parent['build'])
        # Pixel's final closure differs by Java only. Every native compiler
        # input must match both the saved-source producer and this executable.
        assert all(parent_build['files'].get(path)==sha for path,sha in
                   build['source_hashes'].items() if path!=SOURCES[0])
        target=out/(name+'.conf');shutil.copyfile(source,target)
        configs[name]=dict(path=target,sha256=digest(target),source=str(source))
    adb=None;remote=None
    results=[]
    try:
        if args.platform=='arm64':
            serial=json.loads(args.serial_from.read_text())['serial']
            adb=[str(ROOT/'dev/adb'),'-s',serial]
            candidate=subprocess.check_output(adb+['shell','mktemp','-d',
                '/data/local/tmp/t30-compile.XXXXXX'],text=True).strip()
            suffix=candidate.removeprefix('/data/local/tmp/t30-compile.')
            assert candidate.startswith('/data/local/tmp/t30-compile.') and suffix and '/' not in suffix
            remote=candidate
            subprocess.run(adb+['push',str(build_dir/'cost'),remote+'/cost'],check=True,
                           stdout=subprocess.DEVNULL)
            subprocess.run(adb+['shell','chmod','755',remote+'/cost'],check=True)
            for name in CONFIGS:
                subprocess.run(adb+['push',str(configs[name]['path']),remote+'/'+name+'.conf'],
                               check=True,stdout=subprocess.DEVNULL)
            for local,actual in [(build_dir/'cost',remote+'/cost')]+[
                (configs[name]['path'],remote+'/'+name+'.conf') for name in CONFIGS]:
                observed=subprocess.check_output(adb+['shell','sha256sum',actual],text=True).split()[0]
                assert observed==digest(local),(local,observed)
        for repetition in range(3):
            for name in (CONFIGS if repetition%2==0 else tuple(reversed(CONFIGS))):
                if adb:
                    command=adb+['shell',remote+'/cost',remote+'/'+name+'.conf',str(args.repetitions)]
                else:
                    command=[str(build_dir/'cost'),str(configs[name]['path']),str(args.repetitions)]
                raw=subprocess.check_output(command,text=True,timeout=90)
                filename=f'{args.platform}-{repetition}-{name}.txt'
                (out/filename).write_text(raw)
                header,rows,query=parse(raw)
                assert len(rows)==args.repetitions and int(header['compile_peak_bytes'])==2045364
                assert int(header['source_rules'])==(4 if name=='linux-baseline-c' else 64)
                assert int(header['domain_entries'])==(1 if name=='linux-baseline-c' else 65)
                results.append(dict(label=name,repetition=repetition,raw=filename,
                    raw_sha256=digest(out/filename),samples=rows,query=query))
    finally:
        if adb and remote:
            cleanup=subprocess.run(adb+['shell','rm','-rf',remote],capture_output=True,text=True)
            (out/'cleanup.txt').write_text(f'exit={cleanup.returncode}\n'+cleanup.stdout+cleanup.stderr)
            assert cleanup.returncode==0
    summary={}
    for name in CONFIGS:
        rows=[row for item in results if item['label']==name for row in item['samples']]
        summary[name]={key:dict(median_ns=statistics.median(row[key] for row in rows),
            p90_ns=sorted(row[key] for row in rows)[int(.9*len(rows))-1],
            max_ns=max(row[key] for row in rows))
            for key in ('activate_ns','publish_compile_ns','old_destroy_ns')}
        summary[name]['query']={key:statistics.median(item['query'][key]
            for item in results if item['label']==name)
            for key in ('domain_ns_each','match_ns_each')}
    answer=dict(status='VALID',platform=args.platform,build=str(build_dir/'build.json'),
        binary_sha256=build['binary_sha256'],source_hashes=build['source_hashes'],
        config_hashes={name:value['sha256'] for name,value in configs.items()},
        environment=(subprocess.check_output(adb+['shell','uname','-a'],text=True)
                     if adb else subprocess.check_output(['uname','-a'],text=True)),
        repetitions=args.repetitions,results=results,summary=summary,
        runner_sha256=digest(__file__))
    write(out/'result.json',answer)
    print(json.dumps(dict(status='VALID',platform=args.platform,summary=summary),indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='op',required=True)
    b=sub.add_parser('build');b.add_argument('--platform',choices=('host','arm64'),required=True)
    b.add_argument('--compiler',required=True);b.add_argument('--product-build',type=Path,required=True)
    b.add_argument('--output',type=Path,required=True)
    r=sub.add_parser('run');r.add_argument('--platform',choices=('host','arm64'),required=True)
    r.add_argument('--build',type=Path,required=True);r.add_argument('--evidence',type=Path,required=True)
    r.add_argument('--output',type=Path,required=True);r.add_argument('--serial-from',type=Path)
    r.add_argument('--repetitions',type=int,default=100)
    args=parser.parse_args()
    assert args.op!='run' or 10<=args.repetitions<=1000
    build(args) if args.op=='build' else run(args)
