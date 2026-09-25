#!/usr/bin/env python3
"""Build source-bound T08/T09 cost executables; compare complete-result signatures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import statistics

ROOT=Path(__file__).resolve().parents[2]
BASELINE='0473988ad13a998cf45ce580381566c290d127df'

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def build(output,compiler):
    output.mkdir(parents=True,exist_ok=False)
    helper=ROOT/'tests/device/helpers/t09_policy_cost.c'
    manifest=dict(baseline_commit=BASELINE,compiler=compiler,
                  compiler_version=subprocess.check_output([compiler,'--version'],text=True),
                  helper_sha256=digest(helper),variants={})
    (output/helper.name).write_bytes(helper.read_bytes())
    for variant in ('ordered','indexed'):
        source=output/variant;source.mkdir()
        for name in ('product_l4_policy.c','product_l4_policy.h'):
            path='src/product/vpp/'+name
            data=(subprocess.check_output(['git','show',BASELINE+':'+path],cwd=ROOT)
                  if variant=='ordered' else (ROOT/path).read_bytes())
            (source/name).write_bytes(data)
        binary=output/('cost-'+variant)
        command=[compiler,'-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(source),
                 str(output/helper.name),str(source/'product_l4_policy.c'),'-o',str(binary)]
        subprocess.run(command,check=True)
        manifest['variants'][variant]=dict(command=command,binary_sha256=digest(binary),
            files={p.name:digest(p) for p in source.iterdir()})
    (output/'build.json').write_text(json.dumps(manifest,indent=2)+'\n')

def compare(before,after):
    old=[json.loads(line) for line in before.read_text().splitlines()]
    new=[json.loads(line) for line in after.read_text().splitlines()]
    assert len(old)==len(new)==20
    rows=[]
    for a,b in zip(old,new):
        assert (a['workload'],a['rules'],a['signature'],a['query_iterations'],a['compile_iterations']) == (b['workload'],b['rules'],b['signature'],b['query_iterations'],b['compile_iterations'])
        rows.append(dict(workload=a['workload'],rules=a['rules'],signature=a['signature'],
            query_ratio=b['query_ns']/a['query_ns'],compile_ratio=b['compile_ns']/a['compile_ns'],
            ordered_query_ns=a['query_ns']/a['query_iterations'],indexed_query_ns=b['query_ns']/b['query_iterations'],
            ordered_compile_ns=a['compile_ns']/a['compile_iterations'],indexed_compile_ns=b['compile_ns']/b['compile_iterations'],
            ordered_view_bytes=a['view_bytes'],indexed_view_bytes=b['view_bytes'],masks=b['masks'],
            ordered_residuals=a['residual_probes']/a['query_iterations'],indexed_residuals=b['residual_probes']/b['query_iterations']))
    return dict(status='PASS full-result signature equivalence',rows=rows)

def summary(directory):
    manifest=json.loads((directory/'build.json').read_text())
    run=json.loads((directory/'run.json').read_text())
    assert digest(directory/'t09_policy_cost.c')==manifest['helper_sha256'], 'cost helper source identity'
    for variant in ('ordered','indexed'):
        for name,expected in manifest['variants'][variant]['files'].items():
            assert digest(directory/variant/name)==expected, 'compiler/matcher source identity'
        assert digest(directory/('cost-'+variant))==manifest['variants'][variant]['binary_sha256']
        observed=run.get(variant+'_sha256',run.get('binary_hashes',{}).get(variant))
        assert observed==manifest['variants'][variant]['binary_sha256'], 'executed binary identity'
    results=[compare(directory/f'ordered-{i}.jsonl',directory/f'indexed-{i}.jsonl') for i in range(run['repetitions'])]
    rows=[]
    for index in range(20):
        samples=[result['rows'][index] for result in results];row=dict(samples[0])
        for key in ('query_ratio','compile_ratio','ordered_query_ns','indexed_query_ns','ordered_compile_ns','indexed_compile_ns'):
            row[key]=statistics.median(sample[key] for sample in samples)
        row['query_ratio_min']=min(sample['query_ratio'] for sample in samples)
        row['query_ratio_max']=max(sample['query_ratio'] for sample in samples)
        rows.append(row)
    return dict(status='PASS full-result signature equivalence',repetitions=len(results),rows=rows,
                build_sha256=digest(directory/'build.json'),run_sha256=digest(directory/'run.json'))

if __name__=='__main__':
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='op',required=True)
    b=sub.add_parser('build');b.add_argument('output',type=Path);b.add_argument('--compiler',default='cc')
    c=sub.add_parser('compare');c.add_argument('before',type=Path);c.add_argument('after',type=Path);c.add_argument('--output',type=Path)
    a=sub.add_parser('summary');a.add_argument('directory',type=Path);a.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.op=='build':build(args.output.resolve(),args.compiler)
    else:
        result=summary(args.directory) if args.op=='summary' else compare(args.before,args.after)
        text=json.dumps(result,indent=2)+'\n'
        if args.output:args.output.write_text(text)
        print(text)
