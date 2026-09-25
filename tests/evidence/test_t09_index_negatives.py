#!/usr/bin/env python3
"""Reject altered T09 query/resource witnesses; originals are copied, never edited."""
import argparse
import json
from pathlib import Path
import re
import shutil
import tempfile
import verify_t09_index as verifier

def run(directory):
    directory=Path(directory);verifier.verify(directory)
    data=json.loads((directory/'result.json').read_text());pixel='serial' in data
    trace_name='root-stop.log' if pixel else 'first-vpp.log'
    mutations=[('query-'+key,'query',key) for key in ('rule','rank','revision','snapshot_hash','position','residuals','keys','masks','query_ns')]
    mutations += [('resource-'+key,'resource',key) for key in ('entries','hash','max_query_work')]
    mutations += [('missing-query','missing-query',None),('missing-resource','missing-resource',None)]
    rejected=[]
    with tempfile.TemporaryDirectory(prefix='sakamoto-t09-negative-') as tmp:
        for name,kind,key in mutations:
            target=Path(tmp)/name;shutil.copytree(directory,target,ignore=shutil.ignore_patterns('configuration'))
            if kind in ('query','missing-query'):
                path=target/trace_name;text=path.read_text()
                tokens=verifier.v.claimed_probe_tokens(text,data)
                line=next(line for line in text.splitlines() if line.startswith('t09 event=query ')
                          and re.search(r'\btoken=(\d+)',line).group(1) in tokens)
                if kind=='missing-query':replacement=''
                else:
                    value=int(re.search(r'\b'+key+r'=(\d+)',line).group(1))
                    new=-1 if key=='query_ns' else 129 if key in ('residuals','keys','masks') else value+1
                    replacement=re.sub(r'\b'+key+r'=\d+',key+'='+str(new),line,count=1)
                path.write_text(text.replace(line,replacement,1))
            else:
                paths=sorted(target.glob('*-index.txt'));path=paths[0]
                text=path.read_text();line=next(line for line in text.splitlines() if line.startswith('policy.index '))
                if kind=='missing-resource':
                    # Remove the file, not just its line, to exercise the join.
                    path.unlink()
                else:
                    value=int(re.search(r'\b'+key+r'=(\d+)',line).group(1))
                    replacement=re.sub(r'\b'+key+r'=\d+',key+'='+str(1 if key=='max_query_work' else value+1),line,count=1)
                    path.write_text(text.replace(line,replacement,1))
            try:verifier.verify(target)
            except (AssertionError,KeyError,ValueError):rejected.append(name)
            else:raise AssertionError('accepted forged witness: '+name)
            shutil.rmtree(target)
    return dict(status='PASS',rejected=rejected,count=len(rejected))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory');parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=run(args.directory);text=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text)
    print(text)
