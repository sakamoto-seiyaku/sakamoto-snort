#!/usr/bin/env python3
"""Corrupt copies of T10 witnesses and require independent rejection."""
import argparse
import json
from pathlib import Path
import re
import shutil
import tempfile
import verify_t10_plans as verifier


def replace_field(path, prefix, key, value, token=None):
    text = path.read_text()
    line = next(line for line in text.splitlines() if line.startswith(prefix)
                and (token is None or re.search(r'\btoken='+re.escape(token)+r'\b',line)))
    pattern = r'\b'+re.escape(key)+r'=\d+'
    assert re.search(pattern,line), (path,prefix,key)
    changed = re.sub(pattern,key+'='+str(value),line,count=1)
    assert changed != line
    path.write_text(text.replace(line,changed,1))


def run(directory):
    directory = Path(directory)
    verifier.verify(directory)
    run = json.loads((directory/'result.json').read_text())
    pixel = 'serial' in run
    prefix = 'root-' if pixel else ''
    trace_name = 'root-stop.log' if pixel else 'first-vpp.log'
    case = run['cases'][0]
    payload = case['nonce'].encode()
    trace = (directory/trace_name).read_text()
    packet = next(row for row in verifier.v.rows(trace,'s216 stage=admit ')
                  if row.get('uid') == str(case['uid']) and row.get('direction') == '3'
                  and bytes.fromhex(row.get('raw',''))[28:] == payload)
    token = packet['token']
    mutations = [('index-'+key,'policy.index ',key,value) for key,value in
                 [('hash',1),('entries',1),('masks',255),('view_bytes',1),('max_query_work',1)]]
    mutations += [('plan-'+key,'policy.plan ',key,value) for key,value in
                  [('hash',1),('direct',0),('factorized',1),('conditions',0),('direct_limit',33),
                   ('query_state_bytes',0),('compile_scratch_bytes',0),('publication_peak_bytes',1)]]
    mutations += [('budget-'+key,'rule.budget ',key,value) for key,value in
                  [('peak_bytes',1),('limit_bytes',1),('effective_rules_limit',129)]]
    mutations += [('query-'+key,'t09 event=query ',key,value) for key,value in
                  [('rule',1),('rank',99),('revision',1),('snapshot_hash',1),('position',2),
                   ('residuals',129),('keys',257),('masks',257),('query_ns',-1)]]
    mutations += [('winner-'+key,'s209 event=l4 ',key,value) for key,value in
                  [('mode',3),('actual_action',3),('action',3)]]
    mutations += [('failure-'+key,'failure',key,value) for key,value in
                  [('saved',1),('active',1),('compile',0),('compiler',0),('version',1)]]
    mutations += [('duplicate-logical-hit','counter','hits',None),
                  ('missing-resource','remove','resource',None),
                  ('missing-query','remove','query',None),
                  ('lost-saved-edit','source','action',None)]
    rejected = []
    with tempfile.TemporaryDirectory(prefix='sakamoto-t10-negative-') as temporary:
        for name, kind, key, value in mutations:
            target = Path(temporary)/name
            shutil.copytree(directory,target,ignore=shutil.ignore_patterns('configuration'))
            if kind in ('policy.index ','policy.plan ','rule.budget '):
                replace_field(target/(prefix+'direct-resources.txt'),kind,key,value)
            elif kind in ('t09 event=query ','s209 event=l4 '):
                replace_field(target/trace_name,kind,key,value,token)
            elif kind == 'failure':
                field = {'saved':'savedRevision' if pixel else 'config.saved_revision',
                         'active':'activeRevision' if pixel else 'config.active_revision',
                         'compile':'compileError' if pixel else 'config.compile_error',
                         'compiler':'compilerStatus' if pixel else 'config.compiler_status',
                         'version':'activeVersion.0' if pixel else 'config.active_version.0'}[key]
                path = target/(prefix+'over-limit-apply'+('.properties' if pixel else '.txt'))
                replace_field(path,field+'=',field,value)
            elif kind == 'counter':
                path = target/case['query'];text = path.read_text()
                field = 'logicalHits' if pixel else 'query.logical_hits'
                old = int(re.search(r'^'+re.escape(field)+r'=(\d+)',text,re.M).group(1))
                replace_field(path,field+'=',field,old+1)
            elif kind == 'remove' and key == 'resource':
                (target/(prefix+'direct-resources.txt')).unlink()
            elif kind == 'remove':
                path = target/trace_name;text = path.read_text()
                line = next(line for line in text.splitlines() if line.startswith('t09 event=query ')
                            and re.search(r'\btoken='+re.escape(token)+r'\b',line))
                path.write_text(text.replace(line,'',1))
            else:
                path = target/(prefix+'over-limit-source.conf')
                data = bytearray(path.read_bytes())
                retained = int.from_bytes(data[20:24],'little')
                action = 24+8*retained+16+8*4
                assert int.from_bytes(data[action:action+4],'little') == 1
                data[action:action+4] = (2).to_bytes(4,'little')
                path.write_bytes(data)
            try:
                verifier.verify(target)
            except (AssertionError,KeyError,ValueError,OSError):
                rejected.append(name)
            else:
                raise AssertionError('accepted forged witness: '+name)
            shutil.rmtree(target)
    return dict(status='PASS',count=len(rejected),rejected=rejected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser();parser.add_argument('directory',type=Path)
    parser.add_argument('--output',type=Path);args = parser.parse_args()
    result = run(args.directory);text = json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text)
    print(text)
