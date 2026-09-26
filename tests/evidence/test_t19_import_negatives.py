#!/usr/bin/env python3
"""Altered import witnesses must fail even with updated per-file checksums."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile

spec=importlib.util.spec_from_file_location('t19_verify',Path(__file__).with_name('verify_t19_import.py'))
verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)


def run(directory):
    directory=Path(directory);assert verify.verify(directory)['status']=='PASS'
    original=json.loads((directory/'result.json').read_text())
    profile=original['lifetimes'][0]['profile'] if 'serial' in original else 'root'
    first=next(c for c in original['configurations'] if c.get('profile','root')==profile)
    prefix='t19-'+profile+'-failures';rejected=[]
    with tempfile.TemporaryDirectory(prefix='t19-negative-') as temporary:
        copied=Path(temporary)/'evidence'
        shutil.copytree(directory,copied,ignore=shutil.ignore_patterns('*.png','*.xml','configuration'))
        assert verify.verify(copied,packet_check=False)['status']=='PASS'

        def trial(name,label,field,edit):
            state=json.loads((copied/'result.json').read_text())
            record=next(r for r in state['imports'] if r['label']==label)
            path=copied/record[field];before=path.read_bytes();value=json.loads(before)
            edit(value);after=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode();assert after!=before
            path.write_bytes(after);record[field+'_sha256']=hashlib.sha256(after).hexdigest()
            (copied/'result.json').write_text(json.dumps(state))
            try:
                try:verify.verify(copied,packet_check=False)
                except (AssertionError,KeyError,ValueError,OSError,IndexError,StopIteration):rejected.append(name)
                else:raise AssertionError('altered import witness accepted: '+name)
            finally:
                path.write_bytes(before);(copied/'result.json').write_text(json.dumps(original))

        def rule_field(value,index,new):
            fields=value['rules'][0]['definition'].split();fields[index]=new
            value['rules'][0]['definition']=' '.join(fields)
        trial('full-port-condition',first['label'],'input',lambda v:rule_field(v,14,'1'))
        trial('source-syntax',first['label'],'input',lambda v:v['lists'][1].update(syntax='plain-exact-v1'))
        trial('unicode-input',first['label'],'input',lambda v:v['lists'][0]['entries'].__setitem__(1,'exact wrong.example'))
        trial('generation',first['label'],'reply',lambda v:v.update(generation=v['generation']+1))
        trial('identity-conflict',prefix+'-identity-content-conflict','reply',lambda v:v.update(result=0))
        trial('reference-index',prefix+'-missing-list-reference','reply',lambda v:v.update(error_index=1))
        trial('save-before-compile',prefix+'-save-failure','reply',lambda v:v.update(compile_error=4))
        trial('old-active-retention',prefix+'-compile-failure','reply',lambda v:v.update(active_revision=v['saved_revision']))
        trial('normalization-mode',first['label']+'-export','reply',
              lambda v:v['configuration']['lists'][0]['entries'].__setitem__(0,'descendants example.test'))
        if 'serial' not in original:
            trial('startup-error-envelope','t19-startup-save-failure','reply',lambda v:v.pop('save_error'))
            trial('startup-invented-source','t19-startup-export','reply',lambda v:v.update(configuration={}))
        path=copied/first['source'];before=path.read_bytes();after=before.replace('规则 0'.encode(),'规则 9'.encode(),1)
        assert after!=before;path.write_bytes(after)
        try:
            try:verify.verify(copied,packet_check=False)
            except (AssertionError,KeyError,ValueError,OSError,IndexError,StopIteration):rejected.append('saved-provenance')
            else:raise AssertionError('altered source metadata accepted')
        finally:path.write_bytes(before)
        state=json.loads((copied/'result.json').read_text())
        state['imports']=[r for r in state['imports'] if r['label']!=first['label']+'-reimport']
        (copied/'result.json').write_text(json.dumps(state))
        try:
            try:verify.verify(copied,packet_check=False)
            except (AssertionError,KeyError,ValueError,OSError,IndexError,StopIteration):rejected.append('missing-roundtrip')
            else:raise AssertionError('missing reimport accepted')
        finally:(copied/'result.json').write_text(json.dumps(original))
        assert verify.verify(copied,packet_check=False)['status']=='PASS'
    return dict(status='PASS',rejected=rejected,count=len(rejected))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory');parser.add_argument('--output',type=Path)
    args=parser.parse_args();value=run(args.directory);text=json.dumps(value,indent=2)+'\n'
    if args.output:args.output.write_text(text)
    print(text,end='')
