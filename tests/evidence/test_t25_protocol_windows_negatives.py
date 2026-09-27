#!/usr/bin/env python3
"""Check that the independent T25 oracle rejects plausible wrong summaries."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('oracle',ROOT/'tests/evidence/verify_t25_protocol_windows.py')
oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)

def main(directory):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text())
    configs=oracle.t12.configs(directory,run,False)
    packets,*_=oracle.t12.verify_trace((directory/'first-vpp.log').read_text(),'root',run['generation'],
        sorted({case['port'] for case in run['cases']}),configs,12001)
    snapshot=json.loads((directory/'udp-added-observation.json').read_text())
    expected=oracle.expected_for_snapshot(snapshot,packets)
    labels=oracle.catalog()
    oracle.verify_snapshot(snapshot,expected,labels)
    def one(layer,ident,value):
        return next(row for row in value['consumer']['persistent']['protocol_windows'].values()
            if row['layer']==layer and row['protocol_id']==ident)
    variants={}
    for name,mutate in [
        ('new_label_backfills_old_bytes',lambda value:one('l7',1004,value)['counts']['bytes'].__setitem__(0,99999)),
        ('double_count_app',lambda value:next(iter(value['consumer']['persistent']['application_windows'].values()))['counts']['packets'].__setitem__(0,99999)),
        ('wrong_direction_denominator',lambda value:one('l7',1006,value)['denominator']['packets'].__setitem__(1,99999)),
        ('exclusive_normalization',lambda value:one('l7',1006,value)['share']['packets'].__setitem__(0,0.01)),
        ('invented_label',lambda value:one('l7',1006,value).__setitem__('protocol_id',1005)),
        ('hidden_unavailable',lambda value:value['consumer']['persistent']['l7_unknown']['packets'].__setitem__(0,0)),
    ]:
        value=copy.deepcopy(snapshot);mutate(value)
        try:oracle.verify_snapshot(value,expected,labels)
        except (AssertionError,KeyError):variants[name]='REJECTED'
        else:raise AssertionError('oracle accepted '+name)
    return dict(status='PASS',variants=variants)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();result=main(a.directory)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
