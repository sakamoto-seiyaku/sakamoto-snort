#!/usr/bin/env python3
"""Tamper one phone query at a time; the packet/query oracle must reject it."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('pixel_oracle',ROOT/'tests/evidence/verify_t25_pixel.py')
oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)

def main(directory):
    directory=Path(directory).resolve();oracle.verify(directory)
    def row(query,ident):
        return next(value for value in query['consumer']['persistent']['protocol_windows'].values()
            if value['layer']=='l7' and value['protocol_id']==ident)
    def remove_label(query,ident):
        rows=query['consumer']['persistent']['protocol_windows']
        key=next(key for key,value in rows.items() if value['layer']=='l7' and value['protocol_id']==ident)
        del rows[key]
    variants=[
        ('invent_tls_at_first','root-tcp-first-observation.json',lambda q:
            next(r for r in q['consumer']['overview']['records'] if r and 46100 in r['ports'])['attribution'][0].__setitem__('protocol_set',6)),
        ('remove_tls_window','root-tcp-added-observation.json',lambda q:remove_label(q,1003)),
        ('change_share','root-udp-added-observation.json',lambda q:row(q,1006)['share']['packets'].__setitem__(0,0.01)),
        ('cross_scope_denominator','vpn-tcp-added-observation.json',lambda q:row(q,1003)['denominator']['packets'].__setitem__(0,99999)),
        ('hide_quic','vpn-udp-added-observation.json',lambda q:remove_label(q,1004)),
        ('backfill_legacy','root-tcp-added-observation.json',lambda q:q['consumer']['persistent']['legacy_protocol_unavailable']['packets'].__setitem__(0,0)),
    ]
    results={}
    for name,file,mutate in variants:
        with tempfile.TemporaryDirectory(prefix='t25-phone-mutant-') as tmp:
            target=Path(tmp)
            for original in directory.iterdir():
                if original.is_file():(target/original.name).symlink_to(original)
            changed=json.loads((directory/file).read_text());mutate(changed)
            (target/file).unlink()
            (target/file).write_text(json.dumps(changed))
            try:oracle.verify(target)
            except (AssertionError,KeyError,StopIteration):results[name]='REJECTED'
            else:raise AssertionError('oracle accepted '+name)
    return dict(status='PASS',variants=results)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();result=main(a.directory)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
