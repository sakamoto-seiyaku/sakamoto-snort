#!/usr/bin/env python3
"""Compare full source semantics and common real packet inputs, T08 vs T09."""
import argparse
import json
from pathlib import Path
import verify_t08_placement as v
import verify_t09_index as indexed

def collect(directory):
    directory=Path(directory);verification=v.verify(directory)
    run=json.loads((directory/'result.json').read_text());pixel='serial' in run
    configs=v.configurations(directory,run,pixel)
    answers={};semantics={};counts={}
    lifetimes=run['lifetimes'] if pixel else [dict(profile='root',generation=run['generation'])]
    for life in lifetimes:
        profile=life['profile'];trace=(directory/(profile+'-stop.log' if pixel else 'first-vpp.log')).read_text()
        ports=[c['port'] for c in run['cases'] if c['profile']==profile] if pixel else [43100,43101,43102,43200,43201,43202,43300]
        packets,_,totals=v.verify_trace(trace,profile,life['generation'],ports,configs,run['uid'] if pixel else 12001)
        counts[profile]=totals
        for packet in packets:
            config=packet['config'];facts=packet['facts'];result=packet['expected']
            entry=next(e for e in run['configurations'] if e.get('profile','root')==profile and e['revision']==int(packet['match']['revision']))
            context=(profile,packet['scenario'],entry['mode'],entry['protocol'])
            normalized=[{k:(value.hex() if isinstance(value,bytes) else value) for k,value in rule.items() if k!='version'} for rule in config['rules']]
            semantics[context]=(normalized,config['bindings'],config['groups'],config['edges'])
            key=context+tuple(facts[name] for name in ('uid','family','protocol','direction','network','interface','src','dst','sport','dport','ct','flowdir'))
            identities={r['version']:i for i,r in enumerate(config['rules'])}
            answer=(identities.get(result['rule_id'],-1),result.get('winner_rank',0),result.get('priority',0),result.get('order',0),result.get('mode',0),result['action'],result['actual_action'],packet['flow'] is not None)
            if key in answers:assert answers[key]==answer
            answers[key]=answer
    return semantics,answers,counts,verification

def compare(before,after):
    old_rules,old,old_counts,old_verified=collect(before)
    new_rules,new,new_counts,new_verified=collect(after)
    assert old_verified['source_sha256']=='43bae86c42a14f1c6370338cd3896a5dc906f1b922b5a3de7440adbc37872133', 'pinned ordered T08 baseline'
    index_evidence=indexed.verify(after)
    assert old_rules==new_rules, 'same complete source conditions and bindings'
    common=set(old)&set(new)
    assert common and {key[:4] for key in common}==set(old_rules), 'every scenario/mode/protocol/profile compared'
    assert all(old[key]==new[key] for key in common), 'full winner/action/mode/Flow behavior changed'
    return dict(status='PASS',common_input_classes=len(common),contexts=len(old_rules),ordered=old_counts,indexed=new_counts,
        ordered_source=old_verified['source_sha256'],indexed_source=new_verified['source_sha256'],index_evidence=index_evidence,
        verifier_sha256=v.digest(__file__))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('before');parser.add_argument('after');parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=compare(args.before,args.after);text=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text)
    print(text)
