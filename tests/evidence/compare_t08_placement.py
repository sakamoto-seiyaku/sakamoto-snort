#!/usr/bin/env python3
"""Compare identical rule semantics and packet inputs across T07/T08 Pixel runs.

Retransmission counts need not coincide between separate real TCP sessions.
Each run is first independently verified including its own accounting; this
comparison joins common policy inputs and whole winners, not wall-clock totals.
"""
import argparse
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('t08_verify',Path(__file__).with_name('verify_t08_placement.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)

def collect(directory,baseline):
    directory=Path(directory)
    verified=v.verify(directory)
    run=json.loads((directory/'result.json').read_text())
    configs=v.configurations(directory,run,True)
    semantics={}; answers={}; counts={}
    for life in run['lifetimes']:
        profile=life['profile']
        cases=[case for case in run['cases'] if case['profile']==profile]
        trace=(directory/(profile+'-stop.log')).read_text()
        packets,sessions,totals=v.verify_trace(trace,profile,life['generation'],
            [c['port'] for c in cases],configs,run['uid'],baseline)
        counts[profile]=dict(totals,flow_observations=sum(p['flow'] is not None for p in packets),
                            early_drops=sum(s['early_drops'] for s in sessions.values()))
        for packet in packets:
            config=packet['config']
            rule_index={r['version']:i for i,r in enumerate(config['rules'])}
            mode=next(e['mode'] for e in run['configurations']
                      if e['profile']==profile and e['revision']==int(packet['match']['revision']))
            scenario=packet['scenario']
            context=(profile,scenario,mode)
            # Decode saved source, remove only version identity; every actual
            # condition and effective binding stays in the comparison.
            normalized=[{k:(value.hex() if isinstance(value,bytes) else value)
                         for k,value in rule.items() if k!='version'} for rule in config['rules']]
            semantics[context]=(normalized,config['bindings'],config['groups'],config['edges'])
            facts=packet['facts']
            key=context+tuple(facts[name] for name in ('uid','family','protocol','direction','network','interface',
                'src','dst','sport','dport','ct','flowdir'))
            result=packet['expected']
            answer=(rule_index.get(result['rule_id'],-1),result.get('winner_rank',0),
                    result.get('mode',0),result['action'],result['actual_action'])
            if key in answers:assert answers[key]==answer
            answers[key]=answer
    return semantics,answers,counts,verified

def compare(before,after):
    old_rules,old,old_counts,old_verified=collect(before,True)
    new_rules,new,new_counts,new_verified=collect(after,False)
    assert old_rules==new_rules, 'same competing complete rules and bindings'
    common=set(old)&set(new)
    assert common and {key[:3] for key in common}==set(old_rules), 'all scenario/mode/profile inputs compared'
    assert all(old[key]==new[key] for key in common), 'whole logical winner/mode/action changed'
    for profile in ('root','vpn'):
        assert old_counts[profile]['flow_observations']==old_counts[profile]['packets']
        assert old_counts[profile]['early_drops']==0
        assert new_counts[profile]['early_drops']>0
        assert new_counts[profile]['flow_observations']==new_counts[profile]['packets']-new_counts[profile]['early_drops']
    return dict(status='PASS',common_input_classes=len(common),scenario_modes=len(old_rules),
        baseline=old_counts,optimized=new_counts,baseline_source=old_verified['source_sha256'],
        optimized_source=new_verified['source_sha256'],verifier_sha256=v.digest(__file__))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('before');parser.add_argument('after');parser.add_argument('--output')
    args=parser.parse_args();result=compare(args.before,args.after)
    if args.output:Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
