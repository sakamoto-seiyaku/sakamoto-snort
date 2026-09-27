#!/usr/bin/env python3
"""R2/R3/R4 packet and endpoint facts through the maintained protocol windows."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
oracle=module('t25_windows',ROOT/'tests/evidence/verify_t25_protocol_windows.py')
SCOPE={
    'r2':('verify_r2_mail.py',{1007,1008,1009,1010}),
    'r3':('verify_r3_tunnels.py',{1011,1012,1013,1014,1015}),
    'r4':('verify_r4_realtime.py',{1016,1017,1018,1019,1020}),
}

def verify(directory,scope):
    directory=Path(directory);file,required=SCOPE[scope]
    source=module('supplemental',ROOT/'tests/evidence'/file)
    run=json.loads((directory/'result.json').read_text())
    assert run['status']=='RAW_COMPLETE' and run['observation'] is True
    assert run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    build=source.base.build_reader.verify_product_build(run['build'])
    assert build['source_sha256']==run['source_sha256']
    assert oracle.digest(directory/'runner.py')==run['runner_sha256']
    assert oracle.digest(directory/'observation-helper.py')==run['observation_helper_sha256']
    assert oracle.digest(directory/'socket-peer.py')==run['peer_sha256']
    assert oracle.digest(directory/'fixtures.json')==run['fixtures_sha256']
    configs=source.t.configs(directory,run,False)
    trace=(directory/'first-vpp.log').read_text()
    fixtures=json.loads((directory/'fixtures.json').read_text())
    observe=source.observe if scope=='r2' else source.oracle(run,fixtures,'127.0.0.2')
    ports={case['port'] for case in run['cases']}
    if scope=='r2':
        # The controlled FTP-data endpoint opens its second socket at
        # source+1000; the observation query includes that Flow too.
        ports.add(next(case['port'] for case in run['cases'] if case['application']=='data')+1000)
    packets,sessions,trace_summary,_=source.t.verify_trace(trace,'root',run['generation'],
        sorted(ports),configs,12001,observe)
    endpoint=[json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    if scope=='r2':source.endpoints(directory,run,False,'root',endpoint,packets)
    else:source.endpoints(directory,run,False,'root',endpoint,packets,fixtures)
    labels=oracle.catalog();snapshots={}
    for case in run['cases']:
        source.flow_query(directory,case,packets)
        snapshot=json.loads((directory/case['observation']).read_text())
        expected=oracle.expected_for_snapshot(snapshot,packets)
        count=oracle.verify_snapshot(snapshot,expected,labels)
        snapshots[case['label']]=dict(packets=count,protocol_rows=len(snapshot['consumer']['persistent']['protocol_windows']))
    final=json.loads((directory/'final-observation.json').read_text())['consumer']['persistent']
    found={row['protocol_id'] for row in final['protocol_windows'].values() if row['layer']=='l7'}
    assert required<=found,('new catalog labels missing from Rust windows',sorted(required-found))
    assert not final['protocol_query_truncated']
    return dict(status='VALID',scope=scope,source_sha256=run['source_sha256'],
        runner_sha256=run['runner_sha256'],verifier_sha256=oracle.digest(__file__),
        trace_sha256=oracle.digest(directory/'first-vpp.log'),
        total_packets=trace_summary['packets'],actual_drops=trace_summary['actual_drops'],
        published_changes=trace_summary['published_changes'],
        stable_labels=sorted(required),snapshots=snapshots)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('scope',choices=sorted(SCOPE))
    p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();result=verify(a.directory,a.scope)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
