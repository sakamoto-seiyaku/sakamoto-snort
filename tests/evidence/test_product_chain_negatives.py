#!/usr/bin/env python3
"""Requested S244 adversarial evidence inputs; never operate a device."""
import argparse,importlib.util,json,shutil
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('chain',HERE/'product_chain.py');chain=importlib.util.module_from_spec(spec);spec.loader.exec_module(chain)
p=argparse.ArgumentParser();p.add_argument('request');p.add_argument('--output',required=True);args=p.parse_args()
q=json.loads(Path(args.request).read_text());base=Path(q['run_dir']);out=Path(args.output);out.mkdir(parents=True,exist_ok=False)
positive=chain.verify(args.request);assert positive['status']=='PASS',positive
results=[]
def case(name,mutate,expected,source=base):
 dest=out/name;shutil.copytree(source,dest);mutate(dest);r=chain.verify(args.request,dest)
 assert r['status']=='HOLD' and any(expected in e for e in r['errors']),(name,r)
 results.append({'case':name,'status':'REJECTED','required_rejection':expected,'errors':r['errors']})
def change_result(path,key,value):
 f=path/'result.json';d=json.loads(f.read_text());d[key]=value;chain.write(f,d)
case('old-artifact-hash',lambda d:change_result(d,'apk_sha256','0'*64),'stale/wrong APK')
def old_run(d):
 # This older run used the same APK, so a hash-only check would miss it.
 shutil.copy2(base/'installed-apk-sha256.txt',d/'installed-apk-sha256.txt')
case('old-run-directory',old_run,'stale run/nonce',base.parent/'pixel')
def missing_node(d):
 f=d/'before-stop-vpp-stdout.log';f.write_text('\n'.join(l for l in f.read_text().splitlines() if 'event=admit ' not in l)+'\n')
case('missing-real-node',missing_node,'one native node/settlement path')
def poc(d):
 for n in ['first.properties','restart.properties']:
  f=d/n;f.write_text(f.read_text().replace('root-nfqueue-udp4-owner-local','poc-handcrafted-direct-bridge'))
case('poc-readiness',poc,'POC/wrong readiness')
def injected(d):
 change_result(d,'source','GRAPH_INJECTED')
 for f in d.glob('*-vpp-stdout.log'):f.write_text(f.read_text().replace('source=NFQ_CAPTURED','source=GRAPH_INJECTED'))
case('graph-injection-as-capture',injected,'claim source mismatch')
def stale_node_generation(d):
 r=json.loads((d/'result.json').read_text());f=d/'before-stop-vpp-stdout.log';f.write_text(f.read_text().replace('generation='+r['generation'],'generation=1'))
case('old-node-generation',stale_node_generation,'node trace belongs to another generation')
case('broader-owner-claim',lambda d:change_result(d,'scope','all-owners'),'owner scope overstated')
chain.write(out/'results.json',results)
print(json.dumps({'positive':'PASS','negative_cases':len(results),'all_rejected':True},indent=2))
