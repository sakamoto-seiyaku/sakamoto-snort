#!/usr/bin/env python3
"""Build both explicit E01 experiment artifacts and always restore Product source."""
import argparse,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--artifact',type=Path,required=True);p.add_argument('--host-stage',type=Path,required=True);p.add_argument('--android-stage',type=Path,required=True);a=p.parse_args()
out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
def run(*arguments,env=None):subprocess.run([sys.executable,*map(str,arguments)],cwd=ROOT,env=env,check=True)
overlay=ROOT/'tests/evidence/e01_overlay.py';state=out/'overlay'
run(overlay,'apply','--state',state)
try:
    run(ROOT/'tests/evidence/build_s230_linux.py','--output',out/'linux-build','--artifact',a.artifact.resolve(),'--stage',a.host_stage.resolve())
    run(ROOT/'tests/evidence/product_chain.py','build',out/'pixel-build',env=dict(os.environ,SAKAMOTO_VPP_STAGE_DIR=str(a.android_stage.resolve())))
finally:
    run(overlay,'restore','--state',state)
linux=json.loads((out/'linux-build/build.json').read_text());pixel=json.loads((out/'pixel-build/build.json').read_text());assert linux['source_sha256']==pixel['source_sha256']
print(json.dumps({'source_sha256':linux['source_sha256'],'product_source_restored':True}))
