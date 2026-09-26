#!/usr/bin/env python3
"""Mandatory isolated launcher for E01 Linux packet experiments."""
import argparse,hashlib,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--stage',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('extra',nargs=argparse.REMAINDER);a=p.parse_args()
out=a.output.resolve();assert out.is_relative_to(ROOT/'build-output') and not out.exists()
name='e01-'+hashlib.sha256(str(out).encode()).hexdigest()[:12]
args=['docker','run','--rm','--name',name,'--network','none','--cap-add','NET_ADMIN','--cap-add','NET_RAW',
    '-v',str(ROOT)+':'+str(ROOT),'-w',str(ROOT),'-e','E01_HOST_NETNS='+os.readlink('/proc/self/ns/net'),
    '-e','GIT_CONFIG_COUNT=1','-e','GIT_CONFIG_KEY_0=safe.directory','-e','GIT_CONFIG_VALUE_0='+str(ROOT),
    'sakamoto-vpp-nfq-poc:dev','python3','tests/device/e01-linux-pipeline.py','--build',str(a.build.resolve()),
    '--stage',str(a.stage.resolve()),'--output',str(out),*(a.extra[1:] if a.extra[:1]==['--'] else a.extra)]
result=subprocess.run(args)
# Root-created 0600 fixture files must be readable to the owner for verification.
# Ownership only changes; data and permission-mode evidence remain intact.
if out.is_dir():
    subprocess.run(['docker','run','--rm','--network','none','-v',str(out)+':/evidence',
        'sakamoto-vpp-nfq-poc:dev','chown','-R',f'{os.getuid()}:{os.getgid()}','/evidence'],check=True)
raise SystemExit(result.returncode)
