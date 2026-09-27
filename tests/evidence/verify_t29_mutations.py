#!/usr/bin/env python3
"""Reject semantic corruption of T29 packet, policy, UI and stress witnesses."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser()
for name in ('linux-run','linux-build','pixel-run','pixel-build','stress-run','stress-build'):
    p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
rejected=[]
def check(name,original,verifier,mutate):
    with tempfile.TemporaryDirectory(prefix='t29-mutation-') as tmp:
        work=Path(tmp)/'run'
        # The Linux runtime leaves owner-only config/SQLite files; independent
        # oracles consume the copied responses and packet captures instead.
        shutil.copytree(original.resolve(),work,ignore=shutil.ignore_patterns('configuration','observation'))
        selected_build=(a.linux_build if verifier.endswith('linux_combined.py') else
                        a.stress_build if verifier.endswith('pixel_stress.py') else a.pixel_build)
        command=[sys.executable,str(ROOT/'tests/evidence'/verifier),'--run',str(work),
                 '--build',str(selected_build.resolve()),
                 '--output',str(Path(tmp)/'verdict.json')]
        if verifier.endswith('pixel_combined.py'):command.append('--require-ui')
        baseline=command.copy();baseline[baseline.index('--output')+1]=str(Path(tmp)/'baseline.json')
        clean=subprocess.run(baseline,capture_output=True,text=True)
        assert clean.returncode == 0,(name,'copied baseline failed',clean.stdout,clean.stderr)
        mutate(work)
        proc=subprocess.run(command,capture_output=True,text=True)
        assert proc.returncode != 0,(name,proc.stdout,proc.stderr)
        rejected.append(dict(name=name,exit_code=proc.returncode,
                             failure_sha256=hashlib.sha256(proc.stderr.encode()).hexdigest()))
def edit_flow(run,name,port):
    path=run/name;lines=path.read_text().splitlines(keepends=True);found=False
    for i,line in enumerate(lines):
        if line.startswith('flow.entry ') and str(port) in line and 'decision=2' in line:
            lines[i]=line.replace('decision=2','decision=1',1);found=True;break
    assert found,name
    path.write_text(''.join(lines))
def lose_quic_echo(run):
    path=run/'quic-endpoint.jsonl';lines=path.read_text().splitlines(keepends=True)
    index=next(i for i,line in enumerate(lines) if '"kind": "echo"' in line)
    lines.pop(index);path.write_text(''.join(lines))
def damage_dashboard(run):
    path=run/'vpn-combined-selected-dashboard.json';value=json.loads(path.read_text())
    value['vpp']['policy_active_revision']='0';path.write_text(json.dumps(value)+'\n')
def damage_pixel_explanation(run):
    path=run/'root-combined-selected-dashboard.json';value=json.loads(path.read_text())
    row=next(v for v in value['consumer']['persistent']['rule_windows'].values()
             if v['attribution']['actual_action']==2)
    row['interpretation']['actual_action']=1
    path.write_text(json.dumps(value)+'\n')
def damage_linux_explanation(run):
    path=run/'final-observation.json';value=json.loads(path.read_text())
    row=next(v for v in value['consumer']['persistent']['rule_windows'].values()
             if v['attribution']['actual_action']==2)
    row['interpretation']['actual_action']=1
    path.write_text(json.dumps(value)+'\n')
def damage_stress(run):
    path=run/'result.json';value=json.loads(path.read_text())
    value['lifetimes'][1]['full_tail_packets'][1]+=1
    path.write_text(json.dumps(value)+'\n')
def inject_cleanup_error(run):
    path=run/'result.json';value=json.loads(path.read_text())
    value['cleanup_error']='simulated stop failure'
    path.write_text(json.dumps(value)+'\n')
def inject_config_cleanup_error(run):
    path=run/'result.json';value=json.loads(path.read_text())
    value['cleanup_config_error']='simulated saved rule cleanup failure'
    path.write_text(json.dumps(value)+'\n')
check('linux_drop_relabel',a.linux_run,'verify_t29_linux_combined.py',
      lambda run:edit_flow(run,'rtp-blocked-flow.txt',45302))
check('linux_missing_quic_echo',a.linux_run,'verify_t29_linux_combined.py',lose_quic_echo)
check('linux_explanation_action',a.linux_run,'verify_t29_linux_combined.py',damage_linux_explanation)
check('pixel_drop_relabel',a.pixel_run,'verify_t29_pixel_combined.py',
      lambda run:edit_flow(run,'vpn-rtp-blocked-flow.txt',46410))
check('pixel_stale_dashboard',a.pixel_run,'verify_t29_pixel_combined.py',damage_dashboard)
check('pixel_explanation_action',a.pixel_run,'verify_t29_pixel_combined.py',damage_pixel_explanation)
check('pixel_cleanup_error',a.pixel_run,'verify_t29_pixel_combined.py',inject_cleanup_error)
check('pixel_config_cleanup_error',a.pixel_run,'verify_t29_pixel_combined.py',inject_config_cleanup_error)
check('stress_invented_return',a.stress_run,'verify_t29_pixel_stress.py',damage_stress)
check('stress_cleanup_error',a.stress_run,'verify_t29_pixel_stress.py',inject_cleanup_error)
answer=dict(status='VALID',mutations_rejected=rejected,
            verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
a.output.write_text(json.dumps(answer,indent=2)+'\n')
print(json.dumps({'status':answer['status'],'mutations_rejected':[x['name'] for x in rejected]},indent=2))
