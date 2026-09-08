#!/usr/bin/env python3
"""S231 source/artifact, independent link/NFQ matrix, and native cleanup gate."""
import argparse
import hashlib
import importlib.util
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


oracle=module('fragments','tests/device/s231-fragment-verify.py')
chain=module('chain','tests/evidence/product_chain.py')
digest,rows=chain.digest,oracle.rows


def props(path):
    return dict(l.split('=',1) for l in path.read_text().splitlines() if '=' in l and not l.startswith('#'))


def verify(out,build_file,platform):
    out,build_file=Path(out),Path(build_file)
    errors,summaries=[],[]
    build={}
    try:
        result=json.loads((out/'result.json').read_text());build=json.loads(build_file.read_text())
        assert result['status']=='RAW_COMPLETE','collector incomplete'
        assert build['files']==chain.source_files(),'current Product source changed'
        assert hashlib.sha256(chain.encode(build['files'])).hexdigest()==build['source_sha256']
        assert digest(build_file.parent/'dirty.diff')==build['dirty_diff_sha256']
        for n,h in build['files'].items():
            if h is not None:assert digest(build_file.parent/'source'/n)==h,'source snapshot '+n
        assert build['started_ns']<build['completed_ns']<result['started_ns']<result['completed_ns'],'fresh build/run'
        pixel=platform=='pixel'
        if pixel:
            assert result['source']=='NFQ_CAPTURED' and result['profile']=='root' and result['serial']=='28201JEGR0XPAJ'
            assert digest(build['apk'])==build['apk_sha256']==result['apk_sha256']==(out/'installed-apk-sha256.txt').read_text().split()[0]
            installed={Path(l.split()[1]).name:l.split()[0] for l in (out/'installed-native-sha256.txt').read_text().splitlines()}
            assert installed==build['native_sha256']==result['native_sha256']
            with zipfile.ZipFile(build['apk']) as z:
                assert {Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}==installed
            assert result['wifi_before']==result['wifi_after']==(out/'final-wifi.txt').read_text().strip()
            assert not re.search(r'libvpp_runtime.so|s231-net|s231-echo',(out/'final-processes.txt').read_text()),'device process residue'
            assert int(result['generations'][0])>int(props(out/'before.properties')['generation'])
            stage=props(build_file.parent/'stage/product-stage.properties')
            helpers={'s231-net':ROOT/'build-output/s231-fragments/pixel-net','s231-policy':ROOT/'build-output/s210-capacity/policy-client','s231-echo':ROOT/'build-output/s207-owner/echo'}
            for name,path in helpers.items():assert result['helper_sha256'][name]==digest(path),'helper '+name
            for filename in ('rules-after.txt','routes-after.txt'):
                text=(out/filename).read_text()
                assert '198.18.231' not in text and 'fd20:6231' not in text,'temporary route/rule residue'
        else:
            artifact=Path(build['artifact']);assert build['host_evidence'] is False
            for n,h in build['artifact_hashes'].items():assert digest(artifact/n)==h,'artifact '+n
            for n,h in build['control_hashes'].items():assert digest(build_file.parent/n)==h,'control '+n
            for n,h in build['build_inputs'].items():assert digest(build_file.parent/'source'/n)==h==digest(ROOT/n),'build input '+n
            assert digest(artifact/'product-vpp-artifact.properties')==result['artifact_manifest_sha256']
            assert 'SAKAMOTO_PRODUCT_HOST_EVIDENCE:BOOL=OFF' in (artifact/'plugin-build/CMakeCache.txt').read_text()
            uid_map=(out/'uid-map.txt').read_text().split()
            assert uid_map[0]=='0' and uid_map[1]!='0' and uid_map[2]=='1'
            for n in ('linux-net','linux-echo'):assert result['helper_sha256'][n]==digest(ROOT/'build-output/s231-fragments'/n)
        assert 's231rx' not in (out/'links-after.txt').read_text() and 's231tx' not in (out/'links-after.txt').read_text()
        assert len(result['cases'])==4 and len({str(c['generation']) for c in result['cases']})==4
        assert {(c['family'],c['hook']) for c in result['cases']}=={(f,h) for f in (4,6) for h in ('INPUT','OUTPUT')}
        for index,case in enumerate(result['cases']):
            label=f'g{index}'
            def path(name):return out/(label+'-'+name) if pixel else out/label/name
            def read(name):return path(name).read_text()
            assert json.loads(read('case.json'))==case
            endpoint=[l.split('nonce=',1)[1] for l in read('endpoint.log').splitlines() if 'nonce=' in l]
            sends={f['nonce']:read(f'raw-{f["reverse"]}.txt') for f in case['fragments']}
            for text in sends.values():
                assert all(r['uid']==r['euid']==str(case['uid']) for r in rows(text,'send ')),'real sender UID'
            if pixel:
                running=props(out/(label+'.properties'))
                assert running['generation']==str(case['generation']) and running['artifact']==stage['artifactId'] and running['version']==stage['vppRevision']
                assert digest(path('wire.pcap'))==read('pcap-sha256.txt').strip(),'binary PCAP transfer'
            summaries.append(oracle.verify_case(case,read('vpp.log'),read('runtime.txt'),path('wire.pcap').read_bytes(),read('capture.log'),sends,endpoint))
            hook_text=read('fragment-hooks.txt')
            assert not any(l.startswith('-A PREROUTING') and ('NFQUEUE' in l or 'SAKAMOTO' in l) for l in hook_text.splitlines()),'earlier Product hook'
            assert 's231rx' in hook_text and 'NFQUEUE' in hook_text
            initial=rows(read('initial.txt'),'root.lane ')
            assert len(initial)==4 and len({l['fd'] for l in initial})==4 and all(l['ready']=='1' for l in initial)
            assert 'root.stop=ok' in read('close.txt')
            closed=read('closed.txt');lanes=rows(closed,'root.lane ')
            assert len(lanes)==4 and all(l['fd']=='-1' and l['ready']==l['pending']=='0' for l in lanes)
            completion=rows(closed,'completion.status ')[0]
            assert all(completion[k]=='0' for k in ('pending','frames','buffers','obligations','duplicate','stale'))
            primary=rows(closed,'primary.status ')[0]
            assert primary['pending_returns']==primary['handoff_debt']==primary['flows']=='0' and primary['credit0']==primary['credit1']=='32'
            assert all(p['entries']=='0' for p in rows(closed,'flow.pool '))
            snapshot=rows(closed,'policy.snapshot ')[0]
            assert snapshot['readers0']==snapshot['readers1']==snapshot['packet_lock_acquisitions']=='0'
            before,after=read('fds-before.txt'),read('fds-closed.txt')
            for lane in initial:
                line=next(l for l in before.splitlines() if (' '+lane['fd']+' -> ' in l if pixel else l.startswith(lane['fd']+' ')))
                inode=re.search(r'socket:\[\d+\]',line)
                assert inode and inode[0] not in after,'actual NFQUEUE socket residue'
            if pixel:
                assert props(path('stopped.properties'))['state']=='stopped'
                assert 'productRootNfqueueResidueClean=true' in read('cleanup.properties')
                assert not read('nfqueue-after.txt').strip() and 'libvpp_runtime.so' not in read('process-after.txt')
                assert 'SAKAMOTO' not in read('hooks-after.txt')
            else:
                assert all(v==0 for v in json.loads(read('queues-free.json')).values())
                assert json.loads(read('stop.json'))['process_absent'] is True
                assert not any(l.startswith('-A ') for l in read('hooks-after.txt').splitlines())
    except (AssertionError,OSError,KeyError,ValueError,IndexError,StopIteration) as error:
        errors.append(str(error) or repr(error))
    return dict(status='HOLD' if errors else 'PASS',errors=errors,source_sha256=build.get('source_sha256'),
                cases=summaries,packets=sum(c['packets'] for c in summaries),
                verifier_sha256=digest(__file__),semantic_verifier_sha256=digest(ROOT/'tests/device/s231-fragment-verify.py'))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--build',type=Path,required=True)
    p.add_argument('--platform',choices=['linux','pixel'],required=True);p.add_argument('--output',type=Path)
    a=p.parse_args();r=verify(a.run,a.build,a.platform);text=json.dumps(r,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    print(text);raise SystemExit(r['status']!='PASS')
