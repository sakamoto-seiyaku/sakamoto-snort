#!/usr/bin/env python3
"""Exercise the real APK entrypoint's crypto identity admission, before packaging."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
def run(stage):
    manifest=(stage/'product-stage.properties').read_text()
    results=[]
    with tempfile.TemporaryDirectory(prefix='sakamoto-t15-stage-') as temp:
        root=Path(temp);candidate=root/'stage';candidate.mkdir()
        (candidate/'.sakamoto-android-product-stage').write_text('sakamoto-android-product-stage/v1\n')
        for key in ('quicCrypto','quicVersion'):
            for mutation in ('missing','wrong','duplicate'):
                lines=manifest.splitlines()
                assert sum(line.startswith(key+'=') for line in lines)==1
                if mutation=='missing':lines=[line for line in lines if not line.startswith(key+'=')]
                elif mutation=='wrong':lines=[key+'=wrong' if line.startswith(key+'=') else line for line in lines]
                else:lines.append(key+'=wrong')
                (candidate/'product-stage.properties').write_text('\n'.join(lines)+'\n')
                env=dict(os.environ,SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR=str(candidate),
                    SAKAMOTO_ANDROID_VERSION_STATE_FILE=str(root/'version-code'),
                    SAKAMOTO_ANDROID_APK_OUTPUT_DIR=str(root/'apk'))
                result=subprocess.run(['bash',str(ROOT/'app/android-runtime/scripts/build-debug-apk.sh'),'--apk-only'],
                    env=env,text=True,capture_output=True,timeout=30)
                # A later failure for omitted native payload is not proof that
                # the required crypto identity was rejected at admission.
                rejected=result.returncode!=0 and key in result.stderr
                results.append(dict(key=key,mutation=mutation,code=result.returncode,
                                    rejected=rejected,stderr=result.stderr))
    return dict(status='PASS' if all(r['rejected'] for r in results) else 'FAIL',cases=results)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    result=run(args.stage);args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(result['status'],sum(r['rejected'] for r in result['cases']),'of',len(result['cases']),'crypto admission mutations rejected')
    raise SystemExit(result['status']!='PASS')
