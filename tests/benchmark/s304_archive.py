#!/usr/bin/env python3
"""Create or independently verify the portable S304 raw Product evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile

import pixel_quick as quick
import s304_summary

ROOT = Path(__file__).resolve().parents[2]
CAMPAIGNS = (
    's304-vpn-topology-20261022-b',
    's304-vpn-udp-topology-20261022',
    's304-vpn-udp-paced-20261022-b',
)
FAILED = ('s304-vpn-topology-20261022', 's304-vpn-udp-paced-20261022')
DIRECTORIES = tuple('build-output/' + name for name in (*CAMPAIGNS, *FAILED)) + (
    'build-output/s304-source-snapshots',
)
FILES = (
    'build-output/s304-prepared/manifest.json',
    'build-output/s304-prepared/socket-load-arm64',
    'build-output/s304-prepared/socket-load-host',
    'build-output/s304-udp-prepared/manifest.json',
    'build-output/s304-udp-paced-prepared/manifest.json',
    'build-output/s304-udp-paced-prepared-b/manifest.json',
    'build-output/s304-summary-20261022/summary.json',
    'build-output/vpn-diagnosis-default-20261021/default/apk/sakamoto-runtime-debug.apk',
    'build-output/s303-apk-a/sakamoto-runtime-debug.apk',
    'build-output/s300-apk-g/sakamoto-runtime-debug.apk',
    'build-output/vpn-diagnosis-default-20261021/default/build.json',
    'build-output/vpn-diagnosis-default-20261021/default/stage/product-stage.properties',
    'build-output/android-product-stage-s302-e/product-stage.properties',
    'build-output/vpn-diagnosis-default-20261021/cache-warm-proof/result.json',
    'build-output/s303-native-cache-pinned/result.json',
    'build-output/s303-apk-cache-check/result.json',
)
INDEX_NAME = 's304-vpn-product-20261022-index.json'


def paths():
    found = set(FILES)
    for directory in DIRECTORIES:
        found.update(str(path.relative_to(ROOT)) for path in (ROOT / directory).rglob('*') if path.is_file())
    for name in found:
        if not (ROOT / name).is_file():
            raise RuntimeError('missing S304 raw input: ' + name)
    return sorted(found)


def create(output):
    output.mkdir(parents=True, exist_ok=True)
    if (output / INDEX_NAME).exists():
        raise RuntimeError('existing evidence index must not be replaced')
    temp = output / 's304-vpn-product-20261022-pending.zip'
    if temp.exists():
        raise RuntimeError('pending archive already exists')
    listing = []
    try:
        with zipfile.ZipFile(temp, 'w') as archive:
            for name in paths():
                data = (ROOT / name).read_bytes()
                listing.append(dict(path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_STORED if name.endswith('.apk') else zipfile.ZIP_DEFLATED
                archive.writestr(info, data, compresslevel=6)
        sha = quick.digest(temp)
        final = output / ('s304-vpn-product-20261022-' + sha[:16] + '.zip')
        if final.exists():
            raise RuntimeError('content-addressed archive already exists')
        temp.rename(final)
        index = dict(schema='s304-portable-raw-evidence/v1', archive=final.name,
                     archive_sha256=sha, archive_bytes=final.stat().st_size,
                     source_checkout=str(ROOT), files=listing)
        (output / INDEX_NAME).write_text(json.dumps(index, indent=2) + '\n')
        print(json.dumps(dict(archive=str(final), sha256=sha, bytes=index['archive_bytes'],
                              files=len(listing)), indent=2))
    finally:
        temp.unlink(missing_ok=True)


def comparable(cohort):
    return dict(suite=cohort['suite'], collector_sha256=cohort['collector_sha256'],
                helper_sha256=cohort['helper_sha256'],
                rows=[{key: value for key, value in row.items() if key != 'raw_result'}
                      for row in cohort['rows']],
                n2_descriptive_means=cohort['n2_descriptive_means'])


def verify(index_path):
    index = json.loads(index_path.read_text())
    assert index['schema'] == 's304-portable-raw-evidence/v1'
    archive_path = index_path.parent / index['archive']
    assert quick.digest(archive_path) == index['archive_sha256']
    assert archive_path.stat().st_size == index['archive_bytes']
    expected = {row['path']: row for row in index['files']}
    with zipfile.ZipFile(archive_path) as archive:
        assert set(archive.namelist()) == set(expected)
        with tempfile.TemporaryDirectory(prefix='s304-verify-') as temporary:
            root = Path(temporary)
            for name, row in expected.items():
                data = archive.read(name)
                assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            snapshots = {quick.digest(path): path for path in
                         (root / 'build-output/s304-source-snapshots').glob('*-pixel_quick.py')}
            saved = json.loads((root / 'build-output/s304-summary-20261022/summary.json').read_text())
            assert saved['status'] == 'VERIFIED_RAW' and len(saved['cohorts']) == 3
            for campaign, claimed in zip(CAMPAIGNS, saved['cohorts']):
                actual = s304_summary.check_campaign(root / 'build-output' / campaign, snapshots, root)
                assert comparable(actual) == comparable(claimed), campaign
    print(json.dumps(dict(status='VERIFIED', archive=index['archive'],
                          sha256=index['archive_sha256'], files=len(expected),
                          Product_windows=18), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('create').add_argument('--output', type=Path, required=True)
    sub.add_parser('verify').add_argument('--index', type=Path, required=True)
    args = parser.parse_args()
    if args.operation == 'create':
        create(args.output)
    else:
        verify(args.index)


if __name__ == '__main__':
    main()
