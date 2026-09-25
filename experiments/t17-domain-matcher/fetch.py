#!/usr/bin/env python3
"""Fetch immutable public experiment inputs; never install a Product dependency."""
import argparse
import hashlib
import json
import tarfile
import urllib.request
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('out', type=Path)
args = p.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
for source in json.loads(Path(__file__).with_name('sources.json').read_text()):
    archive = args.out / (source['name'] + '.tar.gz')
    if not archive.exists():
        url = f'https://codeload.github.com/{source["repository"]}/tar.gz/{source["revision"]}'
        archive.write_bytes(urllib.request.urlopen(url, timeout=60).read())
    if hashlib.sha256(archive.read_bytes()).hexdigest() != source['archive_sha256']:
        raise SystemExit('source archive digest mismatch: ' + source['name'])
    target = args.out / (source['name'] + '-' + source['revision'])
    if target.exists():
        raise SystemExit('refusing to overwrite extracted source: ' + str(target))
    with tarfile.open(archive) as contents:
        contents.extractall(args.out, filter='data')
