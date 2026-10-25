#!/usr/bin/env python3
"""Execute the full Product Root DNS Adapter with controlled VPP/I/O calls.

No dependency build is created here. The caller supplies persistent Host
libraries; the temporary files are only the one source-linked test executable.
Real POSIX socket coverage lives in product_root_dns_io_test.c, and actual App
receipt requires the Android acceptance run.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GRAPH = (ROOT / 'src/product/vpp/product_packet_graph.c').read_text()


def function(name, result):
    match = re.search(r'\n' + name + r'\s*\([^;]*?\n\{', GRAPH, re.S)
    assert match, name
    depth = 0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]', GRAPH[match.end()-1:], re.S):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth:
                return result + '\n' + GRAPH[match.start()+1:match.end()-1+token.end()] + '\n'
    raise AssertionError(name)


parser = argparse.ArgumentParser()
parser.add_argument('libraries', nargs='+')
parser.add_argument('--records')
parser.add_argument('--evidence',type=Path)
parser.add_argument('--case', choices=('all', 'generation', 'crossover', 'reverse-crossover', 'vpn-return', 'vpn-authority', 'idle-health', 'tcp-proxy', 'tcp-unknown', 'vpn-tcp-off', 'vpn-tcp-view'), default='all')
args = parser.parse_args()
cache = Path(args.libraries[1]).resolve().parent / 'CMakeCache.txt'
batch = re.search(r'^SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT:BOOL=(ON|OFF)$', cache.read_text(), re.M)
assert batch
defines = ['-DSAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT=1'] if batch[1] == 'ON' else []
with tempfile.TemporaryDirectory(prefix='sakamoto-root-dns-adapter-') as tmp:
    directory = Path(tmp)
    (directory / 'vlib').mkdir()
    (directory / 'vlib/vlib.h').write_text('/* Controlled VPP buffer dependency. */\n')
    (directory / 'vlib/file.h').write_text('/* Controlled VPP file dependency. */\n')
    (directory / 'root_dns_projection.inc').write_text(
        function('product_packet_graph_l4_direction_from_platform', 'static void')
        + function('product_packet_graph_l4_packet_projection', 'static void')
        + function('product_packet_graph_dns_identity', 'static product_dns_identity_t')
        + function('product_packet_graph_dns_response_prepare', 'static void'))
    binary = directory / 'test'
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
        '-Wno-unused-function', '-Wno-unused-variable', *defines,
        '-I'+str(directory), '-I'+str(ROOT/'src/product/vpp'), '-I'+str(ROOT/'src/product/include'),
        str(ROOT/'tests/host/product_root_dns_adapter_test.c'),
        str(ROOT/'src/product/vpp/product_packet.c'), str(ROOT/'src/product/vpp/product_flow_udp.c'),
        *args.libraries, '-lm', '-o', str(binary)], check=True)
    command = [str(binary)]
    if args.case != 'all':
        command.append(args.case)
        if args.records: command.append(str(Path(args.records).resolve()))
    elif args.records:
        command.append(str(Path(args.records).resolve()))
    evidence=None
    if args.evidence:
        args.evidence.mkdir(parents=True,exist_ok=False)
        shutil.copy2(binary,args.evidence/'test')
        shutil.copy2(directory/'root_dns_projection.inc',args.evidence/'root_dns_projection.inc')
        evidence=dict(command=command,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()for name in(
                'tests/host/product_root_dns_adapter_test.c','tests/host/product_root_dns_adapter_test.py',
                'src/product/vpp/product_root_dns_adapter.inc','src/product/vpp/product_packet_graph.c')},
            libraries={str(Path(name).resolve()):hashlib.sha256(Path(name).read_bytes()).hexdigest()for name in args.libraries})
    try:
        result=subprocess.run(command,check=True,timeout=20,env=os.environ.copy())
        if evidence is not None:evidence['code']=result.returncode
    except subprocess.CalledProcessError as error:
        if evidence is not None:evidence['code']=error.returncode
        raise
    finally:
        if evidence is not None:(args.evidence/'execution.json').write_text(json.dumps(evidence,indent=2)+'\n')
