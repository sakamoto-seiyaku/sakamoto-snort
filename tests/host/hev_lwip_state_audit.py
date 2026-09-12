#!/usr/bin/env python3
"""Audit the dual-stack TCP/UDP lwIP archive, including unnamed writable storage.

This is a dependency-object check, not proof of final product RELRO or runtime
ownership. The only permitted writable object sections hold the TLS current
context pointer and the relocation-bearing, const memp descriptor table.
"""
import argparse
import re
import subprocess


def audit(readelf, archive):
    output = subprocess.check_output(
        [readelf, '-SWs', archive], text=True, env={'LC_ALL': 'C'})
    member = None
    sections = {}
    symbols = {}
    seen = set()

    def check():
        for index, (name, size, flags) in sections.items():
            if member == 'tcp.c.o' and name == '.rodata.tcp_state_str.rel':
                # Clang's optimized AArch64 table uses eleven signed relative
                # offsets instead of eleven relocation-bearing pointers.
                assert flags == 'A' and size == 44
                assert symbols.get(index) == [('OBJECT', 'tcp_state_str.rel', 0, 44)]
                seen.add('tcp_names')
                continue
            if not size or 'W' not in flags or 'A' not in flags:
                continue
            objects = symbols.get(index, [])
            if member == 'hev-lwip-context.c.o' and name in ('.tbss', '.tbss.current'):
                assert objects == [('TLS', 'current', 0, size)], objects
                assert size in (4, 8) and 'T' in flags
                seen.add('context')
            elif member == 'memp.c.o' and name.startswith('.data.rel.ro'):
                assert objects == [('OBJECT', 'memp_pools', 0, size)], objects
                descriptors = {obj[1] for values in symbols.values() for obj in values
                               if obj[1].startswith('memp_') and obj[1] != 'memp_pools'}
                assert descriptors == {'memp_UDP_PCB', 'memp_ND6_QUEUE', 'memp_PBUF', 'memp_PBUF_POOL',
                                       'memp_TCP_PCB', 'memp_TCP_PCB_LISTEN', 'memp_TCP_SEG'}
                assert size in (28, 56)  # Seven const descriptor pointers, 32/64-bit.
                seen.add('descriptors')
            elif member == 'tcp.c.o' and name.startswith('.data.rel.ro'):
                assert objects == [('OBJECT', 'tcp_state_str', 0, size)], objects
                assert size in (44, 88)  # Eleven immutable state-name pointers.
                seen.add('tcp_names')
            else:
                raise AssertionError(f'unexpected mutable storage: {member}:{name} ({size} bytes)')

    for line in output.splitlines():
        match = re.match(r'File: .*\(([^()]+)\)$', line)
        if match:
            check()
            member = match[1]
            sections, symbols = {}, {}
            continue
        match = re.match(
            r'\s*\[\s*(\d+)\]\s+(\S+)\s+\S+\s+[0-9a-f]+\s+[0-9a-f]+'
            r'\s+([0-9a-f]+)\s+\S+\s+([A-Z]+)\s+', line)
        if match:
            sections[match[1]] = (match[2], int(match[3], 16), match[4])
            continue
        fields = line.split()
        # AArch64 emits zero-sized mapping markers (including TLS $d). They
        # occupy no storage; the permitted object must still cover every byte
        # of its section, so filtering markers cannot hide extra allocation.
        if len(fields) == 8 and fields[3] in ('OBJECT', 'TLS') and int(fields[2], 0):
            symbols.setdefault(fields[6], []).append(
                (fields[3], fields[7], int(fields[1], 16), int(fields[2], 0)))
    check()
    assert seen == {'context', 'descriptors', 'tcp_names'}, f'missing expected objects: {seen}'
    print('lwIP TCP/UDP4/6 archive state audit PASS: TLS selector + immutable relocations only')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--readelf', required=True)
    parser.add_argument('archive')
    args = parser.parse_args()
    audit(args.readelf, args.archive)
