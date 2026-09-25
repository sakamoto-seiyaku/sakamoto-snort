#!/usr/bin/env python3
"""Independent multi-Initial test vectors with hand-decided per-step outcomes."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
from quic_initial_vectors import crypto, hello, protect

# Wire bytes, literal result, stop, retained bytes, direction, time advance (us).
def step(frames, result=0, stop=0, retained=0, side=0, advance=0, **options):
    return protect(frames, **options), result, stop, retained, side, advance

def cases():
    named, absent = hello('Example.TEST'), hello()
    for text,result in ((named,1),(absent,2)):
        for cut in range(1,len(text)):
            yield f'{result}-ordered-{cut}', [step(crypto(text[:cut]),retained=cut,pn=0),
                step(crypto(text[cut:],cut),result,1,pn=1)]
            yield f'{result}-reversed-{cut}', [step(crypto(text[cut:],cut),retained=len(text)-cut,pn=1),
                step(crypto(text[:cut]),result,1,pn=0)]
    yield 'coalesced-initials', [(protect(crypto(named[20:],20),pn=1,minimum=600)+
        protect(crypto(named[:20]),pn=0,minimum=600),1,1,0,0,0)]
    small=protect(crypto(named[:1]),minimum=50)
    yield 'coalesced-limit', [(small*8+bytes(800),0,0,1,0,0)]
    yield 'coalesced-over-limit', [(small*9+bytes(750),0,5,0,0,0)]
    yield 'duplicate-overlap', [step(crypto(named[10:30],10),retained=20,pn=10),
        step(crypto(named[10:30],10),retained=20,pn=10),
        step(crypto(named[20:],20),retained=len(named)-10,pn=11),
        step(crypto(named[:20]),1,1,pn=12),step(crypto(hello()),1,1,pn=13)]
    yield 'conflict-terminal', [step(crypto(named[:20]),retained=20),
        step(crypto(b'bad',10),stop=2,pn=3),step(crypto(named),stop=2,pn=4)]
    yield 'dcid-change', [step(crypto(named[:20]),retained=20),
        step(crypto(named[20:],20),stop=3,dcid=b'different'),step(crypto(named),stop=3)]
    yield 'version-after-partial', [step(crypto(named[:20]),retained=20),step(crypto(named),stop=9,version=2)]
    bad=bytearray(protect(crypto(named[20:],20),pn=3));bad[-1]^=1
    yield 'auth-after-partial', [step(crypto(named[:20]),retained=20),(bytes(bad),0,10,0,0,0)]
    yield 'reverse-isolation', [step(crypto(named[:20]),retained=20),
        step(crypto(hello()),retained=20,side=1,version=2),
        step(crypto(named[20:],20),1,1,pn=3)]
    for pn in (255,65535,16777215,4294967295):
        width=(pn.bit_length()+7)//8
        yield f'pn-window-{width}', [step(crypto(named[20:],20),retained=len(named)-20,pn=pn,pn_bytes=width),
            step(crypto(named[:10]),retained=len(named)-10,pn=pn+1,pn_bytes=width),
            step(crypto(named[10:20],10),1,1,pn=pn-1,pn_bytes=width)]
    sparse=b''.join(crypto(b'x',i*2+1) for i in range(32))
    yield 'range-32-then-33', [step(sparse,retained=32),step(crypto(b'x',65),stop=5,pn=3)]
    yield 'range-merge-at-capacity', [step(sparse,retained=32),
        step(crypto(b'xxx',1),retained=33,pn=3),step(crypto(b'x',65),retained=34,pn=4)]
    yield 'offset-limit', [step(crypto(b'x',4095),retained=1),step(crypto(b'xx',4095),stop=5,pn=3)]
    yield 'packet-budget', [step(crypto(named[20:],20),retained=len(named)-20,pn=i) for i in range(19)]+[
        step(crypto(named[20:],20),stop=6,pn=19),step(crypto(named),stop=6,pn=20)]
    yield 'deadline-no-packet', [step(crypto(named[:20]),retained=20),(b'',0,7,0,0,5000000),
        step(crypto(named),stop=7)]
    yield 'deadline-last-byte', [step(crypto(named[:20]),retained=20),
        step(crypto(named[20:],20),stop=7,advance=5000000)]
    yield 'just-before-deadline', [step(crypto(named[:20]),retained=20),
        step(crypto(named[20:],20),1,1,advance=4999998)]
    yield 'empty-crypto', [step(crypto(b'')),step(crypto(named),1,1,pn=3)]
    # Each 4096-byte datagram contributes 4096+4000 work. Sixteen fit,
    # the seventeenth cannot admit its CRYPTO bytes. No offset-zero prefix.
    heavy=crypto(bytes(4000),1)
    yield 'work-budget', [step(heavy,retained=4000,pn=i,minimum=4096) for i in range(16)]+[
        step(heavy,stop=5,pn=16,minimum=4096),step(crypto(named),stop=5,pn=17)]

def write(path,steps):
    with path.open('wb') as file:
        for packet,result,stop,retained,side,advance in steps:
            file.write(f'{len(packet)} {result} {stop} {retained} {side} {advance}\n'.encode()+packet)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('binary',type=Path)
    parser.add_argument('--directory',type=Path);args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='t16-quic-sequences-') as temporary:
        directory=args.directory or Path(temporary);directory.mkdir(parents=True,exist_ok=True)
        count=0
        for name,steps in cases():
            path=directory/(name+'.seq');write(path,steps)
            subprocess.run([str(args.binary),'--sequence',str(path)],check=True);count+=1
        for capacity in (1,64,1024):
            subprocess.run([str(args.binary),'--load',str(directory/'range-32-then-33.seq'),str(capacity),'1'],check=True)
        print(json.dumps(dict(status='PASS',independent_sequences=count)))
if __name__=='__main__':main()
