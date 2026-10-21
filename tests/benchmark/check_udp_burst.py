#!/usr/bin/env python3
"""Observe burst timing at independent UDP receivers, not helper counters."""
import json
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import tempfile
import time

SOURCE=Path(__file__).with_name('socket_load.c')
with tempfile.TemporaryDirectory(prefix='sakamoto-udp-burst-') as directory:
    binary=Path(directory)/'socket-load'
    subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread',str(SOURCE),'-o',str(binary)],check=True)
    sockets=[]
    for port in range(43000,64000,64):
        try:
            for offset in range(4):
                sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sockets.append(sock)
                sock.bind(('127.0.0.1',port+offset));sock.setblocking(False)
            break
        except OSError:
            for sock in sockets:sock.close()
            sockets=[]
    assert len(sockets)==4
    selector=selectors.DefaultSelector()
    for sock in sockets:selector.register(sock,selectors.EVENT_READ)
    child=subprocess.Popen([str(binary),'client','127.0.0.1',str(port),'0','udp-fixed',
                            '450','4','1','0','1','100','32'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    arrivals={};deadline=time.monotonic()+2
    try:
        while time.monotonic()<deadline and child.poll() is None:
            for key,_ in selector.select(.02):
                sock=key.fileobj
                while True:
                    try:data,peer=sock.recvfrom(2048)
                    except BlockingIOError:break
                    magic,identity,operation,size,sequence=struct.unpack('!IIIIQ',data[:24])
                    assert magic==0x53424e31 and identity==0
                    if operation==ord('P'):sock.sendto(data,peer)
                    else:
                        assert operation==ord('U') and size==len(data)==1200
                        assert sequence not in arrivals
                        arrivals[sequence]=time.monotonic_ns()
        stdout,stderr=child.communicate(timeout=1)
        assert child.returncode==0,(child.returncode,stderr)
        client=json.loads(stdout);begin=client['start_monotonic_ns']
        assert set(arrivals)==set(range(45)),(len(arrivals),client)
        assert client['packets']==45 and client['pacing_missed']==0
        # First train is due at start, second at320ms; a singleton schedule
        # would distribute the first32 packets over310ms and fail here.
        assert max(arrivals[i] for i in range(32))-begin<100_000_000
        assert min(arrivals[i] for i in range(32,45))-begin>=280_000_000
        assert max(arrivals[i] for i in range(32,45))-begin<420_000_000
        print('PASS independent UDP burst timing:32 immediate packets,13 at320ms,45 exact identities,legacy duration retained')
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=1)
        selector.close()
        for sock in sockets:sock.close()
