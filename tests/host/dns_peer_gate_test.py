#!/usr/bin/env python3
"""Real POSIX DNS fixture I/O with controlled monotonic and gate-read clocks."""
import importlib.util
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('gate_peer',ROOT/'tests/device/helpers/s316_dns_peer.py')
peer_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(peer_module)

class Clock:
    offset=0
    def monotonic(self):return time.monotonic()+self.offset
    def monotonic_ns(self):return int(self.monotonic()*1_000_000_000)

clock=Clock();peer_module.time=clock
query=bytes.fromhex('12340100000100000000000001610000010001')
reply=query[:2]+bytes.fromhex('8180')+query[4:]

def wait(predicate):
    deadline=time.monotonic()+2
    while not predicate():
        assert time.monotonic()<deadline,'fixture test prerequisite did not settle'
        time.sleep(.005)

def close(peer,expect_error=False):
    try:peer.close()
    except AssertionError:
        assert expect_error and peer.error is not None
    assert not peer.thread.is_alive() and all(s.fileno()==-1 for s in peer.sockets)
    received=[r['request']for r in peer.messages if r['kind']=='received']
    settled=[r['request']for r in peer.messages if r['kind']in('exchange','cancelled')]
    assert sorted(received)==sorted(settled)

def exercise(seconds,advance,expired):
    with tempfile.TemporaryDirectory(prefix='s316-peer-gate-') as tmp:
        out=Path(tmp);gate=out/'release';clock.offset=0
        peer=peer_module.Peer(['127.0.0.1','::1'],out,clock.monotonic()+300,port=0)
        try:
            options={} if seconds is None else dict(gate_seconds=seconds)
            peer.register(query,reply,gate=gate,**options)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(.1);client.sendto(query,peer.sockets[0].getsockname())
                wait(lambda:bool(peer.waiting));clock.offset=advance
                if expired:
                    wait(lambda:peer.error is not None)
                    assert 'gate deadline' in str(peer.error)
                else:
                    assert peer.error is None
                    try:client.recv(65535)
                    except TimeoutError:pass
                    else:raise AssertionError('gated reply escaped before release')
                    gate.touch();client.settimeout(2)
                    assert client.recv(65535)==reply
        finally:close(peer,expired)

class PausedGate:
    def __init__(self,pause_on=1):
        self.entered=threading.Event();self.resume=threading.Event()
        self.calls=0;self.pause_on=pause_on
    def exists(self):
        self.calls+=1
        if self.calls==self.pause_on:
            self.entered.set();assert self.resume.wait(2)
        return True

def expired_released(seconds,overall=300):
    # A scheduler/filesystem pause crosses the budget while the release exists.
    with tempfile.TemporaryDirectory(prefix='s316-peer-expired-release-') as tmp:
        clock.offset=0;gate=PausedGate()
        peer=peer_module.Peer(['127.0.0.1'],Path(tmp),clock.monotonic()+overall,port=0)
        try:
            options={} if seconds is None else dict(gate_seconds=seconds)
            peer.register(query,reply,gate=gate,**options)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(.1);client.sendto(query,peer.sockets[0].getsockname())
                assert gate.entered.wait(2)
                clock.offset=min(seconds or 30,overall)+1;gate.resume.set()
                try:client.recv(65535)
                except TimeoutError:pass
                else:raise AssertionError('expired released gate sent a real UDP reply')
                wait(lambda:peer.error is not None)
                assert 'gate deadline' in str(peer.error)
                assert not any(r['kind']=='exchange'for r in peer.messages)
        finally:gate.resume.set();close(peer,peer.error is not None)

def tcp_partial(expire):
    with tempfile.TemporaryDirectory(prefix='s316-peer-tcp-gate-') as tmp:
        clock.offset=0;gate=PausedGate(pause_on=2)
        peer=peer_module.Peer(['127.0.0.1'],Path(tmp),clock.monotonic()+300,port=0)
        try:
            peer.register(query,reply,protocol='tcp',gate=gate,gate_seconds=120,split=True)
            with socket.create_connection(peer.sockets[1].getsockname(),timeout=2) as client:
                client.sendall(struct.pack('!H',len(query))+query)
                assert gate.entered.wait(2)
                first=client.recv(65535);assert len(first)==1
                if expire:clock.offset=121
                else:clock.offset=31
                gate.resume.set();received=first
                if expire:
                    wait(lambda:peer.error is not None)
                    while part:=client.recv(65535):received+=part
                    assert len(received)==1 and 'gate deadline' in str(peer.error)
                    assert not any(r['kind']=='exchange'for r in peer.messages)
                else:
                    while len(received)<len(reply)+2:received+=client.recv(65535)
                    assert received==struct.pack('!H',len(reply))+reply
        finally:gate.resume.set();close(peer,expire)

def planned_silence():
    with tempfile.TemporaryDirectory(prefix='s316-peer-silence-') as tmp:
        clock.offset=0;peer=peer_module.Peer(['127.0.0.1'],Path(tmp),clock.monotonic()+300,port=0)
        try:
            peer.register(query,reply,drop=True)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(.1);client.sendto(query,peer.sockets[0].getsockname())
                wait(lambda:any(r.get('reason')=='planned_silence'for r in peer.messages))
                try:client.recv(65535)
                except TimeoutError:pass
                else:raise AssertionError('planned silence produced a reply')
                assert peer.error is None
        finally:close(peer)

exercise(120,31,False)
exercise(None,31,True)
exercise(120,121,True)
expired_released(None)
expired_released(120)
expired_released(120,overall=20)
tcp_partial(False)
tcp_partial(True)
planned_silence()
with tempfile.TemporaryDirectory(prefix='s316-peer-gate-bounds-') as tmp:
    clock.offset=0;peer=peer_module.Peer(['127.0.0.1'],Path(tmp),clock.monotonic()+300,port=0)
    try:
        for seconds in (0,121):
            try:peer.register(query,reply,gate=Path(tmp)/'gate',gate_seconds=seconds)
            except AssertionError:pass
            else:raise AssertionError('unbounded gate budget accepted')
    finally:close(peer)
print('real POSIX UDP/TCP gate budgets/default30/explicit120/expiredrelease/overallcap/partialframe/silence/cleanup: PASS')
