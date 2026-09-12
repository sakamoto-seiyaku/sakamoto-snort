#!/usr/bin/env python3
"""Bounded diagnostic uprobes/syscalls on the installed VPP, not a perf gate.

The single instruction probe observes the return of the real seq_cst exchange.
No code, eventfd, worker state, or notification behavior is patched by the test.
"""
import hashlib
import json
from pathlib import Path
import re
import select
import shlex
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SIMPLEPERF = Path('/home/js/.local/share/android-sdk/ndk/29.0.14206865/simpleperf')


class NativeTrace:
    def __init__(self, directory, build, pid, generation, mapped_library, wake_fds):
        self.directory, self.pid, self.wake_fds = directory, pid, wake_fds
        self.remote = f'/data/local/tmp/s239-notify-{generation}.data'
        self.adb = [str(ROOT / 'dev/adb'), '-s', '28201JEGR0XPAJ']
        library = Path(build['apk']).parents[1] / 'stage/lib/arm64-v8a/libvlib.so'
        binary = library.read_bytes()
        assert hashlib.sha256(binary).hexdigest() == build['native_sha256']['libvlib.so']
        assert build['native_sha256']['libvlib.so'] == '06b64e815c1322600798a63ab93b0a7acd89d7d24244bbd47707c4a4f9fa4318', \
            'review instruction/register probe mapping for the new VPP artifact'
        # Pinned compiler/artifact instruction: CBZ w0 after the exchange;
        # x19 retains destination thread index. Translate ELF VA to file offset.
        virtual = 0x321c8
        phoff = struct.unpack_from('<Q', binary, 32)[0]
        entsize, count = struct.unpack_from('<HH', binary, 54)
        offset = None
        for i in range(count):
            kind, flags, file_offset, va, _, length, _, _ = struct.unpack_from('<IIQQQQQQ', binary, phoff + i * entsize)
            if kind == 1 and flags & 1 and va <= virtual < va + length:
                offset = file_offset + virtual - va
        assert offset is not None and binary[offset:offset + 4] == bytes.fromhex('a0000034')
        self.metadata = dict(pid=pid, library_sha256=hashlib.sha256(binary).hexdigest(),
                             virtual_address=virtual, file_offset=offset, wake_fds=wake_fds,
                             claim='instrumented correctness trace, not latency or CPU qualification')
        probe = f'p:s239_notify_latch {mapped_library}:{offset:#x} previous=%x0:u32 target=%x19:u32'
        command = ['simpleperf', 'record', '--uprobe', probe,
                   '-e', 'uprobes:s239_notify_latch',
                   '-e', 'raw_syscalls:sys_enter', '--tp-filter', 'id == 63 || id == 64 || id == 22 || id == 441',
                   '-e', 'raw_syscalls:sys_exit', '--tp-filter', 'id == 63 || id == 64 || id == 22 || id == 441',
                   '-e', 'sched:sched_switch', '-p', str(pid), '--duration', '12',
                   '--start_profiling_fd', '1', '--size-limit', '64M',
                   '--no-dump-kernel-symbols', '-o', self.remote]
        self.metadata['command'] = command
        self.process = subprocess.Popen(self.adb + ['shell', 'su', '-c', shlex.quote(shlex.join(command))],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.output = bytearray()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if select.select([self.process.stdout], [], [], .2)[0]:
                chunk = self.process.stdout.read1(8192)
                self.output.extend(chunk)
                if b'STARTED' in self.output:
                    break
                if not chunk:
                    raise RuntimeError(self.output.decode(errors='replace'))
        else:
            raise RuntimeError('simpleperf start deadline: ' + self.output.decode(errors='replace'))

    def finish(self):
        output, _ = self.process.communicate(timeout=20)
        self.output.extend(output)
        text = self.output.decode(errors='replace')
        (self.directory / 'simpleperf-record.txt').write_text(text)
        assert self.process.returncode == 0, text
        assert not re.search(r'(?:lost|Lost)\s+[1-9]', text), text
        local = self.directory / 'native-notify.perf.data'
        subprocess.run(self.adb + ['shell', 'su', '-c',
                       shlex.quote('chmod 644 ' + self.remote)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
        # The repo wrapper translates existing absolute host paths for Windows
        # ADB. Pull into the existing directory, then name the local witness.
        subprocess.run(self.adb + ['pull', self.remote, str(self.directory.resolve())], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
        (self.directory / Path(self.remote).name).rename(local)
        sys.path.insert(0, str(SIMPLEPERF))
        from simpleperf_report_lib import ReportLib
        lib = ReportLib()
        lib.SetRecordFile(str(local))
        events = []
        while True:
            sample = lib.GetNextSample()
            if sample is None:
                break
            event = lib.GetEventOfCurrentSample()
            data = lib.GetTracingDataOfCurrentSample()
            events.append(dict(time=sample.time, pid=sample.pid, tid=sample.tid,
                               event=event.name, data=data))
        lib.Close()
        (self.directory / 'native-notify-events.json').write_text(json.dumps(events, indent=2) + '\n')
        self.metadata['perf_sha256'] = hashlib.sha256(local.read_bytes()).hexdigest()
        self.metadata['events'] = len(events)
        (self.directory / 'native-notify.json').write_text(json.dumps(self.metadata, indent=2) + '\n')
        return self.metadata
