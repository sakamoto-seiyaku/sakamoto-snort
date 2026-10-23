"""Optional owned remote completion witnesses for S314 foreground controls."""
import base64
import hashlib
import json
import math
from pathlib import Path
import re
import shlex
import subprocess
import time


def identity(stat, uid):
    pid = int(stat.split(' ', 1)[0])
    fields = stat.rsplit(') ', 1)[1].split()
    uids = uid.split()
    assert len(uids) == 5 and uids[0] == 'Uid:' and all(value.isdigit() for value in uids[1:])
    result = dict(pid=pid, parent=int(fields[1]), start=int(fields[19]), uid=int(uids[2]))
    assert pid > 0 and result['start'] > 0
    return result


def same_actor(left, right):
    return left is not None and all(left[key] == right[key] for key in ('pid', 'start', 'uid'))


def witness(item):
    """Validate values, never equate a successful cat with remote completion."""
    gaps, values = [], {}
    for label in ('meta', 'out'):
        raw = item.get('remote_' + label, {})
        if raw.get('code') != 0:
            gaps.append(label)
    lines = item.get('remote_meta', {}).get('text', '').splitlines()
    if len(lines) % 2:
        gaps.append('metadata_layout')
    for index in range(0, len(lines)-1, 2):
        key, value = lines[index:index+2]
        if key in values:
            gaps.append('duplicate:' + key)
        values[key] = value
    result = dict(identities={})
    for label in ('wrapper', 'child'):
        try:
            result['identities'][label] = identity(values[label + '_stat'], values[label + '_uid'])
        except (KeyError, ValueError, IndexError, AssertionError):
            gaps.append(label + '_identity')
    try:
        begin, end = float(values['begin'].split()[0]), float(values['end'].split()[0])
        assert math.isfinite(begin) and math.isfinite(end) and 0 <= begin <= end
        result['remote_seconds'] = end-begin
    except (KeyError, ValueError, IndexError, AssertionError):
        gaps.append('chronology')
    try:
        assert re.fullmatch(r'\d+', values['exit'])
        code = int(values['exit'])
        assert 0 <= code <= 255
        result.update(exit_code=code, semantic_success=code == 0)
    except (KeyError, ValueError, AssertionError):
        gaps.append('exit')
    result['gaps'] = gaps
    return result


class AdbTrace:
    def __init__(self, output, adb, remote_parent='/data/local/tmp'):
        self.output, self.adb = Path(output), list(adb)
        self.nonce = 's314-control-' + str(time.monotonic_ns())
        self.remote = remote_parent + '/' + self.nonce
        self.items, self.created, self.closed = [], False, False
        self.output.joinpath('source-s314_adb_trace.py').write_bytes(Path(__file__).read_bytes())

    @staticmethod
    def handles(command):
        if len(command) < 2 or command[0] != 'shell':
            return False
        if command[1] in ('am', 'wm', 'dumpsys', 'input', 'rm'):
            return True
        # This source's synchronous RuleConfig apply is the only supported sh
        # program. Do not infer ownership of arbitrary background shell jobs.
        return command[1:3] == ('sh', '-c') and len(command) == 4 and 'am start -n ' in command[3] and '--es completeRuleText ' in command[3]

    def execute(self, original, wire, timeout, check=True, kind='traced-control'):
        started, monotonic = time.time_ns(), time.monotonic_ns()
        process, failure, stdout, stderr = None, None, b'', b''
        cleanup_error = None
        try:
            process = subprocess.Popen(self.adb + list(map(str, wire)), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException as error:
            failure = error
            if isinstance(error, subprocess.TimeoutExpired):
                stdout, stderr = error.output or b'', error.stderr or b''
        finally:
            if process is not None and (failure is not None or process.poll() is None):
                try:
                    if process.poll() is None:
                        process.kill()
                    try:
                        stdout, stderr = process.communicate(timeout=2)
                    except BaseException as drain:
                        if isinstance(drain, subprocess.TimeoutExpired):
                            stdout, stderr = drain.output or stdout, drain.stderr or stderr
                        for pipe in (process.stdout, process.stderr):
                            if pipe:
                                pipe.close()
                        process.wait(timeout=2)
                except BaseException as error:
                    cleanup_error = repr(error)
            record = dict(started_ns=started, completed_ns=time.time_ns(), started_monotonic_ns=monotonic,
                          completed_monotonic_ns=time.monotonic_ns(), argv=list(map(str, original)), wire_argv=list(map(str, wire)),
                          local_pid=process.pid if process else None, code=process.returncode if process else None,
                          trace_kind=kind, local_reaped=process is None or process.returncode is not None)
            for label, data in (('stdout', stdout), ('stderr', stderr)):
                if isinstance(data, str):
                    data = data.encode()
                path = 'adb-trace-host-' + str(monotonic) + '.' + label
                self.output.joinpath(path).write_bytes(data)
                record[label + '_path'] = path
            if failure:
                record.update(outcome='timeout' if isinstance(failure, subprocess.TimeoutExpired) else 'cancelled-or-error',
                              error=repr(failure), timeout_seconds=timeout,
                              stdout_base64=base64.b64encode(stdout).decode(), stderr_base64=base64.b64encode(stderr).decode())
            if cleanup_error:
                record['local_cleanup_error'] = cleanup_error
            with (self.output / 'operations.jsonl').open('a') as stream:
                stream.write(json.dumps(record) + '\n')
            if failure:
                failure.s314_operation = record
        if failure:
            if isinstance(failure, subprocess.TimeoutExpired):
                self.output.joinpath('transport-timeout-' + str(started) + '.json').write_text(json.dumps(record, indent=2) + '\n')
            raise failure
        if cleanup_error or not record['local_reaped']:
            raise RuntimeError('local trace client did not settle: ' + str(cleanup_error))
        if check and process.returncode:
            raise RuntimeError((stdout + stderr).decode(errors='replace'))
        return stdout, stderr, process.returncode, record

    def collect(self, item):
        for suffix in ('meta', 'out'):
            name = item['label'] + '-remote-' + suffix
            command = ['exec-out', 'cat', item['remote_stem'] + '.' + suffix]
            try:
                stdout, stderr, code, record = self.execute(command, command, 5, check=False, kind='trace-witness-read')
                self.output.joinpath(name + '.stdout').write_bytes(stdout)
                self.output.joinpath(name + '.stderr').write_bytes(stderr)
                item['remote_' + suffix] = dict(code=code, text=stdout.decode(errors='replace'))
            except Exception as error:
                item['remote_' + suffix] = dict(read_error=repr(error))
        item['witness'] = witness(item)

    def run(self, command, deadline, check=True):
        if not self.created:
            remaining = deadline-time.monotonic() if deadline else 5
            assert remaining > 0, 'end-to-end capture budget exhausted'
            self.created = True  # An ambiguous mkdir still requires cleanup.
            create = ['exec-out', 'mkdir', self.remote]
            self.execute(create, create, min(5, remaining), kind='trace-owned-directory')
        number, original = len(self.items)+1, list(map(str, command))
        stem = self.remote + '/op-' + str(number)
        program = ' '.join(original[1:])
        child = f'while [ ! -f {stem}.gate ]; do sleep 0.01; done; exec sh -c {shlex.quote(program)}'
        # The command child waits until its identity has been retained. It then
        # execs the exact original foreground program, preserving start identity.
        script = (f'printf "begin\\n" > {stem}.meta; cat /proc/uptime >> {stem}.meta; '
                  f'printf "wrapper_stat\\n" >> {stem}.meta; if ! cat /proc/$$/stat >> {stem}.meta; then exit 125; fi; '
                  f'printf "wrapper_uid\\n" >> {stem}.meta; if ! grep "^Uid:" /proc/$$/status >> {stem}.meta; then exit 125; fi; '
                  f'printf "__S314_BEGIN_{number}__\\n"; sh -c {shlex.quote(child)} > {stem}.out 2>&1 & child=$!; '
                  f'printf "child_stat\\n" >> {stem}.meta; '
                  f'if cat /proc/$child/stat >> {stem}.meta && printf "child_uid\\n" >> {stem}.meta && '
                  f'grep "^Uid:" /proc/$child/status >> {stem}.meta; then '
                  f': > {stem}.gate; wait "$child"; code=$?; else kill "$child"; wait "$child"; code=125; fi; '
                  f'printf "end\\n" >> {stem}.meta; '
                  f'cat /proc/uptime >> {stem}.meta; printf "exit\\n%s\\n" "$code" >> {stem}.meta; cat {stem}.out; exit "$code"')
        wire = ['shell', 'sh', '-c', shlex.quote(script)]
        timeout = min(10, deadline-time.monotonic()) if deadline else 60
        assert timeout > 0, 'end-to-end capture budget exhausted'
        item = dict(label='adb-trace-' + str(number), original_argv=original, remote_stem=stem)
        self.items.append(item)
        try:
            stdout, stderr, code, record = self.execute(original, wire, timeout, check=False)
            item.update(outcome='completed', host_operation=record)
            prefix = ('__S314_BEGIN_' + str(number) + '__\n').encode()
            assert stdout.startswith(prefix), 'trace preamble missing; exact output cannot be established'
            value = (stdout[len(prefix):] + stderr).decode(errors='replace').replace('\r', '')
            if check and code:
                raise RuntimeError(value)
            return value
        except BaseException as error:
            item.update(outcome='timeout' if isinstance(error, subprocess.TimeoutExpired) else 'error',
                        host_operation=getattr(error, 's314_operation', item.get('host_operation')))
            raise
        finally:
            # Both successful and failed witnesses wait until protected cleanup.
            self.save('IN_PROGRESS')

    def save(self, status, **extra):
        self.output.joinpath('adb-trace.json').write_text(json.dumps(dict(status=status, nonce=self.nonce,
            remote_directory=self.remote, helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            operations=self.items, **extra), indent=2) + '\n')

    def live_identity(self, pid):
        script = (f'if [ ! -d /proc/{pid} ]; then echo ABSENT; else cat /proc/{pid}/stat && '
                  f'grep "^Uid:" /proc/{pid}/status; fi')
        command = ['exec-out', 'su', '-c', script]
        stdout, stderr, code, record = self.execute(command, command, 5, kind='trace-owned-identity')
        lines = stdout.decode().splitlines()
        return None if lines == ['ABSENT'] else identity(lines[0], lines[1])

    def process_rows(self, label):
        command = ['exec-out', 'su', '-c', 'ps -A -o PID,PPID,UID,ARGS']
        stdout, stderr, code, record = self.execute(command, command, 5, kind='trace-owned-process-check')
        self.output.joinpath(label + '.txt').write_bytes(stdout)
        return {int(parts[0]): (int(parts[1]), ' '.join(parts[3:])) for line in stdout.decode(errors='replace').splitlines()
                if len(parts := line.split()) >= 4 and parts[0].isdigit()}

    def close(self):
        if self.closed or not self.created:
            return
        try:
            for item in self.items:
                self.collect(item)
            rows, known = self.process_rows('adb-trace-processes-before'), {}
            for item in self.items:
                for actor in item['witness']['identities'].values():
                    if actor['pid'] in rows and same_actor(self.live_identity(actor['pid']), actor):
                        known[actor['pid']] = actor
            # Descendants are authorized only after their live start/UID and
            # ancestry match the retained snapshot. Reparenting later does not
            # turn the same identified actor into a different process.
            while True:
                added = False
                for pid, (parent, args) in rows.items():
                    if parent in known and pid not in known:
                        actor = self.live_identity(pid)
                        assert actor and actor['parent'] == parent, 'descendant ancestry changed before identity capture'
                        known[pid], added = actor, True
                if not added:
                    break
            def depth(pid):
                count, parent = 0, known[pid]['parent']
                while parent in known:
                    count, parent = count+1, known[parent]['parent']
                return count
            for pid in sorted(known, key=depth, reverse=True):
                actor = known[pid]
                condition = (f'[ "$(sed "s/^.*) //" /proc/{pid}/stat | awk \'{{print $20}}\')" = "{actor["start"]}" ] && '
                             f'[ "$(awk \'/^Uid:/{{print $3}}\' /proc/{pid}/status)" = "{actor["uid"]}" ]')
                command = ['exec-out', 'su', '-c', f'if {condition}; then kill -TERM {pid}; fi']
                self.execute(command, command, 5, kind='trace-owned-process-termination')
            if known:
                time.sleep(.2)
                for item in self.items:
                    if item['witness']['gaps']:
                        self.collect(item)
            final = self.process_rows('adb-trace-processes-after')
            for pid, actor in known.items():
                assert pid not in final or not same_actor(self.live_identity(pid), actor), 'owned trace actor remains'
            assert not any(self.nonce in args for parent, args in final.values()), 'unidentified nonce actor remains'
            gaps = {item['label']: item['witness']['gaps'] for item in self.items if item['witness']['gaps']}
            assert not gaps, ('remote completion/identity not established; orphan absence unproved', gaps)
            remove = ['exec-out', 'rm', '-rf', self.remote]
            self.execute(remove, remove, 5, kind='trace-owned-directory-cleanup')
            self.closed = True
            self.save('COMPLETE_REMOTE_WITNESSES', owned_actor_absent=True, remote_directory_removed=True,
                      limit='Only validated remote exit/identity witnesses establish completion; old timeouts remain unclassified')
        except BaseException as error:
            self.save('HOLD', cleanup_error=repr(error))
            raise
