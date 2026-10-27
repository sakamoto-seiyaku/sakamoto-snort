"""Task-local ADB connection relay; retries TCP connect before forwarding bytes."""
import hashlib
import json
from pathlib import Path
import select
import shlex
import signal
import socket
import subprocess
import threading
import time


class AdbRoute:
    def __init__(self, output, client, upstream=('127.0.0.1', 5037), *,
                 connect_timeout=.5, attempts=6, max_active=16, max_connections=4096,
                 connection_lifetime=65, cleanup_connections=0):
        self.output, self.client, self.upstream = Path(output), Path(client), upstream
        assert 0 < connect_timeout <= .5 and 1 <= attempts <= 6
        assert 1 <= max_active <= 16 and 1 <= max_connections <= 32768
        assert 0 <= cleanup_connections <= 4096
        assert 0 < connection_lifetime <= 125
        self.connect_timeout, self.attempts = connect_timeout, attempts
        self.max_active, self.max_connections = max_active, max_connections
        self.cleanup_budget, self.cleanup_used = cleanup_connections, 0
        self.cleanup_marker = self.output/'cleanup.phase'
        self.cleanup_started_at_connection = None
        self.connection_lifetime = connection_lifetime
        self.stop = threading.Event()
        self.closing = threading.Event()
        self.lock = threading.Lock()
        self.workers, self.sockets, self.records, self.errors = [], set(), [], []
        self.accepted = self.active = self.peak_active = 0
        self.listener = self.thread = self.endpoint = None
        self.source_hash = self.client_hash = None
        self.closed = False

    def record(self, item):
        with self.lock:
            self.records.append(item)
            with (self.output/'connections.jsonl').open('a') as stream:
                stream.write(json.dumps(item) + '\n')

    def release(self, *sockets):
        for item in sockets:
            if item is None:
                continue
            try:
                item.close()
            except OSError as error:
                with self.lock:
                    self.errors.append(dict(stage='socket-close', error=repr(error)))
            finally:
                if item.fileno() == -1:
                    with self.lock:
                        self.sockets.discard(item)

    def connect(self, identifier):
        for attempt in range(1, self.attempts+1):
            if self.stop.is_set():
                return None
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with self.lock:
                self.sockets.add(remote)
            transferred = False
            try:
                remote.settimeout(self.connect_timeout)
                item = dict(connection=identifier, event='connect-attempt', attempt=attempt,
                            started_monotonic_ns=time.monotonic_ns(), endpoint=list(self.upstream),
                            forwarded_request_bytes=0)
                try:
                    remote.connect(self.upstream)
                    item.update(status='connected', local=list(remote.getsockname()))
                except OSError as error:
                    item.update(status='connect-failed', error=repr(error), local=list(remote.getsockname()))
                finally:
                    item['completed_monotonic_ns'] = time.monotonic_ns()
                    self.record(item)
                if item['status'] == 'connected':
                    remote.setblocking(False)
                    transferred = True
                    return remote
            finally:
                if not transferred:
                    self.release(remote)
        return None

    def forward(self, identifier, local, remote):
        sockets = (local, remote)
        other = {local: remote, remote: local}
        buffers = {local: bytearray(), remote: bytearray()}
        eof, shutdown = set(), set()
        totals = {local: 0, remote: 0}
        started = time.monotonic()
        reason = 'both-eof'
        while not self.stop.is_set():
            for target in sockets:
                if other[target] in eof and not buffers[target] and target not in shutdown:
                    try:
                        target.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    shutdown.add(target)
            if len(eof) == 2 and not any(buffers.values()):
                break
            assert time.monotonic()-started < self.connection_lifetime, 'local relay connection exceeded bounded lifetime'
            readable = [s for s in sockets if s not in eof and len(buffers[other[s]]) < 65536]
            writable = [s for s in sockets if buffers[s]]
            reads, writes, _ = select.select(readable, writable, [], .1)
            for source in reads:
                try:
                    data = source.recv(min(16384, 65536-len(buffers[other[source]])))
                except BlockingIOError:
                    continue
                except ConnectionResetError:
                    eof.update(sockets)
                    buffers[local].clear()
                    buffers[remote].clear()
                    reason = 'peer-reset'
                    break
                if not data:
                    eof.add(source)
                else:
                    buffers[other[source]].extend(data)
            for target in writes:
                if not buffers[target]:
                    continue
                try:
                    count = target.send(buffers[target])
                except BlockingIOError:
                    continue
                except (BrokenPipeError, ConnectionResetError):
                    eof.update(sockets)
                    buffers[local].clear()
                    buffers[remote].clear()
                    reason = 'peer-closed-during-write'
                    break
                assert count > 0, 'zero-byte relay write'
                del buffers[target][:count]
                totals[target] += count
        self.record(dict(connection=identifier, event='stream-closed',
                         reason='task-close' if self.stop.is_set() else reason,
                         forwarded_request_bytes=totals[remote], returned_bytes=totals[local],
                         buffer_limit_per_direction=65536))
        if self.stop.is_set() and totals[remote]:
            with self.lock:
                self.errors.append(dict(connection=identifier, stage='forced-stream-close',
                                        error='request bytes forwarded; remote completion requires independent witnesses'))

    def handle(self, identifier, local):
        remote = None
        try:
            remote = self.connect(identifier)
            if remote is None:
                self.record(dict(connection=identifier, event='no-upstream', forwarded_request_bytes=0))
                return
            with self.lock:
                self.sockets.add(remote)
            local.setblocking(False)
            # There is deliberately no connect/retry call in the stream path.
            self.forward(identifier, local, remote)
        except BaseException as error:
            with self.lock:
                self.errors.append(dict(connection=identifier, error=repr(error)))
        finally:
            self.release(local, remote)
            with self.lock:
                self.active -= 1

    def serve(self):
        try:
            while not self.closing.is_set():
                try:
                    local, address = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.closing.is_set():
                        break
                    raise
                with self.lock:
                    self.accepted += 1
                    identifier = self.accepted
                    if self.cleanup_started_at_connection is not None or(self.cleanup_budget and self.cleanup_marker.is_file()):
                        if self.cleanup_started_at_connection is None:
                            self.cleanup_started_at_connection = identifier
                        self.cleanup_used += 1
                    cleanup = self.cleanup_started_at_connection is not None
                    capacity = self.cleanup_used <= self.cleanup_budget if cleanup else identifier <= self.max_connections
                    allowed = (address[0] == '127.0.0.1' and self.active < self.max_active
                               and capacity)
                    if allowed:
                        self.active += 1
                        self.peak_active = max(self.peak_active, self.active)
                        self.sockets.add(local)
                    else:
                        self.errors.append(dict(connection=identifier, phase='cleanup'if cleanup else'main',
                                                error='bounded route capacity exceeded'))
                if not allowed:
                    self.release(local)
                    continue
                thread = threading.Thread(target=self.handle, args=(identifier, local), name='s314-adb-route-'+str(identifier))
                try:
                    thread.start()
                except BaseException as error:
                    self.release(local)
                    with self.lock:
                        self.active -= 1
                        self.errors.append(dict(connection=identifier, stage='worker-start', error=repr(error)))
                    self.closing.set()
                    break
                self.workers.append(thread)
        except BaseException as error:
            with self.lock:
                self.errors.append(dict(error=repr(error), stage='accept'))

    def __enter__(self):
        self.output.mkdir(parents=True, exist_ok=False)
        try:
            source = Path(__file__).read_bytes()
            self.output.joinpath('source-s314_adb_route.py').write_bytes(source)
            self.source_hash = hashlib.sha256(source).hexdigest()
            self.client_hash = hashlib.sha256(self.client.read_bytes()).hexdigest()
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.bind(('127.0.0.1', 0))
            self.listener.listen(self.max_active)
            self.listener.settimeout(.1)
            self.endpoint = self.listener.getsockname()
            self.wrapper = self.output/'adb-client'
            self.wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(str(self.client))+' -H 127.0.0.1 -P '+str(self.endpoint[1])+' "$@"\n')
            self.wrapper.chmod(0o700)
            self.thread = threading.Thread(target=self.serve, name='s314-adb-route-listener')
            self.thread.start()
        except BaseException as error:
            self.errors.append(dict(stage='startup', error=repr(error)))
            try:
                self.close(primary_error=repr(error))
            except BaseException:
                pass  # The startup exception remains the primary failure.
            raise
        return self

    def close(self, primary_error=None):
        if self.closed:
            return
        self.closing.set()
        if self.listener:
            self.release(self.listener)
        if self.thread and self.thread.ident is not None:
            self.thread.join(timeout=2)
        # Give already closed clients one pump iteration to record normal EOF.
        settle_deadline = time.monotonic()+.3
        while time.monotonic() < settle_deadline:
            with self.lock:
                active = self.active
            if not active:
                break
            time.sleep(.01)
        self.stop.set()
        # Normal clients settle before their enclosing runner leaves the route.
        # Shutdown still bounds local resources on runner cancellation; it does
        # not claim that an Android command has terminated.
        with self.lock:
            owned = list(self.sockets)
        for item in owned:
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = time.monotonic()+2
        for thread in self.workers:
            if thread.ident is not None:
                thread.join(timeout=max(0, deadline-time.monotonic()))
        with self.lock:
            remaining_owned = list(self.sockets)
        self.release(*remaining_owned)
        alive = [t.name for t in ([self.thread] if self.thread else [])+self.workers if t.is_alive()]
        with self.lock:
            remaining = len(self.sockets)
        log_hash = None
        try:
            if (self.output/'connections.jsonl').exists():
                log_hash = hashlib.sha256((self.output/'connections.jsonl').read_bytes()).hexdigest()
        except BaseException as error:
            self.errors.append(dict(stage='receipt-log-hash', error=repr(error)))
        receipt = dict(status='COMPLETE_TASK_LOCAL_ROUTE' if not alive and not remaining and not self.errors and not primary_error else 'HOLD',
                       endpoint=list(self.endpoint) if self.endpoint else None, upstream=list(self.upstream), accepted=self.accepted,
                       peak_active=self.peak_active, max_active=self.max_active, max_connections=self.max_connections,
                       cleanup_connection_budget=self.cleanup_budget, cleanup_connections=self.cleanup_used,
                       cleanup_started_at_connection=self.cleanup_started_at_connection,
                       connect_timeout=self.connect_timeout, max_connect_attempts=self.attempts,
                       connection_lifetime=self.connection_lifetime,
                       remaining_sockets=remaining, live_threads=alive, errors=self.errors,
                       source_sha256=self.source_hash, client_sha256=self.client_hash,
                       log_sha256=log_hash, primary_error=primary_error,
                       limit='Only TCP connect is retried before forwarding bytes; stream bytes never replay. Local cleanup is not Android command termination.')
        self.closed = True
        (self.output/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
        assert receipt['status'] == 'COMPLETE_TASK_LOCAL_ROUTE', receipt

    def __exit__(self, exc_type, exc, traceback):
        try:
            self.close(primary_error=repr(exc) if exc else None)
        except BaseException:
            if exc is None:
                raise
        return False


def run_owned(command, *, env, stdout, cancel, receipt, cleanup_timeout=180):
    """Keep the route alive while the owned child handles one cancellation."""
    assert 0 < cleanup_timeout <= 180
    if cancel.is_set():
        receipt.update(cancelled=True, code=130, local_pid=None, local_reaped=True,
                       cancellation_scope='cancelled before child launch')
        return 130
    process, primary = None, None
    try:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        receipt.update(local_pid=process.pid, started_monotonic_ns=time.monotonic_ns())
        while not cancel.is_set():
            try:
                process.wait(timeout=.1)
                break
            except subprocess.TimeoutExpired:
                pass
    except BaseException as error:
        primary = error
        receipt['supervision_error'] = repr(error)
    finally:
        if process is not None:
            if process.poll() is None:
                receipt.update(cancelled=True, cancellation_signal='SIGINT', cancellation_monotonic_ns=time.monotonic_ns())
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=cleanup_timeout)
                except subprocess.TimeoutExpired:
                    receipt['forced_termination'] = 'cleanup deadline expired; Android cleanup remains unproved'
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
            receipt.update(code=process.returncode, local_reaped=process.returncode is not None,
                           completed_monotonic_ns=time.monotonic_ns())
            if cancel.is_set():
                receipt['cancelled'] = True
    if primary is not None:
        raise primary
    assert process is not None and receipt['local_reaped']
    return process.returncode
