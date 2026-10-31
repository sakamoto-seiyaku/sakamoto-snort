"""Independent bounded HTTPS DoH peer (HTTP/1.1 POST application/dns-message).

Test-owned sockets and one thread only. The interface mirrors s322_dot_peer.Peer so the
shared routed-exchange helpers work unchanged; `mode` selects the planned HTTP behavior
for the next exchanges: ok, age=<n>, chunked, split, status404, redirect, wrongtype,
early_close, close_delimited, alpn_refuse (HTTP/2-only endpoint).
"""
import json
import selectors
import ssl
import socket
import threading
import time

REQUEST_LIMIT = 70000


class Peer:
    def __init__(self, addresses, out, deadline, context, port=15353, *, path='/dns-query', handshake_gate=None):
        self.tls_context, self.handshake_gate, self.path = context, handshake_gate, path
        self.out, self.deadline, self.port = out, deadline, port
        self.mode = 'ok'
        self.transports = ('tcp',)
        self.lock = threading.RLock()
        self.messages, self.responses, self.connections, self.waiting = [], {}, {}, []
        self.sequence = self.connection_sequence = 0
        self.retained_bytes = 0
        self.error = None
        self.stop_event, self.ready = threading.Event(), threading.Event()
        self.selector, self.sockets = selectors.DefaultSelector(), []
        self.log = (out / 'peer-linux.jsonl').open('x')
        try:
            for address in addresses:
                family = socket.AF_INET6 if ':' in address else socket.AF_INET
                channel = socket.socket(family, socket.SOCK_STREAM)
                self.sockets.append(channel)
                channel.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6: channel.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                channel.bind((address, port)); channel.setblocking(False); channel.listen(16)
                self.selector.register(channel, selectors.EVENT_READ, 'listener')
            self.emit(dict(kind='ready', backend='independent Python/OpenSSL HTTPS server', port=port, path=path,
                           endpoints=[list(s.getsockname()) for s in self.sockets], relative_clock='monotonic'))
            self.thread = threading.Thread(target=self.run, name='s323-independent-doh-peer')
            self.thread.start(); self.ready.set()
        except BaseException:
            for channel in self.sockets: channel.close()
            self.selector.close(); self.log.close()
            raise

    def emit(self, row):
        row = dict(row, host_monotonic_ns=time.monotonic_ns())
        with self.lock:
            encoded = json.dumps(row) + '\n'
            assert len(self.messages) < 32768 and self.retained_bytes + len(encoded) <= 32 * 1024 * 1024
            self.retained_bytes += len(encoded)
            self.messages.append(row)
            self.log.write(encoded); self.log.flush()

    def register(self, query, reply, *, protocol='tcp', port=None, gate=None, delay=0, drop=False, split=False, gate_seconds=30):
        port = self.port if port is None else port
        assert port == self.port and protocol == 'tcp'
        assert len(query) >= 2 and len(reply) <= 65535 and 0 <= delay <= 15000
        assert 1 <= gate_seconds <= 120 and (gate or gate_seconds == 30)
        with self.lock:
            self.responses[query[2:]] = dict(reply=reply, gate=gate, delay=delay / 1000, drop=drop, split=split,
                                             gate_seconds=gate_seconds)

    def cursor(self):
        with self.lock:
            if self.error: raise RuntimeError('independent peer failed') from self.error
            return self.sequence

    def received(self, query, protocol='tcp', port=None, *, after=0):
        port = self.port if port is None else port
        assert protocol == 'tcp'
        with self.lock:
            if self.error: raise RuntimeError('independent peer failed') from self.error
            return [r for r in self.messages if r['kind'] == 'received' and r['resolver'][1] == port
                    and r['request'] > after and bytes.fromhex(r['request_hex'])[2:] == query[2:]]

    def requests(self, *, after=0):
        with self.lock:
            return [r for r in self.messages if r['kind'] == 'received' and r['request'] > after]

    # --- HTTP -------------------------------------------------------------------------
    @staticmethod
    def parse_request(data):
        """Returns (headers, body) when complete, None while incomplete; raises on a bad request."""
        end = data.find(b'\r\n\r\n')
        if end < 0:
            assert len(data) <= 8192, 'request head too large'
            return None
        lines = bytes(data[:end]).decode('latin-1').split('\r\n')
        method, target, version = lines[0].split(' ')
        headers = {}
        for line in lines[1:]:
            name, value = line.split(':', 1)
            assert name.lower() not in headers, 'duplicate request header'
            headers[name.lower()] = value.strip()
        length = int(headers.get('content-length', '-1'))
        assert 0 <= length <= 65535, 'request length'
        if len(data) < end + 4 + length: return None
        assert len(data) == end + 4 + length, 'bytes after request'
        return dict(method=method, target=target, version=version, headers=headers), bytes(data[end + 4:])

    def response_bytes(self, mode, reply):
        head = lambda status, extra, length=None: (f'HTTP/1.1 {status}\r\n' + extra
            + ('' if length is None else f'Content-Length: {length}\r\n') + 'Connection: close\r\n\r\n').encode()
        typed = 'Content-Type: application/dns-message\r\n'
        if mode == 'ok' or mode == 'split':
            return head('200 OK', typed, len(reply)) + reply
        if mode.startswith('age='):
            return head('200 OK', typed + 'Age: ' + mode[4:] + '\r\n', len(reply)) + reply
        if mode == 'chunked':
            out = head('200 OK', typed + 'Transfer-Encoding: chunked\r\n')
            for at in range(0, len(reply), 24):
                piece = reply[at:at + 24]
                out += f'{len(piece):x};part\r\n'.encode() + piece + b'\r\n'
            return out + b'0\r\nX-Trailer: ignored\r\n\r\n'
        if mode == 'close_delimited':
            return head('200 OK', typed) + reply
        if mode == 'status404':
            return head('404 Not Found', 'Content-Type: text/plain\r\n', 9) + b'not found'
        if mode == 'redirect':
            return head('301 Moved Permanently', 'Location: https://redirect.invalid/dns-query\r\n', 0)
        if mode == 'wrongtype':
            return head('200 OK', 'Content-Type: application/json\r\n', len(reply)) + reply
        raise AssertionError(mode)

    def admit(self, request, wire, remote, channel, connection):
        assert 12 <= len(wire) <= 65535 and len(self.waiting) < 1024
        headers = request['headers']
        with self.lock:
            assert self.sequence < 8192
            self.sequence += 1
            row = dict(kind='received', request=self.sequence, request_hex=wire.hex(), protocol='tcp',
                       resolver=list(channel.getsockname())[:2], peer=list(remote)[:2], connection=connection,
                       http=dict(method=request['method'], target=request['target'], version=request['version'],
                                 host=headers.get('host'), content_type=headers.get('content-type'),
                                 accept=headers.get('accept'), connection=headers.get('connection'),
                                 content_length=headers.get('content-length'), alpn=channel.selected_alpn_protocol()),
                       mode=self.mode)
            self.emit(row)
            entry = self.responses.get(wire[2:])
        if entry is None:
            reply = bytearray(wire)
            reply[2:4] = b'\x81\x83'; reply[6:10] = bytes(4)
            entry = dict(reply=bytes(reply), gate=None, delay=0, drop=False, split=False, gate_seconds=30)
            row['unplanned'] = True
        self.waiting.append(dict(row=row, wire=wire, channel=channel, entry=entry, mode=self.mode,
                                 due=time.monotonic() + entry['delay'],
                                 deadline=min(self.deadline, time.monotonic() + entry['gate_seconds']),
                                 offset=0, payload=None))

    def close_connection(self, channel, reason, *, orderly=False):
        item = self.connections.pop(channel, None)
        if item is None: return
        if channel in self.selector.get_map(): self.selector.unregister(channel)
        if orderly:
            try:
                channel.setblocking(True); channel.settimeout(1); channel.unwrap()
            except (OSError, ssl.SSLError, ValueError):
                pass
        channel.close()
        for pending in list(self.waiting):
            if pending['channel'] is channel:
                self.emit(dict(pending['row'], kind='cancelled', reason=reason))
                self.waiting.remove(pending)
        self.emit(dict(kind='connection_closed', connection=item['id'], reason=reason))

    def run(self):
        try:
            while not self.stop_event.is_set():
                assert time.monotonic() < self.deadline, 'independent Linux peer deadline'
                for key, _ in self.selector.select(.005):
                    channel = key.fileobj
                    if key.data == 'listener':
                        client, remote = channel.accept()
                        if len(self.connections) == 32: client.close(); raise RuntimeError('peer TCP capacity')
                        if self.mode == 'alpn_refuse':
                            # An HTTP/2-only endpoint: no mutual ALPN protocol, so the server answers the
                            # ClientHello with a plaintext fatal no_application_protocol (120) alert.
                            client.setblocking(True); client.settimeout(2)
                            try:
                                hello = client.recv(4096)
                                client.sendall(b'\x15\x03\x03\x00\x02\x02\x78')
                            except OSError:
                                hello = b''
                            client.close()
                            self.connection_sequence += 1
                            self.emit(dict(kind='alpn_alert', connection=self.connection_sequence, hello_bytes=len(hello)))
                            continue
                        client.setblocking(False)
                        client = self.tls_context.wrap_socket(client, server_side=True, do_handshake_on_connect=False)
                        self.connection_sequence += 1
                        self.connections[client] = dict(id=self.connection_sequence, remote=remote, bytes=bytearray(),
                                                        eof=False, authenticated=False, served=False)
                        self.selector.register(client, selectors.EVENT_READ, 'tcp')
                        self.emit(dict(kind='connected', connection=self.connection_sequence))
                        continue
                    item = self.connections.get(channel)
                    if item is None: continue
                    if not item['authenticated']:
                        if self.handshake_gate is not None and not self.handshake_gate.is_set(): continue
                        try: channel.do_handshake()
                        except ssl.SSLWantReadError:
                            self.selector.modify(channel, selectors.EVENT_READ, 'tcp'); continue
                        except ssl.SSLWantWriteError:
                            self.selector.modify(channel, selectors.EVENT_WRITE, 'tcp'); continue
                        except (ssl.SSLError, ConnectionError) as error:
                            self.emit(dict(kind='tls_refused', connection=item['id'], reason=repr(error)[:160]))
                            self.close_connection(channel, 'tls_authentication_closed'); continue
                        item['authenticated'] = True
                        self.selector.modify(channel, selectors.EVENT_READ, 'tcp')
                        self.emit(dict(kind='authenticated', connection=item['id'], version=channel.version(),
                                       cipher=channel.cipher(), alpn=channel.selected_alpn_protocol()))
                    try: data = channel.recv(65536)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError): continue
                    except (ConnectionResetError, BrokenPipeError, ssl.SSLError): self.close_connection(channel, 'read_disconnect'); continue
                    if not data:
                        self.selector.unregister(channel); item['eof'] = True
                        continue
                    item['bytes'].extend(data)
                    assert len(item['bytes']) <= REQUEST_LIMIT
                    parsed = None if item['served'] else self.parse_request(item['bytes'])
                    if parsed is not None:
                        item['served'] = True
                        request, wire = parsed
                        self.admit(request, wire, item['remote'], channel, item['id'])
                for pending in list(self.waiting):
                    entry, channel = pending['entry'], pending['channel']
                    waiting = time.monotonic() < pending['due'] or (entry['gate'] and not entry['gate'].exists())
                    if entry['gate'] or waiting:
                        assert time.monotonic() < pending['deadline'], 'independent peer gate deadline'
                    if waiting: continue
                    mode = pending['mode']
                    if entry['drop'] or mode == 'early_close':
                        self.emit(dict(pending['row'], kind='cancelled', reason='planned_silence' if entry['drop'] else 'early_close'))
                        self.waiting.remove(pending)
                        if mode == 'early_close': self.close_connection(channel, 'early_close')
                        continue
                    reply = pending['wire'][:2] + entry['reply'][2:]
                    try:
                        if pending['payload'] is None: pending['payload'] = self.response_bytes(mode, reply)
                        payload, offset = pending['payload'], pending['offset']
                        take = 7 if mode == 'split' else len(payload)
                        pending['offset'] += channel.send(payload[offset:offset + take])
                        if pending['offset'] < len(payload):
                            pending['due'] = time.monotonic() + (.03 if mode == 'split' else 0); continue
                    except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError): continue
                    except (ConnectionResetError, BrokenPipeError, ssl.SSLError): self.close_connection(channel, 'write_disconnect'); continue
                    self.emit(dict(pending['row'], kind='exchange', reply_hex=reply.hex(), sent_bytes=len(pending['payload']), mode=mode))
                    self.waiting.remove(pending)
                    # One exchange per connection; an orderly TLS close also ends close-delimited bodies.
                    self.close_connection(channel, 'response_sent', orderly=True)
                for channel, item in list(self.connections.items()):
                    if item['eof'] and not any(p['channel'] is channel for p in self.waiting):
                        self.close_connection(channel, 'eof_after_replies')
        except BaseException as error:
            self.error = error; self.emit(dict(kind='error', error=repr(error)))
        finally:
            for channel in list(self.connections): self.close_connection(channel, 'peer_stop')
            for item in self.waiting: self.emit(dict(item['row'], kind='cancelled', reason='peer_stop'))
            self.waiting.clear()
            for channel in self.sockets: channel.close()
            self.selector.close()
            self.emit(dict(kind='stopped', pending=0, connections=0, sockets=0))

    def close(self):
        self.stop_event.set(); self.thread.join(timeout=5)
        assert not self.thread.is_alive(), 'owned Linux peer did not stop'
        self.log.close()
        assert not self.error, self.error
        received = [r for r in self.messages if r['kind'] == 'received']
        settled = [r for r in self.messages if r['kind'] in ('exchange', 'cancelled')]
        assert sorted(r['request'] for r in received) == sorted(r['request'] for r in settled)
        assert all(channel.fileno() == -1 for channel in self.sockets)
        (self.out / 'peer-linux-cleanup.json').write_text(json.dumps(dict(status='PASS', thread_stopped=True,
            sockets_closed=True, received=len(received), settled=len(settled)), indent=2) + '\n')
