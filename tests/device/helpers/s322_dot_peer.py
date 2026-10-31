"""Independent bounded authenticated DoT peer; only test-owned sockets/threads."""
import json
import selectors
import ssl
import socket
import struct
import threading
import time


class Peer:
    def __init__(self, addresses, out, deadline, context, port=15353, *, handshake_gate=None):
        self.tls_context=context
        self.handshake_gate=handshake_gate
        transports=('tcp',)
        self.out, self.deadline, self.port = out, deadline, port
        self.transports = tuple(transports)
        assert self.transports and len(set(self.transports)) == len(self.transports)
        assert all(transport in ('udp', 'tcp') for transport in self.transports)
        self.lock = threading.RLock()
        self.messages, self.responses, self.connections, self.waiting = [], {}, {}, []
        self.sequence = self.connection_sequence = 0
        self.retained_bytes = 0
        self.error = None
        self.stop_event, self.ready = threading.Event(), threading.Event()
        self.selector, self.sockets = selectors.DefaultSelector(), []
        self.log = (out/'peer-linux.jsonl').open('x')
        try:
            for address in addresses:
                family = socket.AF_INET6 if ':' in address else socket.AF_INET
                for kind, protocol in ((socket.SOCK_DGRAM, 'udp'), (socket.SOCK_STREAM, 'listener')):
                    if ('tcp' if protocol == 'listener' else protocol) not in self.transports: continue
                    channel = socket.socket(family, kind)
                    self.sockets.append(channel)
                    if family == socket.AF_INET6: channel.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    channel.bind((address, port)); channel.setblocking(False)
                    if protocol == 'listener': channel.listen(16)
                    self.selector.register(channel, selectors.EVENT_READ, protocol)
            self.emit(dict(kind='ready', backend='independent Python/OpenSSL TLS server', port=port, transports=list(self.transports),
                           endpoints=[list(s.getsockname()) for s in self.sockets], relative_clock='monotonic'))
            self.thread = threading.Thread(target=self.run, name='s322-independent-dot-peer')
            self.thread.start(); self.ready.set()
        except BaseException:
            for channel in self.sockets: channel.close()
            self.selector.close(); self.log.close()
            raise

    def emit(self, row):
        row = dict(row, host_monotonic_ns=time.monotonic_ns())
        with self.lock:
            encoded = json.dumps(row)+'\n'
            assert len(self.messages) < 32768 and self.retained_bytes+len(encoded) <= 32*1024*1024
            self.retained_bytes += len(encoded)
            self.messages.append(row)
            self.log.write(encoded); self.log.flush()

    def register(self, query, reply, *, protocol='udp', port=None, gate=None, delay=0, drop=False, split=False, gate_seconds=30):
        port = self.port if port is None else port
        assert port == self.port and protocol in self.transports
        assert len(query) >= 2 and len(reply) <= 65535 and 0 <= delay <= 15000
        assert 1 <= gate_seconds <= 120 and (gate or gate_seconds == 30)
        with self.lock:
            self.responses[(protocol, query[2:])] = dict(reply=reply, gate=gate, delay=delay/1000, drop=drop, split=split, gate_seconds=gate_seconds)

    def cursor(self):
        with self.lock:
            if self.error: raise RuntimeError('independent peer failed') from self.error
            return self.sequence

    def received(self, query, protocol='udp', port=None, *, after=0):
        port = self.port if port is None else port
        assert protocol in self.transports
        with self.lock:
            if self.error: raise RuntimeError('independent peer failed') from self.error
            return [r for r in self.messages if r['kind'] == 'received' and r['protocol'] == protocol
                    and r['resolver'][1] == port and r['request'] > after
                    and bytes.fromhex(r['request_hex'])[2:] == query[2:]]

    def admit(self, wire, remote, channel, protocol, connection=0):
        assert 2 <= len(wire) <= 65535 and len(self.waiting) < 1024
        with self.lock:
            assert self.sequence < 8192
            self.sequence += 1
            row = dict(kind='received', request=self.sequence, request_hex=wire.hex(), protocol=protocol,
                       resolver=list(channel.getsockname())[:2], peer=list(remote)[:2], connection=connection)
            self.emit(row)
            entry = self.responses.get((protocol, wire[2:]))
        if entry is None:
            reply = bytearray(wire)
            if len(reply) >= 12: reply[2:4] = b'\x81\x83'; reply[6:10] = bytes(4)
            entry = dict(reply=bytes(reply), gate=None, delay=0, drop=False, split=False, gate_seconds=30)
            row['unplanned'] = True
        self.waiting.append(dict(row=row, wire=wire, channel=channel, remote=remote,
                                 entry=entry, due=time.monotonic()+entry['delay'], deadline=min(self.deadline,time.monotonic()+entry['gate_seconds']),
                                 offset=0, framed=None))

    def close_connection(self, channel, reason):
        item = self.connections.pop(channel, None)
        if item is None: return
        if channel in self.selector.get_map(): self.selector.unregister(channel)
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
                    if key.data == 'udp':
                        while True:
                            try: wire, remote = channel.recvfrom(65536)
                            except BlockingIOError: break
                            self.admit(wire, remote, channel, 'udp')
                    elif key.data == 'listener':
                        client, remote = channel.accept()
                        if len(self.connections) == 32: client.close(); raise RuntimeError('peer TCP capacity')
                        client.setblocking(False)
                        client = self.tls_context.wrap_socket(client, server_side=True, do_handshake_on_connect=False)
                        self.connection_sequence += 1
                        self.connections[client] = dict(id=self.connection_sequence, remote=remote, bytes=bytearray(), eof=False, authenticated=False)
                        self.selector.register(client, selectors.EVENT_READ, 'tcp')
                        self.emit(dict(kind='connected', connection=self.connection_sequence))
                    else:
                        item = self.connections[channel]
                        if not item['authenticated']:
                            if self.handshake_gate is not None and not self.handshake_gate.is_set(): continue
                            try: channel.do_handshake()
                            except ssl.SSLWantReadError:
                                self.selector.modify(channel, selectors.EVENT_READ, 'tcp'); continue
                            except ssl.SSLWantWriteError:
                                self.selector.modify(channel, selectors.EVENT_WRITE, 'tcp'); continue
                            except (ssl.SSLError, ConnectionError):
                                self.close_connection(channel, 'tls_authentication_closed'); continue
                            item['authenticated']=True
                            self.selector.modify(channel, selectors.EVENT_READ, 'tcp')
                            self.emit(dict(kind='authenticated', connection=item['id'], version=channel.version(), cipher=channel.cipher()))
                        try: data = channel.recv(65536)
                        except (ssl.SSLWantReadError, ssl.SSLWantWriteError): continue
                        except (ConnectionResetError, BrokenPipeError, ssl.SSLError): self.close_connection(channel, 'read_disconnect'); continue
                        if not data:
                            self.selector.unregister(channel); item['eof'] = True
                            continue
                        item['bytes'].extend(data)
                        assert len(item['bytes']) <= 131074
                        while len(item['bytes']) >= 2:
                            size = int.from_bytes(item['bytes'][:2], 'big')
                            if len(item['bytes']) < size+2: break
                            wire = bytes(item['bytes'][2:size+2]); del item['bytes'][:size+2]
                            self.admit(wire, item['remote'], channel, 'tcp', item['id'])
                for pending in list(self.waiting):
                    entry, channel = pending['entry'], pending['channel']
                    waiting = time.monotonic() < pending['due'] or (entry['gate'] and not entry['gate'].exists())
                    if entry['gate'] or waiting:
                        assert time.monotonic() < pending['deadline'], 'independent peer gate deadline'
                    if waiting: continue
                    if entry['drop']:
                        self.emit(dict(pending['row'], kind='cancelled', reason='planned_silence'))
                        self.waiting.remove(pending); continue
                    reply = pending['wire'][:2]+entry['reply'][2:]
                    try:
                        if pending['row']['protocol'] == 'udp':
                            assert channel.sendto(reply, pending['remote']) == len(reply)
                        else:
                            if pending['framed'] is None: pending['framed'] = struct.pack('!H', len(reply))+reply
                            framed, offset = pending['framed'], pending['offset']
                            take = (1 if offset == 0 else 5 if offset == 1 else len(framed)) if entry['split'] else len(framed)
                            pending['offset'] += channel.send(framed[offset:offset+take])
                            if pending['offset'] < len(framed):
                                pending['due'] = time.monotonic()+(.04 if entry['split'] else 0); continue
                    except (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError): continue
                    except (ConnectionResetError, BrokenPipeError, ssl.SSLError): self.close_connection(channel, 'write_disconnect'); continue
                    self.emit(dict(pending['row'], kind='exchange', reply_hex=reply.hex(), sent_bytes=len(reply)))
                    self.waiting.remove(pending)
                for channel, item in list(self.connections.items()):
                    if item['eof'] and not any(p['channel'] is channel for p in self.waiting): self.close_connection(channel, 'eof_after_replies')
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
        (self.out/'peer-linux-cleanup.json').write_text(json.dumps(dict(status='PASS', thread_stopped=True,
            sockets_closed=True, received=len(received), settled=len(settled)), indent=2)+'\n')
