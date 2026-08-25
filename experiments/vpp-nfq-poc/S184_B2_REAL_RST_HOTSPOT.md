# S184 B2 real LAN TCP RST hotspot

Execution and retry are governed by
[`ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md`](ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md),
especially the distinct timeout/reset/refusal rule and the bounded hotspot
retry rule.

Date: 2026-08-25
Status: `CLOSED_FOR_BOUNDED_REAL_RST_SLICE`

## Decision

S184 was the smallest remaining B2 slice after S183: retain the real
full-device AppA → VpnService → OI3 multi path, keep a passing UDP control,
and replace S181's unbound TCP port with a WSL2/LAN listener that sends a real
TCP reset using `SO_LINGER(1, 0)`.  The test was valid and the reset fixture
was reached, but the current owner connector did not surface the reset as a
transport error.  The later bounded correction surfaced the exact owner-local
`ECONNRESET` and exposed the remaining downstream reset-propagation gap.
That downstream propagation seam is now corrected and the bounded real-device
oracle passes on the raw authoritative evidence.  The hotspot stop is lifted
for S184.  Do not generalize this narrow result to public-Internet refusal,
arbitrary TCP teardown, or production timeout policy.

This is a new transport-event/cleanup design gap, not a UID-drop regression.
S183's UID sentinel correction remains untouched and its evidence remains
valid.

## Accepted run

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s184-b2-real-rst-20260825/
```

Run ID: `20260825-193618-437793`
Device: `28201JEGR0XPAJ` (Pixel 6a)
Fixture host: `192.168.4.5`
Reset port: `53546`

Runner and fixture:

```text
experiments/vpp-nfq-poc/scripts/android-run-s184-b2-real-rst.sh
experiments/vpp-nfq-poc/scripts/s184-rst-fixture.py
experiments/vpp-nfq-poc/scripts/tests/test_verify_s184_b2_real_rst.py
```

Artifact provenance is recorded in `apk-provenance.tsv` and
`source-provenance.properties`.  The accepted VPN APK hash is
`a222fd3a82993903aa67f1f377b0787891556ee72036c682719597663c2fd12c`; AppA is
`24eb2af558fdb44a300e86a08643125b048c3d31b14ca9272cebc0674a2d3a88`.

## Result

The wrapper waited for S181's `tcp_timeout_port_unbound` event before binding
the reset listener.  The fixture then recorded all three required events:

```text
tcp_rst_ready port=53546
tcp_rst_connection peer=192.168.4.151:45954 port=53546
tcp_rst_sent peer=192.168.4.151:45954 port=53546
```

The positive control passed.  Its AppA record was
`udp_datagram_sent/dns_response_received`; the fixture received and answered
the query; native Direct/TUN output and cleanup were valid.

The real-RST cell did not produce a refusal verdict:

| Evidence | Observed result |
| --- | --- |
| AppA | `tcp_connect_succeeded/dns_response_timeout`, `tuple_attempted=true` |
| Fixture | one TCP connection accepted and one RST sent |
| Broker | `broker=1/1` / protected path admitted |
| Native output | `output=1`, `handshake=1`, `rewritten=1`, `direct=0` |
| Native error | `transport-failures=0`, `connector-error=0`, `reported=0`, `infrastructure-failures=0` |
| Cleanup | `oi3_cleanup result=FAIL outcome=EXPECTED_REAL_TRANSPORT_REFUSAL ... error=unexpected-real-refused` |
| Settlement | `buffers=12/12 residue=0`, no residual VPP or `tun0` |

The machine-readable summary is `status=FAIL`, `pass_count=1`,
`failure_count=1`.  The failure is the expected hotspot: fixture evidence
proves a reset was sent, while neither AppA nor the owner connector publishes
a reset/refusal event.

Key raw lines from
`cells/20260825-193618-437793/closed-tcp-timeout/vpp-stdout.log`:

```text
oi3 connector-connect result=-1 errno=115 endpoint-port=53546 ...
oi3 connector-so-error step=2 fd=36 error=0 OK
oi3 connector-so-error step=3 fd=36 error=0 OK
oi3_cleanup result=FAIL outcome=EXPECTED_REAL_TRANSPORT_REFUSAL ... transport-failures=0 ... connector-error=0 reported=0 ... error=unexpected-real-refused
```

## Root cause and boundary

The full-device TUN parser assigns this packet's cell as ordinary `TCP4` and
sets `expected_real_refused` from the test intent.  The existing bounded
`oi3_probe_refusal()` path is guarded by `tm->cell == OI3_CELL_REFUSED`, so it
does not run for this real-TUN packet.  The normal connector watcher only
reported `SO_ERROR=0` before the owner stopped; no `POLLERR`/`POLLHUP`,
`ECONNRESET`, or equivalent HEV read/close event was joined to the generation.
The cleanup classifier nevertheless entered the real-refusal branch because
the expectation flag was set, then correctly rejected the missing transport
evidence and emitted `FAIL`.

This proves a real post-SYN reset fixture reaches the LAN listener, but it does
not prove that Android's underlay delivered a pre-connect `ECONNREFUSED`, and it
does not justify synthesizing refusal from a timeout.  The current result is
therefore neither policy drop nor infrastructure failure:

- policy drop is ruled out by broker/protected admission and TUN handshake;
- bind/protect failure is ruled out by `broker=1/1`;
- infrastructure failure is ruled out by `infrastructure-failures=0` and exact
  buffer settlement;
- timeout-only classification is insufficient because the fixture sent RST,
  yet the owner never observed a reset event.

## Owner-event correction and valid rerun

The selected correction was the owner-local HEV event seam, not a descriptor
observer that competes for `SO_ERROR`:

- readiness only wakes the canonical owner generation;
- the HEV session that owns `readv`/`writev` publishes the exact result
  synchronously through a connector callback;
- post-SYN reset uses the distinct
  `EXPECTED_REAL_TRANSPORT_RESET`/`PASS_EXPECTED_REAL_RESET` vocabulary;
- EOF is not relabelled as `ECONNRESET`, and the plugin does not use
  `MSG_PEEK` or a second `SO_ERROR` consumer.

The rebuilt HEV, plugin, VPN APK, and AppA were exercised once in:

```text
experiments/vpp-nfq-poc/evidence/s184-b2-real-rst-owner-event-20260825/
```

Run ID: `20260825-203915-342533`.  VPN APK SHA-256:
`afa2fa1965e1d1cf17791ab43e889957f25b136dbdfe7af8d2b2933e440205e8`;
OI3 plugin:
`fb72ef36acf6919fd983cdd62cc0c8f667b02d7b0ec1ad8f3cc58ca1cc6e7b05`;
HEV:
`3afc3c4896ffa5ba16bfe954fd49c278cc4a6aaa0c71f73d94739bf77513ae1f`;
AppA:
`05a6081804235ba8618cd1d27f329c9e7080161661f8144fd6034388acc9b24c`.

The UDP control passed and the registered fixture again accepted the AppA
connection and sent its RST.  The owner-event seam also worked exactly once:

```text
oi3 transport-event result=READ_ERROR errno=104 Connection reset by peer \
  owner=2 generation=1 ... reset-observed=1
```

This closes the original observation half of VPN-F058.  It also falsifies the
old reset-cell assumption that `direct=0`: the App payload had already crossed
the protected connector before the post-SYN RST, so `direct=1` is required and
expected.  The valid run recorded `broker=1/1`, `handshake=1`, `direct=1`,
`transport-failures=1`, `connector-error=104`, `reported=1`,
`reset-observed=1`, `peer-eof=0`, `infrastructure-failures=0`, and exact
`buffers=7/7 residue=0` settlement.

## Downstream-reset correction and closure

The remaining cause was concrete: HEV detected the protected-socket
`ECONNRESET`, but owner-context `tcp_abort_ctx()` was a silent
`tcp_close_ctx()` purge/free and emitted no terminal segment toward AppA.  A
global change to every abort would have altered timeout, stop, and cleanup
semantics, so the correction adds the narrow owner-context operation
`tcp_send_reset_ctx()` and invokes it only when the owning HEV TCP session sees
an exact `ECONNRESET`.  It builds an owner-local `RST|ACK` from the current PCB,
passes it through the existing output/rewrite callback, and leaves PCB
destruction to the ordinary teardown path.  Per-session attempted/sent fields
make the operation once-only.

The single bounded device rerun is:

```text
experiments/vpp-nfq-poc/evidence/s184-b2-real-rst-downstream-reset-20260825/
run_id=20260825-210129-290257
```

Artifact SHA-256 values:

```text
VPN APK  17de535ad2a9f4e424bfdf73795d86fd1bba87ff07732ea2ce58701184fb4187
AppA     05a6081804235ba8618cd1d27f329c9e7080161661f8144fd6034388acc9b24c
OI3      b2242cd7bcc523e1f5128277cc2af74fdb08e9a24a30b5fd0176e7798060487e
HEV      420e67e71029888c3d6423b24a513bf6ed760fd159762903f22ee4235d016466
```

The positive UDP control passed.  In the reset cell the fixture accepted the
connection and sent its registered RST; the owner recorded one
`READ_ERROR errno=104`; output hex carried TCP flags `0x14` (`RST|ACK`); AppA
recorded `tcp_payload_sent/dns_response_reset` with `Connection reset`; and
cleanup recorded:

```text
oi3 downstream-transport result=RST ... reset-observed=1
oi3 transport-event result=READ_ERROR errno=104 ... reset-observed=1
oi3_cleanup result=PASS_EXPECTED_REAL_RESET \
  outcome=EXPECTED_REAL_TRANSPORT_RESET output=3 handshake=1 direct=1 \
  rewritten=3 broker=1/1 transport-failures=1 infrastructure-failures=0 \
  downstream-reset-observed=1 direct-send=1 buffers=7/7 residue=0 error=
```

There was no residual VPP process or `tun0`.

The run wrapper returned `1` only because the old verifier concatenated
`native-combined.log` (which already embeds `vpp-stdout.log`) and then read
`vpp-stdout.log` again.  It counted one reset event twice and wrote a false
`downstreamReset=2` into the derived CSV/manifest.  Each authoritative source
contains exactly one event and the owner cleanup counters are one.  The parser
is corrected to treat mirrored reset log lines as presence markers while
retaining the exact-once cleanup gates.  Raw device evidence was not rewritten
and the device cell was not rerun for this verifier-only defect.

The S184 oracle is therefore satisfied:

1. exact upstream owner-local `ECONNRESET`, once;
2. downstream owner-output `RST|ACK` on the same generation;
3. AppA `dns_response_reset`, not timeout or EOF;
4. one transport failure, zero infrastructure/policy fallback, and exact
   cleanup settlement.

This closes VPN-F058 for the bounded AppA → VpnService → OI3 multi → controlled
LAN reset slice.  It does not prove pre-connect `ECONNREFUSED`, public-Internet
behavior, arbitrary teardown mapping, long soak, Doze, or production timeout
constants.

## Reproduction and verification

```bash
rtk bash experiments/vpp-nfq-poc/scripts/android-run-s184-b2-real-rst.sh
rtk bash -n experiments/vpp-nfq-poc/scripts/android-run-s184-b2-real-rst.sh experiments/vpp-nfq-poc/scripts/android-run-s181-b2-full-device-transport-explore.sh
rtk env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest experiments.vpp-nfq-poc.scripts.tests.test_verify_s184_b2_real_rst
```

The current S184 static suite passes 9/9 tests; the adjacent S181--S184 suite
passes 21/21.  Shell syntax and `git diff --check` pass.  The full historical
`test_verify_s*.py` discovery currently also exposes an unrelated pre-existing
S168 assertion about TCP stale-tail clearing; that is not S184 evidence and was
not changed as part of this correction.

Evidence hashes:

```text
tcp-rst-fixture.log       d5168de02790a01af588f8008052ce1befa2e8a88c85250bb44895c0e778bf03
fixture-*.log             4fc101be7f12733439322be528cb62b087f0f1a43165347711bb63a44237c979
cells-*.csv               cd432602b4aadd8200d60805876df2e9e94661f55b7445384ba7daed4d11b3bf
run-*-manifest.json       22fa5ee868602777016b7538750d3b39b7ed42799d943f9519cd322b5d8257bc
```

Owner-event rerun hashes:

```text
tcp-rst-fixture.log       1e00dcd55ad0465a76982a34209b7bbdbd503a996a43326541661a371f5ef39e
cells-*.csv               86222f6ee17597a9223d979b023cfc2e8d7778f829e698b76d4cee92759e2abd
run-*-manifest.json       94a5d3278cf1d2cd38fe141d7362f2d829cbf98554c740596f12b0f9e1178a8f
closed native log         412a2b893353d85d27d179e57cf156f696ac48af249bc82bf677a50584ea095c
```

Downstream-reset closure hashes:

```text
tcp-rst-fixture.log       77e9472627985acf7c12003effefd4a92d2b5df545673e84342a5f38f08ce252
closed native log         c5b56429f4c8ef8b7c423976a716fec6f3f6b2609c93722544a13871b44785a3
AppA runtime JSONL        71d04ae329862e18e75079bd71233a0a5f4785d4cc99815086115b2e1ad2bcaa
APK provenance            8d173f2777eb777627814d46cca2ca6060b74d6fbdae1c9112530a403bd256e7
```
