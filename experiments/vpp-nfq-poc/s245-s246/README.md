# S245 / S246 single-owner UDP4 copy experiment

Execution registration: 2026-09-07. This directory contains a throwaway C/VPP
experiment, not a product implementation or import source. Plane S245 and S246
remain the acceptance authority. Existing OI3 Android broker, TUN, HEV session,
and bounded external-driver tools are experimental scaffolding only.

## Registered scope and stopping rules

- Pixel 6a `28201JEGR0XPAJ`, one real VPP worker, IPv4 UDP, real pinned HEV/lwIP.
- Fresh native/plugin/JNI/APK builds with source snapshots and SHA-256 manifests.
- A controlled Android application socket traverses its narrow VPN route, TUN,
  VPP, HEV/lwIP and the existing bind/protect broker to a real UDP endpoint.
  The historical harness projects the controlled destination to a loopback
  endpoint. That projection and its extra staging copies are recorded; this is
  not an unmodified public-Internet or product graph claim.
- Each cell has at most three application datagrams, a 4-second receive timeout
  per datagram, a 30-second observation window and a 10-second bounded stop.
  Endpoint delay is 250 ms in the delayed cell. No CPU/performance claim.
- Input cells: ordinary success, delayed reply with native-buffer reuse,
  packet-credit rejection, pbuf allocation rejection, and rejection after pbuf
  allocation. Failure affects only the selected datagram; a following datagram
  on the same application socket must succeed without an implicit flow stop.
- Output cells, after S245: ordinary success, policy DROP, allocation failure,
  allocated-buffer submit rejection, TUN completion failure, controlled chain,
  and controlled synchronous lwIP output. Controlled variants are labelled and
  do not impersonate naturally occurring chain/reentrancy evidence.
- All cells require per-object ordering and separate input/output/native-buffer,
  pbuf and credit conservation. Input native free follows submit return and
  adapter completion. Output graph execution follows callback return on the
  same owner. Only submission determines the callback result; downstream DROP
  and TUN failures do not alter it. Return provenance is FLOW_STACK_RETURN/INPUT.
- Unexpected payload, ownership/order mismatch, nonzero resource residue,
  unbounded execution or an unexplained crash is HOLD. Preserve the failure;
  do not relax the registered criterion. Corrections get a new artifact/run.

2026-09-07 execution refinement before the S246 correction rerun: the first
output-allocation failure exposed 399 owner steps, most with zero task quanta,
after HEV disabled its receive half. Classify 32 consecutive zero-quanta owner
steps as a no-progress failure in this three-datagram experiment. This detects
the observed readable-socket wake loop; it is not a production CPU budget.

The first experimental pass verifies the actual available seam and documents
limitations. S245/S246 cannot be marked complete using old logs, a host-only
test, a handcrafted replacement transport, or a passing subset of these cells.
