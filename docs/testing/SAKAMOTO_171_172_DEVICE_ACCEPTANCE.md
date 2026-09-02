# SAKAMOTO-171/172 device acceptance

Date: 2026-08-28

This is the acceptance authority for the Product Spine work currently tracked
by Plane [SAKAMOTO-171](http://192.168.4.22:2080/work/browse/SAKAMOTO-171) and
[SAKAMOTO-172](http://192.168.4.22:2080/work/browse/SAKAMOTO-172). It is a
ticket-local clarification, not a general recovery standard.

Current tracker state: Plane marks SAKAMOTO-171 and SAKAMOTO-172 Done as of
2026-08-30. This file remains the criterion record for that closure; it is not
evidence for later Root, VPN, packet, policy, network, or performance claims.

SAKAMOTO-171's committed Host Rust/C ABI/VAPI work is supporting implementation
and fast semantic evidence. It no longer has a separate real-Host-VPP closure
gate. SAKAMOTO-172 owned the integrated device run below. A valid
SAKAMOTO-172 PASS closes both tickets.

## What counts as PASS

Only this installed-product path qualifies:

```text
new debug APK versionCode
  -> installed through ./dev/adb
  -> visible Debug Activity start action
  -> Java Supervisor / legal foreground service
  -> Rust Product Core
  -> production generated-VAPI bridge
  -> product VPP plugin
```

Pushing and launching a build-tree binary, calling VAPI or native internals
directly, or substituting the Host fixture may help diagnosis but cannot PASS
the tickets.

The qualifying run must complete this sequence on the controlled Android
device:

1. Build and install a debug APK with a new `versionCode`; confirm that the
   installed package reports that version.
2. Start from the visible Debug Activity.
3. Observe a fresh generation with VPP core ready, Adapter unavailable, and
   protection not reported as running.
4. Query twice without restarting. Both replies report the same generation and
   product API identity.
5. Close and reopen the Activity. A new query still reports that generation;
   Activity lifetime did not create or replace the runtime.
6. Stop from the product control and observe `stopped` with no active
   generation.
7. Verify that no product VPP process, API/control socket, generation marker,
   or other generation-owned runtime file remains. An existing empty runtime
   parent directory is allowed.

Every step must pass in the same run. A Host PASS cannot override a failure in
this device sequence.

This S172 sequence is scoped to one continuously alive RuntimeService;
service/process death, lost handles, child adoption, and fresh recovery belong
to S173 and do not block this acceptance.

Product Core does not depend on a numeric PID. The Android public API compile
boundary must reject unsupported `Process.pid()`, `ProcessHandle`, and
`Process.toHandle()` APIs. The visible device Start/Query/Stop sequence above
is the final runtime decision.

## Build boundary

The Android build links only the production generated-VAPI bridge. The
`sakamoto_product_host_fixture_abi.c` fixture remains Host-test-only. Missing
generated VAPI inputs fail the Android build; there is no fixture fallback.

The fresh installed `versionCode` and successful runtime identity query are
the required artifact check for this ticket. Per-library hashes, APK
attestation, and a general external-install provenance framework are not
required.

## Existing boundaries kept elsewhere

- Host ABI, tag/error/panic, session, and stale-generation tests remain useful
  fast evidence in `SAKAMOTO_171_HOST_EVIDENCE.md`.
- Concurrent connect/reconnect, a second VAPI writer, injected identity and
  handshake failures, Task Manager stop, stale callbacks, cleanup failure, and
  fresh recovery belong to SAKAMOTO-173. They do not block the SAKAMOTO-172
  happy path.
- Root/NFQUEUE, VPN/TUN, packet, policy, network, performance, and release
  behavior remain outside both tickets.

## Review changes

After implementation starts, a new review blocker must include a concrete case
showing that the device sequence above can incorrectly PASS, or that a correct
implementation can incorrectly FAIL. Other hardening does not change these
ticket criteria and belongs in its owning later work item.
