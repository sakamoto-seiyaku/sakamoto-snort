## 1. Settings and vNext Config

- [x] 1.1 Add an internal `NfqueueTopology` enum/string conversion with `split-in-out` as the default
- [x] 1.2 Persist `nfqueue.topology` through `Settings` with older save files defaulting to `split-in-out`
- [x] 1.3 Extend device-scope `CONFIG.GET` to return `nfqueue.topology`
- [x] 1.4 Extend device-scope `CONFIG.SET` to accept only `split-in-out` and `shared-flow-pool`
- [x] 1.5 Reject app-scope or non-string `nfqueue.topology` values with `INVALID_ARGUMENT`

## 2. PacketListener Topology

- [x] 2.1 Add a startup-only queue plan helper for `split-in-out` and `shared-flow-pool`
- [x] 2.2 Keep `split-in-out` installing disjoint INPUT and OUTPUT queue ranges
- [x] 2.3 Install identical INPUT and OUTPUT queue ranges for `shared-flow-pool`
- [x] 2.4 Keep one listener thread per queue in the selected IP-family queue range

## 3. Packet Direction

- [x] 3.1 Add a small NFQUEUE hook-to-direction helper mapping `NF_INET_LOCAL_IN` to input and `NF_INET_LOCAL_OUT` to output
- [x] 3.2 Replace packet decision direction inputs that currently use `_inputTLS` with the per-packet hook-derived direction
- [x] 3.3 Fail open or skip policy processing for unsupported hooks without falling back to listener partition direction
- [x] 3.4 Verify remote IP selection, IPRULES direction, traffic counters, Flow Telemetry direction, and Debug Stream direction all use the same derived direction

## 4. Tests and Verification

- [x] 4.1 Add host coverage for topology config defaults, persistence, valid set/get, and invalid values
- [x] 4.2 Add focused host coverage for queue plan ranges in both topology modes for IPv4 and IPv6
- [x] 4.3 Add focused host coverage for NFQUEUE hook-to-direction mapping and unsupported hook behavior
- [x] 4.4 Run `openspec validate add-nfqueue-topology-modes --strict`
- [x] 4.5 Build and run focused host tests covering Settings/config and PacketListener helpers
- [x] 4.6 Run device datapath validation in `split-in-out` and `shared-flow-pool`, or document why device validation is unavailable

## 5. Documentation

- [x] 5.1 Update the Chinese vNext contract in `docs/INTERFACE_SPECIFICATION.md` with the `nfqueue.topology` device config key, enum values, default, and next-start-only behavior
- [x] 5.2 Add or update Chinese quick-check examples for `CONFIG.GET/SET` covering `nfqueue.topology`
- [x] 5.3 Update roadmap/decision docs if implementation changes any assumption captured by the proposal
