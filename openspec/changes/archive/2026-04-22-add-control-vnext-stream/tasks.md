## 1. Stream Core

- [x] 1.1 Add `ControlVNextStreamManager` with per-type subscription + caps
- [x] 1.2 Implement ring buffer + pending queue (drop-oldest) + per-second notice aggregation
- [x] 1.3 Add strict-JSON event builders/encoders for `dns|pkt|activity|notice`

## 2. vNext Command Surface

- [x] 2.1 Add `STREAM.START/STOP` handler with strict args validation
- [x] 2.2 Enforce stream mode state machine (`STATE_CONFLICT` rules, single-subscriber per type)
- [x] 2.3 Implement START ordering: response → `notice="started"` → replay → realtime
- [x] 2.4 Implement STOP semantics: idempotent + ack barrier + clear pending/ring

## 3. Dataplane Hooks

- [x] 3.1 Enqueue DNS verdict snapshots into stream manager (tracked gate + suppressed counters)
- [x] 3.2 Enqueue packet verdict snapshots into stream manager (tracked gate + suppressed counters)
- [x] 3.3 Ensure hot path / `mutexListeners` lock never does socket I/O or heavy JSON

## 4. Lifecycle / Reset / tracked

- [x] 4.1 Change default `tracked=false` (new app + RESETALL baseline) while keeping persistence semantics
- [x] 4.2 Integrate `RESETALL` with stream manager: force stop + disconnect + clear ring/queues + delete legacy stream files

## 5. Tests

- [x] 5.1 Add host tests for `STREAM.START/STOP` started notice ordering and ack barrier
- [x] 5.2 Add host tests for stream `STATE_CONFLICT` rules (non-stream cmds, multi-subscriber)
- [x] 5.3 Extend integration `vnext-baseline.sh` to cover start→event→stop flow (no archive step)

## 6. Build Wiring

- [x] 6.1 Update build files (CMake + `Android.bp`) for new stream sources
