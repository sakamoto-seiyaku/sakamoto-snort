## 1. Endpoint & Build Wiring

- [ ] 1.1 Add vNext socket/port constants in `src/Settings.hpp` (`controlVNextSocketPath`, `controlVNextPort=60607`, `maxRequestBytes/maxResponseBytes`)
- [ ] 1.2 Declare init socket `sucre-snort-control-vnext` in `sucre-snort.rc` (legacy sockets unchanged)
- [ ] 1.3 Extend PacketListener port exemption to cover `60606` + `60607` when `inetControl()` is enabled
- [ ] 1.4 Wire vNext daemon sources into `Android.bp` `sucre-snort` (and keep RapidJSON as SYSTEM include)

## 2. `ControlVNext` Server Skeleton

- [ ] 2.1 Add `src/ControlVNext.hpp` / `src/ControlVNext.cpp` with `start()` spawning unix + gated TCP listeners
- [ ] 2.2 Implement production unix listener via `android_get_control_socket("sucre-snort-control-vnext")`
- [ ] 2.3 Implement dev fallback unix listeners: `/dev/socket/sucre-snort-control-vnext` + `@sucre-snort-control-vnext`
- [ ] 2.4 Implement gated TCP listener on `60607` (only when `settings.inetControl()` is true)
- [ ] 2.5 Wire `ControlVNext` into `src/sucre-snort.cpp` startup (legacy `Control` still starts)

## 3. vNext Session I/O (netstring + strict JSON)

- [ ] 3.1 Implement per-connection session loop: `read()` → `NetstringDecoder(maxRequestBytes)` → strict JSON parse → request envelope validation
- [ ] 3.2 Enforce `len > maxRequestBytes` behavior: immediate disconnect, no response frame
- [ ] 3.3 Implement response write path via codec (`encodeJson` + `encodeNetstring`) and guard `maxResponseBytes`
- [ ] 3.4 Implement structured error helpers for `SYNTAX_ERROR/MISSING_ARGUMENT/INVALID_ARGUMENT/UNSUPPORTED_COMMAND`

## 4. Base Commands (Meta)

- [ ] 4.1 Implement `HELLO` handler: return `protocol/protocolVersion/framing/maxRequestBytes/maxResponseBytes`
- [ ] 4.2 Implement `QUIT` handler: send `ok=true` response then close
- [ ] 4.3 Implement `RESETALL` handler: reuse existing reset pipeline under exclusive `mutexListeners` lock

## 5. Inventory Commands

- [ ] 5.1 Implement `APPS.LIST` (`query/userId/limit` validation, `limit` default=200 clamp max=1000, sorted by uid, `truncated`)
- [ ] 5.2 Implement `IFACES.LIST` (sorted by ifindex; `kind/type` fields aligned to doc)

## 6. Config Commands

- [ ] 6.1 Implement app selector parsing for `{"uid":...}` and `{"pkg":...,"userId":...}` with structured error on not-found/ambiguous
- [ ] 6.2 Implement device-scope `CONFIG.GET` + `CONFIG.SET` for v1 key whitelist with strict validation
- [ ] 6.3 Implement app-scope `CONFIG.GET` + `CONFIG.SET` for v1 key whitelist with strict validation + persistence (`App::save()`)
- [ ] 6.4 Ensure `CONFIG.SET` is all-or-nothing per request (validate all keys/values before applying)

## 7. Host P0 Unit Tests

- [ ] 7.1 Add P0 tests for strict reject: unknown request keys, unknown `cmd`, unknown `args` keys
- [ ] 7.2 Add P0 tests for `HELLO` required fields + id echo + `QUIT` closes after response
- [ ] 7.3 Add P0 test for `len > maxRequestBytes` disconnect semantics (socketpair harness)

## 8. Device Tooling & Integration (P1/P2)

- [ ] 8.1 Extend `dev/dev-android-device-lib.sh` with vNext adb forward helpers (`tcp:60607` ↔ `localabstract:sucre-snort-control-vnext`)
- [ ] 8.2 Add `tests/integration/` vNext baseline case using `sucre-snort-ctl` (HELLO + APPS.LIST + IFACES.LIST + CONFIG.GET/SET)
- [ ] 8.3 Add vNext disconnect/reconnect + two-client last-write-wins coverage to baseline
- [ ] 8.4 (P2) Add vNext TCP `60607` coverage with `inetControl()` enabled + `BLOCK=1` (verifies 60607 exemption)

