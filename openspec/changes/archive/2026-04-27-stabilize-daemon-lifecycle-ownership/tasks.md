## 1. Runtime Shutdown Ownership

- [x] 1.1 Add a reusable shutdown coordinator that supports request, timed wait wakeup, and state reset for host tests
- [x] 1.2 Block `SIGINT` / `SIGTERM` before listener/client threads are started
- [x] 1.3 Start a dedicated `sigwait()` waiter that requests shutdown through the coordinator
- [x] 1.4 Replace main `sleep_for(saveInterval)` with coordinator timed wait and final save on shutdown
- [x] 1.5 Route legacy `DEV.SHUTDOWN` through the coordinator instead of direct worker-thread exit

## 2. Session Ownership and Resource Bounds

- [x] 2.1 Add RAII active-session budget helpers for control and DNS client workers
- [x] 2.2 Enforce budget in legacy control, vNext control, and DNS accept paths before detaching workers
- [x] 2.3 Remove raw fd return/shutdown from vNext stream `resetAll()`
- [x] 2.4 Add stream cancellation observation so owning vNext sessions close their own fd after reset
- [x] 2.5 Add total send deadlines for legacy control, vNext flush, and DNS client writes

## 3. Tests and Documentation

- [x] 3.1 Add host tests for shutdown coordinator wakeup
- [x] 3.2 Add host tests for session budget acquire/release and vNext stream reset cancellation
- [x] 3.3 Update concurrency review lifecycle findings with actual fixed behavior
- [x] 3.4 Run host/ASAN validation and record Android/Soong graph-regen follow-up memo
