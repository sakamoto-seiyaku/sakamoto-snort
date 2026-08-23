# SAKAMOTO-120 External-Driver Memo

## Validated

- A VPP worker can own the HEV/lwIP task system without calling the old
  `hev_task_system_run()` takeover path.
- The external-driver contract is bounded: `driver_step(budget=1)` runs one
  scheduler quantum and returns to VPP.  The next quantum is re-entered by the
  next invocation of the same worker node.
- The owner tasks and lwIP contexts stayed on the target VPP worker pthread:
  setup, event, lwIP I/O, and lwIP timer traces all carry the same pthread id.
- Two owner instances were live in one worker and both joined cleanly. Final
  task and fd residue were zero.

## Design decision

POC-120 is a GO for formalizing the external-driver scheduler seam. The seam
must expose an explicit quantum budget/result and must not let HEV take over a
VPP worker. The worker-local instance model remains valid; multi-worker
replication is still a later POC, not a product decision.

## Boundary

This POC does not validate VPP packet-buffer ownership, real packet ingress or
egress, zero-copy, or production lwIP changes. Those remain the scope of
SAKAMOTO-121.
