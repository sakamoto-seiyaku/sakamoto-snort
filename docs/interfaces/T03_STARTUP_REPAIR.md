# T03 startup repair lifecycle

The existing rule-management/save/apply and runtime status boundaries remain the
test seams. VPP owns the only saved source and immutable active snapshot. A
saved configuration with no active snapshot keeps a healthy control session
available and reports `rule_configuration_not_active`; it is not protection.
Query and complete replacement retain T02 identities, errors and retry semantics.

RuntimeService validates management identity/health separately from policy and
Adapter readiness. Before a valid snapshot exists it creates neither Root hooks
nor an Android TUN. The existing diagnostic rule API can repair the source.
An explicit Start continues the same healthy generation through the normal
profile prerequisites; Stop and profile switching still own complete teardown.
Successful repair alone does not claim Android protection or bypass VPN gating.
The health summary classifies an invalid saved source as an apply failure with
rule-correction guidance, and a repaired source awaiting Start as `start_required`.
Neither state asks for crash recovery or a nonexistent previous snapshot.

VPP retries its previously configuration-blocked Adapter startup after a
successful source publication. This is a main-thread process event, not a polling
loop or worker-side lifecycle action. Adapter startup faults remain faults and
are not reclassified as editable policy failures. Runtime updates preserve the
existing snapshot on compilation failure. A dead process, broken control
session, permission failure or platform failure follows existing teardown.

The diagnostic status distinguishes policy readiness (nonzero active revision),
native Adapter readiness and platform capture started. The controlled VPN path
continues reporting `protectionRunning=false`, even after successful packet tests.
OS lockdown remains authoritative; no fallback changes its network policy.
