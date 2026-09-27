# T28 independent review

Two independent agents reviewed the scoped T28 implementation against the
SAKAMOTO-280 acceptance criteria and repository standards, using T27 commit
`37c84bd5f38ecb30b8b3bffd7ba37ac36f300b09` as the fixed point. Both
axes reached zero remaining findings after the final source changes.

The Standards review found that the new Android `observationCursor` intent
extra bypassed `RuntimeControlProtocol`, and that the Activity had copied the
bounded response-file polling, read and deletion logic from its history query.
The final source owns the cursor constant in `RuntimeControlProtocol` and uses
one `takeObservationResult` method for both queries. The reviewer rechecked
all affected Android and verifier files and found no new documented-standard
breach or actionable code smell.

The Spec review found that the typed live Flow carried `lpi_stop` and
`sni_stop`, but the diagnostic Activity showed only protocol labels and
availability. A stopped recognizer with no label could thus look like an
unfinished or unrecognized Flow. The final Activity displays named LPI stop,
SNI result and SNI stop states. The R1–R4 independent verifier now checks the
raw enum ranges and a concrete budget-stopped live Flow for each tier, tied to
its protocol label. The reviewer confirmed all four final-source Linux runs
as `VALID` and withdrew the finding. Physical Pixel UI XML also shows the
stop-state fields.

The Spec reviewer separately assessed the physical VPN UI Start/Query/Stop
capture. The normal Start reports `vpn_flow_stack_not_ready` as the existing
Product adapter contract requires; Query shows an explicit management error
and the typed RuntimeService snapshot retains its cause. The controlled HEV
VPN run supplies the available packet and live-query branch. The reviewer
found no remaining T28 diagnostic gap and made no ordinary VPN protection
claim.

Both reviews were read-only. Final-source build and packet evidence are in
the [acceptance record](2026-09-27_T28_DASHBOARD_RESULTS.md); earlier failed
attempts and the original review reports remain retained as evidence of the
review sequence.
