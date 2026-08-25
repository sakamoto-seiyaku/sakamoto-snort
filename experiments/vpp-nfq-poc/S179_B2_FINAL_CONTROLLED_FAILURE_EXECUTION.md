# S179 B2 final-artifact controlled failure-semantics regression

Date: 2026-08-25
Status: `PASS`

## Scope

S179 reran the S146/S147 controlled B2 negative-outcome contract on the current
S176/S178 final VpnLite artifact.  This is a controlled full-TUN regression,
not the complete external/default-route B2 proof.

Artifact under test:

- VPN APK:
  `f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541`
- OI3 plugin:
  `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`
- HEV owner-context library:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

Runner and static guard:

```text
experiments/vpp-nfq-poc/scripts/android-run-s179-b2-final-controlled-failure.sh
experiments/vpp-nfq-poc/scripts/verify-s146-b2.py
experiments/vpp-nfq-poc/scripts/tests/test_verify_s179_b2_final_controlled_failure.py
```

## Selection note

S178 closed the current-artifact B1 positive DNS dataplane slice.  The next B1
sub-gap is large-response / forced UDP-to-TCP DNS fallback, but the current
AppA B1 helper only sends a supplied DNS payload over the requested protocol
and validates the response.  It does not implement a resolver fallback state
machine.  Treating independent UDP and TCP requests as forced fallback would
overstate the claim.

Therefore S179 used the next executable bounded POC: rerun the existing B2
negative semantics contract on the current final artifact.

## Accepted run

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s179-b2-final-controlled-failure-20260825/
```

Run ID: `20260825-172718-237536`

Manifest summary:

```text
status=PASS
scope=bounded_final_artifact_controlled_b2_failure_semantics
claim_boundary=controlled full-TUN negative semantics regression; not external/default-route B2 closure
cellsRecorded=3
passCount=3
failureCount=0
```

Cell summary:

| Cell | Mode | App result | Native outcome | Residue | Verdict |
| --- | --- | --- | --- | --- | --- |
| refused | `vpp-oi3-controlled-refused` | `EXPECTED_TRANSPORT_FAILURE` | `EXPECTED_TRANSPORT_REFUSAL`, `transport-failures=1`, `broker=1/1`, `direct=0` | no VPP, no `tun0` | PASS |
| no-reply | `vpp-oi3-controlled-no-reply` | `EXPECTED_NO_REPLY_TIMEOUT` | `EXPECTED_TIMEOUT`, `endpoint=1/0`, `broker=1/1`, `direct=0` | no VPP, no `tun0` | PASS |
| policy-drop | `vpp-oi3-controlled-policy-drop` | `EXPECTED_POLICY_DROP_NO_TRANSPORT` | `EXPECTED_POLICY_DROP`, `output=0`, `broker=0/0`, `transport-failures=0` | no VPP, no `tun0` | PASS |

All three rows had `verifierRc=0`, VPN session provenance, VPP start
provenance, native `PASS_EXPECTED_FAILURE` cleanup, and zero post-run residue.
An independent post-run check also found no `vpp` process and no root-visible
`tun0`.

## Interpretation

S179 supports that the corrected negative-outcome contract still holds on the
current final VpnLite artifact for the controlled full-TUN seam:

- transport refusal remains a transport failure, not a policy drop;
- no-reply remains a timeout/no-reply outcome, not a successful direct reply;
- policy drop stops before broker/socket transport and records zero downstream
  transport.

S179 does not close complete B2.  Remaining B2 work still needs real
external/default-route AppA allow/drop, representative IP/policy drop, refused
and no-reply endpoints, bind/protect/infrastructure failures, and no fallback
on the full-device path.
