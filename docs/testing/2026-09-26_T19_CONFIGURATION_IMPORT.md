# T19 configuration import evidence

[SAKAMOTO-270](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/ad9b89d0-16cc-4d70-b5b8-3888eaa7b639)
implements the [published import contract](../interfaces/T19_CONFIGURATION_IMPORT.md).
Rust prepares bounded complete source requests; the actual Product VAPI saves and
compiles them in VPP. Names and sources survive V6 persistence and online export.
The result below is representative evidence, not a public release claim.

## Source and artifacts

Product source closure:
`7bc1ba55964329b4033a9ed0689c49b0d28d2740444da191eeeacbf946064bb1`.
Generated API: `product_core.api/1.0.0@8342a672`.
Debug APK SHA-256:
`64be42d9dca14d13b21b30f8092b15b4bd6f1b0418b59e7284da0f0e5096b400`.

The local evidence root is `build-output/t19-20260926/`. `linux-build-final/build.json`
and `pixel-build-final/build.json` retain complete source snapshots, exact build inputs,
stage identities and artifact hashes. Installed APK/native hashes are checked in
`pixel-root-final/` and `pixel-vpn-capture-run/`; device generations are 1586 Root
and 1585 controlled VPN. Device
selection stays in local evidence. The app's KernelSU grant was checked after
installation before starting Root acceptance.

## Representative result

| Boundary | Import/export operations | Rejected input cases | Actual packets | Result |
| --- | ---: | ---: | ---: | --- |
| Linux Product Root/NFQUEUE | 121 | 14 | 781 | PASS |
| Pixel Product Root/NFQUEUE | 117 | 14 | 493 | PASS |
| Pixel Product controlled VPN | 117 | 14 | 493 | PASS |

The operations include initial imports, canonical export/re-import, rejected
submissions and readbacks. Each profile additionally proves stale-revision
rejection, a real source-directory save failure and a saved-but-uncompilable
configuration followed by correction. The latter source keeps its new full
rule version while the old active revision/versions remain in service; correction
advances the rule version again. Save failure retains the old source and has no
compiler error/publication. All mutations use the actual Rust import entry and
Product VAPI, including Android's serial RuntimeService/JNI path.

Accepted fixtures combine explicit native entries, the supported Adblock-domain
subset and Clash-domain subset. Unicode `BÜCHER.Example.` exports as
`xn--bcher-kva.example`; Chinese rule/list names and source labels persist.
Exact names, descendants, label-boundary lookalikes, overlapping lists, confirmed
absence and unavailable SNI remain distinct. Full definitions retain ports,
Boolean conditions, groups and enforce/observe modes. Two list-only publications
per profile change the same-action logical winner, including the A-label case,
without replacing its existing Flow identity.

The independent verifier reads the saved V6 bytes and actual JSON input/output,
then joins real QUIC v1 Initial packets, typed SNI queries, the full logical
winner/rank/mode/declared and actual action, counts, cache results, completion and
endpoint evidence. QUIC packets come from the independent aioquic 1.3.0 fixture
and real endpoint. This is Initial exchange evidence, not a completed handshake.
No reference evaluator or import preparation output substitutes for packet
evidence. See `linux-import-final-verified.json`, `pixel-root-final-verified.json` and
`pixel-vpn-final-verified.json`.

The rejection matrix covers equal full ID with changed conditions or name,
duplicate identity, malformed name/A-label, invalid Unicode label, URL path,
wildcard, filter option, an extra Clash condition, unknown JSON field, missing
list reference, group cycle and effective-mode conflict. Readback proves source
and active identity retention. Thirteen deliberately altered Linux import witnesses and eleven per Pixel
profile are rejected even when their per-file checksums are updated; these
include lost port restrictions, wrong source syntax, changed Unicode input,
metadata loss, wrong generation/error stage, premature active publication and a
missing roundtrip. See the final import negative records. The packet verifier additionally rejects
49 altered Linux witnesses and 50 per Pixel profile.

Host Rust tests cover complete Unicode preparation, source syntax/rejection and
IPv6/group/observe-mode export roundtrip; its suite passed 21 tests. The C source
boundary covers metadata persistence/reopen, full-version name/source conflicts,
revision advancement, list-metadata-only publication, invalid/overlong UTF-8,
controls, missing terminators and nonzero unused metadata. Existing source,
compiler, domain allocation failure/retry and old-result tests remain applicable.
ASan/UBSan with leak detection passed the source/configuration and domain tests.
The source representation budget is 1,961,396 bytes within the existing 2 MiB
admission ceiling; it is not a measured full-process RSS peak.

Host CTest passed all 50 tests. With no valid saved source, the final Linux run
additionally checks query, rejected recovery import, initial save failure and
successful repair. All retain the full VPP result/error envelope; unavailable
export returns null configuration and an explicit export error. The two added
Linux negative witnesses reject missing errors and invented configuration.
Independent standards/spec reviews and their corrections are recorded in
[the review](../reviews/2026-09-26_T19_CODE_REVIEW.md).

## Retained failures and limits

`pixel-quic-final/` retains a HOLD: Root completed, but VPN `named_suffix`
recovery echo `:8` timed out. The endpoint received and echoed it; Product logged
outbound ALLOW/ADMITTED but no corresponding FLOW_STACK_RETURN. No underlay
capture exists for that run, so external packet loss versus protected-socket
receive behavior remains unresolved. Teardown had no owned completion debt.
No Product change or retry relaxation was made to turn that run into a PASS.

A separate same-source VPN run (`pixel-vpn-capture-run/`) passes independently.
Its bounded existing tcpdump capture (`vpn-capture/`) accounts for all 200 echoes
at TUN-out, underlay-out, underlay-in and TUN-in, with zero kernel capture drops.
Maximum captured RTT was 66.484 ms and underlay-in to TUN-in 9.435 ms. The
original timeout did not recur; these observations do not establish its cause
or a fix. A separate fresh Root run (`pixel-root-final/`) also passes. T29 must
retain this unresolved event for repeated protected-socket/underlay stress.

`linux-startup-red-b/` retains the reproduced missing-source error-envelope bug;
`linux-startup-red/` retains an earlier harness readiness mistake. The final
Linux run demonstrates the corrected behavior without relabeling either run.

`linux-quic-a/` is a retained HOLD before Product startup: its low-privilege
endpoint UID could not traverse the host Python tool installation. The successful
run mounts the same read-only Python/dependency trees at traversable container
paths. It does not change host permissions or use POC implementation code.

The first sandboxed Rust lifecycle run could not create its required local UDS;
the same suite passed with that permission. The first sanitizer run hit
LeakSanitizer's documented traced-process restriction; the same tests passed
outside that traced sandbox, with leak detection still enabled. Two old API test
fixtures initially lacked the new metadata field; their typed request/reply
fixtures were updated and their targeted contracts passed. These are retained
validation failures, not silently relabeled passes.

Supported import syntax is intentionally bounded and strict. General Adblock/
Clash configurations, globs/regexes, URL/path filters and arbitrary extra
conditions are rejected. The strict IDNA profile and source capacities are
documented in the interface contract. This ticket does not claim universal
Unicode/import-format compatibility, full-process peak RSS, large-list
throughput, or a new persistent archive of old rule/list contents.

Real T19 packet evidence is QUIC on Linux and Pixel Root/VPN. TLS metadata and
matching use the existing C semantic seam; the complete prior T18/T14 device TCP
segmentation matrix was not rerun for import preparation. Broader cross-feature
stress belongs to [T29 / SAKAMOTO-281](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/faaa95d4-dfb4-4a8e-9605-9fa22c207c64).
Controlled VPN evidence continues to report `protectionRunning=false`; it is not
ordinary-user VPN protection or a release gate.
