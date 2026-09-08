# Task commits — 2026-09-08

Completed work was committed by task after the implementation/acceptance runs.
These commits were created now; original build commits, source hashes and raw
evidence remain historical witnesses. Product source bytes in each milestone
commit were checked against its recorded accepted source snapshot.

| Task | Commit | Change |
| --- | --- | --- |
| architecture | `28643f6fc01e` | docs(architecture): record accepted native packet ownership decisions |
| S245/S246 | `a7a6149dde58` | test(s245,s246): validate independent HEV and VPP buffer ownership |
| S247 | `52303ff96ab9` | test(s247): qualify bounded overlap and stop ownership |
| S200 | `f8b02499737f` | refactor(s200): isolate handcrafted VPN bridge from the product |
| S203 | `42942b7df73e` | feat(s203): route real Root packets through native graph nodes |
| S244 | `c513fcf11b98` | test(s244): bind runtime evidence to source and installed artifacts |
| S216 | `9ee48d036411` | refactor(s216): define typed packet metadata and inline ownership |
| S204 | `bc71a28c9896` | feat(s204): complete native buffers on their original adapter lane |
| S205 | `4621027f8e08` | feat(s205): add the single retained primary handoff path |
| S206 | `b791d03e0956` | feat(s206): make Root NFQUEUE lanes worker-owned and dual-stack |
| S230 | `f95e1ad92b37` | test(s230): verify real Linux NFQUEUE and endpoint closure |
| S207 | `5f0a1fab21a1` | feat(s207): assign immutable canonical packet owners once |
| S208 | `d4c16148c0cf` | feat(s208): keep flow entries and policy decisions owner-local |
| S209 | `534b5e28b727` | feat(s209): publish immutable per-packet policy snapshots |
| S210 | `21179abb6170` | fix(s210): retain originals across capacity and completion pressure |
| S231 | `5b5905dcdc37` | test(s231): establish actual fragment visibility at each NFQUEUE hook |
| S212 | `467c4c127781` | feat(s212): retain every original across native IPv4 reassembly |
| S217 | `b584bde02def` | fix(s217): derive Root platform facts only from real netlink attributes |

S245/S246 share one experiment harness and artifact boundary, so they are
recorded together. The remaining completed implementation tasks have separate
commits. Accepted architecture documentation is a separate commit.

The split preserved all 207 originally dirty paths byte-for-byte, including
deletions; no working source was checked out or reverted. Each Product task
tree was checked against its accepted source manifest before committing.
Unified-diff patch files retain their exact hashed context whitespace.

S228 remains unaccepted work in the working tree. Its fifth core patch,
IPv6 graph changes, related contract changes and collector/report were not
included in the completed-task commits. It requires its own runtime acceptance
and subsequent commit.

The task reports under this directory retain the original source/artifact and
device evidence. Committing the work does not retroactively claim that those
artifacts were built from these newly created Git commit IDs.
