# OVS userspace conntrack semantic baseline

Verified on 2026-09-11 for S221 (FlowRuntime/timeouts), S223 (UDP), S222 (TCP), and S224 (ICMP). This records upstream semantic evidence, not an import of OVS implementation or an assertion of complete behavioral parity.

## Immutable revision and verification

Repository: [openvswitch/ovs](https://github.com/openvswitch/ovs).
Release tag: `v3.1.0`.
Annotated tag object: `07dab84a2e0defd633831ead8d5031450d3bb2fd`.
Peeled commit: [`3c2bea086ef8912d57331173af266f21d36740a0`](https://github.com/openvswitch/ovs/commit/3c2bea086ef8912d57331173af266f21d36740a0).

`git ls-remote` against the upstream HTTPS repository returned both object IDs. A shallow checkout of that tag independently returned the same `HEAD`; `git cat-file -p refs/tags/v3.1.0` identified that commit and the release name. The annotated tag contains a PGP signature, but signer trust and the signature were **not** independently verified. This is a verified upstream revision and content pin, not a claim of authenticated release signing. The inspection checkout was `/tmp/ovs-conntrack-baseline.k3Ci9f/ovs`; no upstream source was placed in Product.

SHA-256 below covers the complete bytes of each inspected source/license file. Links are immutable commit URLs.

| File | SHA-256 |
| --- | --- |
| [lib/conntrack-private.h](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-private.h) | `f918e4492fbb5147a37e7d94e6b5e8eceae64f5ddc01e7ca0cb67d79a12da185` |
| [lib/conntrack-tcp.c](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-tcp.c) | `94f0b7379399334824ebfd9fa3ae7ec14545eb252cfea789efbc6ec0ec23fdb1` |
| [lib/conntrack-other.c](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-other.c) | `f28510258788459115bfa6dfd2a4404252b5e658a374ad2ab5686685f711ff73` |
| [lib/conntrack-icmp.c](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-icmp.c) | `dae4df8530bfea21cfc0980e8bf75b245099f4d3b04d266081b38b1dd4448a5f` |
| [lib/conntrack-tp.h](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-tp.h) | `82608f5c0f0ca9ec25ad559b177427a2f52a0776e3a8b156662b09d366a56232` |
| [lib/conntrack-tp.c](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-tp.c) | `bdf813dbe6d356f8d605225454fa381121ff1f0cb12ed65616250f4d93a3a44a` |
| [lib/conntrack.c](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack.c) | `a578eac06319ccf4efa7aac58d9250a3646d2f53b1e3cfa0844427839df669a2` |
| [lib/ct-dpif.h](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/ct-dpif.h) | `eb901d613be105e060580ac5994138d513e7eaed322ec1b80ba3f2e66f20b8ac` |
| [LICENSE](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/LICENSE) | `f41f887b04dd604250193ddd88691ecd168dacdecca2d0d6581d8840e3f0b0dc` |
| [NOTICE](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/NOTICE) | `dd58304d83968b9a7e3fe836008dd798a176a715c12cc696cc63e2bbde7f7250` |

## Exact default timeout classes

The authoritative values are `ct_dpif_netdev_tp_def` in `lib/conntrack-tp.c`, in **seconds**. `tm_to_ct_dpif_tp()` maps internal classes to policy attributes. Initialization and refresh calculate expiration as `now + value * 1000` in milliseconds. A configured policy can override these defaults; absent policy lookup falls back to this table. [Defaults and mapping](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-tp.c#L35).

| Internal class (`CT_TM_` prefix) | Policy attribute (`CT_DPIF_TP_ATTR_` prefix) | Seconds | Milliseconds |
| --- | --- | ---: | ---: |
| TCP_FIRST_PACKET | TCP_SYN_SENT | 30 | 30000 |
| TCP_OPENING | TCP_SYN_RECV | 30 | 30000 |
| TCP_ESTABLISHED | TCP_ESTABLISHED | 86400 | 86400000 |
| TCP_CLOSING | TCP_FIN_WAIT | 900 | 900000 |
| TCP_FIN_WAIT | TCP_TIME_WAIT | 45 | 45000 |
| TCP_CLOSED | TCP_CLOSE | 30 | 30000 |
| OTHER_FIRST | UDP_FIRST | 60 | 60000 |
| OTHER_MULTIPLE | UDP_SINGLE | 60 | 60000 |
| OTHER_BIDIR | UDP_MULTIPLE | 30 | 30000 |
| ICMP_FIRST | ICMP_FIRST | 60 | 60000 |
| ICMP_REPLY | ICMP_REPLY | 30 | 30000 |

In particular, internal `OTHER_MULTIPLE` means multiple packets before seeing a reply and maps to policy `UDP_SINGLE`. Policy `UDP_MULTIPLE` means the internal bidirectional state. These names must not be matched by spelling alone. TCP `CLOSING` and `FIN_WAIT` also have distinct policy names. [Explicit mapping](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-tp.c#L213).

## Protocol state shapes and direction

UDP uses the shared `ct_proto_other` handler; protocols without a dedicated handler also use it. Its protocol-specific persistent state is one packed enum with three values, beyond the common connection record. Creation starts at `OTHERS_FIRST`. Another ORIG packet advances FIRST to `OTHERS_MULTIPLE`; the first REPLY advances either to `OTHERS_BIDIR`. BIDIR persists on subsequent packets. Every update refreshes expiration using the resulting state. FIRST/MULTIPLE updates return `CT_UPDATE_VALID_NEW`; BIDIR returns `CT_UPDATE_VALID`. The generic handler's new-packet predicate always accepts, but upstream UDP parsing/validation occurs before that predicate. [Protocol dispatch](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack.c#L327), [state and transitions](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-other.c#L23).

TCP carries two peers, selected by the supplied reply direction. Each peer holds 32-bit `seqlo` and `seqhi`, 16-bit `max_win`, 8-bit `wscale` (including negotiation/unknown flags), and a packed TCP state enum. This is sequence/window tracking, not merely a connection-wide handshake enum. The vocabulary includes CLOSED, LISTEN, SYN_SENT, SYN_RECV, ESTABLISHED, CLOSE_WAIT, FIN_WAIT_1, CLOSING, LAST_ACK, FIN_WAIT_2, and TIME_WAIT; not every vocabulary member is assigned by this tracker. New connections initialize ORIG to SYN_SENT and REPLY to CLOSED. [Peer shape and direction](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-tcp.c#L53), [enum vocabulary](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/ct-dpif.h#L66), [initialization](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-tcp.c#L440).

TCP normal accepted updates select CLOSED when both peers are at least FIN_WAIT_2; otherwise FIN_WAIT when both are at least CLOSING; otherwise OPENING when either is below ESTABLISHED; otherwise CLOSING when either is at least CLOSING; otherwise ESTABLISHED. Creation and an early SYN path use FIRST_PACKET. A separate permissive sequence path can accept a packet without refreshing expiration, so accepted packet does not universally mean refresh. [Timeout selection and permissive path](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-tcp.c#L341).

ICMPv4 and ICMPv6 share a one-enum protocol state, `ICMPS_FIRST` or `ICMPS_REPLY`. ORIG repeats remain FIRST; the first REPLY advances to REPLY permanently. Each update refreshes its resulting timeout. FIRST ORIG updates return VALID_NEW; the first and subsequent replies, and ORIG after a reply, return VALID. Valid new ICMPv4 queries are echo, information, and timestamp requests; ICMPv6 accepts echo requests. [State, predicates and transitions](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-icmp.c#L29).

ICMP identity and errors are separate from that small state: upstream extraction pairs request/reply types, requires zero code for supported queries, and uses the identifier; supported ICMP errors extract a quoted inner tuple for related-flow lookup and forbid recursive error extraction. This baseline identifies the boundary; it does not authorize adding packet parsing or related-flow lookup to a protocol tracker. [ICMPv4/v6 extraction](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack.c#L1752).

## Attribution and project boundary

`conntrack-private.h`, `conntrack-other.c`, `conntrack-icmp.c`, and `conntrack.c` carry Nicira, Inc. copyright 2015–2019 and Apache-2.0 headers. `conntrack-tp.c` and `.h` carry VMware, Inc. copyright 2020 and Apache-2.0 headers. `ct-dpif.h` carries Nicira, Inc. copyright 2015, 2018 and Apache-2.0. The root license is Apache-2.0; there is no root `COPYING` in this revision. File-specific headers remain authoritative. [Root license](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/LICENSE).

`conntrack-tcp.c` instead has a BSD two-clause license header and credits Daniel Hartmeier (2001), Henning Brauer (2002–2008), Gleb Smirnoff (2012), and Nicira, Inc. (2015, 2016), with FreeBSD pf/OpenBSD provenance. Preserve its complete notice, conditions, and disclaimer if later adapting source; do not label that file Apache-only. Root `NOTICE` explicitly identifies the BSD-licensed TCP tracker. [TCP notice](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/lib/conntrack-tcp.c#L1), [distribution notice](https://github.com/openvswitch/ovs/blob/3c2bea086ef8912d57331173af266f21d36740a0/NOTICE).

The product keeps its existing OwnerAssignment/hash, worker-local mutation, packet-fact input and ORIG/REPLY contract. OVS common-record locks, concurrent maps, shared cleaner, zone/NAT/helper machinery and allocation strategy are outside the semantic baseline. No removed C++ mainline or C/VPP POC source was used. This source inspection did not run OVS interoperability tests or establish parity for every TCP corner case; each protocol implementation still needs scoped behavior tests.
