# Unified VPP rule engine and bounded normal observability

Date: 2026-09-24; protocol-recognition scope revised 2026-09-25;
application DNS filtering direction accepted 2026-10-07.
Status: accepted design; implementation and validation are tracked per work item.
This specification synthesizes the confirmed September rule-engine discussion,
including its completed startup-repair review and supplemental-recognition correction.
Plane owns implementation work
and acceptance state; this repository copy records product intent.

Plane: [SAKAMOTO-251](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/28bb5f21-f21c-4018-a3c6-60a5dbfdb82e).

## Problem Statement

A local-endpoint firewall user needs predictable rules that combine packet,
connection and application-protocol facts without understanding physical
execution stages. Moving a rule earlier for efficiency must not change which
logical rule wins. Missing recognition data must not silently become a negative
match, and changes to configuration must not produce partially updated policy.

The user also needs to see network activity and rule effects over time, identify
actual blocking and distinguish it from runtime failure. This must remain useful
when records are delayed or lost, while keeping packet processing independent of
the history consumer and bounding mobile memory, storage and wakeup costs.

The C mainline now has scoped T01–T12 evidence for online configuration, unified
static/CT rules, bounded execution plans, caching and initial protocol facts.
That evidence does not establish the supplemental-recognition scope added here,
TLS/QUIC SNI policy or the complete normal observation pipeline.

Personal-endpoint protocol rules need more than the initial library-only
mapping plus an isolated QUIC supplement. Useful supplementary signatures,
cross-packet checks and corrections must participate in one recognition process.
More protocol names or a different source project alone do not establish better
identification; supported behavior and heuristic limitations must be verifiable.

## Solution

Provide one logical rule model with explicit priority, reusable rules and groups,
and application bindings. VPP owns online rule management and a single persistent
configuration file. It expands applicable rules, compiles a bounded execution
plan and publishes one consistent immutable Runtime Snapshot. Workers execute
the plan using their own flow facts and caches.

Rules can combine packet, platform, CT, published LPI and protocol-applicable
domain facts, including the sources selected in the accepted DNS extension below.
The compiler assigns each whole rule to a safe position before or after flow
processing while preserving the logical winner. Application network disabling
uses a highest-priority ordinary DROP rule maintained by its configuration
entrypoint. Complete matching without a winner defaults to ALLOW.

Keep libprotoident as the base recognizer and add bounded Supplemental Protocol
Recognition before project-catalog mapping and publication. Use nDPI detection
logic as the primary reference, with selected reference-fork features and useful
protocol distinctions as supplements for personal endpoints. This is selective
adaptation, not integration of the complete nDPI engine or wholesale replication
of the fork. Published protocol facts continue to feed the same rules and caches.

Configuration is fully saved before compilation. Saved and applied outcomes are
reported separately. Failed updates preserve both the saved edits and the old
active snapshot. At startup, successful compilation is a prerequisite for
product traffic capture; configuration failure leaves the management API
available for user repair when VPP and its control infrastructure are healthy.

VPP maintains independent basic accounting and exports bounded cumulative
observations without waiting for Rust. Rust incrementally maintains four normal
traffic views, recent attribution and longer-lived aggregates in an observation
store separate from configuration. Frontends query APIs; screen design remains
outside this specification.

## Accepted DNS design extension, 2026-10-07

[ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md) formally aligns
application DNS filtering across Root/NFQUEUE and VPN. Reliably attributed queries
use the application's applicable policy before original-path forwarding or the
optional product proxy's answer cache/upstream. Unknown original applications
are allowed without waiting; a system resolver UID alone is not the original
calling application's identity. Available
Domain-IP Association evidence supports later connection evaluation with that
connection's own application identity and available domain/address facts. DNS
allow does not authorize a subsequent connection.

Both opportunities consume the same VPP configuration authority and whole-rule
constraints; they do not create stage-specific priorities or infer unknown
business conditions. The first version targets Root's packet-based DNS route and
VPN sharing DNS judgment, parsing, correlation and result processing on both
original-resolver and optional proxy paths. Proxy clients/cache are also shared;
ingress, platform socket operations and reply delivery use their Adapters.
KSU/libnetd is deferred
to a future extension; its selected local decision/result collection and
Android-owned resolver/cache/encrypted upstream do not add first-version
implementation dependencies. Its planned NFQ allowance for 53/5353 is scoped to
that future route, not a blanket exemption for first-version Root traffic.

The first version also captures ordinary UDP/TCP port-53 DNS queries to
application-selected public or local-network resolvers, rather than limiting DNS
handling to the product-configured server address. These ordinary unicast queries
enter the same DNS core for applicable filtering and records. mDNS and
application-owned encrypted DNS follow their separate choices below.

On 2026-10-11 the user confirmed that ordinary DNS query handling covers
A/AAAA, TXT, MX, SRV, HTTPS and other record types under the same applicable
query-domain policy and selected resolution path. Preserve query/answer content
and semantics, including data of record types without a type-specific extractor;
do not reduce replies to address-only answers. The proxy's existing TTL and
resolver-view cache contracts remain. Domain-IP Association updates use actual,
reliably extracted address records, while CNAME filtering retains its already
selected scope and whole-rule Rank. Text and other embedded fields are not
automatically address records, SNI or additional domain-policy facts. Caller
requirements and the deferred association application scope remain unchanged.
This is first-version design scope, not implementation evidence.

Existing local-network DNS settings, including self-hosted resolvers and their
domain-routing choices, must be preserved. DNS ingress capture and upstream
replacement are separate decisions. Public-looking names may have local answers;
neither name shape nor a resolver's address supplies a complete internal/public
classification. Without an explicitly user-selected replacement, allowed queries
retain their original resolver destination and network resolution context through
Root's normal kernel forwarding or VPN's existing direct transport. Allowed
answers pass through unchanged while DNS inspection collects actual results.
The proposed fixed VPN DNS proxy entry belongs to the proxy path, not a mandatory
local resolver for original-path traffic.

The user confirmed that upstream configuration supports ordinary UDP/TCP DNS,
DoT and DoH, with encrypted upstream requests enabled only by the user's
configuration and choice. Filtering remains available without encrypted DNS.
Selecting a custom ordinary DNS server is also an explicit user choice, not an
implicit product redirect. This supersedes the earlier mandatory-encrypted
forwarding assumption. Local-name exception routing follows the choice below;
other compatibility and detailed failure behavior remain to be specified;
existing system/app encrypted paths are not silently replaced or downgraded by
this decision. Answer caching
must retain the selected resolver/network view, not mix answers across views.

On 2026-10-11 the user confirmed that DoT/DoH endpoint configuration accepts
hostnames and IP addresses. Use IP-form addresses directly; for hostnames,
prefer configured connection IPs or otherwise resolve the service hostname
through the system/original-network DNS resolver. Preserve the configured
service identity for TLS authentication; selecting an IP does not disable
certificate or identity validation.

DNS Upstream Bootstrap is limited to product-generated address acquisition
for connecting to the configured encrypted service. Keep it outside the
product proxy to avoid recursive bootstrap. It is not a domain-based permission
exemption for other applications, an implicitly chosen public bootstrap
resolver, or ordinary-DNS fallback for application queries. Application queries
retain their selected encrypted upstream and Local DNS Resolution Exceptions.
An unavailable service address follows configured primary/backup and final
failure behavior. Address refresh, cancellation, platform integration and
configuration representation remain implementation contracts; no new runtime
or packet-holding behavior is selected.

The user then confirmed that enabling the configured encrypted upstream sends
captured ordinary DNS queries addressed to public resolvers through the product
DNS proxy, including application-selected public DNS destinations such as
`8.8.8.8:53`. A permitted query uses the selected-context answer cache or the
configured DoT/DoH upstream, rather than preserving that original public DNS
destination as a separate forwarding choice. Root and VPN share this behavior;
without enabled replacement the original-resolver path remains. Existing
local-network/self-hosted DNS protection follows the explicit exception choice
below, with other compatibility details still to specify. This confirmation
does not classify all internal/public names or replace application-owned
encrypted DNS or mDNS.

The user accepted Local DNS Resolution Exceptions for specified hostnames or
name-and-descendants scopes: resolve them through the network-original DNS or a
selected local-network DNS server while other proxy queries use the configured
DoT/DoH upstream. Preserve available explicit resolution scopes and allow user
supplements. Both routes apply applicable current policy before cache/upstream
processing and retain records; exception routing does not grant permission.
Answer caches retain their respective resolver/network views. This is explicit
routing rather than a complete automatic internal/public-name classifier.
Exception representation, overlap handling and platform discovery remain to be
specified.

On 2026-10-08 the user confirmed that first-version mDNS traffic on UDP 5353
continues through the original network/system handling path. When observable,
retain existing protocol recognition and flow records. Do not send it through
the encrypted DNS proxy or DNS-domain query filtering, or introduce a
product-owned mDNS resolver. General application/IP and other independently
applicable rules continue to execute; this is not a blanket permission
exemption. The choice concerns mDNS traffic rather than every ordinary unicast
query ending in `.local`. Multicast transport compatibility and observation
coverage require subsequent implementation/device validation.

On 2026-10-08 the user clarified that application-owned DoH/DoT is not
transparently replaced or decrypted by the product. Optional connection blocking
through applicable rules is the selected control direction. Complete the
product's own DoH/DoT functionality and provide a usable resolution path before
recommending that users enable external encrypted-DNS blocking rules. Until
then, preserve those connections without automatically adding/enabling such
blocking. Once the prerequisite is met, enabling remains the user's choice;
readiness does not automatically activate a rule. Independently applicable,
explicitly configured general rules retain the existing whole-rule semantics.
Connection blocking is not a DNS query-domain decision or proof that an
application switched to the product resolver. Blocking targets and identification
coverage still need specification; complete detection is not promised. This
records a design prerequisite, not an implemented encrypted client.

On 2026-10-08 the user accepted primary/backup selection for multiple configured
DoT/DoH upstreams. A permitted query requiring upstream work prefers the earliest
currently available entry in the user's configured order. Normally use one
upstream; connection failures, timeouts or other upstream faults allow sequential
attempts at later available entries in that configured encrypted list. This
does not select default parallel broadcasting/racing. Normal DNS results such
as NXDOMAIN are not transport failures requiring another server's positive
answer. Local DNS Resolution Exceptions retain their routing and resolver view.
Exact failure classification, retry/deadline budgets, availability tracking and
recovery remain implementation contracts; this is not evidence of a working
encrypted client.

On 2026-10-08 the user confirmed that, if all configured DoT/DoH upstreams fail
and no valid answer cache is available, report resolution failure while retaining
the selected configuration. Do not automatically fall back to the original or
another ordinary DNS resolver. For a permitted query, record this as resolution
failure, not DNS policy denial; it adds no successful address association. Valid
cache answers still require current policy and the selected resolution context.
The failure response/status format and retry/deadline budgets remain to be
specified; no refusal code or policy DROP was selected for this failure case.

Both paths continuously update Domain-IP Association evidence from actual
answers and valid proxy cache answers, retaining available caller/network
provenance. System-mediated queries remain caller-unknown; later business flows
are evaluated using their own application identity. Synthetic policy refusals
or replacement addresses are not successful upstream address evidence.

For recognized TLS/QUIC business connections, subsequently extended to DTLS,
the user selected no
connection-domain action while SNI recognition is pending. Otherwise permitted
packets continue; other independently applicable application/IP rules still
execute. If recognition obtains a usable SNI, use it as the domain input without
replacing it or independently denying the domain from conflicting DNS data.
If recognition finishes without a usable name, including absence, failure or
exhaustion, attempt DNS-association fallback. Record the true outcome and source;
failure/exhaustion is not Confirmed No SNI, and no admissible association leaves
the domain unavailable. Packets are not held/replayed and completed verdicts or
observations are not changed retroactively.

The user corrected the scope to also include HTTP's visible request-target
authority/Host as a direct target-domain source. On 2026-10-08 the user confirmed
per-request domain updates and evaluation for visible cleartext HTTP, including
successive requests to different names on the same HTTP proxy connection.
Each obtained effective request target supplies that request's domain input;
evaluation uses the actual application and current applicable whole rules. An
earlier request's allow is not permission for subsequent requests. Completed
verdicts and observations remain unchanged. One proxy connection/session may
carry multiple requests; each request has its own effective protocol target.
Version/framing, detailed fact lifetime and unavailable-target fallback need
subsequent specification. The user then chose the existing DROP path for HTTP
domain-policy denial: block subsequent traffic on the TCP connection, affecting
other requests that share it. This is connection-level enforcement of a
request-level decision; selective request removal, generated HTTP errors and
active TCP reset are not selected. Existing policy-revision re-evaluation
remains applicable. Encrypted HTTP follows the selected
observable SNI/DNS-association paths; the SNI sequence does not apply
indiscriminately to every protocol.
The user also accepted fallback for an HTTP request whose effective target is
an IP address: use that requested remote IP to look up an admissible DNS
association, preserving the actual application and DNS-derived provenance.
Reuse the provisional two-hour window, network-switch reset and unique-candidate
rules. No candidate or multiple candidates leave the domain unavailable while
other rules still execute. The proxy server's endpoint is not the requested
target, and packet-address facts retain their own meaning.

The user also selected SOCKS4
and SOCKS5 target-domain processing: SOCKS4a within the SOCKS4 tag and domain-type
SOCKS5 requests provide direct names. IP-only SOCKS4/SOCKS5 association fallback
is also accepted: look up an admissible DNS association using the remote target
IP in the request, retaining association provenance and the actual application's
policy view. No admissible association leaves the domain unavailable while
other applicable rules still execute. The requested SOCKS destination is
distinct from the proxy server's endpoint and does not replace actual packet
address semantics. Association expiry follows the provisional age choice below;
multiple-name handling follows the KISS choice below.

DTLS is now selected for SNI domain processing using its own real handshake
facts and the same recognition sequence. SNI applicability therefore includes
DTLS in the target below; current TLS/QUIC source and evidence do not validate
that addition. DNS, HTTP and SOCKS facts are not inserted into explicit SNI
predicates; whole-rule Rank remains unchanged. HTTP/SOCKS target and fallback
domain facts require their own typed applicability. SIP domain processing is
deferred while existing SIP recognition remains; other sources are not selected.
Association admissibility and detailed lifetime contracts remain to be specified;
this discussion adds no numeric recognition budget.

On 2026-10-08 the user chose a KISS ambiguity rule for the selected DNS fallback
paths: one admissible candidate name supplies the fallback domain; zero or
multiple candidates leave the domain unavailable. Multiple names remain
observation evidence and do not trigger a domain-policy action from the
association. Other independently applicable rules still execute. Direct SNI,
HTTP or SOCKS target facts retain their selected meaning and precedence; a
single DNS candidate remains indirect evidence rather than proven target
identity. Candidate admissibility/context and detailed lifetime contracts are
separate from this count decision and still need specification.

After reviewing Portmaster's profile/global behavior, the user deferred the
application/profile partitioning and cross-application use of IP-domain
associations until actual data is available. Neither same-application-only
lookup nor global sharing of all known-application records is selected.
The existing query filtering, direct domain sources, unique-candidate fallback,
provisional age and network-reset choices remain in place; this scope is not
settled through further hypothetical IP-only examples in the current discussion.

On 2026-10-08 the user selected an independent, provisional **two-hour
(7,200-second)** expiry window for fallback Domain-IP Associations. DNS answer
cache freshness continues to follow TTL; TTL expiration alone does not expire
the association. Expired associations are excluded from subsequent fallback
lookups; without another admissible candidate, the domain remains unavailable
and other rules still execute. Historical evidence does not extend eligibility.
The value is temporary and may change through later optimization or redesign.
Detailed refresh, other context-admissibility and established-flow fact lifetimes
remain to be specified.

The user also confirmed that switching networks resets the affected path's
active Domain-IP Association cache, even before the provisional two-hour window
expires. Prior-network associations do not supply fallback names in the new
network; current evidence is learned again from actual results. Historical
observations may retain the old evidence. This reset concerns association
state and does not guarantee a new visible system/app DNS query; answer-cache
TTL and resolver-view rules remain separate. Detailed refresh, same-network
resolver changes and established-flow fact lifetime still need specification.

The user selected direct DROP for reliably attributed DNS queries whose
applicable policy denies them with the facts available before resolution.
Stop them before original-path forwarding or
proxy answer-cache/upstream processing, without generating DNS refusal or
substitute answers. Clients may retry or time out; record the actual query
denial rather than an upstream failure or a response never sent. Allowed
ordinary answers permitted by the applicable query/response policy pass through
unchanged.

On 2026-10-08 the user accepted Portmaster's CNAME-filtering functionality as a
first-version direction. The original query name and the actual connected CNAME
chain from an answer or valid selected-context cache answer supply distinct DNS
facts to the same current applicable whole rules and Rank. An alias match does
not create a separate deny priority or automatically override an explicit allow.
The query check precedes forwarding/cache/upstream work; the response check
uses alias facts once they become available. Prepare and match those facts
before the product proxy delivers the complete answer, including cache hits.
Reuse the selected DROP behavior when policy denies delivery, without rewriting
the answer or synthesizing a refusal/substitute response.

Original-resolver traffic is controlled using response facts available at the
actual control point, preserving No Recognition Hold. Do not hold/replay packets
to await aliases or promise complete inspection before any transparent TCP bytes
pass. The original App must still be reliably known for application DNS policy;
system-mediated caller-unknown queries are not assigned guessed App rules.
Retain resolution outcome and policy outcome separately; rejecting delivery
after a successful upstream result is not an upstream failure or successful
App delivery. Result collection and association eligibility remain independent.
CNAME evidence does not replace the original QName or populate explicit SNI
facts, nor override the selected business-connection direct-domain precedence.
This chooses functionality, not Portmaster's implementation, default settings
or endpoint/list hierarchy; parsing/framing and exact delivery seams remain to
be implemented and verified.

DNS query denial, resolution failure and subsequent connection denial remain
distinct. System/app cache hits may never reach product DNS ingress, so complete
per-application pre-answer interception is not promised. Association evidence
retains provenance and ambiguity and is not direct SNI or a guaranteed unique
domain. Existing SNI predicates below retain their TLS/QUIC applicability; DNS
query and association fact/record Interfaces, admissibility and detailed lifetimes
require their subsequent specification. This accepted scope extension supersedes the
former blanket DNS exclusion, not existing implementation or validation evidence.

## User Stories

1. As an endpoint user, I want rules to use explicit priority and order, so that I can predict which matching rule wins.
2. As an endpoint user, I want rules to combine conditions with AND, OR and NOT, so that I can express my intended policy without splitting it into unrelated stages.
3. As an endpoint user, I want reusable rules and groups bound to applications, so that shared policy can be maintained in one place.
4. As an endpoint user, I want repeated references to the same rule to execute once, so that organization does not multiply enforcement or counts.
5. As an endpoint user, I want conflicting enforce/observe bindings rejected explicitly, so that the system does not choose an unexpected mode.
6. As an endpoint user, I want application network disabling to participate in the same rule semantics, so that its effect can be explained and counted consistently.
7. As an endpoint user, I want an explicit lowest-priority DROP to express default denial, so that the fallback remains visible in my rules.
8. As an endpoint user, I want automatic rule placement to preserve the logical winner, so that optimization does not change policy.
9. As an endpoint user, I want source and destination to mean the current packet endpoints, so that address and port conditions are unambiguous.
10. As an endpoint user, I want device direction and flow direction distinguished, so that incoming traffic is not confused with a flow reply.
11. As an endpoint user, I want CT and application-protocol facts usable together, so that their production order does not define rule precedence.
12. As an endpoint user, I want published protocol results to participate immediately, so that I do not wait for all recognition to finish.
13. As an endpoint user, I want unavailable input distinguished from a confirmed result, so that negation does not match missing information.
14. As an endpoint user, I want SNI rules restricted to recognized TLS, QUIC or DTLS flows with their applicable producer facts, so that unrelated protocols are not treated as lacking SNI.
15. As an endpoint user, I want a confirmed-no-SNI condition, so that I can explicitly allow or block that case.
16. As an endpoint user, I want TLS, QUIC and DTLS SNI included in this version, so that domain conditions cover the agreed encrypted-transport scope.
17. As an endpoint user, I want exact-domain and domain-with-descendants matching, so that those two intentions remain distinct.
18. As an endpoint user, I want supported domain imports normalized and validated, so that malformed or unsupported entries do not silently broaden policy.
19. As an endpoint user, I want packets processed using currently available facts, so that waiting for SNI does not hold original packets.
20. As an endpoint user, I want recognition limits reported without fabricating facts, so that a timeout does not masquerade as confirmed absence.
21. As an endpoint user, I want configuration managed through one online API, so that independent rule databases cannot diverge.
22. As an endpoint user, I want a complete submitted configuration saved before compilation, so that the saved edits are the identifiable input being applied.
23. As an endpoint user, I want save failure to prevent compilation, so that a failed save cannot be reported as a successful configuration update.
24. As an endpoint user, I want failed compilation to retain my saved edits and the old running policy, so that I can correct the problem without losing either state.
25. As an endpoint user, I want saved and active versions reported separately, so that I know whether my latest changes are protecting traffic.
26. As an endpoint user, I want startup configuration errors repairable through the management API, so that a failed restart does not lock me out of rule management.
27. As an endpoint user, I want protection readiness to require a valid compiled snapshot, so that process startup alone is not reported as protection.
28. As an endpoint user, I want a policy update published as one complete version, so that packets cannot observe a half-updated rule set.
29. As an endpoint user, I want existing flow facts retained across policy updates, so that changing rules does not implicitly reset or terminate connections.
30. As an endpoint user, I want newly available facts to invalidate affected cached decisions, so that an earlier ALLOW does not conceal a later matching DROP.
31. As an endpoint user, I want rule versions distinguishable in observations, so that later edits do not rewrite what happened earlier.
32. As an endpoint user, I want conflicting imported rule identities reported, so that an identity cannot silently acquire different contents.
33. As an endpoint user, I want basic packet and byte accounting independent of history export, so that observation loss does not change packet decisions or basic totals.
34. As an endpoint user, I want actual allows, actual policy drops and runtime failures distinguished, so that rule effectiveness is not confused with delivery failure.
35. As an endpoint user, I want a rule counted once when it is the logical winner, so that cache hits and compiler fragments do not distort statistics.
36. As an endpoint user, I want observe-mode rule hits separated from actual blocking, so that a declared DROP is not mistaken for a dropped packet.
37. As an endpoint user, I want early blocked traffic represented in recent observations, so that blocking before flow creation is still visible.
38. As an endpoint user, I want one flow to retain its identity when its winning rule changes, so that traffic is attributed to the correct intervals.
39. As an endpoint user, I want request and reply attribution maintained separately, so that different directional rules do not overwrite each other.
40. As an endpoint user, I want overall traffic, application traffic, application protocol and rule-effect views, so that common questions have direct queries.
41. As an endpoint user, I want all published L7 labels counted according to their coverage, so that a multi-protocol flow is not forced into one arbitrary category.
42. As an endpoint user, I want historical classification based on facts known at the time, so that later recognition does not invent earlier knowledge.
43. As an endpoint user, I want pending observation changes exported without requiring another real packet, so that quiet flows can still update recent views.
44. As an endpoint user, I want history gaps and shortened retention reported, so that incomplete data is not presented as complete.
45. As an endpoint user, I want recent attribution retained after a flow ends, so that I can investigate recent rule effects.
46. As an endpoint user, I want older statistics compressed within a storage budget, so that normal observation remains suitable for a personal device.
47. As an endpoint user, I want history queries to use maintained summaries, so that opening a view does not rescan all raw observations.
48. As an endpoint user, I want historical rule names, versions and actions retained, so that edits or deletion do not relabel past activity.
49. As an endpoint user, I want unavailable old rule conditions reported honestly, so that the latest rule is never substituted for an old version.
50. As an endpoint user, I want current runtime, policy, flow, resource and channel status queryable, so that I can distinguish policy behavior from an unhealthy runtime.
51. As an endpoint user, I want a slow or absent observation consumer not to block packet processing, so that history maintenance cannot stall protection.
52. As an endpoint user, I want shared rule semantics across Root and VPN, so that the capture mechanism does not silently redefine policy.
53. As a personal-endpoint user, I want useful protocol coverage selected for my device traffic, so that industrial protocols do not consume effort or resources without a product need.
54. As an endpoint user, I want supplementary detection and corrections applied before protocol publication, so that an early provider mapping does not discard information needed to identify the traffic.
55. As an endpoint user, I want maintained public detector logic used as the main reference, so that coverage is not restricted to unverified historical heuristics.
56. As an endpoint user, I want useful port, short-payload and nonstandard-port heuristics retained where selected, so that recognition is not restricted to complete handshakes or conventional ports.
57. As an endpoint user, I want the supported protocol and supplementary-rule coverage stated explicitly, so that a reference project's large protocol list is not mistaken for tested product support.
58. As an endpoint user, I want different recognizers to publish the same stable protocol identity, so that my rules do not depend on the source library's private numbering or naming.
59. As an endpoint user, I want overlapping detection paths to have deterministic behavior, so that duplicate recognition or an incidental callback order does not change the published result.
60. As an endpoint user, I want protocol labels distinguished from completed or authenticated handshakes, so that a heuristic TLS, QUIC or DTLS label is not mistaken for valid SNI evidence.
61. As an endpoint user, I want supplemental recognition to retain bounded state in the existing flow, so that broader coverage does not introduce packet detention or a second flow engine.
62. As an endpoint user, I want supplemental facts to participate in existing optimized and cached matching immediately, so that added protocols do not work only in an uncached test path.
63. As an endpoint user, I want completed verdicts and historical attribution preserved when later protocol facts arrive, so that later classification does not rewrite prior traffic.
64. As an endpoint user, I want recognition limitations and representative device results reported separately, so that successful synthetic samples do not imply universal protocol accuracy or delivery.

## Implementation Decisions

### 1. Product and ownership boundary

The packet-domain target remains VPP-native C under ADR-0006, ADR-0007 and
ADR-0008. RuntimeService retains Android lifecycle ownership. Root and VPN
remain mutually exclusive profiles with their existing capture and transport
boundaries. The removed product C++ daemon, host model and artifacts are not
implementation references or compatibility fallbacks. Forks and POCs provide
evidence, not source to import directly.

The VPP main thread owns the loaded rules, groups and application bindings,
online management, configuration serialization and compilation. Workers read
immutable compiled programs rather than the mutable source graph. Rust owns
request adaptation, basic input validation, supported external import handling,
configuration-side normalization and normal observation consumption/storage.
Rust does not duplicate the editable rule model or choose physical rule
placement. VPP still validates its own input, capabilities and resource limits.

Configuration has one agreed-format persistent source file and VPP is its sole
writer. Observation storage is physically separate and maintained by Rust.
Temporary serialization and compilation representations do not create a second
authoritative configuration. Frontends access product APIs. Ordinary offline
rule viewing/editing is not required in this initial version.

### 2. Logical rules, applicability and precedence

For each application, expand all applicable direct rules, groups and bounded
group references into one effective rule set. Groups organize reuse and source
attribution; they have no independent winner or default action. Same-source,
same-effective-mode references deduplicate. Conflicting effective enforce and
observe modes reject the configuration. Different rule identities remain
distinct even when their contents coincide.

Precedence is ascending priority, ascending explicit order, then ascending
stable logical rule identity. Compile that complete order into Rank. Neither
match specificity, group traversal, index order nor physical stage adds
priority. Application identity selects the effective view; network/interface
and packet conditions remain rule inputs. Existing platform subject identity
and nonblocking attribution contracts remain in force.

Application network disabling is expressed by a highest-priority ordinary DROP
maintained by its configuration entrypoint. The matcher has no privileged Gate
branch. An empty effective set or a completed full lookup with no winner
defaults to ALLOW; explicit default denial uses a lowest-priority catch-all
DROP. A runtime fault, incomplete lookup or capacity bypass is not NoMatch.

Policy actions are packet-level ALLOW and DROP. Observe mode retains the winner,
declared action and source attribution while its actual policy action is ALLOW.
Policy ALLOW is not a promise of successful transport or delivery.

### 3. Conditions and availability

Support bounded AND, OR and NOT expressions over the agreed field classes:

| Facts | Conditions and meaning |
| --- | --- |
| Current packet | Address family, IP transport protocol, source/destination IP or CIDR, source/destination port or range, device input/output direction |
| Platform context | Applicable application, network and interface facts supplied by existing platform contracts |
| CT / Flow | CT state and ORIG/REPLY direction relative to the first observed flow direction |
| LPI | Membership in the currently published, deduplicated application-protocol result set |
| Domain | Protocol-applicable exact-name or name-and-descendants matching: TLS/QUIC/DTLS SNI, selected HTTP/SOCKS targets and DNS fallback; explicit confirmed absence remains SNI-specific |

Source and destination always mean current packet endpoints; do not implicitly
swap them for replies. Device direction and flow direction are separate facts.
Types carry availability as well as values. NOT cannot turn unavailable input
into a match. An OR may be proven true by an available true branch even when
another branch is unavailable. Published protocol results participate while
recognition continues; NOT examines the current published result set rather
than waiting for the whole recognition process to finish.

A rule containing any SNI condition has an implicit whole-rule applicability
requirement: the flow must already have a published TLS, QUIC or DTLS recognition
result and that protocol's applicable SNI producer facts. DTLS is an accepted
addition requiring implementation and validation; it is not covered by prior
TLS/QUIC evidence. AND, OR and NOT cannot bypass that requirement. Once applicable:

| SNI fact | SNI domain predicate | Negated SNI domain predicate | Confirmed-no-SNI predicate |
| --- | --- | --- | --- |
| No definite result | Unavailable | Unavailable | Unavailable |
| Valid matching name | True | False | False |
| Valid nonmatching name | False | True | False |
| Valid parse confirms no SNI | False | True | True |

An explicit valid Unknown protocol result can be compared normally. A temporary
detector miss, unmapped result, disabled producer, parse error or exhausted
budget must not automatically be promoted to that result. Existing supported
protocol-catalog identities and mappings remain the source of protocol names;
no commercial/private upstream number space is imported as a universal AppID.

### 4. Execution planning and bounded compilation

Reference expansion, deduplication, Rank, dependency analysis, overlap analysis,
placement and index construction are internal VPP compilation responsibilities.
L4 and general matchers may have separate implementations while sharing the
same logical ordering and combined snapshot.

Mark rules requiring CT/LPI/SNI or unsupported early predicates as post-flow.
Process rules in full Rank order. A rule that may overlap any higher-ranked
already-post-flow rule also becomes post-flow, including constraints propagated
through otherwise static rules. Only proven-safe whole rules go before flow
processing. Inconclusive proof chooses post-flow. A logical rule and all of its
fragments, factors and completion checks occupy one position.

Use simple conservative static envelopes over device direction, address family,
transport protocol, addresses and ports. Only prove disjointness when a
corresponding field is provably disjoint. Unknown NOT/dynamic structure widens
the envelope; it never removes a possible winner. Do not add a full-history CT
equivalence requirement or an application-wide observation prerequisite.

Within each matcher, same-mask entries can share subtables across priorities.
Prune using full Rank bounds, validate candidates completely, and continue
searching when a high-ranked candidate fails residual checks. Compile suitable
ranges into exact bounded mask representations. Small combinations may expand;
large combinations retain factorization and bounded residual evaluation rather
than unbounded DNF. The initial direct-expansion budget is 32 complete entries
per logical rule, adjustable after measurement. Total effective-view costs also
include mask reuse, candidates, factors, temporary state and update peak memory.

Worker-local query state is preallocated and scoped to one query. Partial
conjunction evidence never crosses packets or becomes a winner. If every legal
plan exceeds the total limits, reject publication with a useful error; do not
truncate the rule set or publish a partial program.

The correctness invariant is equality of logical winner, effective mode,
declared action, actual action and attribution between optimized execution and
flat ordered evaluation for the same rule version, input values and availability.

### 5. Packet execution, snapshots and caches

Early NoMatch continues through necessary flow/fact processing and the post-flow
program. An early actual DROP completes immediately without querying, creating
or updating FlowEntry, CT or LPI, even if a matching flow already exists. An
early actual ALLOW retains its full winner; lower-ranked post-flow rules cannot
overturn that decision. Required flow maintenance, observation, transport and
Adapter completion still occur on the applicable path.

Publish all required compatible programs, application views, Rank, attribution
and dependency metadata as one immutable Runtime Snapshot. Keep the existing
protected double-bank lifecycle: a packet uses one acquired snapshot throughout
its policy work, old readers may finish, and storage cannot be reused before
its readers leave. Reuse compatible old compiled products only when the new
complete plan permits it. Do not add an unbounded retired-snapshot chain or a
new global worker-stop publication mechanism.

Each worker has a fixed-capacity private cache of complete Match or NoMatch
results. Direct matching and cache hits use the same attribution/accounting
path. Guards conservatively cover the whole applicable program, relevant input
values and availability, application view and complete snapshot identity; the
last winner's fields alone are insufficient. Fact generations are meaningful
only with the correct flow instance. Opposite packet directions cannot share
results merely because they share a bidirectional flow key.

New snapshots lazily invalidate old decisions without scanning or terminating
all flows. Flow identity, CT/LPI facts and cumulative counters survive. Full
snapshot identity includes the established generation/revision/hash safeguards;
matching revision numbers alone are insufficient. Cache miss, capacity pressure
or failed guards return to normal matching without changing semantics.

### 6. LPI, SNI and domain matching

Use the researched normal process as evidence: flow/direction and necessary
contiguous TCP data support LPI feature updates, base recognition, supplemental
recognition/correction, project mapping and deduplicated result publication;
TLS/QUIC/DTLS parsing then publishes its applicable SNI facts.
LPI stopping and SNI stopping are independent. A result produced synchronously
before this packet's decision cutoff may affect that packet; later facts affect
later packets and never rewrite a completed verdict.

#### Supplemental recognition scope and selection

Retain libprotoident as the base provider. Use nDPI's protocol-specific detection
logic as the primary reference for the supplemental layer; select useful fork
features rather than inheriting all fork detectors or their original ordering.
Heuristics are permitted, including port and short-payload clues. Neither the
source project's name nor a finer output label is proof of greater accuracy.
GB/T 32960 is excluded from this personal-endpoint product scope.

Deliver an auditable coverage matrix for the correction, covering the existing
DNS, HTTP, TLS, QUIC and SSH facts and the additional protocols/features selected
for personal endpoints. For each assessed item, record inclusion or exclusion
and its rationale. Each included detector must identify its fixed reference
revision, input and transport/direction constraints, ordinary/nonstandard-port
coverage, single- or cross-packet evidence, relevant budget and stopping behavior,
project-catalog output, overlap/correction behavior and positive/negative cases.
This matrix is a tested capability description, not a second work tracker or an
automatic promise to implement the entire nDPI protocol inventory.

Useful fork supplements include SMTP/FTP banner correction, selected
nonstandard-port or short-payload features, and useful distinctions such as
SOCKS versions. Include them according to personal-endpoint value and reproducible
evidence; do not automatically duplicate nDPI coverage or retain every broad
fallback. Ordinary detector selection, internal structure and initial limits are
engineering choices within this scope. Changes to published-fact semantics,
packet ownership or product scope require a separate decision.

Keep the upstream guess and the features needed by supplemental checks until
that attempt's result has been resolved. Do not first reduce unrelated provider
results to an unmapped value if that loses information required for correction.
Use explicit applicability and deterministic precedence for overlapping checks;
do not blindly concatenate two first-match registries or union conflicting
provider guesses. A supplemental check may replace the current unpublished
guess. Map the resolved result through the project-owned catalog, then publish
and deduplicate it. Bring the existing standalone QUIC supplement into this same
path. Detection precedence is internal to recognition, not an extra firewall
Rank or policy action.

Preserve existing stable protocol IDs and keys; add selected supported facts to
the same catalog. Provider enum values, application brands and presentation
categories do not automatically become protocol facts. A version or finer label
must have its own supported meaning rather than merely copying another
provider's taxonomy. QUIC recognition does not automatically establish HTTP/3,
and a heuristic TLS/QUIC label does not establish a valid ClientHello, completed
handshake, cryptographic authentication or confirmed absence of SNI.

Published results remain a deduplicated accumulated set. Correcting this
attempt's guess does not withdraw facts already published by an earlier attempt.
Normal protocol coexistence or HTTP-to-TLS progression is not automatically an
error. Do not introduce cross-packet fact retraction, confidence scores or a new
public provisional-versus-confirmed policy model. Temporary misses, unmapped
results and exhausted budgets retain existing facts and unavailable inputs;
they do not fabricate Unknown. Newly published facts and their availability
participate in the existing whole-application cache dependency guards, complete
winner semantics and attribution without a separate policy path.

Keep supplemental state bounded and owned by the existing FlowOwner. Cross-packet
checks may retain small state and only the bounded bytes they require, not
references to original packet buffers or a second flow table. Preserve identity
checks, policy-update retention, budget stopping and FlowEnd/slot-reuse cleanup.
The existing 20-payload-attempt/32-KiB recognition window is an engineering
baseline, not a reason to increase limits automatically when adding detectors;
measure any adjustment and its per-owner memory and work cost. Supplemental
recognition does not bring nDPI's module lifecycle or independent TLS byte cache
into the product. Necessary TCP bytes use the agreed shared reconstruction
cache; QUIC handshake assembly retains its separate bounded contract.

Pin and record any reused public source and its applicable license obligations.
Fork/POC behavior remains evidence to adapt, not code to import directly. The
removed product C++ implementation and leaked code without an established
reuse license are not implementation sources. Choosing detector references
does not replace the agreed owner, packet, configuration or observation model.

#### SNI and domain consumers

Do not hold original packets while waiting for SNI and do not introduce an
automatic first-N-packets allow exception. TCP stream reconstruction owns one
bounded byte cache with independent directional sequence spaces; TLS/SNI reads
that cache and keeps only the needed parser state and final small result.
Retransmission does not create duplicate logical byte ranges. Bound byte length,
span, metadata, work and lifetime; do not restore the rejected independent
32-parser quota. QUIC uses its own bounded handshake-data assembly.

On timeout or parsing/recognition budget exhaustion, stop the affected attempt,
release data no longer needed by agreed consumers, retain existing flow/CT and
published facts, and record why remaining facts are unavailable. Exhaustion is
not evidence of no SNI or final Unknown. Do not reset budgets to retry forever.

Domain matching distinguishes exact name from the name plus all descendant
labels. ASCII comparison is case-insensitive. Configuration/import may normalize
one absolute-name trailing dot and convert internationalized names to A-labels;
no packet-path Unicode conversion is required. Network SNI follows its own
validity rules and is not treated as arbitrary URL input. Imported wildcards
must follow an explicitly supported source syntax, not a guessed meaning.
Unsupported conditions or invalid entries are reported rather than stripped to
a domain that broadens the original rule.

Multiple matching names/lists remain available to the logical rule engine;
longest name or whitelist membership has no implicit action priority. Compare
libdatrie and maintained Valkey rax with a VPP hash baseline under identical
semantics; Knot QP remains a backup candidate. The library choice requires
ARM64/device measurements and is not settled by this specification.

### 7. Saving, applying and startup repair

Form a complete configuration version from submitted rules, groups and bindings,
perform basic format/reference consistency validation, then finish reliable
saving before compiling that fixed version. Later edits must not leak into an
in-progress compilation. Publish only the fully successful result.

| Situation | Persistent configuration | Packet execution and reported outcome |
| --- | --- | --- |
| Basic validation or saving fails | Previous saved configuration remains | Do not compile; preserve the active snapshot and report the failure |
| Saving succeeds, compilation fails during operation | Retain the new saved edits | Continue the old active snapshot; report saved but not applied with a useful error |
| Compilation and publication succeed | Saved source identifies the compiled version | New snapshot becomes available to subsequently acquiring packets; report saved and active identities |
| Startup/restart cannot compile the saved configuration | Preserve the configuration for correction | No product traffic capture or protection-running claim; retain healthy VPP management APIs so the user can repair and retry |
| VPP/control infrastructure itself is unavailable | File survives independently | Report management unavailable; do not fabricate empty rules or successful operations |

Successful compilation and valid publication are necessary policy prerequisites,
not replacements for permissions, Adapter readiness or platform lifecycle
requirements. The user corrects failed rules through the same VPP management
entrypoint; the system must not silently discard rules or revert saved edits to
manufacture success. Startup config failure is distinct from a VPP crash and
from an update failure with an existing valid snapshot. Existing OS lockdown
and platform connectivity policies retain their authority.

Saved and applied results remain distinguishable even if one request performs
both operations sequentially. API splitting, temporary-file mechanics and UI
save/apply interactions are engineering or later interaction decisions. There
is no claim of an atomic transaction spanning disk and worker memory. Reusing an
old in-memory snapshot after restart is impossible; automatic persistent
last-known-good recovery is not promised.

### 8. Rule identity and historical interpretation

Use one 64-bit rule-version identifier in ordinary messages: a fixed nonzero
random 48-bit logical-rule identity and a 16-bit monotonically increasing
revision beginning at one. Check retained local identities for collision when
creating a rule. A logical rule keeps its fixed portion; revisions do not wrap
or rebind the same complete identifier to different content. Report revision
exhaustion. A readable form may show the fixed hexadecimal identity and revision.

Importing the same complete identifier with different contents reports a
conflict. This is not a mathematical global uniqueness guarantee. Do not add a
snapshot-local message-reference mapping merely to compress the eight-byte ID.
Snapshot identity separately describes binding, list and program context.

Recent history retains the contemporaneous rule name, full version identifier,
actual action and accounting. Longer-lived aggregates retain enough identity
to recognize historical rule effects. Editing/deleting current rules does not
rewrite saved history. Full old conditions are available only if the matching
configuration and required referenced material still exist; otherwise report
them unavailable. Normal observation does not create a complete old-rule/list
archive, and the latest version must never stand in for the old one.

### 9. Accounting and observation lifecycles

Measure IP packets and IP-layer bytes including headers at the shared policy
boundary. Retransmitted packets count when observed again. Internal handoffs,
copies, timers and FlowEnd signals do not add business traffic. Reassembled
policy accounting is distinct from raw Adapter fragment counters.

Count one logical winning-rule hit per packet, independent of index fragments,
OR branches, factorization or cache use. Default ALLOW has no invented winner.
Keep actual ALLOW, actual policy DROP, runtime/processing failure and transport
outcome distinct. An observe-mode declared DROP may count as a rule hit while
actual allowed traffic increases. Blocked bytes are packet sizes, not a promise
of saved transfer volume.

Normal Flow observations keep their lifecycle identity and directional
cumulative totals when policy, application or classification changes. Necessary
attribution boundaries precede the first contribution under a new attribution.
Do not attribute an entire cumulative difference to the newest rule when a
boundary was lost.

Pre-flow actual DROP uses a separate bounded, owner-local Blocked Observation
with tuple and relevant attribution context. It is not a FlowEntry and performs
no CT, LPI or stream reconstruction. Idle timeout retires it; no FIN/RST is
required. Rule identity is attribution, not observation identity. Retired tuple
reuse creates a new instance. A Flow and Blocked Observation may overlap in
time and remain independent; each real packet contributes to only its actual
path, and the objects do not convert into each other.

Basic VPP accounting does not depend on allocating an observation object or
successfully exporting records. History-derived values may therefore have
explicit coverage gaps relative to basic counters. Do not invent proportional
attribution to force agreement.

### 10. Export and consumer behavior

Export cumulative snapshots at creation/end, necessary attribution changes,
growth thresholds and low-frequency time-driven flushing of pending changes.
Do not write ordinary records for every packet or clear totals after export.
Reuse owner scheduling; observation flushing does not advance CT, refresh real
last activity, change protocol expiry or retire the flow.

One message may carry cumulative growth, attribution/state changes and END.
Rust must process all of them together, including the tail contribution before
marking an object ended. Ordinary growth may coalesce; coalescing cannot erase
known attribution boundaries. END does not require an earlier separate UPDATE.

VPP export is bounded and nonblocking. Queue failure drops observation evidence
with counters and gaps; it does not wait for Rust reads, durable storage, ACKs
or retransmission. Rust uses one clear consumption flow and minimal instance /
update state to prevent duplicate accounting, counter rollback, instance reuse
confusion or stale UPDATE resurrection after END. Persisted consumption state
and summaries advance consistently. Interruptions preserve known information
with incompleteness indicators rather than requiring replay or complex reordering.

Normal and future debug payloads have independent bounded channel capacity and
loss accounting, with reusable transport infrastructure. Retain VPP svm_msg_q
and an Aeron C SPSC ring subset as candidates; implement a minimal ring plus
eventfd only if those reuse options prove unsuitable. This is an experimental
choice, not three simultaneous backends or runtime fallback. Mobile tests must
include wakeups, batching, memory and actual nonblocking behavior.

### 11. Rust windows, retention and historical classification

Rust incrementally maintains four predefined views: overall traffic, application
traffic, per-application L4/L7 protocol traffic, and rule effects. APIs read
maintained summaries with bounded aggregation rather than rescanning all raw
records. Arbitrary multidimensional analytics is not a requirement.

Classify contributions using facts available when they were counted; later
recognition does not automatically backfill earlier traffic. Each distinct
published L7 label receives that contribution once, while application/overall
totals receive it once in total. Protocol shares use the same-scope application
total as denominator and may sum above 100%; do not normalize them into an
exclusive partition.

Initial adjustable retention defaults:

| Data | Retention |
| --- | --- |
| One-minute statistical buckets | Most recent 48 hours |
| One-hour aggregates | Until data age 30 days |
| One-day aggregates | Until data age 180 days |
| Ended observation overview and necessary attribution | 24 hours from Rust's first consumption of END; duplicate END does not extend it |
| Normal persistent observation budget | 256 MiB including indexes and maintenance logs, with working space reserved |

Assign an attributable cumulative increment to the minute containing that
increment's last activity, not END send/receive time. Distinct attribution
segments are processed separately. This is approximate temporal placement,
without interpolation or a promised one-bucket error bound. Use UTC-aligned
minute/hour/day buckets; timeout and scheduling use monotonic time. Clock
mapping and clock-change handling are implementation correctness work.

Roll up counts within the same classifications before removing finer data.
Derive ratios from counts rather than averaging percentages. Query each
contribution from one granularity only. Retention age does not restart after
compression. Active observations may lose old detail but retain the baseline
needed for subsequent deltas; END does not immediately erase recent context.

Apply time and space limits together: expire old data first, then remove oldest
ended detail, advance coarser aggregation of old fine data, and finally shorten
the oldest aggregate coverage. Report actual coverage. Never save space by
deleting an active baseline and recounting its next cumulative value from zero.

### 12. Query scope and errors

Provide authoritative typed queries for runtime/profile/Adapter status, saved
and applied policy identity and errors, RX/TX counters, current flows, logical
rule counts, policy drops versus runtime failures, resource use and observation
export/consume/store health. Current flow information includes endpoints,
application/network context, protocol facts, timing, directional accounting and
current attribution within bounded query contracts.

VPP supplies its state, RuntimeService supplies platform state, and Rust supplies
its consumption/storage state. Reuse existing CLI/API capabilities and add
missing typed queries; do not scrape logs to construct authoritative statistics.
Channel health must remain queryable when the record channel is full. These
are backend capabilities, not a requirement to expose every engineering field
in the initial UI.

### 13. Resource behavior and adjustable choices

Insufficient optimization/proof budget chooses a correct conservative plan.
Exceeding all legal compilation plans rejects publication. Query-cache pressure
falls back to matching. Parser limits stop the affected attempt without
inventing a result. Observation pressure loses evidence with explicit gaps,
while persistent space pressure follows the stated retention order.

Keep the existing FlowRuntime and Adapter contracts for new-flow capacity and
processing bypass; do not evict active flows, fabricate CT facts or relabel an
infrastructure bypass as Policy ALLOW. Existing policy DROP is not reopened by
capacity failure. Publication-time validation must bound expression size,
compiled memory and worst-case query work; a partially scanned query cannot
return its current best candidate as the final winner.

Choose remaining expression, flow-cache, parser, total-memory and execution
limits during implementation and device experiments. Include old/new snapshot
coexistence, per-owner state and metadata. The direct-expansion and history
defaults are starting values, not measured optimal settings or immutable limits.

## Testing Decisions

The agreed highest product seam is rule-management/save/apply and status/query
behavior through the existing product control boundary, paired with observable
packet decisions. Reuse existing compiler/matcher Interfaces for focused
semantic tests and existing owner/snapshot/Adapter seams for lifecycle tests.
Do not expose index arrays or add a second production engine to make tests easy.

1. Build a simple test-only ordered reference evaluator, calibrated first with hand-decided examples. Compare logical winner, declared action, effective mode, actual action and attribution for identical effective rules, input values and availability; comparing ALLOW/DROP alone is insufficient.
2. Cover precedence ties, direct/group applicability, same-source deduplication, conflicting modes, empty sets, explicit fallback DROP and ordinary network-disabling rules.
3. Cover AND/OR/NOT availability, available true OR branches, current packet endpoints, device versus flow direction, CT conditions and additional published protocol results.
4. Test the whole-rule TLS/QUIC/DTLS prerequisite and applicable producer facts for every SNI Boolean shape, valid matching/nonmatching names, confirmed absence, incomplete parsing, errors and budget exhaustion. Validate the newly selected DTLS source independently; none of the latter outcomes may fabricate confirmed absence.
5. Compare exact and descendant domain matching, label boundaries, case normalization, valid A-labels, overlapping lists and rejection of imports that would silently lose conditions.
6. Compare direct expansion, factorized evaluation, residual checks, full-Rank pruning and conservative placement against the same reference result, including propagated post-flow constraints and same-action competing rules.
7. Confirm query-local partial state cannot cross packets or directions, and that cache hits preserve the full logical result and accounting.
8. Exercise protocol/SNI availability changes, application context changes, opposite packet directions, snapshot changes, flow retirement and slot reuse to verify cache guards and identities.
9. Exercise old/new packet overlap, delayed readers and bank reuse under repeated publication. A bound packet completes against its original snapshot; a new packet cannot combine views from different versions. Publication does not scan or reset owner flow state.
10. At the product control seam, test validation failure, save failure, compilation rejection, successful publication, separate saved/applied identities and retained user edits. Include a saved configuration that fails compilation, process restart, a still-available management API, user correction and successful retry before enabling capture.
11. Verify configuration failure with a healthy control plane is distinguished from VPP/control failure and platform permission/Adapter failure. A running management process is not sufficient for a protection-running claim.
12. Test rule-version creation, revision progression/exhaustion, collision rejection and import conflicts; editing or deleting current rules must not rewrite historical identity, names or actions.
13. Check one logical hit and correct IP byte counts across direct matching, cache hits, observe mode, early DROP and post-flow DROP. Internal scheduling, handoffs and compiler fragments add no business counts.
14. Check separate Flow and Blocked Observation instances, directional attribution boundaries, tuple reuse, idle retirement and no double counting when their lifetimes overlap.
15. Check growth-triggered and time-triggered cumulative export, combined END with tail growth and state-only updates. Time-driven export must not refresh real flow activity or invoke CT progression.
16. Exercise full/unavailable channels, missing boundaries, duplicates, stale updates, instance restarts and interrupted consumption. VPP keeps progressing; Rust does not guess missing attribution, double-count recovered cumulative values or resurrect ended instances.
17. Verify multi-label protocol arithmetic, no automatic historical backfill, last-activity time placement, UTC bucket rollups, single-granularity query accounting and first-END-based retention.
18. Exercise time and storage pressure, including index/log budget costs, active baseline preservation and explicit shortened coverage. Verify that old conditions are marked unavailable when their source material is gone.
19. Use current static L4, complete-bundle, S209 protected-snapshot, owner-flow, expiry/FlowEnd and Android runtime/Root/VPN contracts as prior art. Extend their observable behavior coverage; their historical PASS results do not validate the new engine.
20. After semantic and lifecycle checks, run actual Android ARM64 Root and VPN integration, with Linux host integration where applicable. Verify packet outcomes, exported records, queries, resource cleanup and update behavior; use the repository's Android device wrapper.
21. Compare domain matcher and record-channel candidates under identical semantics and representative device workloads. Measure compilation time, lookup cost, peak memory, batching/wakeups and mobile power/thermal effects as relevant. No new numeric performance threshold or candidate winner is implied before measurement.
22. For supplemental recognition, reuse the existing rule-management/save/apply/query and real-packet boundary as the highest integration seam. Extend the existing owner-local producer and independent logical-reference tests; do not create another production classifier or expose detector internals solely for tests. T12's bounded producer, protocol queries and T09–T11 plan/cache comparisons are prior art, not proof that added detectors pass.
23. Make every included detector's coverage-matrix row executable with positive and relevant negative examples. Include short/truncated or malformed payloads, lookalike bytes, standard/nonstandard ports, available directions, and packet sequences where the selected rule uses them. Test overlapping supplemental checks and provider corrections before catalog mapping, deduplication, unmapped outputs and useful label distinctions. Record intended heuristic acceptance and known limitations; do not claim zero false positives from a few samples.
24. Verify new recognition state against the correct Flow generation/incarnation, same-slot reuse, policy updates and packet/byte/work limits. Preserve accumulated facts and independent availability across misses and stopping; confirm that no original packet is held and no second TCP byte cache or unbounded retry is introduced. Keep protocol recognition distinct from valid SNI parsing and its error/absence contract.
25. Immediately extend the independent complete-winner comparison for each newly published protocol fact across direct, factorized and residual plans, whole-rule PRE/POST placement, cold/hot cache and changed set/availability. Include a losing or negated protocol predicate becoming relevant, observe mode and exactly one logical hit. Compare full winner, mode, declared/actual action and attribution, not only ALLOW/DROP.
26. At the actual Linux and Android Root/controlled-VPN product boundaries, submit representative supplemental-protocol rules through the real API and join saved/applied configuration, protocol queries, real payloads, policy decisions and endpoint outcomes. Bind evidence to the source, artifact, profile and runtime identity. Representative platform tests complement the per-detector Host matrix; neither a pcap-only detector run nor a screenshot substitutes for live product behavior. Preserve failed probes and distinguish Initial exchange, completed handshake and successful delivery.
27. Record selected detectors' bounded state, call counts, resource peaks and representative ARM64 costs under comparable workloads. Report coverage gains, false-positive/false-negative examples and regressions without assuming nDPI logic is universally more accurate or faster. No new performance threshold, full-nDPI equivalence or all-protocol device matrix is implied.

Tests assert externally meaningful behavior at these Interfaces. Generated cases
may supplement deterministic boundary cases. Test-only reference evaluation is
not the retired C++ host model and must not restore or depend on it. Precise
tooling, case counts and practical capacity values can be selected during
implementation within these acceptance contracts.

## Out of Scope

- Concrete UI layout, editors, drag ordering, save/apply buttons and detailed debug interactions.
- A complete debug capture, simulation, replay or long-term diagnostic archive. Preserve only the already agreed independent-channel, single-session and truthful-evidence boundaries for later design.
- Detailed DNS-query and association fact/record Interfaces, admissibility, ambiguity and lifecycle contracts are not defined by the September packet-rule tables. The application DNS filtering direction is now accepted by ADR-0011 and must preserve whole-rule conditions and source distinctions when these contracts are specified.
- Tunnel-inner parsing, general protocol decoding, general STARTTLS coverage or DTLS coverage beyond the selected SNI source, JA3/JA4 and other future consumers.
- Complete nDPI engine integration or replacement of libprotoident, wholesale fork-detector parity, and automatic implementation of every protocol listed by a reference project.
- GB/T 32960 and vehicle-specific recognition in this personal-endpoint scope; application-brand databases, risk scoring and fingerprints merely because a reference engine offers them.
- Complex cross-packet protocol-fact withdrawal, confidence-score policy and a new provisional/confirmed public fact model. A supplementary heuristic label is not complete-handshake, SNI or cryptographic-validation evidence.
- Complex domain glob/regex matching or universal import-format compatibility.
- Ordinary offline rule management, a second editable Rust rule database, a persistent full old-rule/list archive added for normal observations, and automatic last-known-good configuration recovery.
- Per-stage priority spaces, special backend Gate privileges, split execution of one logical rule across flow boundaries and user-selected physical placement.
- JIT/user scripts, unbounded DNF, full SAT optimization, exact minimal cache invalidation, live worker resharding or new shared mutable worker rule graphs.
- Reliable observation ACK/retransmit/replay, arbitrary analytics cubes, exact per-packet historical timing or gap-free history guarantees.
- Restoring or porting removed product C++ code or treating a fork/POC as importable product source.
- Declaring an Android public release, performance pass or device acceptance merely because this specification is published.

## Further Notes

The 2026-09-25 correction makes the supplemental step explicit after reviewing
T12 against the previously accepted fork process. The selected direction is
libprotoident plus bounded supplemental recognition, primarily informed by
nDPI, with useful fork features selected for personal endpoints. Preserve T12's
original scoped evidence and failures; its completion does not establish this
new coverage. Implementing work and affected downstream acceptance/dependencies
belong to Plane and must follow this revision without rewriting historical PASS
claims. Publishing this specification does not resume the paused implementation
run or create new implementation tickets.

Supporting evidence: [the accepted fork process](../reviews/2026-09-23_LPI_SNI_FORK_PROCESS_REVIEW.md),
[public detector references and selected scope](../reviews/2026-09-25_PROTOCOL_RECOGNITION_REFERENCES.md),
[nDPI adaptation boundaries](../reviews/2026-09-25_NDPI_ADAPTATION_BOUNDARIES.md),
and [T12's original acceptance](../testing/2026-09-25_T12_PUBLISHED_PROTOCOL_FACTS.md).

The September discussion is resolved for this backend and normal-observation
scope. The final rule-management prerequisite was explicitly confirmed: rule
compilation must succeed before new protection starts, and configuration errors
remain the user's responsibility to correct through the available management
entrypoint. Implementation must retain that repair path.

ADR-0009 records the accepted change from stage-owned precedence and Rust-owned
configuration persistence to unified rule semantics and VPP-owned online
configuration. ADR-0006/0007/0008 and existing worker ownership, packet completion,
platform and transport contracts remain authoritative. Older authoring,
checkpoint and observation descriptions must not silently reintroduce rejected
requirements. This specification does not authorize a new checkpoint retention
product or decide UI behavior.

Format/ABI details, allocation layout, remaining numerical budgets and candidate
selection are implementation and experiment work, not reasons to reopen agreed
semantics. Decompose the resulting multi-session build into independently
verifiable complete behavior slices with real blocking relationships in Plane.
The previously suggested implementation order is a planning input, not an
approved second specification or an extra release split.
