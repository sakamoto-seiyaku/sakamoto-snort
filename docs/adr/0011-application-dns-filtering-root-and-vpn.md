---
status: accepted
date: 2026-10-07
---

# Application DNS filtering across Root and VPN

Root/NFQUEUE and VPN use the same application-scoped DNS filtering policy,
combining query-stage control with domain-aware control of subsequent business
connections. The user explicitly selected this as a formal decision after
reviewing Portmaster's two Linux resolution paths and Android's attribution and
system-cache limits. One policy intent spans both modes; available evidence and
the point at which an action can occur depend on the query path.

When a captured query's original application is reliably known, evaluate that
application's applicable DNS policy before forwarding the query or consulting a
product answer cache/upstream. When the original application is unknown, allow
resolution without waiting or guessing the caller. A system resolver's UID alone
identifies the process performing resolution, not the application it represents;
such system-mediated queries are allowed at the application DNS policy stage.
Retain actual Domain-IP Association evidence and evaluate subsequent connections
using their own application identity and available domain/address facts. A
permitted DNS query does not grant permission to the subsequent connection.

Root's packet-based DNS route and VPN share DNS policy checks, message parsing,
query/answer correlation and result collection on both original-resolver and
product-proxy paths. Product answer caching and ordinary DNS/DoT/DoH clients are
shared by the optional proxy path; permitted ordinary traffic need not enter
that proxy. KSU's system-hook route is a future extension using local policy
checks and result collection while Android owns resolution, answer caching and
encrypted upstream. Its planned NFQUEUE allowance for 53/5353 is scoped to that
future hook route, not the first-version Root DNS ingress.

## First-version scope

The first version targets Root/NFQUEUE and VPN with one implementation for their
shared DNS responsibilities. Parsing, applicable application policy, correlation,
result processing and the optional proxy's transactions/cache/upstream clients
are reused; ingress, platform socket operations and reply delivery use their
respective Adapters. This is code reuse, not a requirement for one global mutable
cache or for every query to traverse a full local DNS resolver.

The first-version ingress scope includes ordinary unicast UDP/TCP DNS queries on
port 53 to application-selected public or local-network DNS servers, as well as
the product-configured DNS entry. Such queries enter the common DNS core for
applicable policy and records without automatically changing their upstream
destination. mDNS and application-owned encrypted DNS follow their separate
choices below.

The user also requires preserving existing local-network DNS configuration,
including self-hosted resolvers. Capturing a query does not authorize silently
replacing its resolver or the network's existing domain-routing choices. A name
that looks public may have a local answer in that resolver's view; name shape,
resolver address and search-domain metadata do not provide an exhaustive
internal/public classifier. Existing resolver choices and domain routing must be
retained unless the user explicitly configures a replacement for the affected
path; enabling query filtering alone does not authorize replacement.

KSU/libnetd implementation is deferred. The design may accommodate its future
local filtering and result collection, but the first version does not implement
the system hook, installer or cross-process policy projection. Root and VPN DNS
operation must not depend on those future facilities. This scope update does
not change the selected filtering behavior or claim that implementation has
started or passed validation.

### Ordinary DNS query-type compatibility choice, 2026-10-11

The user confirmed that first-version ordinary DNS handling is not limited to
A/AAAA address lookups. Queries for TXT, MX, SRV, HTTPS and other record types
use the same applicable query-domain policy and selected resolution path.
The existing reliable-caller requirement, unknown-caller allowance and CNAME
response-policy choice continue to apply.

Preserve the query and answer content and semantics rather than reconstructing
an address-only answer. Record types whose data format is not understood remain
eligible for forwarding with their data preserved; lack of a type-specific
extractor is not itself a reason to discard the record. This follows
[RFC 3597's transparent handling of unknown resource records](https://www.rfc-editor.org/rfc/rfc3597.html#section-3).
Proxy caching retains the existing TTL and selected-context contracts.

Domain-IP Association updates use actual, reliably extracted address records;
text or other embedded fields are not treated as address records or SNI.
CNAME filtering keeps its already selected scope and whole-rule Rank. Forwarding
other record types does not make every name inside their data a new policy fact.
Association provenance, admissibility and the deferred application scope remain
separate. This records query compatibility and limited fact extraction for both
Root and VPN, not an implemented parser, proxy or device validation.

## User-selected upstream behavior

The user confirmed that encrypted resolution is used only after the user
configures and enables an encrypted DNS upstream. Without a user-selected
replacement, permitted ordinary queries retain their original resolver
destination and network resolution context on the existing forwarding path.
The previously proposed fixed VPN DNS proxy entry belongs to the proxy path; it
is not a requirement to send ordinary original-resolver traffic through that
proxy. Automatic VPN setup must preserve the original network DNS choice when
upstream replacement is disabled.

The upstream configuration supports ordinary UDP/TCP DNS as well as DoT and
DoH. A user may explicitly select an ordinary DNS server; that intentional
choice is distinct from the product silently rewriting a destination. The proxy
shares filtering, wire data, transactions, answer caching and result handling
across these transports. DoT/DoH names the encrypted transports,
not the whole module. Product-generated encrypted upstream traffic must follow
the user's enabled configuration; this decision does not authorize replacing or
downgrading an existing system/app encrypted path outside the captured scope.

This supersedes the earlier assumption that every permitted captured query is
forwarded to an encrypted remote resolver. Filtering can operate without
enabling encrypted DNS, and ordinary DNS support is not merely an emergency
fallback. Local-name exception routing follows the choice below; detailed
compatibility and failure contracts require subsequent specification. Answer
reuse must respect the selected resolver/network context rather than return
another resolver's view of the same name; precise cache layout remains under design.

### Upstream address and bootstrap choice, 2026-10-11

The user confirmed that DoT/DoH endpoint configuration supports both hostnames
and IP addresses. An IP-form endpoint uses its configured address directly.
For a hostname endpoint, prefer configured connection IPs; if none are provided,
obtain the service address through the system/original-network DNS resolver.
Keep the configured service identity for TLS authentication when selecting a
connection IP. IP-form configuration does not authorize disabling certificate
or service-identity validation.

DNS Upstream Bootstrap applies only to product-generated resolution needed to
connect to the selected upstream service. Use the original system/network path
outside the product proxy so that bootstrap does not recursively require the
still-unconnected encrypted service. This choice does not create a hostname
permission exemption for another application's query.

Application DNS queries continue to use their already selected encrypted
upstream and Local DNS Resolution Exceptions. Failure to obtain a usable
upstream address follows configured primary/backup selection and the existing
final failure behavior; it does not send application queries to ordinary DNS.
The address source is system/network resolution or configured IPs, not an
implicitly selected third-party public bootstrap resolver.

Address refresh, cancellation, platform integration and exact configuration
representation remain implementation contracts under the existing owner,
event-progress and bounded-resource model. [RFC 8484's operational discussion](https://www.rfc-editor.org/rfc/rfc8484.html#section-10)
explains the bootstrap problem and address-acquisition alternatives. This
records the shared Root/VPN design without claiming implementation or device
validation.

### Encrypted DNS replacement scope choice, 2026-10-08

The user confirmed that enabling the selected encrypted DNS upstream routes
captured ordinary DNS queries addressed to public resolvers through the product
DNS service, including queries an application sends to another public DNS
server. After applicable query policy permits a request, the proxy uses its
selected-context answer cache or the configured DoT/DoH upstream. It does not
retain an application's original public DNS destination as an independent
forwarding path merely because that application selected it.

For example, an application query to `8.8.8.8:53` is handled by the same product
proxy and selected encrypted upstream as a query to the configured product DNS
entry. Root and VPN adapt ingress/reply delivery while sharing this behavior.
The no-replacement path remains available when upstream replacement is disabled.

The user's existing protection of local-network/self-hosted DNS and domain
routing remains in force, with the local-name exception choice below and other
compatibility details still to specify. This choice does not supply an exhaustive
internal/public name classifier. Application-owned encrypted DNS and mDNS remain outside this
ordinary port-53 replacement decision. The user referenced Portmaster's local
resolver model; its [fixed-source investigation](../reviews/2026-10-05_LINUX_PORTMASTER_DNS_REFERENCE_RESEARCH.md)
provides supporting evidence rather than additional product contracts.

### Local DNS resolution exception choice, 2026-10-08

The user accepted explicit local-name routing exceptions while encrypted DNS is
enabled. A specified hostname or name-and-descendants scope uses the network's
original DNS or a selected local-network DNS server. Other queries on the proxy
path use the selected DoT/DoH upstream. Preserve existing explicit resolution
scopes when available and allow users to supplement them with exceptions.
This retains the local answer view even for a public-looking name such as
`git.example.com`.

Both routes apply current applicable query policy before answer-cache lookup or
upstream dispatch and retain observations. An exception selects resolution
routing, not query or connection permission. Answer reuse retains its selected
network/resolver view. Hostname shape, resolver addresses and search-domain
metadata remain insufficient to promise a complete automatic local-name list.
Exact exception representation, overlap handling and platform discovery are
subsequent implementation contracts; mDNS follows its separate choice below.

### mDNS compatibility choice, 2026-10-08

The user confirmed that first-version mDNS traffic on UDP 5353 retains the
original network/system handling path. When observable, it remains eligible for
existing protocol recognition and flow records. It does not enter the product's
encrypted DNS proxy or DNS-domain query filtering, and this choice introduces
no product-owned mDNS resolver. General application/IP and other independently
applicable packet rules still execute; preserving the resolution path is not a
blanket permission exemption.

The user referenced Portmaster's local-network compatibility as a direction;
its [fixed-source investigation](../reviews/2026-10-05_LINUX_PORTMASTER_DNS_REFERENCE_RESEARCH.md#局域网mdns-与-split-dns-不是自动等同系统行为)
does not make all of its resolver behavior part of this product. This choice
concerns mDNS traffic, not every ordinary unicast query whose name ends in
`.local`. Platform multicast reachability and observation coverage still need
implementation and device validation; this records the target behavior rather
than proving that the current VPN transport already preserves it.

### Application-owned encrypted DNS blocking prerequisite, 2026-10-08

The user clarified that the product does not transparently replace or decrypt
another application's DoH/DoT queries. The available control is optional
connection blocking through applicable rules, distinct from ordinary DNS
query-domain filtering and the product's own encrypted upstream client.

Complete the product's own DoH/DoT functionality and provide a usable resolution
path before recommending that users enable external encrypted-DNS blocking
rules. Until that prerequisite is met, preserve those connections without
automatically introducing or enabling such blocking. Meeting the prerequisite
allows a recommendation, not automatic activation; the user chooses whether to
enable the rules. Independently applicable, explicitly configured general rules
continue under the existing whole-rule semantics.

Blocking a connection is not evidence that its DNS QNAME was inspected or that
the application will switch to the product's resolver. Exact blocking targets
and identification coverage remain implementation contracts; this choice does
not promise complete DoH/DoT detection or introduce a separate rule priority.
The product's own encrypted client remains to be implemented; this prerequisite
is a design sequence rather than a statement of current readiness.

### Encrypted upstream primary/backup choice, 2026-10-08

The user accepted ordered primary/backup selection when multiple DoT/DoH
upstreams are configured. For a permitted query that needs upstream work,
prefer the earliest currently available entry in the user's configured order.
Normally send it to one selected upstream; connection failures, timeouts and
other upstream faults permit sequential attempts at later available entries
in that configured encrypted list.

This selects ordered failover, without a default parallel broadcast or race
across the configured services. A normal DNS result such as NXDOMAIN is not
itself a transport failure requiring a search for a positive answer elsewhere.
If all configured encrypted upstreams fail and no valid answer cache is
available, retain the failure behavior below. Local DNS Resolution Exceptions
continue to use their already selected routing and resolver view.

Failure classification details, retry/deadline budgets, availability tracking
and recovery remain implementation contracts. The [Portmaster outer query loop](https://github.com/safing/portmaster/blob/882d900dadb6df91150cf87f0a12706d29172586/service/resolver/resolve.go#L419)
provides a sequential-attempt reference; its other routing, stale-cache and
failure settings are not selected by this choice. This is a shared Root/VPN
design, not an implemented upstream client.

### Encrypted upstream failure choice, 2026-10-08

The user confirmed that, when all configured DoT/DoH upstreams fail and no valid
answer cache is available, the product reports resolution failure and retains
the user's selected upstream configuration. It does not automatically switch
the permitted query to the original network resolver or another ordinary DNS
server. Ordinary DNS remains an explicit upstream choice rather than an
implicit outage fallback.

For a policy-permitted query this failure is a resolution outcome, not a DNS
policy denial, and produces no new successful Domain-IP Association. Valid
answers from the selected context's cache remain governed by the existing
current-policy-before-cache rule. Exact response/status Interfaces, deadlines
and bounded retries within configured upstreams remain to be specified; this
choice does not select a wire refusal code or turn failure into policy DROP.

## Original-resolver and proxy paths

| Path | Root/NFQUEUE | VPN | Shared DNS work |
| --- | --- | --- | --- |
| No upstream replacement | Kernel forwards allowed DNS to its original resolver; captured requests and answers are inspected | Existing TUN/HEV direct transport forwards allowed DNS to its original resolver | Application DNS decision, query/answer correlation, actual-answer parsing, association updates and observations |
| User-enabled product proxy | DNS redirection delivers requests and original caller/destination context to the local socket Adapter | Local DNS sessions deliver requests and caller/network context to the shared proxy | The same application checks, plus proxy transactions, context-scoped answer cache, selected ordinary DNS/DoT/DoH upstream and reply handling |

Normal answers permitted by the applicable query/response policy pass through
unchanged on the original-resolver path. The user selected direct DROP for
reliably attributed queries whose applicable policy denies them, on both DNS
paths. Queries denied with the facts available before resolution are stopped before
original-path forwarding or proxy answer-cache/upstream processing. The proxy
does not dispatch a denied request or generate a DNS refusal reply. The first
version does not implement denial by changing an upstream answer or returning
REFUSED/NXDOMAIN/substitute addresses. A client may retry or wait for a timeout;
the product records the actual DNS policy denial rather than an upstream failure
or a refusal response it never sent. This selects first-version behavior, not
existing implementation or acceptance evidence. Available CNAME response facts
extend the policy input as specified below.

### CNAME response-domain filtering choice, 2026-10-08

After reviewing Portmaster, the user accepted its functional direction:
include the actual CNAME chain connected to a handled DNS query in first-version
DNS-domain filtering. Retain the original query name and the returned aliases
as distinct DNS facts. The same current applicable whole rules and Rank decide
permission; an alias match does not create an independent deny override.

Check the original query before forwarding/cache/upstream processing, then use
the alias facts when an actual answer or valid selected-context cache answer
makes them available. On the product proxy path, prepare the CNAME facts and
match the current rules before delivering the complete answer. A previous
query-stage allow or another application's earlier decision is not permanent
permission to deliver that answer. If the resulting policy denies delivery,
reuse the selected DROP behavior without rewriting the answer or generating a
refusal/substitute response.

The original-resolver path uses the response facts actually available at its
control point to govern subsequent delivery. Preserve No Recognition Hold:
do not retain/replay original packets solely to await more CNAME facts, or
claim every transparent TCP response is fully inspected before any bytes pass.
Framing and the exact delivery seam remain implementation contracts.

The existing caller rule is unchanged: a system resolver UID without the
original App does not enable guessed application-specific CNAME filtering.
Record the actual resolution result and the actual response policy decision
separately; a response denied after resolution is not an upstream failure or an
answer successfully delivered to the App. Actual-result collection and
association admissibility remain separate contracts.

CNAME facts do not replace the query name, populate SNI, or provide an extra
business-domain action against an already available direct protocol name.
This adopts the functionality rather than Portmaster's code, settings defaults
or endpoint/list priority model. Its [source investigation](../reviews/2026-10-08_PORTMASTER_CNAME_FILTERING_REFERENCE.md)
also records fact-readiness/list-loading gaps; neither that source nor this
choice is evidence of an implemented product feature.

Both paths update Domain-IP Associations from actual observed or resolved
answers, including valid proxy cache answers, using their available provenance
and resolution context. System-mediated answers do not acquire an invented
original application. A query dropped before resolution produces no new successful DNS answer or
address association. Updates remain bounded; association admissibility retains
its subsequent specification, with the provisional age choice below.
Shared-address ambiguity follows
the user's KISS choice below rather than a most-recent-domain selection.

### Association application scope deferred pending data, 2026-10-08

After reviewing the original direction and Portmaster's profile/global lookup,
the user deferred deciding application/profile partitioning and cross-application
use of IP-domain associations until actual data is available. Neither the
proposed same-application restriction nor sharing all known-application records
globally is selected. Do not continue resolving this scope from hypothetical
IP-only examples in the current discussion.

This deferral leaves the already selected query filtering, direct protocol
domain sources, fallback ambiguity, provisional age and network-reset behavior
in place. It does not turn an IP association into proven connection identity.

### Association ambiguity choice, 2026-10-08

For the selected DNS-association fallback paths, the user chose this simple
behavior after considering allowed and blocked names sharing one IP:

| Admissible candidate names for the target/context | Connection-domain input |
| --- | --- |
| One | Use that name as DNS-derived fallback evidence |
| None | Unavailable |
| More than one | Unavailable; retain the candidate evidence for observation |

Multiple candidates do not produce a domain-policy action from the association;
other independently applicable rules still execute normally. Direct SNI, HTTP
or SOCKS target names retain their already selected precedence and meaning.
A single fallback candidate remains indirect association evidence rather than
proof of the actual target or a fabricated original caller. This choice applies
after the separately specified admissibility/context/expiry checks and selects
no new numeric storage or recognition budget.

### Provisional association age choice, 2026-10-08

After reviewing iodé's independent address-age window, the user selected a
provisional expiry window of **two hours (7,200 seconds)** for Domain-IP
Associations used by the selected fallback paths. This window is separate from
DNS answer-cache TTL: expiration of an answer's TTL alone does not expire the
association. An association whose two-hour window has expired no longer
participates in subsequent fallback lookups. Without another admissible
candidate, the domain remains unavailable and other applicable rules continue.
Historical observations may retain the evidence without extending its
eligibility for current lookup.

The user explicitly chose this as a temporary value, open to later optimization
or redesign. Detailed update/refresh behavior, other network/resolver admissibility
and established-flow fact lifetime remain to be specified; the fixed window
does not settle those contracts. DNS answer caching continues to follow its own
TTL and selected-context rules. The choice is recorded alongside the
[upstream lifetime investigation](../reviews/2026-10-08_IODE_IP_LEAK_ASSOCIATION_LIFETIME_RESEARCH.md).

### Network-switch association reset choice, 2026-10-08

The user confirmed that switching networks resets the affected path's active
Domain-IP Association cache. Old-network associations are excluded from the
new network's fallback lookup even when their provisional two-hour age window
has not expired. The product learns current associations again from actual
results; historical observations may retain the prior evidence.

This choice concerns executable association state. DNS answer-cache TTL and
resolver-view rules remain separate, and resetting product associations does
not guarantee that Android or an application performs another visible DNS
query. System-cache behavior is investigated separately in the
[Android network-switch research](../reviews/2026-10-08_ANDROID_DNS_CACHE_NETWORK_SWITCH_RESEARCH.md).
Detailed same-network resolver changes, refresh and established-flow fact
lifetimes remain to be specified.

## Connection-domain sources and timing

For subsequent business flows, use that flow's own application identity. The
user selected this sequence for recognized TLS/QUIC connections and subsequently
added DTLS to this SNI-processing scope:

1. While SNI recognition is pending, take no connection-domain policy action.
   Forward otherwise permitted packets needed for recognition; do not enforce
   a DNS-association domain decision during this phase. Existing independently
   applicable application/IP and other rules still execute normally.
2. If recognition obtains a usable SNI name, use that name as the connection's
   domain input. Conflicting DNS associations do not replace it or supply an
   additional domain-denial path for that connection.
3. If recognition finishes without a usable name, including confirmed absence,
   parsing failure, exhausted recognition or another finished unavailable
   result, attempt to obtain the domain from an admissible DNS association.
   Retain the actual SNI outcome and association source; an association is not
   SNI, and failure or exhaustion is not Confirmed No SNI. Without an admissible
   association, the domain remains unavailable.

The user then corrected the protocol scope to include HTTP: visible HTTP
request-target authority/Host is a separate direct target-domain source.
The sequence above is SNI-specific, not a requirement to run SNI parsing on
HTTP or every recognized protocol. On 2026-10-08 the user confirmed request-level
handling for visible cleartext HTTP: each obtained request target updates that
request's domain input and triggers evaluation of the actual application's
current applicable policy. This includes different target names in successive
requests over the same HTTP proxy connection/session. A previous request's allow
does not authorize later requests, and prior completed verdicts or observations
are not rewritten.

One request uses its effective target according to HTTP semantics; a shared
proxy connection is not one request with multiple competing target names.
HTTP version/framing, detailed fact lifetime, unavailable-target fallback and
other detailed contracts still need their own subsequent specification.
Encrypted HTTP continues to use the already selected observable
SNI/DNS-association paths.

The user subsequently selected first-version HTTP denial delivery: when an
applicable policy denies an obtained HTTP target domain, use the existing DROP
path to block subsequent traffic on that TCP connection. Other requests sharing
the same proxy connection are also affected. This selects connection-level
blocking after a request-level decision; it does not select selective HTTP
request removal, generated HTTP error responses or active TCP reset. Existing
policy-revision re-evaluation continues to apply.

The user also accepted DNS-association fallback when an HTTP request's effective
target is an IP address rather than a hostname. Look up the request's remote
target IP using the same admissibility, provisional two-hour expiry,
network-switch reset and unique-candidate rules already selected for fallback.
No admissible candidate or multiple candidates leave the domain unavailable;
other applicable rules still execute. Retain DNS provenance rather than
reporting an explicit HTTP hostname or SNI. This uses the requested target,
not the proxy server's endpoint, and does not replace packet-address facts.

The user also selected SOCKS4 and SOCKS5 target-domain handling for the first
version. The direct domain sources are SOCKS4a's requested hostname (within the
existing SOCKS4 classification) and domain-address SOCKS5 requests. Ordinary
SOCKS4 and IP-address SOCKS5 requests contain target IPs rather than explicit
hostnames. The user accepted using the requested remote target IP to look up an
admissible DNS association for these requests; without such an association the
domain remains unavailable. This lookup uses the request's actual target IP,
not the proxy server's own network endpoint. HTTP/SOCKS facts retain their
protocol/request provenance, and a DNS-derived name remains association evidence
rather than an explicit SOCKS hostname. Subsequent policy uses the actual
application identity and available resolution context; missing domain evidence
does not bypass other applicable rules. Association expiry uses the provisional
two-hour window above; multiple names follow the KISS ambiguity choice.

DTLS requires its own handshake/fragment parsing and real SNI facts; it follows
the same selected pending/success/no-name sequence above. Adding it extends SNI
applicability intentionally, rather than treating a DTLS classification label
as TLS or as proof that a hostname was extracted. SIP target-domain filtering
is deferred from the current selection; existing SIP recognition remains.
Other protocol-domain sources are not additional selected requirements.

This extends domain-source scope without populating an explicit SNI predicate
with DNS, HTTP or SOCKS target data or adding a second whole-rule Rank. Packets are not held
or replayed; completed verdicts and observations remain unchanged. Association
admissibility and detailed refresh/fact-lifetime contracts still require their
subsequent specification. The provisional association age above does not select
a new SNI recognition budget.

## Consequences and limits

- VPP remains the sole configuration and rule-compilation authority under
  [ADR-0009](0009-unified-rules-and-vpp-owned-configuration.md). Query and
  connection evaluation use applicable whole rules and available facts; they do
  not add a separate priority system or discard unknown business conditions.
- DNS Query Decisions and connection verdicts remain distinct facts. A later
  connection denial must not be reported as an earlier DNS query denial. A
  system/app cache hit that never reaches product ingress is not a product query
  decision. Complete per-application, pre-answer interception is not promised.
- Domain-IP Association evidence retains provenance and uncertainty. Shared IPs
  and multiple candidate names do not establish a unique flow domain, and
  association data is not direct TLS/QUIC SNI. The decision does not adopt
  Portmaster's most-recent-domain selection algorithm or silently substitute
  association data into existing SNI predicates.
- Each handled query uses current policy even when the product answer cache
  hits. Answer reuse does not reuse another application's permission decision.
  Shared implementation does not require a global mutable cache across owners.
- Existing owner, packet-progress and bounded-resource constraints remain.
  Increasing NFQUEUE copied payload is not a substitute for caller evidence;
  the selected copy-length constraint remains, with concrete limits deferred.

This is an accepted design extension, not implementation or acceptance evidence.
It supersedes the blanket DNS-query/association exclusion in the September rule
specification for this new scope, while preserving existing SNI semantics and
whole-rule constraints. DNS fact/record Interfaces, association admissibility and
lifetime, reply/failure behavior, worker layout and numeric budgets remain for
subsequent specification. UI and user-interaction planning remain deferred until
DNS is complete.

The [Portmaster investigation](../reviews/2026-10-05_LINUX_PORTMASTER_DNS_REFERENCE_RESEARCH.md),
[official resolver-IPC limitation](https://docs.safing.io/portmaster/architecture/os-integration#systemd-resolved)
and [AOSP system-cache path](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/res_send.cpp#499)
explain the trade-off. Reference source is evidence, not product code to import.
