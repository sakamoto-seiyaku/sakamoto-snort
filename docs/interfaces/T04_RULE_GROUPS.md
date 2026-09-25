# T04 rule groups and application bindings

SAKAMOTO-255 extends the complete configuration operation and query. VPP owns
and persists the entire graph, validates references and compiles immutable
per-application views; Rust/Java only adapt requests. Existing saved/applied
revision, conflict, save-before-compile and reader lifecycle contracts remain.

The source contains at most 256 rules, 64 named numeric groups, 512 group edges
and 128 application bindings. Rule UID UINT32_MAX means reusable only; other
UIDs retain their implicit enforce binding. Group IDs are nonzero unique u32.
Edges contain owner group ID, kind (1 rule, 2 group), and target (zero-based
source rule index or group ID). Bindings contain nonzero unique binding ID,
complete UID, kind, target, and mode (0 enforce, 1 observe). Modes belong to
bindings, not groups; nested edges inherit that binding mode. Source indexes
are scoped to the complete saved revision, and queries return full rule versions
so they cannot be confused with stable rule identities.

Missing references, cycles (including unused groups), depth over 8 groups,
invalid modes and conflicting effective modes reject before saving. Expansion
walks at most 4096 references per binding, with at most 128 total effective
rule/application entries accepted by the current compiler. Compiler capacity
failure happens after saving and preserves the preceding snapshot. No traversal
truncation yields a successful partial view. Same logical rule/app/mode dedupes;
identical content with different identities remains distinct. Source graph and
binding IDs remain queryable for all paths, including duplicate references.

An effective rule carries its original full version, UID and mode. Precedence
remains priority, order, logical identity. Observe retains declared action and
winner while actual action is ALLOW. A binding-only edit advances configuration
revision, not rule revision. V2 source files remain readable; new writes use V3.
Legacy one-rule replacement rejects a nonempty graph rather than silently
removing it. Full replacement explicitly replaces all source objects.

Tests use the specification-confirmed rule-management/save/apply/query and
observable matcher/packet boundaries. Linux and Android evidence bind source,
artifact, configuration, generation and packet outcomes independently.

## Diagnostic transport and errors

The existing numeric direct-rule lines remain accepted. Additional request lines
are `group ID`, `edge GROUP KIND TARGET`, and `bind ID UID KIND TARGET MODE`.
The complete response returns all source graph fields, with counts and full
source rule versions. Existing diagnostic queries also expose logical match
count, actual policy drop count and total effective rule/application entries.
A shared rule bound to two applications therefore occupies two effective entries,
while duplicate paths within either application occupy one. Source attribution
is the complete saved graph plus rule version and application, not an arbitrary
single path chosen during traversal.

New graph errors are REFERENCE=10, CYCLE=11, LIMIT=12 and MODE_CONFLICT=13;
configuration-wide errors use error_index UINT32_MAX. Effective compiler overflow
retains COMPILE=5 and compiler CAPACITY_EXCEEDED=2 after saving. Group/binding
identities are revision-scoped source attribution, not logical rule revisions.

Java JNI requests containing a graph use `[-1, rule_count, group_count,
edge_count, binding_count]`, then the existing 26-slot direct rules, then group
IDs, three slots per edge and five per binding. Legacy flat direct arrays remain
accepted. Replies append graph counts and the same graph slots after the active
versions. JNI validates all lengths and unsigned bounds before the C ABI call.
VAPI carries named typed graph fields with generated endian conversion; no
native padding becomes serialized source or wire data. API identity is generated
from product_core.api and pinned in the artifact manifest.
