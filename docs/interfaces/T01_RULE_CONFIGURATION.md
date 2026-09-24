# T01 online rule configuration

SAKAMOTO-252 implements the first slice of [ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md).
The source contract is [SAKAMOTO-251](../product/UNIFIED_RULE_ENGINE_SPEC.md).

The existing serialized Product Core session carries `rule_config` requests to
the VPP main thread. Java and Rust adapt values; neither saves source rules.
The first source schema contains zero or one directly UID-bound rule, with
IPv4 source/destination addresses, exact UDP ports, device direction and ordinary
ALLOW/DROP. Network/interface predicates, groups, Boolean expressions, imports,
and observation history are not delivered by this slice.

Operations are QUERY and REPLACE. REPLACE is a complete source replacement and
requires the last queried saved configuration revision (optimistic concurrency).
VPP assigns configuration revisions. Creating the single rule assigns a random
nonzero 48-bit logical identity and revision one; changing its contents advances
the low 16 bits. The complete 64-bit value is the packet winner identity. Repeating
unchanged contents preserves that rule version. Clearing preserves the last
identity/revision in the source so the next edit cannot reuse a prior version.
Revision exhaustion rejects the request; it never wraps.

The reply carries saved and active configuration revisions, saved and active rule
versions, the saved source fields, save/load and compile/publication error tags,
and the current generation. A returned transport success does not imply apply
success: callers inspect the operation result and both identities. A lost mutation
reply has unknown outcome; clients query a fresh session and do not auto-replay.

VPP owns one source file at the supervisor-provided configuration path, shared
across Root/VPN profiles. It writes the entire bounded encoding to a temporary
file, syncs and atomically renames it, then compiles and publishes through the
existing protected snapshot mechanism. Failed saving prevents compilation;
failed compilation keeps the saved source and old active snapshot. Fresh absence
creates and compiles an explicit empty source; invalid existing bytes never do.
Startup requires that valid snapshot before Adapter packet admission. The source
file is owned by its containing directory's owner, including when Root writes it,
so a subsequent VPN runtime can use the same file.

The old Rust/Java authoring and snapshot persistence entrypoints are retired from
the running product. They cannot silently create another saved policy. Existing
diagnostic packet/status APIs remain useful, with the full rule-version value in
their existing winner field. The new request/status contract is tested at its
public C module, Rust session, and Android control boundaries; packet acceptance
uses actual Linux NFQUEUE and Pixel traffic.

The complete multi-rule/dual-stack source and identity failure matrix belongs to
[SAKAMOTO-253](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/ecec1e20-41de-478a-a12d-69fcbdc18c9b).
The Android management-only startup/repair lifecycle belongs to
[SAKAMOTO-254](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/d7c2eaa5-324a-4c45-8e8b-2315c1eae77c).
T01 fails capture on an invalid startup source but does not claim that later
management-only Android lifecycle is delivered.
