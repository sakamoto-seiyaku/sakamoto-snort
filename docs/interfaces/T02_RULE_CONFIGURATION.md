# T02 complete direct configuration contract

The existing serialized control session carries one complete REPLACE_ALL request
(maximum 256 direct rules; the current compiler accepts 128). VPP copies and validates the request on its main
thread, assigns identities, saves its one source file, then compiles and publishes
that fixed source. The current C L4 compiler remains the sole matcher.

Each entry includes IPv4/IPv6, TCP/UDP, device direction (any/input/output),
CIDRs, inclusive port ranges, complete UID, optional network context and interface,
priority and explicit order. Address bytes are network order; other C ABI fields
are host order. Wildcard network/interface is UINT32_MAX.

For creation both version and base_version are zero. An edit sets base_version
to the current complete ID and version to zero; VPP preserves an unchanged ID
or increments its revision for changed content. An explicit version with zero
base_version requests import: the current full ID requires identical content;
older retained revisions and deleted IDs cannot be rebound. A newer revision
may be imported. Duplicate logical identities in one request reject the whole
request. Random creation checks all retained logical identities, including deleted
ones. The file retains only their maximum revision (at most 4096 identities),
not old conditions or a checkpoint archive; capacity/revision exhaustion is explicit.

Queries return every saved entry, saved/active configuration revisions, active
rule versions, and error code plus offending rule index (UINT32_MAX for a
configuration-wide error). Requests above the source bound reject before saving;
compiler capacity failures occur after saving, retain the complete new source and
the old active snapshot. Duplicate complete submissions preserve configuration
identity and may retry an unsuccessful compilation. Save failure never compiles.
Pre-rename I/O failure leaves the preceding saved source. If rename completed but
directory fsync failed, DURABILITY_UNCERTAIN (9) reports the complete new bytes'
actual saved identity while preserving the active snapshot and forbidding compile;
it does not claim the new bytes will survive a power loss. This preserves the
T01 truthful post-rename contract and distinguishes that case from ordinary I/O failure.

The T01 single-rule operation remains an adapter to this source and rejects
replacing a multi-rule configuration; it does not own another editable store.
The v1 source is read explicitly and the next successful replacement writes v2.
Root and VPN continue using the same app-owned mode-0600 file outside generation
cleanup. No drafts, checkpoint product or new UI workflow is introduced.

Tests use the already agreed rule-management/query and observable matcher seams.

## Diagnostic adapter layout

Transient numeric request text has one rule per line, with 16 whitespace-separated
fields: `version base_version uid network_context ifindex priority order protocol
direction action source_cidr destination_cidr source_port_first source_port_last
destination_port_first destination_port_last`. CIDRs explicitly select one matching
address family. This text is a request adapter, never an independently persisted
configuration file. A zero-line complete replacement explicitly clears the source.

Java/JNI uses 26 64-bit slots per entry: version and base_version in slots 0–1;
the C direct-rule fields from uid through reserved in declaration order in slots
2–17; source address as four network-order u32 values in slots 18–21; destination
in slots 22–25. Numeric values other than the two full IDs must fit unsigned u32.
The reply begins with 13 slots: transport code, generation, saved revision, active
revision, first saved rule version, first active rule version, result, save error,
compile error, saved count, active count, error index, compiler status. All saved
entries follow, then exactly active-count complete version values. Generated VAPI
uses named typed fields with its own endian conversion; no native struct padding
is a wire format. Missing mutation replies require a fresh query, not auto-replay.
