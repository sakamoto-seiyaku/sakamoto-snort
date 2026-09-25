# T05 ordinary network disabling

The schema-1 online configuration operation `NETWORK_DISABLE=3` accepts exactly
one ordinary condition in `rules[0]`, `count=1`, expected saved revision, zero
`version`/`base_version`, and no graph objects. Action 2 disables; action 1
enables. VPP normalizes priority/order to zero and maintains an ordinary DROP
with all the supplied predicates. The application UID must be concrete.

There is no separate Gate source or protected identity. A structurally equal
ordinary direct DROP is the switch representation; editing its condition or
ordering changes that representation. Disable is idempotent when it exists;
otherwise normal random identity allocation creates it. Enable removes the
matching direct entry and remaps later graph indexes. An absent entry is a
no-op. Other rules, identities and graph objects remain intact. Complete source
replacement can edit, reorder, bind or remove the same ordinary rule.

Ambiguous equal direct entries report `CONFLICT=2`; a referenced removal reports
`REFERENCE=10` rather than silently changing another application or binding.
Invalid shape/UID/version reports `INVALID=1`, and source capacity reports
`LIMIT=12`. The existing revision-conflict, save, compile, publication and
exhaustion errors retain their meaning. Validation failure preserves the source;
save failure prevents compilation; saved but unapplied edits retain the previous
runtime snapshot. Queries return normal rule versions and graph objects, with
separate saved/active identities. No disabled Gate row or opening ALLOW is saved.

Family 0 means either supported IP family and requires zero address bytes and
prefixes. Protocol 0 means any IP protocol; port predicates still require
available TCP/UDP ports. Numeric diagnostic text accepts `*` for both wildcard
addresses. Concrete TCP/UDP rules retain their existing semantics. UID, network,
interface and device direction remain ordinary predicates; unavailable facts do
not satisfy a constrained predicate. Priority, order and logical identity remain
the complete ordering, including ALLOW exceptions and lowest-priority fallback
DROP. Observe retains winner/declared DROP while actual action is ALLOW.

VPP's main thread owns mutation, validation, saving and compilation. Rust/Java
adapt online requests only; workers retain the existing protected immutable
snapshot lifetime. Retired Gate authoring remains unsupported, and a nonempty
legacy Gate bundle is rejected instead of installing another runtime table.

The existing Android network switch uses all directions and both IP families.
Its legacy UI enum VPN=3 maps to the existing platform context VPN=4; Wi-Fi=1 and
Mobile=2 are unchanged. The switch is queried from the ordinary saved source,
not the retired catalog Gate fields. Saved/active versions, logical hits, actual
drops and the last ordinary winner remain visible in the diagnostic query.
Network context belongs to each packet: a VPN-origin outbound packet can have
VPN context while its synthesized return has the physical Wi-Fi context.

Tests use the parent specification's already approved configuration-management,
save/apply/query and observable packet seams. This is a backend/diagnostic
contract, not a new product UI or public VPN protection promise.
