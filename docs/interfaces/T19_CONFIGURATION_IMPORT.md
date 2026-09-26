# Online configuration import

T19 extends the existing rule-management/save/apply/query and observable packet
decision seams agreed in the unified rule specification. Rust prepares transient
input; VPP remains the sole configuration writer and compiler. No import-side
configuration database or packet-path normalization is introduced.

## Minimal contract

The import request is a complete replacement, fenced by the caller's expected
saved revision and runtime generation. It contains all rules, groups, bindings
and domain lists together. There is no merge operation. Re-importing exported
complete identities without changes is idempotent; duplicate logical rule identities are errors. Different identities
with equal conditions remain distinct. Existing VPP full-version conflict and
revision-exhaustion checks remain authoritative.

Input is bounded UTF-8 JSON with an explicit `sakamoto-config-v1` format. Unknown
fields, invalid syntax, oversized inputs and unsupported conditions are rejected
before submission. Rules retain the complete existing direct-rule text contract,
including every static field and optional Boolean expression bytecode. Each rule
and list carries a bounded UTF-8 name and source label, saved and queried by VPP.
Rule metadata participates in full-version content equality. List contents and
metadata belong to the complete configuration snapshot; list ordinals are source
references, not compressed rule-message identities.

Lists declare their input syntax. The supported subsets below are explicit native
exact/self-and-descendant entries and strict domain-only filter entries.
Unsupported globs, URL paths, options and additional
conditions are rejected, never stripped. Names are converted using pinned Rust
IDNA processing, ASCII lowercase and removal of at most one absolute-name tail
dot. Network SNI retains its separate existing validity rules.

Export returns canonical normalized source with full unsigned rule versions,
metadata, graph and explicit exact/descendant entries. Re-import uses that same
format without guessing the original syntax. Metadata preserves source labels;
the product does not fetch them or promise an archive of original external files.

Preparation errors identify the affected input; VPP validation, save, compile and
publish outcomes keep their existing result/error indices and distinct saved
and active revisions. A preparation/basic validation failure does not save or
compile. Save failure does not compile. A post-save compile failure retains saved
edits and the preceding active snapshot. Temporary buffers are call-owned; no
borrowed input survives an API call and workers only see protected snapshots.

Acceptance uses Rust preparation/export tests, the existing VPP configuration
and matcher interfaces, and actual Linux/Android import API plus packet results.
Host component results are not platform acceptance.

## Current JSON format

All six top-level fields are required; unknown or duplicate fields are errors.
Names and source labels are opaque UTF-8 descriptions, not URLs to fetch. They
allow at most 63 and 127 UTF-8 bytes respectively and prohibit control characters.
Empty descriptions are supported for sources created before metadata existed.

```json
{
  "format": "sakamoto-config-v1",
  "rules": [{
    "name": "Example TLS/QUIC",
    "source": "my-policy.json",
    "definition": "0 0 12345 4294967295 4294967295 10 0 6 3 2 * * 0 65535 443 443 1100"
  }],
  "groups": [],
  "edges": [],
  "bindings": [],
  "lists": [{
    "name": "Example list",
    "source": "my-domains.txt",
    "syntax": "native-v1",
    "entries": ["exact BÜCHER.Example.", "descendants example.com"]
  }]
}
```

`definition` contains the existing complete source fields, in order:
`version base_version uid network_context ifindex priority order protocol direction
action source_CIDR destination_CIDR source_port_first source_port_last
destination_port_first destination_port_last [expression_hex]`.
CIDRs are numeric IPv4/IPv6 with an explicit prefix; both `*` means unconstrained
address family. Fields retain the meanings and Boolean bytecode of
[T06](T06_STATIC_EXPRESSIONS.md) and [T18](T18_DOMAIN_LISTS.md). For example `1100`
is domain-list membership 0, with the existing whole-rule TLS/QUIC prerequisite.
No filter condition is inferred from a descriptive name or source label.

Version fields are decimal text, preserving all unsigned 64 bits through JSON
and JavaScript callers. `version>0, base_version=0` imports that full identity.
`version=0, base_version>0` explicitly edits the named current version, advancing
its revision when conditions, name or source change. `0 0` explicitly creates a
new logical identity; submitting it again with a fresh saved-revision precondition
creates another identity. Export supplies assigned complete identities for
idempotent re-import. Reusing a deleted/older retained identity is a conflict;
retention remains high-water identity data, not an archive of old conditions.

Groups are numeric IDs. Edges are `[group_id, kind, target]`; bindings are
`[binding_id, uid, kind, target, mode]`. Kind 1 references a zero-based rule
ordinal, kind 2 a group ID; mode 0 is enforce and mode 1 observe. Existing graph
reference, cycle, expansion and effective-mode checks run before saving.
Domain-list ordinals are the list's array position. Every list, including empty
ones, is part of the complete submitted snapshot.

| List syntax | Supported entry | Normalized meaning |
| --- | --- | --- |
| `native-v1` | `exact name` or `descendants name` | Exact name, or name plus all descendant labels |
| `plain-exact-v1` | `name` | Exact name |
| `adblock-domain-v1` | `\|\|name^` only | Name plus all descendant labels |
| `clash-domain-v1` | `DOMAIN,name` or `DOMAIN-SUFFIX,name` | Exact name, or name plus all descendant labels |

These are domain-list subsets, not complete Adblock or Clash configuration
importers. Tokens and separators are exact. Blank/comment entries, wildcards
(`*`, `*.name`, regex, keyword rules), exceptions, URL schemes/paths, filter
options (`$script`, `$third-party`) and extra comma-separated conditions/policy
columns are unsupported. They reject the complete submission. Wildcards have no
cross-source default interpretation and are never changed into subtree matches.

The pinned `idna` 1.0.3 strict, nontransitional UTS #46 profile checks STD3 ASCII,
hyphens and DNS lengths. It rejects non-IDNA DNS forms such as reserved third/
fourth-position hyphens outside valid A-labels. Configuration removes at most one
literal ASCII trailing dot before conversion; whitespace and a second trailing
dot reject. `BÜCHER.Example.` becomes `xn--bcher-kva.example`; `Example.COM.`
becomes `example.com`. Network SNI does not use this convenience conversion.
See the pinned [dependency notices](../../third_party/rust-import/README.md).

Within one list, equal normalized `(mode,name)` entries deduplicate, preserving
first occurrence. Exact and descendant entries stay distinct, and equal entries
in different lists stay in both. Rules are never merged by equal conditions.
The current complete-source limits are 256 rules, 64 groups, 512 edges, 128
bindings, 64 lists and 256 normalized entries across all lists. JSON input and
the required C reply buffer are each bounded to 1 MiB. VPP retains its existing
compile/expansion limits and 2 MiB calculated representation budget; the updated
calculation is 1,961,396 bytes, not measured process RSS.

## Entry points and evidence

Host: `sakamoto-product-core-host rule-import SOCKET GENERATION EXPECTED_SAVED FILE`
and `rule-export SOCKET GENERATION`. The `import.response=` JSON includes a stage,
the VPP result/error indices, saved/active revisions, full active versions as
strings, and `configuration` suitable for re-import. `prepare` errors never
submit to VPP; `transport` errors require query before retry. A VPP rejection
returns its current saved source. A post-save compile error returns the new saved
source and the prior active revision/versions. Export refuses to invent an empty
source when no valid saved revision exists.

Android uses `RuntimeControlNative.Session.ruleImport`, through a bounded UTF-8
byte-array JNI/Rust call. The existing debug Activity accepts `ruleImportNonce`,
`ruleOperation` (0 export, 1 import) and `expectedSavedRevision`. The serial
RuntimeService reads import bytes from `files/product-import/NONCE.json` and
writes the response to `files/product-state/rule-import-NONCE.json`. Nonces are
1–100 alphanumeric/underscore/hyphen characters; the file trigger is debug-only.
This is a development entry, not a formal import UI or second persistent source.

VPP source V6 appends rule/list name and source bytes; V1–V5 load empty metadata.
The matching generated API identity is `product_core.api/1.0.0@8342a672`.
All layers build together; this is not compatibility with independently old
clients. Call-owned request/status storage stays off the VPP management stack,
and the Rust import path allocates complete source/status objects on the heap.
