# T09 same-mask candidate index

The compiler/matcher and owner/snapshot seams remain unchanged. One immutable
view owns whole rules and their index; query-local state never crosses packets
or PRE/POST. Complete Rank remains priority/order/stable identity.

Each whole rule has one conservative masked envelope entry. Equal masks share
a subtable within the application view across priorities and positions; selection
still filters the rule's unique position. Hash collision and residual failure
continue searching. Subtable and candidate bounds use complete Rank, never
priority alone. General Boolean, availability, network/interface and CT conditions
remain complete residual checks. Broad ranges use common-prefix supersets; exact
range expansion and factorization belong to T10.

The existing 128-rule publication limit bounds entries and masks. Fixed storage,
no query allocation and a complete search bound preserve failure behavior.
Resource statistics expose total masks/entries/storage and query work through
module query interfaces, without exposing index arrays or adding business hits.
No source format, public cross-language ABI or user setting changes.

`product_l4_policy_index_resources` reports masks, whole-rule entries, fixed view
bytes and a conservative complete-query bound. Results separately count subject,
subtable, chained-key and full residual probes. At most 128 subtables and 128
entries exist. One query inspects at most all subtables plus each entry once,
with at most 128 full residual evaluations of already bounded 64-byte expressions.
The published work bound is 16 subject probes + mask count + twice the largest
application rule count, at most 400 units; byte comparisons/hashing are fixed
42-byte operations. This is a work bound, not a deadline or truncation budget.

`show product policy-index` queries one acquired immutable snapshot and reports
its generation/revision/hash with these resources. Existing bounded packet trace
emits `t09 event=query` once per actual PRE/POST matcher invocation, with the same
snapshot identity and packet token, complete winner/Rank, work counts and elapsed
projection-plus-matching nanoseconds. It does not add logical rule hits. No
per-query timing is collected outside the existing traced-packet scope.

Engineering initial values: 42 canonical network-order key bytes, 16 hash slots
per shared mask, one conservative entry per whole rule. This avoids expansion
and keeps all supported Boolean/availability semantics in residual evaluation.
Fixed view size is 38,160 bytes on the measured x86-64 and ARM64 targets, versus
T08's 22,544. Mask count and collision density materially affect cost; the dated
T09 report records both gains and regressions. There is no adaptive fallback or
new performance guarantee.
