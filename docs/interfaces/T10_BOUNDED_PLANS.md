# T10 bounded range plans and complete compilation

The native compiler accepts the existing source rules. Its budgeted C seam adds
only compilation limits; it does not change the saved format, public ABI or user
settings. Default compilation uses 32 complete direct entries per logical rule,
256 entries/masks across the entire effective view and the inherited 128-rule,
64-byte expression / depth-eight limits. Every plan retains the same complete
Rank, source identity, effective mode, declared/actual action and whole-rule
PRE/POST position. No fragment executes an action or changes logical-hit counts.

Suitable port ranges use their exact disjoint 16-bit prefix cover. Small pairs
expand only after their bounded product has been counted. Larger pairs retain
two independent inclusive interval factors; there is no Cartesian product in
storage or query state. General OR/NOT uses the original bounded expression as a
residual program without DNF conversion. All paths completely validate the
original rule and availability semantics before supplying a winner.

The compiler reserves one complete entry per remaining rule before spending
spare index capacity. Direct-plan exhaustion selects factorization or a complete
residual plan. Factor exhaustion selects the residual plan. If the smallest
available complete plan exceeds the total entry, condition or storage limit,
compilation returns CAPACITY_EXCEEDED before touching the supplied view. Query
work is completely bounded at compilation; no runtime budget truncates lookup or
returns a temporary best candidate. Query-local deduplication is reset on every
ALL/PRE/POST call and never combines facts across packets or directions.

`product_l4_policy_compile_with_budget` is a native compiler/testing seam.
Inputs are borrowed for the synchronous call; output storage belongs to the
caller and is immutable after publication. Budgets cannot enlarge fixed storage.
The ordinary compiler chooses the default budget. No cache or mutable worker
state is added. Resource queries return counts and representation-storage bounds,
not pointers into indexes. `show product policy-index` reports both `policy.index`
and `policy.plan` from one acquired snapshot identity. `show product rule-budget`
reports saved/active revisions, compilation errors and complete management
storage overlap.

The compiler's publication-storage subtotal includes four views (two protected
banks, preflight and publication), two maximum source arrays, bounded compiler
scratch and one query workspace. The management total adds saved/candidate
source objects, serialization, native request/status adaptation, bounded graph-selection/frame/path scratch, both workers'
existing caller-local empty views and a second query workspace. Fixed array
padding is charged even when unused. Limits are 384 KiB for the compiler subtotal
and 1 MiB for complete policy representation storage. These are not process-RSS
caps: existing thread-stack reservation, API transport pools and allocator metadata
remain separate. Fixed scratch reserves include scalar call frames. The dated T10 report records measured
query/compile cost, storage overlap and process memory rather than equating them.

Later predicates and caches must extend the existing independent complete-winner
comparison at these seams. T10 keeps all currently implemented static/platform
and CT predicates in that matrix; no LPI/SNI/cache implementation is implied.
