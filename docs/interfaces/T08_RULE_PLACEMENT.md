# T08 whole-rule placement and early winners

The existing source API, SKRULE04 format and rule/snapshot identities are unchanged.
`product_l4_policy_match_position` accepts the immutable compiled view, packet
facts, and ALL/PRE/POST selector; it returns the existing complete match result.
Invalid selectors/arguments fail explicitly. ALL remains the ordered semantic
seam. PRE NoMatch is incomplete; the caller must obtain Flow facts and run POST.
A PRE match is final, including rule version, full Rank, mode, declared/actual
action and attribution. It is never a partial expression or cached packet result.

Compilation processes complete Rank, marks CT/direction rules POST, and propagates
possible overlap from every earlier POST rule, including indirectly deferred
static rules. Rectangular envelopes use family, transport protocol, device
direction, current endpoint CIDRs and port ranges. AND intersects, OR widens to
a hull, and NOT/dynamic/unsupported proof fields widen to universal. Only an
empty intersection proves disjointness. A fixed 4096 pair-proof budget defers
remaining inconclusive rules. This bounds optimization; it does not truncate
matching or impose a CT-history or application-observation prerequisite.

One rule and its entire expression occupy one position in the snapshot-owned
view. One reader claim protects both programs and any complete early winner
through synchronous owner-local Flow observation. Actual PRE DROP never calls
Flow observation, including for existing tuples. Actual PRE ALLOW observes Flow
once and retains the winner; lower-ranked POST rules cannot replace it. PRE
NoMatch observes once before POST. Accounting records one final decision/hit.
Capacity/runtime terminal outcomes retain their existing meaning. Publication
never scans or resets Flow state; generation/revision/hash protect identity.

The existing compiler/matcher and owner/snapshot interfaces are the confirmed
test seams. No cross-language ABI or configuration option is added.
