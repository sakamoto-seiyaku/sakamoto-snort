# T07 CT expressions and conservative placement

The complete source API and SKRULE04 format from [T06](T06_STATIC_EXPRESSIONS.md)
carry two additional postfix leaves: opcode 13 followed by CT state (NEW=1,
ESTABLISHED=2, INVALID=3), and opcode 14 followed by flow direction (ORIG=1,
REPLY=2). Unknown is unavailable, not a matchable fourth state. Invalid operands
reject before save; existing depth/size and save-before-compile errors apply.
Existing rule versions, source hash, saved/active identity and query attribution
remain authoritative. No new cross-language structure is introduced.

VPP compiles a snapshot-owned per-application requires-flow dependency. If any
rule requires CT or flow direction, that entire effective application view runs
after the existing owner-local FlowRuntime observation, in its original Rank.
Other views retain pre-flow evaluation. CT state comes from the current packet's
tracker result, including INVALID without an allocated entry. Direction is the
existing first-observed ORIG/REPLY fact; device direction and current endpoints
remain separate. Missing facts retain three-valued Boolean semantics.

One reader claim protects the complete compiled view across observation and
matching. Observation is performed once. Post-flow DROP does not undo CT,
counters or expiry observation and does not terminate transport state. The
borrowed entry stays owner-local and synchronous. Publication never clears Flow
state. Capacity bypass and infrastructure failures retain their existing meaning;
they are not completed NoMatch. No match-result cache is introduced by T07.
