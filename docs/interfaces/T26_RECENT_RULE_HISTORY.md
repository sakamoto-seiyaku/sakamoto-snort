# T26 recent rule interpretation

The V5 Flow and Blocked Observation wire record remains the ordinary input. Its
directional attribution contains the complete 64-bit winner version, snapshot
generation/revision/hash, contemporaneous name when supplied, declared and
actual actions, mode, segment start counters and cumulative counters. No rule
text, list body, pointer, ACK or replay obligation enters the packet path.

Rust owns a bounded version-to-name association for names actually received
from observation records. A repeated complete version may omit the name and
link to that association; a different nonempty name for the same version is a
conflict, never a reason to rename saved history. Distinct snapshots retain
their own recorded names; a same-window conflict is rejected with a gap. The
association is committed
in SQLite with baselines, recent END rows and rule windows. Existing rows reopen
without one and remain explicit about unavailable metadata. A rule window keeps
the complete snapshot identity, full version, contemporary actions and
directional counts. An END retains its last directional attribution and
cumulative baseline for the initial 24-hour recent lifetime. Earlier effects
remain in maintained rule windows; the END row's last segment is not presented
as a full per-flow rule timeline. The active baseline is never removed merely
because recent END detail expires.

The query adds an `interpretation` beside each visible rule window and each
recent directional attribution. It exposes the full version as a decimal string
(safe for JavaScript and signed Java callers), fixed 48-bit logical identity,
16-bit revision, a `recorded`, `linked` or `unavailable` name status, and the
actual action. Recent entries also label their count scope as the last
directional segment. Unavailable provenance stays unavailable; a current rule
never supplies a missing historical name.

Only the VPP-owned **current saved configuration** can supply full conditions.
On a query, Rust checks that a stable VPP active snapshot has the same saved
revision and content hash, then links a historical attribution only when its
snapshot revision/hash and complete rule version match. A matching source is
returned once as `history_source.configuration`; `source_rule_index` identifies
the rule inside it, with its referenced groups, bindings and lists in the same
document. Every other interpretation reports `conditions.status=unavailable`
and a reason; callers must not display the latest rule's definition as an old
one. This query-time read creates no old configuration archive and does not
change VPP's configuration ownership.

Errors are explicit: missing names, conflicting version metadata, absent or
changing source snapshots, missing rule versions and unavailable referenced
material cannot become a condition display. Storage failure remains an
observation error/gap and never blocks the VPP producer. Normal query freshness,
accepted pending increments, bounded transport loss and SQLite commit semantics
remain those of T23/E02. The caller-side store and Product query tests pin the
name and condition interpretation across edit, deletion, END and consumer
restart; Linux and Pixel runs establish actual packet and UI behavior.

The name association has a bounded capacity. At capacity, a newly observed
name still stays in its rule window/recent record, while the optional link for
future blank-name records is skipped and `rule_metadata_association_misses`
reports the loss. Packet totals, windows and baselines continue. T27 owns
retirement of association rows with its complete retention and space policy.
The debug Query button reads and removes its temporary response file; the
normal headless Query entry remains available for diagnostic evidence.
