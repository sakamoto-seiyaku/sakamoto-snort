# T27 observation retention and coverage

The V5 Flow and Blocked Observation record is unchanged. The Rust consumer
accepts one bounded batch of cumulative records and a wall-clock receipt time.
It derives only proven directional increments, places each attributable segment
in the UTC minute of its last activity, and commits the baseline, END state,
all maintained views and retention changes in one SQLite transaction. Repeated
or stale records do not add counts. The packet producer has no storage wait,
acknowledgement or replay obligation.

Rust owns one live aggregate and one SQLite database. Minute, hour and day
tiers each carry overall, unattributed, application, rule and protocol counts.
The existing `minutes`, `application_windows`, `rule_windows` and
`protocol_windows` response fields remain the minute tier. `hour_windows` and
`day_windows` have `overall`, `attribution_unknown`, `application_windows`,
`rule_windows`, `protocol_windows`, row counts, query limit and truncation.
Their row `minute` field is the UTC bucket start in seconds; the enclosing tier
sets its width. The bounded query shows at most 720 hour rows and 180 day
rows per map, with counts and truncation flags for omitted keys. Keys keep the
20-digit UTC bucket prefix. Each stored
contribution occupies one tier at a time. Protocol shares divide by the
application counts in that same tier and scope; multi-label L7 shares may sum
above one. Historical rule condition annotation checks the matching VPP-owned
saved source for visible windows in all three tiers.

Default minimum lifetimes are 48 hours for minute buckets, 30 days for hour
buckets, 180 days for day buckets, and 24 hours from first END consumption for
recent END context. An entire bucket is eligible after its UTC end plus its
lifetime, so a contribution near the end never expires early. Clock rollback
cannot move the persisted retention watermark backward. In ordinary service
operation a forward wall-clock jump is held until the new mapping stays
consistent with monotonic elapsed time for 60 seconds; a same-boot restart
uses persisted boot ID and uptime to include observed downtime. A reboot or
older database without that evidence gets the same stabilization interval
before age-based expiry catches up. `coverage.retention_clock_held` exposes
the current hold. The explicit test clock
offset is labeled and does not establish real elapsed time. Coalesced increments
retain their last-activity placement without per-packet interpolation. Old
minutes merge into hours before removal; old hours merge into days. Day expiry
increments durable `coverage.evicted` counts while leaving lifetime totals
unchanged. A long active observation keeps its cumulative baseline. Expired or
space-evicted ended context leaves a compact per-slot incarnation marker, so
a late duplicate END cannot recount the old cumulative total. A later
incarnation replaces that marker. At a new monotonically increasing VPP
generation, the consumer retires baselines and markers belonging to older
generations and rejects their late records. Recent END context and aggregate
history remain until their own age or space limit. This bounds marker growth
across process lifetimes without reopening old cumulative totals.

The normal query reports lifetime `packets` and `bytes` separately from the
retained tiers. `coverage` reports retained first/last UTC bucket starts,
retention watermark, evicted packet/byte counts, transport gaps, recoveries
and clock changes. The tier maps and truncation flags give exact visible
bucket coverage; missing time between sparse buckets is not asserted to be a
loss of traffic. `storage_space` lists all owned database, WAL, SHM, journal,
lock, predecessor JSON and test-configuration files with actual bytes, the
working reserve and the 256 MiB default budget. The default database cap is
64 MiB including indexes; FULL auto-vacuum and bounded WAL checkpointing
return freed pages. Pressure first runs ordinary expiry, then removes oldest
ended context, retires unreferenced version/name links, promotes oldest minute
and hour buckets, and finally evicts oldest day coverage. It never removes an
active baseline to make space. If required state alone fills the budget,
`observation_storage_budget_exhausted` or SQLite's full error is surfaced;
accepted pending counts and a coverage gap remain explicit.

The existing `overall.json` input path, advisory lock and sibling
`overall.sqlite3` remain stable. Persisted kind 9–18 rows hold the two new
tiers and kind 19 holds END markers. New metadata fields and tiers default
empty when older SQLite or JSON history opens. The same transaction advances
rows and metadata. A crash before commit leaves the previous tier and baseline
intact. Large bucket rollups page one application with its bounded protocol
rows, or one rule, unknown or overall row per transaction. A persisted
transition marker makes the query project the remaining source rows into the
destination tier, so all views report one logical granularity even between
batches or after a restart. Day eviction marks its whole bucket as uncovered
before paged physical deletion; a query then hides that bucket and reports its
counts in `coverage.evicted`. `retention_transition` and maintenance-pending
state expose this work. The consumer checks the clock at idle deadlines and on
query; pending maintenance remains visible until it finishes.

For controlled verification only, a private sibling
`overall.retention-test.json` may set the four lifetimes, budget, reserve and
positive clock offset before opening the store. `limits.scaled_test` labels
such queries. The debuggable Android runtime can select the isolated
`files/observation/t27-test/overall.json` when the private
`files/observation/t27-test.enabled` marker exists. Removing the marker returns
the runtime to its ordinary store without editing the pre-existing history.
These knobs do not change the default 48-hour/30-day/180-day product promise;
short physical tests establish algorithm behavior, not elapsed 180-day device
coverage.
