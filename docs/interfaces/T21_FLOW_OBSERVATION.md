# T21 Flow observation interface

SAKAMOTO-272 implements the current Flow overview; persistent windows and
attribution segments remain later work. T20 selected the pinned VPP `svm_msg_q`.

The test seams are the owner export boundary, C producer → Rust consumer across
processes, and the Product query API on Linux and Android, as required by T21.
The existing packet graph and FlowEnd lifecycle remain authoritative.

Each fixed owner has independent normal and reserved debug queues. There is one
Rust ingestion thread per runtime, independent of UI queries. Records contain
runtime generation, owner, slot, monotonically increasing incarnation and update
sequence, ORIG/REPLY cumulative packet/byte totals, first/last real activity,
current context and END. An END includes tail growth. A stale update cannot
revive a retired slot incarnation. Rust retains bounded slot baselines and
reports losses/rejections instead of inventing historical coverage.
Times are owner monotonic microseconds, not UTC history timestamps. Context is
the latest known context; this ticket does not attribute cumulative differences
to a rule or implement the later attribution-segment contract.

The owner publishes creation, growth and END; a low-frequency pending deadline
uses the existing owner timer. Timer work neither refreshes CT nor changes real
activity. Basic IP accounting at the final logical-packet terminal boundary is independent of
Flow allocation and queue success, including primary-handoff capacity bypass.
Reassembly is counted once before fragment fanout. Runtime failure and policy
DROP are separate.

V1 records are 128 bytes for IPv4 and 152 bytes for IPv6, with no payload bytes.
The queue classes are 128 and 160 bytes, 256 slots each per channel/owner; this
is a development capacity subject to actual Product validation, not a release
budget or the T20 synthetic 2048-byte bound. Later record versions must revise
and validate capacity explicitly.

The generation-owned Unix socket negotiates schema/layout. The application
creates sealed-size memfd and nonblocking eventfds and passes them to VPP using
SCM_RIGHTS, preserving Android's application memory label in the Root profile.
At the first claim VPP quiesces producers, copies its bounded pre-connection
records/counters into that mapping, reattaches local queue pointers and replies.
The consumer cannot access queues before that reply. Peer credentials must match the
configured application UID (or the local same-UID host owner). Only one consumer
holds the connection. An unclaimed, silent negotiation expires after two seconds
on a main-thread timerfd; it does not consume the generation claim.
A disconnected consumer never blocks packet export.
There is one successful consumer claim per runtime generation. An ended or
crashed ingestion service requires a new runtime generation to claim again;
ordinary health/configuration queries do not claim the stream. This avoids
reusing a queue whose former consumer may still hold a borrowed slot. The
Android RuntimeService starts ingestion after initial policy readiness and
reconciliation, before adapter startup; its session disconnect joins ingestion.
Mappings are not recycled while either process can still access them; producers
quiesce before destruction, and the Rust thread joins before unmapping.

Every queue operation is bounded and nonblocking. The consumer copies a record
before releasing its slot, drains notification before rechecking authoritative
queue occupancy, and waits only when no work remains. Independent producer loss
and consumer progress remain queryable even during a consumption pause.
The pinned queue's relaxed slot-release operations are enclosed by separate
release consumption watermarks. Before reusing either descriptor or payload
slots, the sole producer acquires the corresponding watermark. Publication uses
the queue's release publication and the consumer acquires occupancy before
reading. Every publication also exchanges the notification latch with seq_cst
ordering; the consumer drains, acknowledges that latch, rechecks, then waits.
No worker waits for a mutex, capacity, consumer acknowledgement or eventfd read.

`product_core_observation_query` is the generation-fenced typed VAPI health
query. `ProductCore::observation_json` combines it with the independently
maintained Rust overview. The C facade and Android session expose that same
query. A controlled pause/resume operation waits for the Rust ingestion thread
to park; it does not pause VPP. Ordinary command-line query processes only read
health; `observation-serve` owns the Host ingestion lifetime and accepts query,
pause, resume and quit commands on its control input.

Channel status is a sample of individually atomic counters, not a transaction
across running owners. Read stable conservation equations after drain/pause.
After ingestion stops, `consumer.live=false` qualifies retained overview fields
as the last known state. They are not a claim that the stopped runtime remains
active, nor a fabricated END for every unobserved termination.
