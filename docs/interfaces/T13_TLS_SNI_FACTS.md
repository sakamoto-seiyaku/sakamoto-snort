# T13 TLS ClientHello facts

The existing owner `product_flow_entry_identify` operation consumes borrowed
current TCP payload after generation/incarnation and tuple validation. The
barrier-protected Flow query returns SNI result (0 unavailable, 1 valid name,
2 confirmed absence), normalized ASCII name, independent stop reason, attempts,
credited bytes/work and live TCP cache bytes. No packet ownership transfers.
Policy publication preserves the result and attempt budget; Flow end/reuse
releases cache ranges and resets the next incarnation.

Opcode 16 followed by byte 1 means confirmed SNI absence. Other operand values
reject compilation. Names are queryable; full domain matching belongs to T18.
The whole containing rule requires a published TLS or QUIC fact, independently
of its AND/OR/NOT shape. A result of 0 makes the leaf unavailable. Result 1 is
false and result 2 true. Every containing application's dependency union guards
both protocol-set availability/value and SNI result, including losing leaves.
All three execution plans and PRE/POST placement share this contract.

One preallocated TCP cache per Flow provides two independent 4096-byte sequence
spaces. TLS reads record spans in that cache and stores only metadata and the
small final name. This slice accepts consecutive payload sequence numbers;
gaps, overlaps and retransmission stop unavailable (T14 extends reconstruction).
TLS record fragmentation is handled without making another complete Hello.
Initial plaintext/STARTTLS, SSLv2, DTLS and encrypted/tunnel-inner handshakes are
outside this producer. A supplementary protocol label never itself establishes
SNI or absence. Valid ClientHello parsing supplies TLS recognition evidence.

A five-second attempt deadline shares the existing owner timer heap with CT;
a parser timeout clears retained ranges without expiring the Flow or refreshing
CT activity. Twenty payload attempts, directional byte capacity, 32 records,
128 extensions and finite parse work bound processing. Terminal states do not
retry. Stops are running=0, complete=1, malformed=2, unsupported=3, sequence=4,
byte/structure/work budget=5, packet budget=6, timeout=7 and Flow end=8.
Reserved cache capacity belongs to the Flow pool, not a separate parser quota.

Parsing follows [RFC5246](https://www.rfc-editor.org/rfc/rfc5246.html),
[RFC8446](https://www.rfc-editor.org/rfc/rfc8446.html) and
[RFC6066](https://www.rfc-editor.org/rfc/rfc6066.html): complete ClientHello
framing/vectors and extension envelopes, unique extension types, one nonempty
host_name with valid ASCII DNS label form. Unsupported NameType is unavailable.
This is syntactic Hello evidence, not negotiated-version or authenticated-session
validation. Original packets always complete using facts available by their
policy query; no automatic allow window or retention waits for SNI.

## Typed control query

`product_core_sni_query` / `sakamoto_product_core_sni_query` accepts generation,
worker, slot and incarnation. It returns a fixed 320-byte value projection
(`sakamoto_product_sni_status_t`), copied under a bounded main-thread worker
barrier. It retains no Flow pointer. The returned generation and identity are
validated again by VAPI. Wrong/ended/reused identity returns StaleHandle with a
zero result; malformed/omitted transport replies fence the session and return
QueryFailed. No partial query can look like confirmed absence.

Rust `ProductCore::query_sni` and its non-unwinding C facade adapt this query.
The host command is `sni-query SOCKET GENERATION WORKER SLOT INCARNATION`.
Android's existing diagnostic Activity dispatches the read-only query through
RuntimeService's serialized native session; a fresh nonce names its result
file. No diagnostic log scraping constructs the returned SNI facts. Existing
Flow diagnostics supply identity selection until the later normal-flow API/UI.
Generated API identity is `product_core.api/1.0.0@aabf0772`.

On the tested x86-64 and ARM64 targets, SNI metadata/result occupies 288 bytes,
the single directional TCP cache 8208 bytes (8192 byte capacity plus metadata),
and FlowEntry 8888 bytes. A 1024-entry owner reserves 9,122,120 bytes; two owners
reserve 18,244,240 bytes including their existing index/timer metadata. This is
an explicit fixed-capacity reservation, not active parser RSS or another parser
admission quota. The 128-entry policy cache remains 23,584 bytes per worker.
