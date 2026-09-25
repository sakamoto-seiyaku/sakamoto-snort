# T14 TCP cache and TLS consumer

The existing owner `product_flow_entry_identify` input, generation/slot/incarnation
fence and SNI query ABI remain the [T13 contract](T13_TLS_SNI_FACTS.md). A borrowed
current payload is copied into the sole TCP-owned Flow cache; neither original
packet ownership nor completion is transferred to the parser.

Each direction has an independently anchored sequence space. SYN anchors the
first payload byte at ISN+1 (including SYN payload); without observed SYN, the
first payload anchors the bounded attempt. Sequence arithmetic wraps modulo
2^32 within the 4096-byte window. Missing leading/interior bytes remain gaps;
TLS receives only the contiguous prefix from the anchor. Bytes before an
unseeded first-payload anchor are outside that attempt's supported window.

Sorted, disjoint half-open ranges describe received bytes in the existing
4096-byte directional storage. Adjacent/overlapping ranges merge. Identical
retransmitted bytes consume no additional logical byte capacity and do not
repeat a TLS parse when the contiguous prefix is unchanged. Conflicting
overlap stops parsing with sequence failure and an unavailable result.
Original wire packets still receive exactly one normal policy/accounting and
completion treatment each; reconstruction adds no synthetic packet or hit.

Initial engineering bounds are 4096 bytes and sequence span per direction,
16 ranges per direction, 20 payload attempts, 131072 charged work units and
the existing five-second attempt deadline. Each payload is charged even if
it duplicates bytes. Copy/overlap comparison and contiguous parser rescans
are charged to work; bounded record/extension loops retain T13's limits.
No independent parser admission quota or packet-path allocation is introduced.
All terminal outcomes clear both logical byte ranges. CT/Flow lifetime,
published facts and the final small SNI result survive that cleanup.

Recognition and SNI stop independently: valid TLS reconstruction can publish
the TLS fact after duplicate wire traffic has exhausted LPI's attempt/byte
budget. Policy publication does not reset parser budgets or the Flow identity.
The existing owner deadline heap schedules parser expiry without treating
cleanup as packet activity. Actual platform coverage and selected-budget
measurements belong to the dated T14 acceptance report.
