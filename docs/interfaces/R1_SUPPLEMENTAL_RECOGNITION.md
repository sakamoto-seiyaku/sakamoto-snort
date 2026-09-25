# R1 supplemental recognition

The existing owner-only `product_flow_entry_identify` input, identity validation,
borrowed payload lifetime, query, stop reasons and 20-attempt/32-KiB budget from
[T12](T12_PUBLISHED_PROTOCOL_FACTS.md) remain authoritative. No new public API,
Flow table, packet retention or TCP byte cache is introduced.

Each attempt keeps the base provider result distinguishable until deterministic
supplemental checks resolve it. A structurally recognized QUIC v1/v2 Initial
overrides that attempt's UDP guess. Otherwise a bounded DNS message on UDP with
either endpoint port 5353 resolves to mDNS. Otherwise the base result is mapped.
Exactly one resolved alias is mapped through the catalog and unioned with facts
already published. No correction retracts a prior fact. Non-catalog provider
names (including FTP/SMTP) remain available to this internal resolution step.

Catalog ID **1006**, key **mdns**, means a recognized UDP multicast-DNS-format
query or response using port 5353, including direct/legacy unicast exchanges.
It is distinct from ID1001 `dns`: neither fact implies the other. Existing IDs
and source opcode15 stay compatible. Port 5353 alone is insufficient. Recognition
checks the complete question/RR framing, bounded compressed names and declared
record lengths; it does not validate every RR type's application semantics.
Empty, malformed, truncated, excessive-count/work and non-5353 messages do not
produce mDNS. A miss cannot manufacture a comparable Unknown.

The parser accepts datagrams up to 4096 bytes and inspects at most 64 questions/records, 16 compression jumps per name
and 4096 name traversal steps per attempt; labels and expanded names obey DNS
length bounds. A 512-byte call-local bitmap validates previously parsed name
boundaries for compression pointers; it stores no packet bytes or Flow state.
RDATA is opaque, so pointers into names present only inside earlier RDATA are
outside this initial subset. Current datagram bytes are borrowed only during the call. The
recognition label is neither authenticated session nor SNI/HTTP3 evidence.
