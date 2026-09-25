# T16 bounded QUIC CRYPTO assembly

The identity-validated `product_flow_entry_identify` operation continues to
borrow each current UDP payload synchronously. QUIC v1 client Initial CRYPTO
ranges are copied into a separate owner-local offset space; packet buffers,
TCP sequence state and borrowed parser pointers never survive the call.
TCP and QUIC have distinct structures in a protocol-tagged union because a
Flow cannot be both transports. There is no extra parser admission pool.

The first authenticated client Initial anchors DCID and flow direction.
Subsequent same-direction Initials must retain that DCID; a change is unsupported,
not a fresh budget. Reverse-direction traffic consumes attempts but cannot mix
server CRYPTO into the client Hello. Initial packet numbers are reconstructed
from the largest authenticated number after the first observed window.
Retry, connection migration, server Initial decoding and QUIC versions other
than v1 remain unsupported. This is not peer authentication or HTTP/3 support.

The assembly admits offsets in 4096 bytes and at most 32 disjoint ranges,
with up to 32 CRYPTO frames and 64 nonpadding frames per Initial. Up to eight
coalesced Initial packets share one UDP payload attempt; the 1200-byte minimum
applies to the whole datagram. Later opaque short-header data is not decoded. Identical
repeats/overlaps merge; conflicting bytes terminate unavailable/malformed.
Only a contiguous prefix from zero reaches the existing shared ClientHello
reader. Incomplete ranges stay unavailable/running until more data, terminal
failure, 20 payload attempts or the original five-second deadline. Duplicates,
reverse packets, policy changes and DCID changes never reset budgets.
Work is bounded at 131072 diagnostic units, charged for admitted datagram bytes,
range insertion/comparison and complete Hello parsing; cryptographic fixed
costs and bounded metadata loops are additional operations, not CPU units.

`bytes` now counts unique admitted CRYPTO bytes, while `work` includes every
admitted UDP payload and duplicate CRYPTO comparison. Stop11 remains a valid
historical ABI value; incomplete assembly now stays running (stop0).

The existing 320-byte SNI query identity and name/absence semantics remain.
Its `cache_bytes` projects logical retained bytes for the current transport.
All terminal stops, owner deadline expiry and Flow retirement clear assembly
bytes and metadata, while established SNI and accumulated protocol facts remain.
Only a valid full parse confirms absence; newly available QUIC SNI participates
in the same packet cutoff and full cache dependency union. T18 must cover
assembled/reordered QUIC names when connecting domain-list consumers.

Verification uses the already authorized owner lifecycle, actual management
and packet path, and complete-winner/cache seams. Independently generated
protected Initial sequences supply literal expected names and failure states.
Exact tested limits and local resource measurements accompany acceptance.
