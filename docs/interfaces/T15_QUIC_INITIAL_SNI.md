# T15 QUIC v1 Initial producer

[T16](T16_QUIC_CRYPTO_ASSEMBLY.md) extends the original single-Initial slice
below with bounded retained CRYPTO assembly. Its incomplete/running, PN,
coalescing and retained-resource rules supersede those T15 limits.

The existing identity-validated `product_flow_entry_identify` operation accepts
borrowed UDP payloads and produces the same SNI/name/confirmed-absence contract
as [T13](T13_TLS_SNI_FACTS.md). QUIC results publish QUIC, never an additional
TCP TLS label. Packet ownership, the current packet decision cutoff, full-rule
TLS/QUIC applicability and cache dependency guards are unchanged.

This slice supports RFC9000/9001 QUIC version 1 client Initial protection:
DCID-derived Initial secrets, AES-128 header protection and authenticated
AES-128-GCM decryption. Initial authentication validates this packet's public
Initial keys; it does not authenticate a peer or complete a TLS handshake.
The first packet-number window is decoded from an expected number of zero.
Server Initial, Retry processing, later packet-number windows and other
versions are outside this slice.

One bounded Initial may contain multiple CRYPTO frames. Their offset-ordered,
nonoverlapping spans must provide a contiguous complete first ClientHello from
offset zero. The shared Hello reader borrows decrypted spans synchronously;
there is no second Hello copy or use of TCP sequence/reassembly storage.
Cross-Initial gaps or incomplete Hello stay unavailable with a distinct stop
reason; T16 extends assembly. Padding, PING and bounded ACK/ACK_ECN frames may
surround CRYPTO; unsupported frame types remain unavailable.

Initial limits: 4096-byte UDP payload/decrypt scratch, 32 CRYPTO spans,
64 nonpadding frames, 32 ACK ranges, the shared Hello size/extension/work limits,
20 payload attempts and five seconds from the first payload. Non-Initial UDP
packets consume the bounded attempt but do not fabricate absence or immediately
prevent a later supported Initial. No packet-path allocation or retained UDP
bytes are introduced. Terminal outcomes never retry; Flow reuse resets state.
For UDP, `bytes` counts admitted current payload bytes, not retained assembly
bytes; `work` charges those bytes plus the complete Hello reader length. Fixed
key derivation and bounded frame loops are additional bounded operations, not
CPU instructions represented one-for-one by that diagnostic counter.

Existing result values and the 320-byte query ABI are unchanged. Stops 0–8 keep
their T13 meaning; 9 is unsupported QUIC version, 10 is authentication failure,
11 is incomplete QUIC Hello/assembly, 12 is crypto primitive failure.
Malformed framing uses 2; unsupported frame/packet forms use 3; capacity uses 5.
The existing owner deadline reclaims an unfinished attempt independently of CT.

Crypto primitives are the pinned upstream Mbed TLS 3.6.7 C subset, statically
linked with hidden symbols using the same configuration for Host and Android.
Only AES/GCM/SHA-256 primitives are enabled; no platform-private libcrypto ABI,
TLS engine, tunnel decoder, random generator or global parser admission quota.
The existing serialized graph startup primes the dependency's CPU capability
probes before workers process packets; per-packet crypto contexts remain local.

Verification seams are the already agreed public owner lifecycle, rule
management/save/apply/query with actual packets, and compiler/matcher complete
winner/cache behavior. Expected names/absence and negative outcomes come from
RFC9001's vector and independent test traffic generators.
