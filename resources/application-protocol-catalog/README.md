# Application Protocol Catalog

`catalog.tsv` is the authoritative, version-controlled build input for
Sakamoto application protocol identity. It is not runtime hot-loaded user
configuration. Adding a protocol requires a software release and a runtime
restart so generated C/Rust/product/API constants are used consistently.

Each active row owns a stable integer `ApplicationProtocolId` and lowercase
`ApplicationProtocolKey`. Released IDs are append-only: removed protocols stay
as `reserved` tombstones, and a rename uses an explicit migration alias instead
of changing an existing key or reusing an ID.

Provider aliases map recognizer evidence such as `lpi:http` into a catalog ID;
they are not policy identity and must not become authoring keys. Port numbers,
IP protocol numbers, ALPN tokens, and QUIC versions stay in their own typed
namespaces rather than being folded into `ApplicationProtocolId`.

Categories are authoring and presentation groups only. Policy Apply expands a
category selector into the exact active protocol IDs from the current built-in
catalog; packet-path matching still compares exact integer protocol IDs.
