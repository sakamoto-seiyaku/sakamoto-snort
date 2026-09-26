# Rust configuration-import dependencies

The packet-free Product Core uses `idna` 1.0.3 for strict, nontransitional UTS #46
name preparation and `serde` 1.0.219 / `serde_json` 1.0.140 for bounded, explicit
JSON import/export. `Cargo.lock` pins every transitive version and registry
checksum, including IDNA's ICU data. No Unicode conversion runs on VPP workers.

`NOTICE.txt` preserves the license/notice files shipped by all 35 registry
packages in that lockfile, including build-time proc macros. Identical texts are
grouped with every applicable package/version/file listed. Source is obtained by
Cargo from its checksum-verified registry; this directory contains notices, not
a modified implementation. Android payloads include this notice file.

Configuration inputs use strict STD3 ASCII restrictions, IDNA hyphen and DNS
length checks. Non-ASCII U-labels become A-labels. The importer separately rejects
unsupported source syntax, whitespace and multiple trailing dots; this library
is not used as a URL parser or to guess filter semantics.
