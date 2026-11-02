# Retired Activity channel checks

S332 preserved these scripts byte for byte when retiring their current entrypoints.
They depend on missing native Activity fields, retired stage-owned policy commands,
or static Java models. They are historical, non-runnable material; relative paths
retain their original meaning. Their former entrypoints now return77 (retired),
never PASS. Historical evidence, failures and frozen artifacts were not rewritten.

Valid lifecycle, rules and diagnostics checks remain in
`tests/android/android-runtime-contract-test.sh`. Current query data and normal
Root/VPN lifecycle/UI checks use `tests/device/s332-debug-query.py`, the shared
Rust query tests and the dated S330/S331/S61/S332 evidence records. These checks
do not requalify historical release/performance claims.
