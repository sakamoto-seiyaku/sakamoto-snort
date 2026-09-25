# Mbed TLS primitive subset

Source: https://github.com/Mbed-TLS/mbedtls tag `mbedtls-3.6.7`.
Archive SHA-256: `807f0a1cc7c63b571180e9efeb6236b677e550869eb0442ace33aa9c69055fcc`.
Upstream files are unmodified, used under Apache-2.0 (see LICENSE).
`upstream-files.json` records the retained file hashes. Product CMake and
`product_config.h` select only AES, GCM, SHA-256 and their support code.
No TLS/X.509/PSA stack, random generator or platform libcrypto is linked.
QUIC Initial keys are public protocol-derived keys, not session credentials.
