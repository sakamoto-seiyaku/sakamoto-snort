/* Product QUIC Initial primitive subset; no TLS stack, PSA or allocation. */
#ifndef SAKAMOTO_MBEDTLS_CONFIG_H
#define SAKAMOTO_MBEDTLS_CONFIG_H
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_AESNI_C
#define MBEDTLS_AESCE_C
#define MBEDTLS_BLOCK_CIPHER_C
#define MBEDTLS_GCM_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_HAVE_ASM
#endif
