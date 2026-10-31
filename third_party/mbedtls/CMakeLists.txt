# Pinned upstream C primitives, private symbols and the same configuration on Host/NDK.
add_library(sakamoto_quic_crypto STATIC
  library/aes.c library/aesni.c library/aesce.c library/gcm.c
  library/block_cipher.c library/sha256.c library/platform_util.c library/constant_time.c)
target_sources(sakamoto_quic_crypto PRIVATE
  product_memory.c library/platform.c
  library/asn1parse.c library/asn1write.c library/base64.c
  library/bignum.c library/bignum_core.c library/bignum_mod.c library/bignum_mod_raw.c
  library/cipher.c library/cipher_wrap.c library/ecdh.c library/ecdsa.c
  library/ecp.c library/ecp_curves.c library/md.c library/oid.c
  library/pem.c library/pk.c library/pk_ecc.c library/pk_wrap.c library/pkparse.c
  library/rsa.c library/rsa_alt_helpers.c library/sha512.c
  library/ssl_ciphersuites.c library/ssl_client.c library/ssl_msg.c
  library/ssl_tls.c library/ssl_tls12_client.c
  library/x509.c library/x509_crt.c library/x509_crl.c)
target_include_directories(sakamoto_quic_crypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(sakamoto_quic_crypto PUBLIC MBEDTLS_CONFIG_FILE="product_config.h")
target_compile_features(sakamoto_quic_crypto PRIVATE c_std_11)
set_target_properties(sakamoto_quic_crypto PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
