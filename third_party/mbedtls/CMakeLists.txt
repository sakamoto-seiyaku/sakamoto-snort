# Pinned upstream C primitives, private symbols and the same configuration on Host/NDK.
add_library(sakamoto_quic_crypto STATIC
  library/aes.c library/aesni.c library/aesce.c library/gcm.c
  library/block_cipher.c library/sha256.c library/platform_util.c library/constant_time.c)
target_include_directories(sakamoto_quic_crypto PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(sakamoto_quic_crypto PUBLIC MBEDTLS_CONFIG_FILE="product_config.h")
target_compile_features(sakamoto_quic_crypto PRIVATE c_std_11)
set_target_properties(sakamoto_quic_crypto PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
