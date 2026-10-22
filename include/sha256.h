#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Computes SHA-256 hash over an in-memory buffer.
 * @param data Input data pointer.
 * @param len Input data length in bytes.
 * @param out_hash Output buffer of 32 bytes for binary digest.
 */
void durak_sha256(const void* data, size_t len, uint8_t out_hash[32]);
int durak_sha256_selftest(void);

/**
 * @brief Formats a 32-byte binary SHA-256 hash into a 64-character lowercase hex string.
 * @param hash 32-byte binary hash.
 * @param out_hex Output buffer of at least 65 bytes (null-terminated).
 */
void durak_sha256_to_hex(const uint8_t hash[32], char out_hex[65]);

#ifdef __cplusplus
}
#endif
