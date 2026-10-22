#ifndef DURAK_TARGET_VERIFY_H
#define DURAK_TARGET_VERIFY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DURAK_NUM_MODULES 4

typedef struct {
    const char *filename;
    size_t expected_size;
    const char *expected_sha256_hex;
    uint8_t expected_sha256[32];
    const char *expected_build_id;
    size_t expected_alignment;
    size_t max_allowed_size;
} DurakModuleMetadata;

extern const DurakModuleMetadata g_durak_modules[DURAK_NUM_MODULES];

// Find metadata by filename (e.g. "libunity.so" or path ending in "libunity.so")
const DurakModuleMetadata *durak_find_module_metadata(const char *path);

// Verify ELF buffer in memory against canonical expectations
// Returns 0 on success, negative error code on failure:
// -1: null arguments or unknown module
// -2: size mismatch
// -3: SHA-256 mismatch
// -4: ELF header invalid (not AArch64)
// -5: Build-ID mismatch or missing
int durak_verify_target_buffer(const DurakModuleMetadata *meta, const void *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif // DURAK_TARGET_VERIFY_H
