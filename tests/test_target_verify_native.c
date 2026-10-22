#include "../include/durak_target_verify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main(void) {
    const char *modules[DURAK_NUM_MODULES] = {
        "extracted_durak/libsqlite3.so",
        "extracted_durak/libmain.so",
        "extracted_durak/libunity.so",
        "extracted_durak/libil2cpp.so"
    };

    printf("=== Testing Native durak_target_verify ===\n");

    for (int i = 0; i < DURAK_NUM_MODULES; i++) {
        const DurakModuleMetadata *meta = durak_find_module_metadata(modules[i]);
        assert(meta != NULL);

        FILE *f = fopen(modules[i], "rb");
        assert(f != NULL);
        fseek(f, 0, SEEK_END);
        size_t sz = ftell(f);
        fseek(f, 0, SEEK_SET);

        void *buf = malloc(sz);
        assert(buf != NULL);
        size_t nread = fread(buf, 1, sz, f);
        assert(nread == sz);
        fclose(f);

        // Positive test
        int rc = durak_verify_target_buffer(meta, buf, sz);
        printf("[%s] Verification result: %d (expected 0)\n", meta->filename, rc);
        assert(rc == 0);

        // Negative test: size mismatch
        rc = durak_verify_target_buffer(meta, buf, sz - 1);
        assert(rc == -2);

        // Negative test: SHA-256 corruption
        ((uint8_t *)buf)[16] ^= 0x55;
        rc = durak_verify_target_buffer(meta, buf, sz);
        assert(rc == -3);

        free(buf);
    }

    // Negative test: unknown module
    const DurakModuleMetadata *unknown_meta = durak_find_module_metadata("libunknown.so");
    assert(unknown_meta == NULL);

    printf("ALL NATIVE TARGET VERIFY TESTS PASSED!\n");
    return 0;
}
