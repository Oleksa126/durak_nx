#include "durak_target_verify.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <elf.h>

#ifndef NT_GNU_BUILD_ID
#define NT_GNU_BUILD_ID 3
#endif

const DurakModuleMetadata g_durak_modules[DURAK_NUM_MODULES] = {
    {
        .filename = "libsqlite3.so",
        .expected_size = 1797248,
        .expected_sha256_hex = "6df7a75d31c417cae7e877fd7c3d190e0ac47b1f104ae0ae5501d72491b1c32c",
        .expected_sha256 = {
            0x6d, 0xf7, 0xa7, 0x5d, 0x31, 0xc4, 0x17, 0xca, 0xe7, 0xe8, 0x77, 0xfd, 0x7c, 0x3d, 0x19, 0x0e,
            0x0a, 0xc4, 0x7b, 0x1f, 0x10, 0x4a, 0xe0, 0xae, 0x55, 0x01, 0xd7, 0x24, 0x91, 0xb1, 0xc3, 0x2c
        },
        .expected_build_id = "99495662cefa74605573c8dc36a53cb1f842764d",
        .expected_alignment = 0x10000, // 64 KiB
        .max_allowed_size = 4 * 1024 * 1024
    },
    {
        .filename = "libmain.so",
        .expected_size = 6696,
        .expected_sha256_hex = "c11373dffa1bab427e8864a40313111de2a70367d052d87f33a9069ce8949d93",
        .expected_sha256 = {
            0xc1, 0x13, 0x73, 0xdf, 0xfa, 0x1b, 0xab, 0x42, 0x7e, 0x88, 0x64, 0xa4, 0x03, 0x13, 0x11, 0x1d,
            0xe2, 0xa7, 0x03, 0x67, 0xd0, 0x52, 0xd8, 0x7f, 0x33, 0xa9, 0x06, 0x9c, 0xe8, 0x94, 0x9d, 0x93
        },
        .expected_build_id = "c5498ab8c791f1473a54c79a9d3c5b738ff6d941",
        .expected_alignment = 0x4000, // 16 KiB
        .max_allowed_size = 64 * 1024
    },
    {
        .filename = "libunity.so",
        .expected_size = 21388304,
        .expected_sha256_hex = "292f89210151ba0060f77d137cd6a00a52158dc5da760d4bf106158fc9309cef",
        .expected_sha256 = {
            0x29, 0x2f, 0x89, 0x21, 0x01, 0x51, 0xba, 0x00, 0x60, 0xf7, 0x7d, 0x13, 0x7c, 0xd6, 0xa0, 0x0a,
            0x52, 0x15, 0x8d, 0xc5, 0xda, 0x76, 0x0d, 0x4b, 0xf1, 0x06, 0x15, 0x8f, 0xc9, 0x30, 0x9c, 0xef
        },
        .expected_build_id = "bcc661ea2046416d",
        .expected_alignment = 0x4000, // 16 KiB
        .max_allowed_size = 30 * 1024 * 1024
    },
    {
        .filename = "libil2cpp.so",
        .expected_size = 31256704,
        .expected_sha256_hex = "7bc9c2e7e20c741a511e6645589db16d0fa084d79bcfc12ba1fab78931e2271c",
        .expected_sha256 = {
            0x7b, 0xc9, 0xc2, 0xe7, 0xe2, 0x0c, 0x74, 0x1a, 0x51, 0x1e, 0x66, 0x45, 0x58, 0x9d, 0xb1, 0x6d,
            0x0f, 0xa0, 0x84, 0xd7, 0x9b, 0xcf, 0xc1, 0x2b, 0xa1, 0xfa, 0xb7, 0x89, 0x31, 0xe2, 0x27, 0x1c
        },
        .expected_build_id = "d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0",
        .expected_alignment = 0x4000, // 16 KiB
        .max_allowed_size = 40 * 1024 * 1024
    }
};

static const char *get_basename(const char *path) {
    if (!path) return "";
    const char *last = strrchr(path, '/');
    if (!last) last = strrchr(path, '\\');
    return last ? last + 1 : path;
}

const DurakModuleMetadata *durak_find_module_metadata(const char *path) {
    const char *bname = get_basename(path);
    for (int i = 0; i < DURAK_NUM_MODULES; i++) {
        if (strcmp(bname, g_durak_modules[i].filename) == 0) {
            return &g_durak_modules[i];
        }
    }
    return NULL;
}

static int extract_gnu_build_id(const void *buf, size_t size, char *out_hex, size_t max_hex) {
    if (size < sizeof(Elf64_Ehdr)) return -1;
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)buf;
    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) > size) return -1;

    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)((const uint8_t *)buf + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_NOTE) continue;
        if (phdrs[i].p_offset + phdrs[i].p_filesz > size) continue;

        const uint8_t *note_ptr = (const uint8_t *)buf + phdrs[i].p_offset;
        const uint8_t *note_end = note_ptr + phdrs[i].p_filesz;

        while (note_ptr + sizeof(Elf64_Nhdr) <= note_end) {
            const Elf64_Nhdr *nhdr = (const Elf64_Nhdr *)note_ptr;
            size_t namesz_aligned = (nhdr->n_namesz + 3) & ~3;
            size_t descsz_aligned = (nhdr->n_descsz + 3) & ~3;

            const char *name = (const char *)(note_ptr + sizeof(Elf64_Nhdr));
            const uint8_t *desc = (const uint8_t *)(note_ptr + sizeof(Elf64_Nhdr) + namesz_aligned);

            if (note_ptr + sizeof(Elf64_Nhdr) + namesz_aligned + descsz_aligned > note_end)
                break;

            if (nhdr->n_type == NT_GNU_BUILD_ID && nhdr->n_namesz == 4 && memcmp(name, "GNU", 4) == 0) {
                if (nhdr->n_descsz * 2 + 1 > max_hex) return -1;
                for (uint32_t j = 0; j < nhdr->n_descsz; j++) {
                    snprintf(out_hex + j * 2, 3, "%02x", desc[j]);
                }
                out_hex[nhdr->n_descsz * 2] = '\0';
                return 0;
            }

            note_ptr += sizeof(Elf64_Nhdr) + namesz_aligned + descsz_aligned;
        }
    }
    return -1;
}

int durak_verify_target_buffer(const DurakModuleMetadata *meta, const void *buf, size_t size) {
    if (!meta || !buf) {
        printf("[SECURITY] Verification failed: NULL pointer argument\n");
        return -1;
    }

    // 1. File size verification
    if (size != meta->expected_size) {
        printf("[SECURITY] Verification FAILED for %s: size mismatch (actual %zu vs expected %zu)\n",
               meta->filename, size, meta->expected_size);
        return -2;
    }
    if (size > meta->max_allowed_size) {
        printf("[SECURITY] Verification FAILED for %s: size %zu exceeds safety limit %zu\n",
               meta->filename, size, meta->max_allowed_size);
        return -2;
    }

    // 2. SHA-256 verification
    uint8_t actual_hash[32];
    durak_sha256(buf, size, actual_hash);
    if (memcmp(actual_hash, meta->expected_sha256, 32) != 0) {
        char actual_hex[65];
        for (int i = 0; i < 32; i++) snprintf(actual_hex + i * 2, 3, "%02x", actual_hash[i]);
        actual_hex[64] = '\0';
        printf("[SECURITY] Verification FAILED for %s: SHA-256 mismatch!\n  Actual:   %s\n  Expected: %s\n",
               meta->filename, actual_hex, meta->expected_sha256_hex);
        return -3;
    }

    // 3. ELF header verification
    if (size < sizeof(Elf64_Ehdr)) {
        printf("[SECURITY] Verification FAILED for %s: file smaller than ELF header\n", meta->filename);
        return -4;
    }
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)buf;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_machine != EM_AARCH64) {
        printf("[SECURITY] Verification FAILED for %s: invalid ELF header (must be ELFCLASS64 ARM64)\n", meta->filename);
        return -4;
    }

    // 4. GNU Build-ID verification
    char actual_build_id[128];
    if (extract_gnu_build_id(buf, size, actual_build_id, sizeof(actual_build_id)) != 0) {
        printf("[SECURITY] Verification FAILED for %s: missing GNU Build-ID\n", meta->filename);
        return -5;
    }
    if (strcmp(actual_build_id, meta->expected_build_id) != 0) {
        printf("[SECURITY] Verification FAILED for %s: Build-ID mismatch!\n  Actual:   %s\n  Expected: %s\n",
               meta->filename, actual_build_id, meta->expected_build_id);
        return -5;
    }

    printf("[SECURITY] Target Verified OK: %s (size=%zu, Build-ID=%s)\n",
           meta->filename, size, meta->expected_build_id);
    return 0;
}
