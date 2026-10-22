/* test_loader_linker_native.c -- Native C test harness for ELF loader, relocations,
 * symbol resolution, fail-stop thunks, and pre-entry audit gates.
 */

#include "../include/so_util.h"
#include "../include/durak_pre_entry_audit.h"
#include "../include/durak_target_verify.h"
#include "../include/fail_stop_thunks.h"
#include "../include/util.h"
#include "../include/region_patch.h"
#include "../include/frame_pacer.h"
#include "../include/unity_input_hook.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

// Mock implementations for libmain.so's 12 undefined functions
static void  mock_cxa_finalize(void *d) { (void)d; }
static int   mock_cxa_atexit(void (*f)(void *), void *a, void *d) { (void)f; (void)a; (void)d; return 0; }
static int   mock_register_atfork(void (*p)(void), void (*c)(void), void (*r)(void)) { (void)p; (void)c; (void)r; return 0; }
static void *mock_malloc(size_t sz) { (void)sz; return (void *)0x12340001; }
static void *mock_memcpy(void *d, const void *s, size_t n) { (void)s; (void)n; return d; }
static void  mock_free(void *p) { (void)p; }
static void *mock_dlsym(void *h, const char *s) { (void)h; (void)s; return (void *)0x12340002; }
static int   mock_dlclose(void *h) { (void)h; return 0; }
static int   mock_snprintf(char *s, size_t n, const char *fmt, ...) { (void)s; (void)n; (void)fmt; return 0; }
static void *mock_dlopen(const char *f, int flag) { (void)f; (void)flag; return (void *)0x12340003; }
static char *mock_dlerror(void) { return NULL; }
static void  mock_stack_chk_fail(void) {}

static DynLibFunction g_full_shims[] = {
    { "__cxa_finalize", (uintptr_t)mock_cxa_finalize },
    { "__cxa_atexit", (uintptr_t)mock_cxa_atexit },
    { "__register_atfork", (uintptr_t)mock_register_atfork },
    { "malloc", (uintptr_t)mock_malloc },
    { "memcpy", (uintptr_t)mock_memcpy },
    { "free", (uintptr_t)mock_free },
    { "dlsym", (uintptr_t)mock_dlsym },
    { "dlclose", (uintptr_t)mock_dlclose },
    { "snprintf", (uintptr_t)mock_snprintf },
    { "dlopen", (uintptr_t)mock_dlopen },
    { "dlerror", (uintptr_t)mock_dlerror },
    { "__stack_chk_fail", (uintptr_t)mock_stack_chk_fail },
};
static const int g_full_shims_count = sizeof(g_full_shims) / sizeof(g_full_shims[0]);

// Mock hooks for pre-entry audit negative tests
static int mock_query_memory_fail(uintptr_t vaddr, uint32_t *out_perm) {
    (void)vaddr;
    (void)out_perm;
    return 0xD801; // Simulate svcQueryMemory failure
}

static int mock_query_memory_inaccessible(uintptr_t vaddr, uint32_t *out_perm) {
    (void)vaddr;
    *out_perm = 0; // Simulate unmapped page
    return 0;
}

static uintptr_t g_target_relro_vaddr = 0;

static int mock_query_memory_writable_relro(uintptr_t vaddr, uint32_t *out_perm) {
    if (g_target_relro_vaddr != 0 && vaddr == g_target_relro_vaddr) {
        *out_perm = 3; // Perm_Rw (violation: RELRO must be Perm_R)
    } else {
        *out_perm = 1; // Perm_R
    }
    return 0;
}

static int mock_query_memory_rwx(uintptr_t vaddr, uint32_t *out_perm) {
    (void)vaddr;
    *out_perm = 7; // Perm_R | Perm_W | Perm_X (W^X violation)
    return 0;
}

static void test_successful_load_and_pointer_verification(void) {
    printf("[TEST] 1. Loading libmain.so and verifying relocated pointers in memory...\n");
    so_reset_list();

    const size_t buf_size = 2 * 1024 * 1024;
    void *raw_buf = calloc(1, buf_size + 0x10000);
    assert(raw_buf != NULL);
    void *buf = (void *)ALIGN_MEM((uintptr_t)raw_buf, 0x10000);

    so_module mod;
    int rc = so_load(&mod, "extracted_durak/libmain.so", buf, buf_size);
    assert(rc == 0);
    assert(mod.load_size > 0);

    rc = so_relocate(&mod);
    assert(rc == 0);

    durak_fail_stop_init();
    rc = so_resolve(&mod, g_full_shims, g_full_shims_count, 1);
    assert(rc == 0);

    // Active in-memory pointer verification
    int verified_pointers = 0;
    for (int i = 0; i < mod.elf_hdr->e_shnum; i++) {
        char *sh_name = mod.shstrtab + mod.sec_hdr[i].sh_name;
        if (strcmp(sh_name, ".rela.dyn") == 0 || strcmp(sh_name, ".rela.plt") == 0) {
            Elf64_Rela *rels = (Elf64_Rela *)((uintptr_t)mod.load_base + mod.sec_hdr[i].sh_addr);
            int count = mod.sec_hdr[i].sh_size / sizeof(Elf64_Rela);
            for (int j = 0; j < count; j++) {
                Elf64_Sym *sym = &mod.syms[ELF64_R_SYM(rels[j].r_info)];
                if (sym->st_shndx == SHN_UNDEF) {
                    char *name = mod.dynstrtab + sym->st_name;
                    uintptr_t *ptr = (uintptr_t *)((uintptr_t)mod.load_base + rels[j].r_offset);

                    // Look up expected function
                    for (int k = 0; k < g_full_shims_count; k++) {
                        if (strcmp(name, g_full_shims[k].symbol) == 0) {
                            assert(*ptr == g_full_shims[k].func + rels[j].r_addend);
                            assert(*ptr != 0);
                            verified_pointers++;
                            break;
                        }
                    }
                }
            }
        }
    }

    printf("  Verified %d relocated pointers match exact target shim addresses.\n", verified_pointers);
    assert(verified_pointers == 12);
    assert(mod.num_resolved_shims == 12);
    assert(mod.num_fail_stop == 0);
    assert(mod.num_weak_null == 0);
    assert(mod.num_strong_data_unresolved == 0);

    so_free_temp(&mod);
    so_reset_list();
    free(raw_buf);
    printf("  [PASS] Pointer verification successful.\n\n");
}

static void test_fail_stop_thunk_binding(void) {
    printf("[TEST] 2. Testing fail-stop thunk binding when strong function is missing...\n");
    so_reset_list();

    const size_t buf_size = 2 * 1024 * 1024;
    void *raw_buf = calloc(1, buf_size + 0x10000);
    assert(raw_buf != NULL);
    void *buf = (void *)ALIGN_MEM((uintptr_t)raw_buf, 0x10000);

    so_module mod;
    int rc = so_load(&mod, "extracted_durak/libmain.so", buf, buf_size);
    assert(rc == 0);

    rc = so_relocate(&mod);
    assert(rc == 0);

    durak_fail_stop_init();

    // Omit 'snprintf' from shims list
    DynLibFunction partial_shims[16];
    int partial_count = 0;
    for (int k = 0; k < g_full_shims_count; k++) {
        if (strcmp(g_full_shims[k].symbol, "snprintf") != 0) {
            partial_shims[partial_count++] = g_full_shims[k];
        }
    }
    assert(partial_count == 11);

    rc = so_resolve(&mod, partial_shims, partial_count, 1);
    assert(rc == 0); // Functions are safely thunked without failure

    assert(mod.num_resolved_shims == 11);
    assert(mod.num_fail_stop == 1);
    assert(durak_get_fail_stop_count() == 1);

    // Verify GOT entry for snprintf is bound to the fail-stop thunk
    int found_thunk = 0;
    for (int i = 0; i < mod.elf_hdr->e_shnum; i++) {
        char *sh_name = mod.shstrtab + mod.sec_hdr[i].sh_name;
        if (strcmp(sh_name, ".rela.dyn") == 0 || strcmp(sh_name, ".rela.plt") == 0) {
            Elf64_Rela *rels = (Elf64_Rela *)((uintptr_t)mod.load_base + mod.sec_hdr[i].sh_addr);
            int count = mod.sec_hdr[i].sh_size / sizeof(Elf64_Rela);
            for (int j = 0; j < count; j++) {
                Elf64_Sym *sym = &mod.syms[ELF64_R_SYM(rels[j].r_info)];
                if (sym->st_shndx == SHN_UNDEF) {
                    char *name = mod.dynstrtab + sym->st_name;
                    if (strcmp(name, "snprintf") == 0) {
                        uintptr_t *ptr = (uintptr_t *)((uintptr_t)mod.load_base + rels[j].r_offset);
                        assert(*ptr != 0);
                        assert(*ptr != (uintptr_t)mock_snprintf);
                        found_thunk = 1;
                    }
                }
            }
        }
    }
    assert(found_thunk == 1);

    so_free_temp(&mod);
    so_reset_list();
    free(raw_buf);
    printf("  [PASS] Missing strong function successfully bound to fail-stop thunk.\n\n");
}

static void test_negative_unresolved_strong_data_symbol(void) {
    printf("[TEST] 3. Testing negative case: unresolved strong data symbol fails closed...\n");
    so_reset_list();

    const size_t buf_size = 2 * 1024 * 1024;
    void *raw_buf = calloc(1, buf_size + 0x10000);
    assert(raw_buf != NULL);
    void *buf = (void *)ALIGN_MEM((uintptr_t)raw_buf, 0x10000);

    so_module mod;
    int rc = so_load(&mod, "extracted_durak/libmain.so", buf, buf_size);
    assert(rc == 0);

    rc = so_relocate(&mod);
    assert(rc == 0);

    durak_fail_stop_init();

    // Mutate 'malloc' in .dynsym from STT_FUNC to STT_OBJECT (data) and relocation to R_AARCH64_GLOB_DAT
    for (int i = 0; i < mod.elf_hdr->e_shnum; i++) {
        char *sh_name = mod.shstrtab + mod.sec_hdr[i].sh_name;
        if (strcmp(sh_name, ".rela.dyn") == 0 || strcmp(sh_name, ".rela.plt") == 0) {
            Elf64_Rela *rels = (Elf64_Rela *)((uintptr_t)mod.load_base + mod.sec_hdr[i].sh_addr);
            int count = mod.sec_hdr[i].sh_size / sizeof(Elf64_Rela);
            for (int j = 0; j < count; j++) {
                Elf64_Sym *sym = &mod.syms[ELF64_R_SYM(rels[j].r_info)];
                char *name = mod.dynstrtab + sym->st_name;
                if (strcmp(name, "malloc") == 0) {
                    sym->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
                    rels[j].r_info = ELF64_R_INFO(ELF64_R_SYM(rels[j].r_info), R_AARCH64_GLOB_DAT);
                }
            }
        }
    }

    // Omit 'malloc' from shims list
    DynLibFunction shims_no_malloc[16];
    int count = 0;
    for (int k = 0; k < g_full_shims_count; k++) {
        if (strcmp(g_full_shims[k].symbol, "malloc") != 0) {
            shims_no_malloc[count++] = g_full_shims[k];
        }
    }

    rc = so_resolve(&mod, shims_no_malloc, count, 1);
    printf("  so_resolve return code: %d (expected -1)\n", rc);
    assert(rc == -1);
    assert(mod.num_strong_data_unresolved == 1);

    so_free_temp(&mod);
    so_reset_list();
    free(raw_buf);
    printf("  [PASS] Resolver correctly failed closed on unresolved strong data symbol.\n\n");
}

static void test_pre_entry_audit_gates(void) {
    printf("[TEST] 4. Testing Pre-Entry Audit: positive and negative gates...\n");
    so_reset_list();

    const size_t buf_size = 2 * 1024 * 1024;
    void *raw_buf = calloc(1, buf_size + 0x10000);
    assert(raw_buf != NULL);
    void *buf = (void *)ALIGN_MEM((uintptr_t)raw_buf, 0x10000);

    so_module mod;
    int rc = so_load(&mod, "extracted_durak/libmain.so", buf, buf_size);
    assert(rc == 0);
    so_relocate(&mod);
    durak_fail_stop_init();
    so_resolve(&mod, g_full_shims, g_full_shims_count, 1);

    so_module *mods[1] = { &mod };
    DurakPreEntryAuditSummary summary;

    // Positive test: default simulation
    durak_set_query_memory_hook(NULL);
    rc = durak_run_pre_entry_audit(mods, 1, &summary);
    assert(rc == 0);
    assert(summary.audit_passed == 1);
    assert(summary.total_rwx_pages == 0);
    assert(summary.total_writable_relro == 0);
    assert(summary.total_query_failures == 0);
    assert(summary.total_inaccessible_pages == 0);
    printf("  Positive audit gate passed.\n");

    // Negative test A: svcQueryMemory failure
    durak_set_query_memory_hook(mock_query_memory_fail);
    rc = durak_run_pre_entry_audit(mods, 1, &summary);
    assert(rc == -1);
    assert(summary.audit_passed == 0);
    assert(summary.total_query_failures > 0);
    printf("  Negative gate A (Query failure) correctly caught: %zu failures.\n", summary.total_query_failures);

    // Negative test B: Inaccessible page (perm=0)
    durak_set_query_memory_hook(mock_query_memory_inaccessible);
    rc = durak_run_pre_entry_audit(mods, 1, &summary);
    assert(rc == -1);
    assert(summary.audit_passed == 0);
    assert(summary.total_inaccessible_pages > 0);
    printf("  Negative gate B (Inaccessible page) correctly caught: %zu pages.\n", summary.total_inaccessible_pages);

    // Negative test C: Writable RELRO page
    // Find a RELRO page vaddr in libmain.so
    g_target_relro_vaddr = 0;
    for (int i = 0; i < mod.phnum; i++) {
        if (mod.phdr[i].p_type == PT_GNU_RELRO) {
            g_target_relro_vaddr = (uintptr_t)mod.load_virtbase + (mod.phdr[i].p_vaddr & ~0xFFFull);
            break;
        }
    }
    assert(g_target_relro_vaddr != 0);

    durak_set_query_memory_hook(mock_query_memory_writable_relro);
    rc = durak_run_pre_entry_audit(mods, 1, &summary);
    assert(rc == -1);
    assert(summary.audit_passed == 0);
    assert(summary.total_writable_relro > 0);
    printf("  Negative gate C (Writable RELRO) correctly caught: %zu pages.\n", summary.total_writable_relro);

    // Negative test D: RWX violation
    durak_set_query_memory_hook(mock_query_memory_rwx);
    rc = durak_run_pre_entry_audit(mods, 1, &summary);
    assert(rc == -1);
    assert(summary.audit_passed == 0);
    assert(summary.total_rwx_pages > 0);
    printf("  Negative gate D (RWX page violation) correctly caught: %zu pages.\n", summary.total_rwx_pages);

    durak_set_query_memory_hook(NULL);
    so_free_temp(&mod);
    so_reset_list();
    free(raw_buf);
    printf("  [PASS] All pre-entry audit positive and negative gates verified.\n\n");
}

static void test_sqlite3_64k_actual_address_alignment(void) {
    printf("[TEST] 5. Testing actual address alignment on real libsqlite3.so (64 KiB)...\n");
    so_reset_list();

    const size_t buf_size = 4 * 1024 * 1024;
    void *raw_buf = calloc(1, buf_size + 0x10000);
    assert(raw_buf != NULL);
    void *buf = (void *)ALIGN_MEM((uintptr_t)raw_buf, 0x10000);

    so_module mod;
    int rc = so_load(&mod, "extracted_durak/libsqlite3.so", buf, buf_size);
    assert(rc == 0);
    assert(mod.load_size > 0);

    // Verify max_align matches ELF p_align requirement (64 KiB)
    assert(mod.max_align == 0x10000);

    // Verify actual addresses are strictly aligned to 64 KiB
    assert(((uintptr_t)mod.load_virtbase & 0xFFFF) == 0);
    assert(((uintptr_t)mod.load_base & 0xFFFF) == 0);

    rc = so_relocate(&mod);
    assert(rc == 0);

    so_module *mods[1] = { &mod };
    DurakPreEntryAuditSummary summary;
    durak_set_query_memory_hook(NULL);
    rc = durak_run_pre_entry_audit(mods, 1, &summary);
    assert(rc == 0);
    assert(summary.audit_passed == 1);

    so_free_temp(&mod);
    so_reset_list();
    free(raw_buf);
    printf("  [PASS] libsqlite3.so 64 KiB actual address alignment verified.\n\n");
}

static void *g_mock_reserved_addr = NULL;
static size_t g_mock_reserved_size = 0;
static int    g_mock_reservation_freed = 0;

static void *mock_find_unaligned(size_t size, size_t guard_size) {
    (void)guard_size;
    (void)size;
    // Return an address that is 4 KiB page aligned but NOT 64 KiB aligned
    return (void *)0x60001000ULL;
}

static void *mock_add_reservation(void *addr, size_t size) {
    g_mock_reserved_addr = addr;
    g_mock_reserved_size = size;
    return (void *)0xDEADBEEFULL;
}

static void mock_remove_reservation(void *rv) {
    (void)rv;
    g_mock_reservation_freed = 1;
}

static void *mock_find_fail(size_t size, size_t guard_size) {
    (void)size;
    (void)guard_size;
    return NULL; // Simulate allocation failure
}

static void *mock_add_fail(void *addr, size_t size) {
    (void)addr;
    (void)size;
    return NULL; // Simulate reservation failure
}

static void test_virtmem_alignment_and_failure_handling(void) {
    printf("[TEST] 6. Testing virtmem alignment, allocation failure, and reservation failure...\n");
    so_reset_list();

    const size_t buf_size = 4 * 1024 * 1024;
    void *raw_buf = calloc(1, buf_size + 0x10000);
    assert(raw_buf != NULL);
    void *buf = (void *)ALIGN_MEM((uintptr_t)raw_buf, 0x10000);

    // Case A: Unaligned raw address returned by virtmem search must be explicitly aligned
    g_mock_reserved_addr = NULL;
    g_mock_reserved_size = 0;
    g_mock_reservation_freed = 0;
    so_set_virtmem_hooks(mock_find_unaligned, mock_add_reservation, mock_remove_reservation);

    so_module mod;
    int rc = so_load(&mod, "extracted_durak/libsqlite3.so", buf, buf_size);
    assert(rc == 0);
    // Raw address was 0x60001000; aligned address MUST be 0x60010000 (aligned to 64 KiB)
    assert((uintptr_t)mod.load_virtbase == 0x60010000ULL);
    assert(((uintptr_t)mod.load_virtbase & 0xFFFF) == 0);
    // Reservation was made for the raw address covering total allocated size
    assert(g_mock_reserved_addr == (void *)0x60001000ULL);
    assert(g_mock_reserved_size >= mod.load_size);
    so_free_temp(&mod);
    so_unload(&mod);
    assert(g_mock_reservation_freed == 1);
    printf("  Explicit virtbase alignment from unaligned code memory search verified.\n");

    // Case B: Code memory allocation failure fails closed
    so_set_virtmem_hooks(mock_find_fail, mock_add_reservation, mock_remove_reservation);
    rc = so_load(&mod, "extracted_durak/libsqlite3.so", buf, buf_size);
    assert(rc == -6);
    assert(mod.so_base == NULL);
    printf("  Virtmem allocation failure correctly failed closed (rc=-6).\n");

    // Case C: Reservation failure fails closed
    so_set_virtmem_hooks(mock_find_unaligned, mock_add_fail, mock_remove_reservation);
    rc = so_load(&mod, "extracted_durak/libsqlite3.so", buf, buf_size);
    assert(rc == -6);
    assert(mod.so_base == NULL);
    printf("  Virtmem reservation failure correctly failed closed (rc=-6).\n");

    // Case D: Unaligned base buffer rejected
    so_set_virtmem_hooks(NULL, NULL, NULL);
    void *unaligned_buf = (void *)((uintptr_t)buf + 0x1000);
    rc = so_load(&mod, "extracted_durak/libsqlite3.so", unaligned_buf, buf_size);
    assert(rc == -3);
    assert(mod.so_base == NULL);
    printf("  Unaligned base buffer correctly rejected (rc=-3).\n");

    so_set_virtmem_hooks(NULL, NULL, NULL);
    so_reset_list();
    free(raw_buf);
    printf("  [PASS] Virtmem alignment and failure handling verified.\n\n");
}

static void test_diagnostic_logger_verification(void) {
    printf("[TEST] 7. Testing diagnostic logger error tracking and opening/writing checks...\n");

    // Case A: Invalid path must fail and track error
    int rc = durak_log_init("/nonexistent_dir_invalid_12345/durak_test.log");
    assert(rc == -1);
    assert(durak_log_is_open() == 0);
    assert(durak_log_has_error() == 1);
    durak_log_printf("This line should not crash or cause undefined behavior: %d\n", 999);
    assert(durak_log_flush() == -1);
    assert(durak_log_has_error() == 1);
    printf("  Logger invalid path correctly detected and error state tracked.\n");

    // Case B: Valid path must initialize cleanly and report 0 errors
    const char *test_log_path = "tests/test_audit.log";
    rc = durak_log_init(test_log_path);
    assert(rc == 0);
    assert(durak_log_is_open() == 1);
    assert(durak_log_has_error() == 0);

    durak_log_printf("Durak NX Test Line: %s %d\n", "ACTIVE_GATE_A", 2026);
    durak_log_set_file_only(1);
    /* A burst larger than the log buffer must be preserved by checkpoints. */
    for (int i = 0; i < 2000; ++i)
        durak_log_printf("buffered startup record %d\n", i);
    rc = durak_log_flush();
    assert(rc == 0);
    assert(durak_log_has_error() == 0);
    durak_log_close();
    assert(durak_log_is_open() == 0);

    // Verify file content on disk
    FILE *f = fopen(test_log_path, "r");
    assert(f != NULL);
    char line[256] = {0};
    char *res_line = fgets(line, sizeof(line), f);
    assert(res_line != NULL);
    assert(strstr(line, "ACTIVE_GATE_A") != NULL);
    for (int i = 0; i < 2000; ++i) {
        assert(fgets(line, sizeof(line), f));
        char expected[80];
        snprintf(expected, sizeof(expected), "buffered startup record %d\n", i);
        assert(strcmp(line, expected) == 0);
    }
    assert(fgets(line, sizeof(line), f) == NULL);
    fclose(f);
    remove(test_log_path);

#ifndef _WIN32
    /* Buffered failures must still surface at the explicit checkpoint. */
    rc = durak_log_init("/dev/full");
    assert(rc == 0);
    durak_log_printf("buffered write failure\n");
    assert(durak_log_flush() == -1);
    assert(durak_log_has_error());
    durak_log_close();
    assert(durak_log_init(NULL) == 0);
#endif
    durak_log_set_file_only(0);

    printf("  [PASS] Diagnostic logger opening and writing checks verified.\n\n");
}

static void test_constructor_discovery_and_execution_iteration(void) {
    printf("[TEST] 8. Testing constructor iteration and dry-run execution...\n");
    so_module mod;
    memset(&mod, 0, sizeof(mod));
    size_t buf_size = 40 * 1024 * 1024;
    void *raw_buf = calloc(1, buf_size + 0x10000);
    assert(raw_buf != NULL);
    void *buf = (void *)ALIGN_MEM((uintptr_t)raw_buf, 0x10000);

    int rc = so_load(&mod, "extracted_durak/libil2cpp.so", buf, buf_size);
    assert(rc == 0);
    assert(mod.init_array_count == 22);

    rc = so_relocate(&mod);
    assert(rc == 0);

    // Call so_execute_init_array: on x86_64 host it verifies and logs all 22 constructors safely
    rc = so_execute_init_array(&mod);
    assert(rc == 0);

    so_unload(&mod);
    free(raw_buf);
    so_reset_list();
    printf("  [PASS] Constructor iteration and dry-run execution verified (22 ctors).\n\n");
}

static void test_single_game_unlock(void) {
    const size_t size = 0xd7ab48;
    unsigned char *image = calloc(1, size);
    assert(image);
    for (int i = 0; i < DURAK_SINGLE_GAME_UNLOCK_N; ++i)
        memcpy(image + DURAK_SINGLE_GAME_UNLOCK[i].off,
               DURAK_SINGLE_GAME_UNLOCK[i].context, 20);
    assert(durak_patch_single_game_unlock(NULL, size) == -1);
    assert(durak_patch_single_game_unlock(image, size - 1) == -1);
    /* A mismatch at any context word must leave ALL patch sites untouched. */
    for (int i = 0; i < DURAK_SINGLE_GAME_UNLOCK_N; ++i) {
        for (int j = 0; j < 5; ++j) {
            unsigned char *bad = image + DURAK_SINGLE_GAME_UNLOCK[i].off + j * 4;
            *bad ^= 1;
            assert(durak_patch_single_game_unlock(image, size) == -2);
            *bad ^= 1;
            for (int k = 0; k < DURAK_SINGLE_GAME_UNLOCK_N; ++k)
                assert(!memcmp(image + DURAK_SINGLE_GAME_UNLOCK[k].off,
                               DURAK_SINGLE_GAME_UNLOCK[k].context, 20));
        }
    }
    assert(durak_patch_single_game_unlock(image, size) == 0);
    assert(durak_verify_single_game_unlock(image, size) == 0);
    /* Only each cset word changed; surrounding calls/stores remain exact. */
    for (int i = 0; i < DURAK_SINGLE_GAME_UNLOCK_N; ++i) {
        for (int j = 0; j < 5; ++j) {
            uint32_t word;
            memcpy(&word, image + DURAK_SINGLE_GAME_UNLOCK[i].off + j * 4, 4);
            assert(word == (j == 1 ? DURAK_SINGLE_GAME_UNLOCK[i].unlocked
                                  : DURAK_SINGLE_GAME_UNLOCK[i].context[j]));
        }
    }
    image[DURAK_SINGLE_GAME_UNLOCK[2].off + 4] ^= 1;
    assert(durak_verify_single_game_unlock(image, size) == -2);
    free(image);
    printf("[PASS] Single Game unlock fingerprints, atomic failure, RX verification\n");
}

static void test_rate_prompt_patch(void) {
    size_t size = DURAK_RATE_PROMPT_RVA + 20;
    unsigned char *image = calloc(1, size);
    assert(image);
    memcpy(image + DURAK_RATE_PROMPT_RVA, DURAK_RATE_PROMPT_CONTEXT, 20);
    assert(durak_patch_rate_prompt(NULL, size) == -1);
    assert(durak_patch_rate_prompt(image, size - 1) == -1);
    for (int i = 0; i < 5; ++i) {
        image[DURAK_RATE_PROMPT_RVA + i * 4] ^= 1;
        assert(durak_patch_rate_prompt(image, size) == -2);
        image[DURAK_RATE_PROMPT_RVA + i * 4] ^= 1;
        assert(!memcmp(image + DURAK_RATE_PROMPT_RVA, DURAK_RATE_PROMPT_CONTEXT, 20));
    }
    assert(durak_patch_rate_prompt(image, size) == 0);
    assert(durak_verify_rate_prompt(image, size) == 0);
    assert(!memcmp(image + DURAK_RATE_PROMPT_RVA + 4, DURAK_RATE_PROMPT_CONTEXT + 1, 16));
    image[DURAK_RATE_PROMPT_RVA] ^= 1;
    assert(durak_verify_rate_prompt(image, size) == -2);
    free(image);
    printf("[PASS] Rate prompt patch, mismatch rejection and RX verification\n");
}

static void test_premium_offer_patch(void) {
    size_t size = DURAK_SINGLE_PREMIUM_RVA + sizeof(DURAK_SINGLE_PREMIUM_CONTEXT);
    uint8_t *image = calloc(1, size);
    assert(image);
    memcpy(image + DURAK_PREMIUM_OFFER_RVA, DURAK_PREMIUM_OFFER_CONTEXT, sizeof(DURAK_PREMIUM_OFFER_CONTEXT));
    memcpy(image + DURAK_SINGLE_PREMIUM_RVA, DURAK_SINGLE_PREMIUM_CONTEXT, sizeof(DURAK_SINGLE_PREMIUM_CONTEXT));
    assert(durak_patch_premium_offer(NULL, size) == -1);
    assert(durak_patch_premium_offer(image, size - 1) == -1);
    for (int i = 0; i < 12; ++i) {
        image[DURAK_PREMIUM_OFFER_RVA + i * 4] ^= 1;
        assert(durak_patch_premium_offer(image, size) == -2);
        image[DURAK_PREMIUM_OFFER_RVA + i * 4] ^= 1;
        assert(!memcmp(image + DURAK_PREMIUM_OFFER_RVA, DURAK_PREMIUM_OFFER_CONTEXT, sizeof(DURAK_PREMIUM_OFFER_CONTEXT)));
        assert(!memcmp(image + DURAK_SINGLE_PREMIUM_RVA, DURAK_SINGLE_PREMIUM_CONTEXT, sizeof(DURAK_SINGLE_PREMIUM_CONTEXT)));
        image[DURAK_SINGLE_PREMIUM_RVA + i * 4] ^= 1;
        assert(durak_patch_premium_offer(image, size) == -2);
        image[DURAK_SINGLE_PREMIUM_RVA + i * 4] ^= 1;
        assert(!memcmp(image + DURAK_PREMIUM_OFFER_RVA, DURAK_PREMIUM_OFFER_CONTEXT, sizeof(DURAK_PREMIUM_OFFER_CONTEXT)));
        assert(!memcmp(image + DURAK_SINGLE_PREMIUM_RVA, DURAK_SINGLE_PREMIUM_CONTEXT, sizeof(DURAK_SINGLE_PREMIUM_CONTEXT)));
    }
    assert(durak_patch_premium_offer(image, size) == 0);
    assert(durak_verify_premium_offer(image, size) == 0);
    for (int i = 0; i < 12; ++i) {
        image[DURAK_SINGLE_PREMIUM_RVA + i * 4] ^= 1;
        assert(durak_verify_premium_offer(image, size) == -2);
        image[DURAK_SINGLE_PREMIUM_RVA + i * 4] ^= 1;
    }
    free(image);
    puts("[PASS] Premium offer: bounds, fingerprint rejection without mutation, RX verification");
}

static void test_free_key_prompt_patch(void) {
    size_t size = DURAK_FREE_KEY_PROMPT_RVA + 20;
    unsigned char *image = calloc(1, size);
    assert(image);
    memcpy(image + DURAK_FREE_KEY_PROMPT_RVA, DURAK_FREE_KEY_PROMPT_CONTEXT, 20);
    assert(durak_patch_free_key_prompt(NULL, size) == -1);
    assert(durak_patch_free_key_prompt(image, size - 1) == -1);
    for (int i = 0; i < 5; ++i) {
        image[DURAK_FREE_KEY_PROMPT_RVA + i * 4] ^= 1;
        assert(durak_patch_free_key_prompt(image, size) == -2);
        image[DURAK_FREE_KEY_PROMPT_RVA + i * 4] ^= 1;
        assert(!memcmp(image + DURAK_FREE_KEY_PROMPT_RVA, DURAK_FREE_KEY_PROMPT_CONTEXT, 20));
    }
    assert(durak_patch_free_key_prompt(image, size) == 0);
    assert(durak_verify_free_key_prompt(image, size) == 0);
    assert(!memcmp(image + DURAK_FREE_KEY_PROMPT_RVA + 4, DURAK_FREE_KEY_PROMPT_CONTEXT + 1, 16));
    image[DURAK_FREE_KEY_PROMPT_RVA] ^= 1;
    assert(durak_verify_free_key_prompt(image, size) == -2);
    free(image);
    printf("[PASS] Free key prompt patch, mismatch rejection and RX verification\n");
}

static void test_durak_unity_region_patching(void) {
    printf("[TEST] 9. Testing Durak libunity 256MB->64MB region patch fail-closed verification...\n");
    so_module mod;
    memset(&mod, 0, sizeof(mod));
    size_t buf_size = 35 * 1024 * 1024;
    void *raw_buf = calloc(1, buf_size + 0x10000);
    assert(raw_buf != NULL);
    void *buf = (void *)ALIGN_MEM((uintptr_t)raw_buf, 0x10000);

    int rc = so_load(&mod, "extracted_durak/libunity.so", buf, buf_size);
    assert(rc == 0);

    // Negative test: Corrupt site 0 to simulate a mismatched binary
    uint32_t orig_val = *(uint32_t *)((uintptr_t)mod.load_base + DURAK_REGION_PATCH[0].off);
    assert(orig_val == DURAK_REGION_PATCH[0].from);
    *(uint32_t *)((uintptr_t)mod.load_base + DURAK_REGION_PATCH[0].off) = 0xDEADBEEF;

    int patch_rc = durak_patch_unity_regions(mod.load_base, mod.load_size);
    assert(patch_rc != 0); // Must fail closed!

    // Verify site 1 was NOT modified (fail-closed integrity)
    uint32_t site1_val = *(uint32_t *)((uintptr_t)mod.load_base + DURAK_REGION_PATCH[1].off);
    assert(site1_val == DURAK_REGION_PATCH[1].from);

    // Restore original value
    *(uint32_t *)((uintptr_t)mod.load_base + DURAK_REGION_PATCH[0].off) = orig_val;

    // Positive test: Verify and apply all 18 patches
    patch_rc = durak_patch_unity_regions(mod.load_base, mod.load_size);
    assert(patch_rc == 0);

    // Verify all 18 instructions now equal 'to'
    for (int i = 0; i < DURAK_REGION_PATCH_N; i++) {
        uint32_t cur = *(uint32_t *)((uintptr_t)mod.load_base + DURAK_REGION_PATCH[i].off);
        assert(cur == DURAK_REGION_PATCH[i].to);
    }

    // Post-check verification
    int v_rc = durak_verify_unity_regions_post_map(mod.load_base, mod.load_size);
    assert(v_rc == 0);

    so_unload(&mod);
    free(raw_buf);
    so_reset_list();
    printf("  [PASS] Durak libunity 256MB->64MB region patch fail-closed verification and application verified.\n\n");
}

static void test_durak_unity_choreographer_patching(void) {
    printf("[TEST] 10. Testing Durak libunity ChoreographerBase::Get -> NULL fallback patch fail-closed verification...\n");
    so_module mod = {0};
    size_t buf_size = 0x2000000;
    void *raw_buf = calloc(1, buf_size + 0x10000);
    assert(raw_buf != NULL);
    void *buf = (void *)ALIGN_MEM((uintptr_t)raw_buf, 0x10000);

    int rc = so_load(&mod, "extracted_durak/libunity.so", buf, buf_size);
    assert(rc == 0);

    // Negative test: Corrupt site 0 to simulate a mismatched binary
    uint32_t orig_val = *(uint32_t *)((uintptr_t)mod.load_base + DURAK_CHOREOGRAPHER_PATCH[0].off);
    assert(orig_val == DURAK_CHOREOGRAPHER_PATCH[0].from);
    *(uint32_t *)((uintptr_t)mod.load_base + DURAK_CHOREOGRAPHER_PATCH[0].off) = 0xDEADBEEF;

    int patch_rc = durak_patch_unity_choreographer(mod.load_base, mod.load_size);
    assert(patch_rc != 0); // Must fail closed!

    // Verify site 1 was NOT modified (fail-closed integrity)
    uint32_t site1_val = *(uint32_t *)((uintptr_t)mod.load_base + DURAK_CHOREOGRAPHER_PATCH[1].off);
    assert(site1_val == DURAK_CHOREOGRAPHER_PATCH[1].from);

    // Restore original value
    *(uint32_t *)((uintptr_t)mod.load_base + DURAK_CHOREOGRAPHER_PATCH[0].off) = orig_val;

    // Positive test: Verify and apply both patches
    patch_rc = durak_patch_unity_choreographer(mod.load_base, mod.load_size);
    assert(patch_rc == 0);

    // Verify both instructions now equal 'to'
    for (int i = 0; i < DURAK_CHOREOGRAPHER_PATCH_N; i++) {
        uint32_t cur = *(uint32_t *)((uintptr_t)mod.load_base + DURAK_CHOREOGRAPHER_PATCH[i].off);
        assert(cur == DURAK_CHOREOGRAPHER_PATCH[i].to);
    }

    // Post-check verification
    int v_rc = durak_verify_unity_choreographer_post_map(mod.load_base, mod.load_size);
    assert(v_rc == 0);

    so_unload(&mod);
    free(raw_buf);
    so_reset_list();
    printf("  [PASS] Durak libunity ChoreographerBase::Get fallback patch fail-closed verification and application verified.\n\n");
}


typedef struct {
    uint8_t *base;
    size_t pages;
    uint8_t *used;
    uint8_t *committed;
    uint8_t *pool;
    size_t pool_pages;
    size_t pool_bump;
    size_t live_pages;
    int (*mock_map_memory)(void *dst, void *src, size_t size);
} MockOcArena;

static int mock_oc_commit_locked(MockOcArena *arena, void *addr, size_t len) {
    if (!arena || !arena->pages || !arena->base) {
        errno = ENOMEM;
        return -1;
    }
    if ((uint8_t *)addr < arena->base) {
        errno = ENOMEM;
        return -1;
    }
    size_t page_sz = 0x1000;
    size_t first = ((uint8_t *)addr - arena->base) / page_sz;
    size_t cnt = (len + page_sz - 1) / page_sz;
    if (first >= arena->pages) {
        errno = ENOMEM;
        return -1;
    }
    if (first + cnt > arena->pages) cnt = arena->pages - first;

    size_t i = 0;
    while (i < cnt) {
        if (arena->committed[first + i]) { i++; continue; }
        size_t run = 0;
        while (i + run < cnt && !arena->committed[first + i + run]) run++;
        if (run == 0) break;

        if (arena->pool_bump + run > arena->pool_pages) {
            errno = ENOMEM;
            return -1;
        }

        void *dst = arena->base + (first + i) * page_sz;
        void *src = arena->pool + arena->pool_bump * page_sz;
        size_t size_bytes = run * page_sz;

        int rc = arena->mock_map_memory(dst, src, size_bytes);
        if (rc != 0) {
            errno = (rc == 0xd401) ? EFAULT : ENOMEM;
            // Failed pages MUST NOT be marked committed!
            return -1;
        }

        for (size_t k = 0; k < run; k++) arena->committed[first + i + k] = 1;
        arena->pool_bump += run;
        arena->live_pages += run;
        i += run;
    }
    return 0;
}

static int mock_mprotect_fake(MockOcArena *arena, void *addr, size_t len, int prot) {
    if (addr >= (void *)arena->base && addr < (void *)(arena->base + arena->pages * 0x1000)) {
        if (prot != 0) {
            int rc = mock_oc_commit_locked(arena, addr, len);
            if (rc != 0) return -1;
        }
        return 0;
    }
    return 0;
}

static int g_mock_map_rc = 0;
static int mock_map_memory_hook(void *dst, void *src, size_t size) {
    (void)dst; (void)src; (void)size;
    return g_mock_map_rc;
}

static void test_oc_commit_failure_contract(void) {
    printf("[TEST] 10. Testing Overcommit commit failure contract (failed mapping -> failed mprotect, uncommitted pages)...\n");

    const size_t total_pages = 8192; // 32 MB
    uint8_t *arena_mem = calloc(total_pages, 0x1000);
    uint8_t *used = calloc(total_pages, 1);
    uint8_t *committed = calloc(total_pages, 1);
    uint8_t *pool_mem = calloc(total_pages, 0x1000);

    assert(arena_mem && used && committed && pool_mem);

    MockOcArena arena = {
        .base = arena_mem,
        .pages = total_pages,
        .used = used,
        .committed = committed,
        .pool = pool_mem,
        .pool_pages = total_pages,
        .pool_bump = 0,
        .live_pages = 0,
        .mock_map_memory = mock_map_memory_hook
    };

    void *target_addr = arena_mem;
    size_t commit_len = 4096 * 0x1000; // 16 MB = 4096 pages

    // 1. Negative Test: Simulated svcMapMemory failure (0xd401)
    g_mock_map_rc = 0xd401;
    errno = 0;
    int rc = mock_mprotect_fake(&arena, target_addr, commit_len, 3);
    assert(rc == -1);
    assert(errno == EFAULT);

    // Verify contract: ALL 4096 pages MUST remain uncommitted
    for (size_t k = 0; k < 4096; k++) {
        assert(arena.committed[k] == 0);
    }
    // Verify pool bump did NOT advance
    assert(arena.pool_bump == 0);
    assert(arena.live_pages == 0);

    // 2. Negative Test: Pool exhaustion
    arena.pool_bump = 7000; // Only 1192 pages left
    g_mock_map_rc = 0;
    errno = 0;
    rc = mock_mprotect_fake(&arena, target_addr, commit_len, 3);
    assert(rc == -1);
    assert(errno == ENOMEM);
    for (size_t k = 0; k < 4096; k++) {
        assert(arena.committed[k] == 0);
    }
    assert(arena.pool_bump == 7000);

    // 3. Positive Test: Successful mapping
    arena.pool_bump = 0;
    g_mock_map_rc = 0;
    errno = 0;
    rc = mock_mprotect_fake(&arena, target_addr, commit_len, 3);
    assert(rc == 0);
    for (size_t k = 0; k < 4096; k++) {
        assert(arena.committed[k] == 1);
    }
    assert(arena.pool_bump == 4096);
    assert(arena.live_pages == 4096);

    // 4. Repeat Commit: Verify idempotent skip without redundant mapping
    g_mock_map_rc = 0xd401; // Even if mapping would fail, committed pages are skipped!
    rc = mock_mprotect_fake(&arena, target_addr, commit_len, 3);
    assert(rc == 0);
    assert(arena.pool_bump == 4096); // Bump did not change

    free(arena_mem);
    free(used);
    free(committed);
    free(pool_mem);

    printf("  [PASS] Overcommit commit failure contract verified (negative, pool exhaustion, positive, repeat commit).\n\n");
}

static volatile int g_test_vsync_calls = 0;
static volatile uint64_t g_test_last_ts = 0;
static volatile uint64_t g_test_prev_ts = 0;
static volatile uint64_t g_test_counter = 0;
static volatile uint64_t g_test_ts_cur = 0;
static volatile uint64_t g_test_ts_prev = 0;

static void test_mock_on_vsync(uint64_t ts) {
    g_test_prev_ts = g_test_last_ts;
    g_test_last_ts = ts;
    g_test_ts_prev = g_test_prev_ts;
    g_test_ts_cur = ts;
    g_test_counter++;
    g_test_vsync_calls++;
}

static void test_durak_frame_pacer(void) {
    printf("[TEST] Testing Durak 60 Hz VSync frame pacer contract...\n");

    // 1. Initial State
    g_test_vsync_calls = 0;
    g_test_last_ts = 0;
    g_test_counter = 0;

    durak_frame_pacer_set_handler_for_test(
        test_mock_on_vsync,
        &g_test_counter,
        &g_test_ts_cur,
        &g_test_ts_prev
    );

    // 2. Pulse test
    durak_frame_pacer_pulse();
    assert(g_test_vsync_calls == 1);
    assert(g_test_counter == 1);
    assert(durak_frame_pacer_get_counter() == 1);
    assert(g_test_last_ts > 0);

    // 3. Start background pacer thread and observe monotonic ticks
    int start_rc = durak_frame_pacer_start();
    assert(start_rc == 0);

    // Sleep for ~60ms (expect ~3 ticks at 60 Hz / 16.6ms cadence)
    struct timespec sleep_ts = { 0, 60000000L };
    nanosleep(&sleep_ts, NULL);

    int calls_during_run = g_test_vsync_calls;
    assert(calls_during_run >= 2); // At least 2 ticks must have fired
    assert(g_test_counter == (uint64_t)calls_during_run);
    assert(g_test_ts_cur >= g_test_ts_prev);

    // 4. Stop pacer thread cleanly
    durak_frame_pacer_stop();

    int calls_after_stop = g_test_vsync_calls;
    // Sleep another 35ms to ensure no ticks fire after stop
    nanosleep(&sleep_ts, NULL);
    assert(g_test_vsync_calls == calls_after_stop);

    printf("  [PASS] Frame pacer contract verified: ticks=%d, counter=%llu, monotonic timestamps confirmed.\n\n",
           calls_after_stop, (unsigned long long)g_test_counter);
}

int screen_width = 1280, screen_height = 720;

static void test_durak_unity_input_hooks(void) {
    printf("[TEST] Testing Durak Unity Input hooks & touchscreen contract...\n");

    // 1. Verify opcodes of extracted_durak/libil2cpp.so on disk
    FILE *f_so = fopen("extracted_durak/libil2cpp.so", "rb");
    assert(f_so != NULL);

    Elf64_Ehdr ehdr;
    assert(fread(&ehdr, sizeof(ehdr), 1, f_so) == 1);
    assert(memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0);

    fseek(f_so, (long)ehdr.e_phoff, SEEK_SET);
    Elf64_Phdr phdr;
    uint64_t text_vaddr = 0, text_offset = 0;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        assert(fread(&phdr, sizeof(phdr), 1, f_so) == 1);
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            text_vaddr = phdr.p_vaddr;
            text_offset = phdr.p_offset;
            break;
        }
    }
    assert(text_vaddr != 0);
    uint64_t vaddr_to_file = text_vaddr - text_offset; // Expected 0x4000

    struct {
        const char *name;
        uint64_t rva;
        uint32_t insn0;
        uint32_t insn1;
    } expected_sites[] = {
        { "get_touchCount",     DURAK_RVA_get_touchCount,     0xa9bf4ffe, 0xd0002cf3 },
        { "GetTouch",           DURAK_RVA_GetTouch,           0xd101c3ff, 0xa90557fe },
        { "get_mousePosition",  DURAK_RVA_get_mousePosition,  0xd10083ff, 0xa9014ffe },
        { "GetMouseButton",     DURAK_RVA_GetMouseButton,     0xf81e0ffe, 0xa9014ff4 },
        { "GetMouseButtonDown", DURAK_RVA_GetMouseButtonDown, 0xf81e0ffe, 0xa9014ff4 },
        { "GetMouseButtonUp",   DURAK_RVA_GetMouseButtonUp,   0xf81e0ffe, 0xa9014ff4 },
        { "get_touchSupported", DURAK_RVA_get_touchSupported, 0xa9bf4ffe, 0xd0002cf3 },
        { "get_mousePresent",   DURAK_RVA_get_mousePresent,   0xa9bf4ffe, 0xf0002cf3 },
    };
    int num_sites = (int)(sizeof(expected_sites) / sizeof(expected_sites[0]));

    for (int i = 0; i < num_sites; i++) {
        uint64_t foff = expected_sites[i].rva - vaddr_to_file;
        fseek(f_so, (long)foff, SEEK_SET);
        uint32_t actual[2] = {0};
        assert(fread(actual, sizeof(uint32_t), 2, f_so) == 2);
        assert(actual[0] == expected_sites[i].insn0);
        assert(actual[1] == expected_sites[i].insn1);
    }
    fclose(f_so);
    printf("  [PASS] All %d Input hook sites verified against libil2cpp.so binary on disk.\n", num_sites);

    // 2. Mock installation test (fail-closed verification)
    const size_t mock_span = 0x10000;
    uint8_t *mock_mem = (uint8_t *)calloc(1, mock_span);
    assert(mock_mem != NULL);
    uintptr_t mock_il2cpp_base = (uintptr_t)mock_mem - 0x1840000;

    // 2a. Negative test: NULL base
    assert(nx_install_input_hooks(0) == -1);

    // 2b. Negative test: Mismatched opcodes (zeroes) -> must fail closed (-2)
    assert(nx_install_input_hooks(mock_il2cpp_base) == -2);

    // 2c. Positive test: Populate mock memory with expected opcodes
    for (int i = 0; i < num_sites; i++) {
        uint32_t *target = (uint32_t *)(mock_il2cpp_base + expected_sites[i].rva);
        target[0] = expected_sites[i].insn0;
        target[1] = expected_sites[i].insn1;
    }

    int install_rc = nx_install_input_hooks(mock_il2cpp_base);
    assert(install_rc == 0);

    // Verify all 8 sites have trampoline instructions:
    // ldr x16, #8 (0x58000050), br x16 (0xd61f0200)
    for (int i = 0; i < num_sites; i++) {
        uint32_t *target = (uint32_t *)(mock_il2cpp_base + expected_sites[i].rva);
        assert(target[0] == 0x58000050u);
        assert(target[1] == 0xd61f0200u);
        void *fn = NULL;
        memcpy(&fn, &target[2], sizeof(fn));
        assert(fn != NULL);
    }
    free(mock_mem);
    printf("  [PASS] nx_install_input_hooks fail-closed verification & trampoline patching confirmed.\n");

    // 3. State machine transitions test
    assert(nx_input_hook_get_count() == 0);
    assert(nx_input_hook_get_btn() == 0);
    assert(nx_input_hook_get_btn_down() == 0);
    assert(nx_input_hook_get_btn_up() == 0);

    // 3a. Touch Began
    nx_input_hook_update(1, 100.0f, 620.0f, 100.0f, 100.0f);
    assert(nx_input_hook_get_count() == 1);
    assert(nx_input_hook_get_btn() == 1);
    assert(nx_input_hook_get_btn_down() == 1);
    assert(nx_input_hook_get_btn_up() == 0);
    assert(nx_input_hook_get_phase() == 0); // Began
    float cur_x = 0, cur_y = 0;
    nx_input_hook_get_pos(&cur_x, &cur_y);
    assert(cur_x == 100.0f && cur_y == 620.0f);

    // 3b. Touch Moved
    nx_input_hook_update(1, 110.0f, 615.0f, 110.0f, 105.0f);
    assert(nx_input_hook_get_count() == 1);
    assert(nx_input_hook_get_btn() == 1);
    assert(nx_input_hook_get_btn_down() == 0); // Edge cleared
    assert(nx_input_hook_get_btn_up() == 0);
    assert(nx_input_hook_get_phase() == 1); // Moved
    nx_input_hook_get_pos(&cur_x, &cur_y);
    assert(cur_x == 110.0f && cur_y == 615.0f);

    // 3c. Touch Stationary
    nx_input_hook_update(1, 110.0f, 615.0f, 110.0f, 105.0f);
    assert(nx_input_hook_get_count() == 1);
    assert(nx_input_hook_get_btn() == 1);
    assert(nx_input_hook_get_btn_down() == 0);
    assert(nx_input_hook_get_btn_up() == 0);
    assert(nx_input_hook_get_phase() == 2); // Stationary

    // 3d. Touch Ended: Must maintain count=1 and btn_up=1 for 1 release frame!
    nx_input_hook_update(0, 0.0f, 0.0f, 0.0f, 0.0f);
    assert(nx_input_hook_get_count() == 1); // Maintained for release frame
    assert(nx_input_hook_get_btn() == 0);
    assert(nx_input_hook_get_btn_down() == 0);
    assert(nx_input_hook_get_btn_up() == 1); // Release edge trigger
    assert(nx_input_hook_get_phase() == 3); // Ended
    nx_input_hook_get_pos(&cur_x, &cur_y);
    assert(cur_x == 110.0f && cur_y == 615.0f); // Preserved release coordinates

    // 3e. Next Idle frame: count drops to 0, btn_up cleared
    nx_input_hook_update(0, 0.0f, 0.0f, 0.0f, 0.0f);
    assert(nx_input_hook_get_count() == 0);
    assert(nx_input_hook_get_btn() == 0);
    assert(nx_input_hook_get_btn_down() == 0);
    assert(nx_input_hook_get_btn_up() == 0);

    printf("  [PASS] Touchscreen input state-machine & release contract confirmed.\n\n");
}

static void test_audio_output_patch(void) {
    size_t size = 0x108d874 + 20;
    unsigned char *base = calloc(1, size);
    assert(base);
    for (int i = 0; i < 2; ++i)
        memcpy(base + DURAK_AUDIO_OUTPUT_PATCH[i].off, DURAK_AUDIO_OUTPUT_PATCH[i].context, 20);
    assert(durak_patch_audio_output(NULL, size) == -1);
    assert(durak_patch_audio_output(base, size - 1) == -1);
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < 5; ++j) {
            uint32_t *word = (uint32_t *)(base + DURAK_AUDIO_OUTPUT_PATCH[i].off + j * 4);
            *word ^= 1;
            assert(durak_patch_audio_output(base, size) == -2);
            *word ^= 1;
            for (int k = 0; k < 2; ++k)
                assert(memcmp(base + DURAK_AUDIO_OUTPUT_PATCH[k].off, DURAK_AUDIO_OUTPUT_PATCH[k].context, 20) == 0);
        }
    }
    assert(durak_patch_audio_output(base, size) == 0);
    assert(durak_verify_audio_output(base, size) == 0);
    for (int i = 0; i < 2; ++i) {
        assert(memcmp(base + DURAK_AUDIO_OUTPUT_PATCH[i].off + 4,
                      DURAK_AUDIO_OUTPUT_PATCH[i].context + 1, 16) == 0);
    }
    base[0x108d874 + 4] ^= 1;
    assert(durak_verify_audio_output(base, size) == -2);
    free(base);
    puts("  [PASS] Audio output patch: atomic fingerprints, bounds and RX verification");
}

int main(void) {
    printf("================================================================================\n");
    printf("       NATIVE C TEST SUITE: LOADER, RELOCATIONS, LINKER & AUDIT GATES\n");
    printf("================================================================================\n\n");

    test_successful_load_and_pointer_verification();
    test_fail_stop_thunk_binding();
    test_negative_unresolved_strong_data_symbol();
    test_pre_entry_audit_gates();
    test_sqlite3_64k_actual_address_alignment();
    test_virtmem_alignment_and_failure_handling();
    test_diagnostic_logger_verification();
    test_constructor_discovery_and_execution_iteration();
    test_durak_unity_region_patching();
    test_single_game_unlock();
    test_rate_prompt_patch();
    test_free_key_prompt_patch();
    test_premium_offer_patch();
    test_audio_output_patch();
    test_durak_unity_choreographer_patching();
    test_oc_commit_failure_contract();
    test_durak_frame_pacer();
    test_durak_unity_input_hooks();

    printf("================================================================================\n");
    printf("  ALL NATIVE C LOADER & LINKER TESTS PASSED SUCCESSFULLY!\n");
    printf("================================================================================\n");
    return 0;
}
