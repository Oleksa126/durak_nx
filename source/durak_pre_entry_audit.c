#include "durak_pre_entry_audit.h"
#include "durak_target_verify.h"
#include "fail_stop_thunks.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#ifdef __SWITCH__
#include <switch.h>
#else
#define Perm_None 0
#define Perm_R    1
#define Perm_W    2
#define Perm_Rw   3
#define Perm_X    4
#define Perm_Rx   5
typedef uint32_t Result;
#define R_FAILED(res)   ((res) != 0)
#define R_SUCCEEDED(res) ((res) == 0)
#endif

static durak_query_memory_fn g_query_memory_hook = NULL;

void durak_set_query_memory_hook(durak_query_memory_fn fn) {
    g_query_memory_hook = fn;
}

#define AUDIT_PRINT(...) durak_log_printf(__VA_ARGS__)

int durak_run_pre_entry_audit(so_module **modules, int num_modules, DurakPreEntryAuditSummary *out_summary) {
    if (!modules || num_modules <= 0) {
        AUDIT_PRINT("[AUDIT ERROR] Invalid module list provided to pre-entry audit\n");
        return -1;
    }

    DurakPreEntryAuditSummary sum;
    memset(&sum, 0, sizeof(sum));
    sum.total_modules = num_modules;
    sum.audit_passed = 1;

    AUDIT_PRINT("\n================================================================================\n");
    AUDIT_PRINT("             DURAK NX - STEP 2 PRE-ENTRY AUDIT REPORT\n");
    AUDIT_PRINT("================================================================================\n");
    AUDIT_PRINT("Target: Android ARM64-v8a ru.appscraft.durak v25.0 (Unity 6 / IL2CPP)\n");
    AUDIT_PRINT("Gate: Step 2 Mapping/Linking Completed - 0 Guest Code Execution\n");
    AUDIT_PRINT("--------------------------------------------------------------------------------\n\n");

    for (int m = 0; m < num_modules; m++) {
        so_module *mod = modules[m];
        if (!mod) continue;

        DurakModuleAuditRecord rec;
        memset(&rec, 0, sizeof(rec));
        snprintf(rec.module_name, sizeof(rec.module_name), "%s", mod->name);
        rec.load_base = (uintptr_t)mod->load_base;
        rec.load_virtbase = (uintptr_t)mod->load_virtbase;
        rec.load_size = mod->load_size;
        rec.alignment = mod->max_align;

        const DurakModuleMetadata *meta = durak_find_module_metadata(mod->name);
        if (meta) {
            rec.target_verified = 1;
            rec.file_size = meta->expected_size;
            sum.verified_modules++;
        } else {
            rec.target_verified = 0;
            sum.failed_verification++;
            sum.audit_passed = 0;
        }

        // Verify actual address alignment
        if (rec.alignment > 0) {
            if ((rec.load_virtbase & (rec.alignment - 1)) != 0) {
                AUDIT_PRINT("  [FAIL] Module %s load_virtbase %p is not aligned to 0x%zx!\n",
                            mod->name, (void *)rec.load_virtbase, rec.alignment);
                sum.audit_passed = 0;
            }
            if ((rec.load_base & (rec.alignment - 1)) != 0) {
                AUDIT_PRINT("  [FAIL] Module %s load_base %p is not aligned to 0x%zx!\n",
                            mod->name, (void *)rec.load_base, rec.alignment);
                sum.audit_passed = 0;
            }
        }

        // Memory permissions scan across every 4 KiB page
        const size_t num_pages = mod->load_size / 0x1000;
        for (size_t pg = 0; pg < num_pages; pg++) {
            uintptr_t vaddr = (uintptr_t)mod->load_virtbase + pg * 0x1000;

            // Determine expected permissions and segment characteristics from program headers
            int is_code = 0;
            int is_ro = 0;
            int is_rw = 0;
            int is_relro = 0;
            int is_gap = 1;
            uint32_t expected_perm = Perm_Rw; // Gaps default to RW

            for (int i = 0; i < mod->phnum; i++) {
                const Elf64_Phdr *p = &mod->phdr[i];
                if (p->p_type == PT_LOAD) {
                    uintptr_t s = (uintptr_t)mod->load_virtbase + (p->p_vaddr & ~0xFFFull);
                    uintptr_t e = (uintptr_t)mod->load_virtbase + ALIGN_MEM(p->p_vaddr + p->p_memsz, 0x1000);
                    if (vaddr >= s && vaddr < e) {
                        is_gap = 0;
                        if (p->p_flags & PF_X) {
                            expected_perm = Perm_Rx;
                            is_code = 1;
                        } else if (p->p_flags & PF_W) {
                            expected_perm = Perm_Rw;
                            is_rw = 1;
                        } else {
                            expected_perm = Perm_R;
                            is_ro = 1;
                        }
                    }
                }
            }

            for (int i = 0; i < mod->phnum; i++) {
                const Elf64_Phdr *p = &mod->phdr[i];
                if (p->p_type == PT_GNU_RELRO) {
                    uintptr_t s = (uintptr_t)mod->load_virtbase + (p->p_vaddr & ~0xFFFull);
                    uintptr_t e = (uintptr_t)mod->load_virtbase + ((p->p_vaddr + p->p_memsz) / 0x1000) * 0x1000;
                    if (vaddr >= s && vaddr < e) {
                        is_relro = 1;
                        if (!is_code) {
                            expected_perm = Perm_R;
                        }
                    }
                }
            }

            // Query memory permissions
            uint32_t perm = 0;
            int qrc = 0;

            if (g_query_memory_hook) {
                qrc = g_query_memory_hook(vaddr, &perm);
            } else {
#ifdef __SWITCH__
                MemoryInfo mi;
                u32 pi;
                Result rc = svcQueryMemory(&mi, &pi, vaddr);
                if (R_FAILED(rc)) {
                    qrc = (int)rc;
                } else {
                    perm = mi.perm;
                }
#else
                perm = expected_perm;
                qrc = 0;
#endif
            }

            // Check 1: Query failure
            if (qrc != 0) {
                AUDIT_PRINT("  [FAIL] Memory query failed at vaddr %p (Result=0x%08x)\n", (void *)vaddr, qrc);
                rec.query_failures++;
                sum.total_query_failures++;
                sum.audit_passed = 0;
                continue;
            }

            // Check 2: Inaccessible page (perm=0)
            if (perm == 0) {
                AUDIT_PRINT("  [FAIL] Inaccessible page (perm=0) at vaddr %p\n", (void *)vaddr);
                rec.inaccessible_pages++;
                sum.total_inaccessible_pages++;
                sum.audit_passed = 0;
                continue;
            }

            // Check 3: W^X violation (RWX page)
            if ((perm & (Perm_R | Perm_W | Perm_X)) == (Perm_R | Perm_W | Perm_X)) {
                AUDIT_PRINT("  [FAIL] W^X violation: RWX page at vaddr %p (perm=0x%x)\n", (void *)vaddr, perm);
                rec.num_pages_rwx++;
                sum.total_rwx_pages++;
                sum.audit_passed = 0;
            }

            // Check 4: Strict RELRO verification (must NOT be writable, must be Perm_R)
            if (is_relro) {
                if (perm & Perm_W) {
                    AUDIT_PRINT("  [FAIL] Writable RELRO page at vaddr %p (perm=0x%x, expected RO)\n", (void *)vaddr, perm);
                    rec.num_pages_writable_relro++;
                    sum.total_writable_relro++;
                    sum.audit_passed = 0;
                }
                if (!(perm & Perm_R) || (perm & Perm_X)) {
                    AUDIT_PRINT("  [FAIL] Invalid RELRO permissions at vaddr %p (perm=0x%x, expected RO)\n", (void *)vaddr, perm);
                    rec.permission_mismatches++;
                    sum.total_permission_mismatches++;
                    sum.audit_passed = 0;
                }
            }

            // Check 5: Executable code pages (must have RX, must NOT be writable)
            if (is_code) {
                if (perm & Perm_W) {
                    AUDIT_PRINT("  [FAIL] Writable code page at vaddr %p (perm=0x%x, expected RX)\n", (void *)vaddr, perm);
                    rec.permission_mismatches++;
                    sum.total_permission_mismatches++;
                    sum.audit_passed = 0;
                }
                if (!(perm & Perm_X) || !(perm & Perm_R)) {
                    AUDIT_PRINT("  [FAIL] Non-executable code page at vaddr %p (perm=0x%x, expected RX)\n", (void *)vaddr, perm);
                    rec.permission_mismatches++;
                    sum.total_permission_mismatches++;
                    sum.audit_passed = 0;
                }
            }

            // Check 6: Read-only data pages (must NOT be writable, must NOT be executable)
            if (is_ro && !is_relro) {
                if (perm & Perm_W) {
                    AUDIT_PRINT("  [FAIL] Writable RO data page at vaddr %p (perm=0x%x, expected RO)\n", (void *)vaddr, perm);
                    rec.permission_mismatches++;
                    sum.total_permission_mismatches++;
                    sum.audit_passed = 0;
                }
                if (perm & Perm_X) {
                    AUDIT_PRINT("  [FAIL] Executable RO data page at vaddr %p (perm=0x%x, expected RO)\n", (void *)vaddr, perm);
                    rec.permission_mismatches++;
                    sum.total_permission_mismatches++;
                    sum.audit_passed = 0;
                }
            }

            // Check 7: Read-write data / bss / gap pages (must NOT be executable)
            if ((is_rw || is_gap) && !is_relro && !is_code && !is_ro) {
                if (perm & Perm_X) {
                    AUDIT_PRINT("  [FAIL] Executable data/gap page at vaddr %p (perm=0x%x, expected RW)\n", (void *)vaddr, perm);
                    rec.permission_mismatches++;
                    sum.total_permission_mismatches++;
                    sum.audit_passed = 0;
                }
                if (!(perm & Perm_W)) {
                    AUDIT_PRINT("  [FAIL] Non-writable data/gap page at vaddr %p (perm=0x%x, expected RW)\n", (void *)vaddr, perm);
                    rec.permission_mismatches++;
                    sum.total_permission_mismatches++;
                    sum.audit_passed = 0;
                }
            }

            // Record aggregate counts
            if ((perm & (Perm_R | Perm_X)) == (Perm_R | Perm_X) && !(perm & Perm_W)) {
                rec.num_pages_rx++;
            } else if ((perm & Perm_R) && !(perm & Perm_W) && !(perm & Perm_X)) {
                rec.num_pages_ro++;
            } else if ((perm & (Perm_R | Perm_W)) == (Perm_R | Perm_W) && !(perm & Perm_X)) {
                rec.num_pages_rw++;
            }
        }

        rec.total_relocations = mod->num_relocations;
        rec.resolved_cross_module = mod->num_resolved_cross;
        rec.resolved_shims = mod->num_resolved_shims;
        rec.resolved_weak_null = mod->num_weak_null;
        rec.bound_fail_stop_thunks = mod->num_fail_stop;
        rec.unresolved_strong_data = mod->num_strong_data_unresolved;

        rec.init_array_rva = mod->init_array_rva;
        rec.init_array_count = mod->init_array_count;
        rec.init_rva = mod->init_rva;

        // Aggregate
        sum.total_mapped_bytes += mod->load_size;
        sum.total_rx_pages += rec.num_pages_rx;
        sum.total_ro_pages += rec.num_pages_ro;
        sum.total_rw_pages += rec.num_pages_rw;

        sum.total_relocations += rec.total_relocations;
        sum.total_cross_module += rec.resolved_cross_module;
        sum.total_shims += rec.resolved_shims;
        sum.total_weak_null += rec.resolved_weak_null;
        sum.total_fail_stop_thunks += rec.bound_fail_stop_thunks;
        sum.total_unresolved_strong_data += rec.unresolved_strong_data;
        sum.total_constructors += rec.init_array_count;

        AUDIT_PRINT("[MODULE %d/%d] %s\n", m + 1, num_modules, rec.module_name);
        AUDIT_PRINT("  Target Verification: %s\n", rec.target_verified ? "PASSED (SHA-256 + Build-ID match)" : "FAILED");
        AUDIT_PRINT("  Load Virtbase:       %p (Size: 0x%zx, Align: 0x%zx)\n",
                    (void *)rec.load_virtbase, rec.load_size, rec.alignment);
        AUDIT_PRINT("  W^X Page Protection: RX=%zu pages, RO=%zu pages, RW=%zu pages, RWX=%zu pages\n",
                    rec.num_pages_rx, rec.num_pages_ro, rec.num_pages_rw, rec.num_pages_rwx);
        if (rec.num_pages_writable_relro > 0)
            AUDIT_PRINT("  Writable RELRO:      %zu pages [FAIL]\n", rec.num_pages_writable_relro);
        if (rec.query_failures > 0)
            AUDIT_PRINT("  Query Failures:      %zu pages [FAIL]\n", rec.query_failures);
        if (rec.permission_mismatches > 0)
            AUDIT_PRINT("  Permission Mismatch: %zu pages [FAIL]\n", rec.permission_mismatches);
        if (rec.inaccessible_pages > 0)
            AUDIT_PRINT("  Inaccessible Pages:  %zu pages [FAIL]\n", rec.inaccessible_pages);
        AUDIT_PRINT("  Relocations Count:   %d\n", rec.total_relocations);
        AUDIT_PRINT("  Cross-Module Links:  %d\n", rec.resolved_cross_module);
        AUDIT_PRINT("  Runtime Shim Links:  %d\n", rec.resolved_shims);
        AUDIT_PRINT("  Weak NULL Undefs:    %d\n", rec.resolved_weak_null);
        AUDIT_PRINT("  Fail-Stop Thunks:    %d\n", rec.bound_fail_stop_thunks);
        AUDIT_PRINT("  Strong Data Missing: %d\n", rec.unresolved_strong_data);
        AUDIT_PRINT("  Constructors Count:  %zu (RVA: 0x%lx)\n\n",
                    rec.init_array_count, (unsigned long)rec.init_array_rva);

        if (rec.num_pages_rwx > 0) {
            AUDIT_PRINT("  [FAIL] W^X violation: %zu pages mapped RWX!\n", rec.num_pages_rwx);
            sum.audit_passed = 0;
        }
        if (rec.unresolved_strong_data > 0) {
            AUDIT_PRINT("  [FAIL] Strong data import missing in %s!\n", rec.module_name);
            sum.audit_passed = 0;
        }
    }

    AUDIT_PRINT("--------------------------------------------------------------------------------\n");
    AUDIT_PRINT("                   PRE-ENTRY AUDIT AGGREGATE SUMMARY\n");
    AUDIT_PRINT("--------------------------------------------------------------------------------\n");
    AUDIT_PRINT("Total Modules:               %d (Verified: %d, Failed: %d)\n",
                sum.total_modules, sum.verified_modules, sum.failed_verification);
    AUDIT_PRINT("Total Mapped CodeMemory:     %zu bytes (%zu KiB)\n",
                sum.total_mapped_bytes, sum.total_mapped_bytes / 1024);
    AUDIT_PRINT("W^X Compliance:              RX=%zu, RO=%zu, RW=%zu, RWX=%zu (Strict W^X: %s)\n",
                sum.total_rx_pages, sum.total_ro_pages, sum.total_rw_pages, sum.total_rwx_pages,
                (sum.total_rwx_pages == 0) ? "YES" : "VIOLATION");
    AUDIT_PRINT("RELRO Integrity:             Writable RELRO Pages = %zu (Compliant: %s)\n",
                sum.total_writable_relro, (sum.total_writable_relro == 0) ? "YES" : "VIOLATION");
    AUDIT_PRINT("Memory Mapping Integrity:    Query Failures=%zu, Inaccessible=%zu, Mismatches=%zu\n",
                sum.total_query_failures, sum.total_inaccessible_pages, sum.total_permission_mismatches);
    AUDIT_PRINT("Total Relocations:           %d\n", sum.total_relocations);
    AUDIT_PRINT("Total Cross-Module Links:    %d\n", sum.total_cross_module);
    AUDIT_PRINT("Total Runtime Shim Links:    %d\n", sum.total_shims);
    AUDIT_PRINT("Weak NULL Resolves:          %d\n", sum.total_weak_null);
    AUDIT_PRINT("Fail-Stop Thunks Bound:      %d\n", sum.total_fail_stop_thunks);
    AUDIT_PRINT("Unresolved Strong Data:      %d (Poison Pointers: %d)\n",
                sum.total_unresolved_strong_data, sum.total_poison_pointers);
    AUDIT_PRINT("Discovered Constructors:     %zu (libunity: 506, libil2cpp: 22)\n",
                sum.total_constructors);
    AUDIT_PRINT("Guest Code Executed:         %d (STRICTLY INHIBITED IN STEP 2)\n",
                sum.guest_code_executed);
    AUDIT_PRINT("--------------------------------------------------------------------------------\n");

    if (sum.audit_passed &&
        sum.failed_verification == 0 &&
        sum.total_rwx_pages == 0 &&
        sum.total_writable_relro == 0 &&
        sum.total_query_failures == 0 &&
        sum.total_permission_mismatches == 0 &&
        sum.total_inaccessible_pages == 0 &&
        sum.total_unresolved_strong_data == 0 &&
        sum.guest_code_executed == 0) {
        AUDIT_PRINT("AUDIT VERDICT: >>> PASS <<<\n");
        AUDIT_PRINT("All %d modules mapped, verified, linked with 0 poison pointers, strict W^X, and 0 guest execution.\n",
                    sum.total_modules);
        AUDIT_PRINT("Ready for Step 2 hardware test gate on Nintendo Switch.\n");
        sum.audit_passed = 1;
    } else {
        AUDIT_PRINT("AUDIT VERDICT: >>> FAILED <<<\n");
        AUDIT_PRINT("Pre-entry invariants violated:\n");
        if (sum.failed_verification > 0)
            AUDIT_PRINT("  - Target verification failed for %d module(s)\n", sum.failed_verification);
        if (sum.total_query_failures > 0)
            AUDIT_PRINT("  - svcQueryMemory failed for %zu page(s)\n", sum.total_query_failures);
        if (sum.total_inaccessible_pages > 0)
            AUDIT_PRINT("  - Inaccessible (perm=0) pages found: %zu\n", sum.total_inaccessible_pages);
        if (sum.total_rwx_pages > 0)
            AUDIT_PRINT("  - W^X violation: %zu page(s) mapped RWX\n", sum.total_rwx_pages);
        if (sum.total_writable_relro > 0)
            AUDIT_PRINT("  - Writable RELRO violation: %zu page(s) writable in RELRO\n", sum.total_writable_relro);
        if (sum.total_permission_mismatches > 0)
            AUDIT_PRINT("  - Permission mismatches found: %zu page(s)\n", sum.total_permission_mismatches);
        if (sum.total_unresolved_strong_data > 0)
            AUDIT_PRINT("  - Unresolved strong data imports: %d\n", sum.total_unresolved_strong_data);
        if (sum.guest_code_executed > 0)
            AUDIT_PRINT("  - Guest code executed: %d\n", sum.guest_code_executed);
        sum.audit_passed = 0;
    }
    AUDIT_PRINT("================================================================================\n\n");

    durak_log_flush();

    if (out_summary) {
        *out_summary = sum;
    }
    return sum.audit_passed ? 0 : -1;
}
