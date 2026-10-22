#ifndef DURAK_PRE_ENTRY_AUDIT_H
#define DURAK_PRE_ENTRY_AUDIT_H

#include "so_util.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char module_name[64];
    size_t file_size;
    uintptr_t load_base;
    uintptr_t load_virtbase;
    size_t load_size;
    size_t alignment;
    int target_verified;
    
    // Memory permissions (W^X and exact segment verification)
    size_t num_pages_rx;
    size_t num_pages_ro;
    size_t num_pages_rw;
    size_t num_pages_rwx;             // Must be 0
    size_t num_pages_writable_relro;  // Must be 0
    size_t query_failures;            // Must be 0
    size_t permission_mismatches;     // Must be 0
    size_t inaccessible_pages;        // Must be 0
    
    // Relocations & Linking
    int total_relocations;
    int resolved_cross_module;
    int resolved_shims;
    int resolved_weak_null;
    int bound_fail_stop_thunks;
    int unresolved_strong_data;       // Must be 0
    
    // Constructors
    uintptr_t init_array_rva;
    size_t init_array_count;
    uintptr_t init_rva;
} DurakModuleAuditRecord;

typedef struct {
    int total_modules;
    int verified_modules;
    int failed_verification;
    
    // Aggregate W^X and memory mapping metrics
    size_t total_mapped_bytes;
    size_t total_rx_pages;
    size_t total_ro_pages;
    size_t total_rw_pages;
    size_t total_rwx_pages;            // Must be 0
    size_t total_writable_relro;       // Must be 0
    size_t total_query_failures;       // Must be 0
    size_t total_permission_mismatches;// Must be 0
    size_t total_inaccessible_pages;   // Must be 0
    
    // Aggregate Relocations & Linking metrics
    int total_relocations;
    int total_cross_module;
    int total_shims;
    int total_weak_null;
    int total_fail_stop_thunks;
    int total_unresolved_strong_data;  // Must be 0
    int total_poison_pointers;         // Must be 0
    
    // Aggregate Constructor metrics
    size_t total_constructors;
    int guest_code_executed;           // Must be 0
    
    int audit_passed;
} DurakPreEntryAuditSummary;

// Pluggable memory query hook (defaults to svcQueryMemory on Switch, segment-based simulation on host)
typedef int (*durak_query_memory_fn)(uintptr_t vaddr, uint32_t *out_perm);
void durak_set_query_memory_hook(durak_query_memory_fn fn);

// Execute the pre-entry audit across all loaded modules using unified diagnostic logging
int durak_run_pre_entry_audit(so_module **modules, int num_modules, DurakPreEntryAuditSummary *out_summary);

#ifdef __cplusplus
}
#endif

#endif // DURAK_PRE_ENTRY_AUDIT_H
