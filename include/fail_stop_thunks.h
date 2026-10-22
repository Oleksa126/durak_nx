#ifndef FAIL_STOP_THUNKS_H
#define FAIL_STOP_THUNKS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_FAIL_STOP_SYMBOLS 64

typedef struct {
    char module_name[64];
    char symbol_name[128];
    uintptr_t bound_thunk_addr;
    uint64_t call_count;
} DurakFailStopRecord;

// Initialize the fail-stop thunk subsystem
void durak_fail_stop_init(void);

// Register an unresolved strong function symbol and obtain an ABI-safe callable address
// Returns 0 on success, negative if capacity exceeded
int durak_register_fail_stop_function(const char *module_name, const char *symbol_name, uintptr_t *out_thunk_addr);

// Query total number of registered fail-stop functions
int durak_get_fail_stop_count(void);

// Retrieve record by index for pre-entry audit
const DurakFailStopRecord *durak_get_fail_stop_record(int index);

// Default callable fail-stop handler
void durak_fail_stop_default_handler(void);

#ifdef __cplusplus
}
#endif

#endif // FAIL_STOP_THUNKS_H
