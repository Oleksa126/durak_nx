#include "fail_stop_thunks.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __SWITCH__
#include <switch.h>
#endif

static DurakFailStopRecord g_records[MAX_FAIL_STOP_SYMBOLS];
static int g_num_records = 0;

static void durak_fail_stop_dispatch(int index, uintptr_t lr) {
    if (index >= 0 && index < g_num_records) {
        g_records[index].call_count++;
        printf("\n================================================================================\n");
        printf("[FATAL FAIL-STOP TRAP] Unresolved strong function import executed!\n");
        printf("  Module:      %s\n", g_records[index].module_name);
        printf("  Symbol:      %s\n", g_records[index].symbol_name);
        printf("  Caller (LR): %p\n", (void *)lr);
        printf("================================================================================\n");

        durak_log_printf("\n[FATAL FAIL-STOP TRAP] Unresolved strong function import executed!\n");
        durak_log_printf("  Module:      %s\n", g_records[index].module_name);
        durak_log_printf("  Symbol:      %s\n", g_records[index].symbol_name);
        durak_log_printf("  Caller (LR): %p\n", (void *)lr);
        durak_log_flush_critical();
    } else {
        printf("\n[FATAL FAIL-STOP TRAP] Unregistered unresolved thunk called! LR=%p\n", (void *)lr);
        durak_log_printf("\n[FATAL FAIL-STOP TRAP] Unregistered unresolved thunk called! LR=%p\n", (void *)lr);
        durak_log_flush_critical();
    }
    fflush(stdout);

#ifdef __SWITCH__
    fatalThrow(MAKERESULT(Module_Libnx, 0xDEAD));
    for (;;) {
        svcSleepThread(1000000000ULL);
    }
#else
    abort();
#endif
}

#define DECL_THUNK(N) \
    static void durak_thunk_##N(void) { \
        uintptr_t lr = (uintptr_t)__builtin_return_address(0); \
        durak_fail_stop_dispatch(N, lr); \
    }

// Define pool of 64 static callable ABI-safe thunks without dynamic code generation
DECL_THUNK(0)  DECL_THUNK(1)  DECL_THUNK(2)  DECL_THUNK(3)
DECL_THUNK(4)  DECL_THUNK(5)  DECL_THUNK(6)  DECL_THUNK(7)
DECL_THUNK(8)  DECL_THUNK(9)  DECL_THUNK(10) DECL_THUNK(11)
DECL_THUNK(12) DECL_THUNK(13) DECL_THUNK(14) DECL_THUNK(15)
DECL_THUNK(16) DECL_THUNK(17) DECL_THUNK(18) DECL_THUNK(19)
DECL_THUNK(20) DECL_THUNK(21) DECL_THUNK(22) DECL_THUNK(23)
DECL_THUNK(24) DECL_THUNK(25) DECL_THUNK(26) DECL_THUNK(27)
DECL_THUNK(28) DECL_THUNK(29) DECL_THUNK(30) DECL_THUNK(31)
DECL_THUNK(32) DECL_THUNK(33) DECL_THUNK(34) DECL_THUNK(35)
DECL_THUNK(36) DECL_THUNK(37) DECL_THUNK(38) DECL_THUNK(39)
DECL_THUNK(40) DECL_THUNK(41) DECL_THUNK(42) DECL_THUNK(43)
DECL_THUNK(44) DECL_THUNK(45) DECL_THUNK(46) DECL_THUNK(47)
DECL_THUNK(48) DECL_THUNK(49) DECL_THUNK(50) DECL_THUNK(51)
DECL_THUNK(52) DECL_THUNK(53) DECL_THUNK(54) DECL_THUNK(55)
DECL_THUNK(56) DECL_THUNK(57) DECL_THUNK(58) DECL_THUNK(59)
DECL_THUNK(60) DECL_THUNK(61) DECL_THUNK(62) DECL_THUNK(63)

typedef void (*thunk_fn_t)(void);
static const thunk_fn_t g_thunk_pool[MAX_FAIL_STOP_SYMBOLS] = {
    durak_thunk_0,  durak_thunk_1,  durak_thunk_2,  durak_thunk_3,
    durak_thunk_4,  durak_thunk_5,  durak_thunk_6,  durak_thunk_7,
    durak_thunk_8,  durak_thunk_9,  durak_thunk_10, durak_thunk_11,
    durak_thunk_12, durak_thunk_13, durak_thunk_14, durak_thunk_15,
    durak_thunk_16, durak_thunk_17, durak_thunk_18, durak_thunk_19,
    durak_thunk_20, durak_thunk_21, durak_thunk_22, durak_thunk_23,
    durak_thunk_24, durak_thunk_25, durak_thunk_26, durak_thunk_27,
    durak_thunk_28, durak_thunk_29, durak_thunk_30, durak_thunk_31,
    durak_thunk_32, durak_thunk_33, durak_thunk_34, durak_thunk_35,
    durak_thunk_36, durak_thunk_37, durak_thunk_38, durak_thunk_39,
    durak_thunk_40, durak_thunk_41, durak_thunk_42, durak_thunk_43,
    durak_thunk_44, durak_thunk_45, durak_thunk_46, durak_thunk_47,
    durak_thunk_48, durak_thunk_49, durak_thunk_50, durak_thunk_51,
    durak_thunk_52, durak_thunk_53, durak_thunk_54, durak_thunk_55,
    durak_thunk_56, durak_thunk_57, durak_thunk_58, durak_thunk_59,
    durak_thunk_60, durak_thunk_61, durak_thunk_62, durak_thunk_63
};

void durak_fail_stop_init(void) {
    memset(g_records, 0, sizeof(g_records));
    g_num_records = 0;
}

int durak_register_fail_stop_function(const char *module_name, const char *symbol_name, uintptr_t *out_thunk_addr) {
    // Check if already registered
    for (int i = 0; i < g_num_records; i++) {
        if (strcmp(g_records[i].symbol_name, symbol_name) == 0 &&
            strcmp(g_records[i].module_name, module_name) == 0) {
            if (out_thunk_addr) *out_thunk_addr = g_records[i].bound_thunk_addr;
            return 0;
        }
    }

    if (g_num_records >= MAX_FAIL_STOP_SYMBOLS) {
        printf("[FAIL-STOP] Exceeded max fail-stop thunk pool size (%d)!\n", MAX_FAIL_STOP_SYMBOLS);
        return -1;
    }

    int idx = g_num_records++;
    strncpy(g_records[idx].module_name, module_name ? module_name : "unknown", sizeof(g_records[idx].module_name) - 1);
    strncpy(g_records[idx].symbol_name, symbol_name ? symbol_name : "unknown", sizeof(g_records[idx].symbol_name) - 1);
    g_records[idx].bound_thunk_addr = (uintptr_t)g_thunk_pool[idx];
    g_records[idx].call_count = 0;

    if (out_thunk_addr) {
        *out_thunk_addr = g_records[idx].bound_thunk_addr;
    }
    return 0;
}

int durak_get_fail_stop_count(void) {
    return g_num_records;
}

const DurakFailStopRecord *durak_get_fail_stop_record(int index) {
    if (index >= 0 && index < g_num_records) {
        return &g_records[index];
    }
    return NULL;
}

void durak_fail_stop_default_handler(void) {
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    durak_fail_stop_dispatch(-1, lr);
}
