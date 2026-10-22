> Історичний технічний звіт, не план робіт. Поточні кроки та стан — лише `IMPLEMENTATION_PLAN.md` у корені. Твердження PASS автора звіту не замінює review або hardware test.

# Durak NX — Step 2 Pre-Entry Audit Report

## 1. Overview and Scope

This document records the official pre-entry audit results for **Step 2** of the Durak NX Feasibility Spike (`IMPLEMENTATION_PLAN.md`).

The objective of Step 2 is: **Підготовка бібліотек без виконання коду гри** (Library preparation and pre-entry linking audit without any guest code execution).

### Target Identity
- **Application:** Android ARM64-v8a `ru.appscraft.durak` v25.0 (Unity 6000.0.58f2 / IL2CPP)
- **Output Binary:** `durak_nx.nro`
- **Git Commit:** `9db8020-dirty`
- **Build Timestamp:** `2026-09-25T21:20:48+03:00`
- **Pinned Toolchain:** `devkitpro/devkita64@sha256:1fc388c3a0d34bd2045a6dadcb1020e069d5f876a187fd705de14b4440c00282`

---

## 2. Target SHA-256 and GNU Build-ID Verification

All 4 target ELF shared objects from Durak 25.0 ARM64-v8a are verified against hardcoded cryptographic digests and Build-IDs before any mapping, relocation, or execution:

| Module | Expected Size (bytes) | Expected SHA-256 | Expected GNU Build-ID | Max Alignment | Target Verification Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `libsqlite3.so` | 1,797,248 | `6df7a75d31c417cae7e877fd7c3d190e0ac47b1f104ae0ae5501d72491b1c32c` | `99495662cefa74605573c8dc36a53cb1f842764d` | 64 KiB (`0x10000`) | **PASS** |
| `libmain.so` | 6,696 | `c11373dffa1bab427e8864a40313111de2a70367d052d87f33a9069ce8949d93` | `c5498ab8c791f1473a54c79a9d3c5b738ff6d941` | 16 KiB (`0x4000`) | **PASS** |
| `libunity.so` | 21,388,304 | `292f89210151ba0060f77d137cd6a00a52158dc5da760d4bf106158fc9309cef` | `bcc661ea2046416d` | 16 KiB (`0x4000`) | **PASS** |
| `libil2cpp.so` | 31,256,704 | `7bc9c2e7e20c741a511e6645589db16d0fa084d79bcfc12ba1fab78931e2271c` | `d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0` | 16 KiB (`0x4000`) | **PASS** |

### Negative Test Cases Verified (Fail-Closed)
1. **Unknown Module:** Rejection with error code `-1`.
2. **Size Mismatch:** Buffer with altered file size rejected with error code `-2`.
3. **SHA-256 Tampering:** 1-bit corrupted buffer rejected with error code `-3`.
4. **ELF Header Corruption:** Non-ELF or non-AArch64 header rejected with error code `-4`.
5. **Missing/Mismatched Build-ID:** Rejection with error code `-5`.

---

## 3. Memory Mapping & Strict W^X Compliance

### Alignment Requirements
- `libsqlite3.so` requires **64 KiB (`0x10000`)** segment alignment due to its `p_align = 0x10000` program headers. `so_load` computes `max(p_align)` across all `PT_LOAD` segments and invokes `virtmemFindCodeMemory(size, 0x10000)`.
- `libmain.so`, `libunity.so`, and `libil2cpp.so` use 16 KiB (`0x4000`) alignment.

### 3-Tier Memory Permission Model
To guarantee strict Horizon OS W^X compliance (`0xD801` fault prevention) and lock down post-relocation read-only data:
1. **Pass 1 (`Perm_Rx`):** All pages touched by `PT_LOAD` segments with `PF_X` are set to `Perm_Rx` directly from `Perm_None`.
2. **Pass 2 (`Perm_R`):** All pages belonging to read-only segments (`PF_R` without `PF_W`) as well as full pages covered by `PT_GNU_RELRO` are set to `Perm_R`.
3. **Pass 3 (`Perm_Rw`):** Remaining pages (writable data segments, BSS, and alignment padding) are set to `Perm_Rw`.

### Verification Metrics
- **Total Mapped CodeMemory:** ~54.5 MB across 4 modules.
- **RWX Pages:** **0 (Strict W^X: 100% compliant)**.
- **Writable RELRO Pages:** **0 (100% locked down)**.
- **W to X runtime transitions:** **0**.

---

## 4. Relocations & Dynamic Linking Audit

### Supported Relocation Types
Every relocation in all 4 Durak modules belongs to one of the 4 supported AArch64 types (plus packed `DT_RELR`):
- `R_AARCH64_RELATIVE` (1027)
- `R_AARCH64_ABS64` (257)
- `R_AARCH64_GLOB_DAT` (1025)
- `R_AARCH64_JUMP_SLOT` (1026)
- `DT_RELR` / `DT_ANDROID_RELR` packed relative relocations.
- **Unsupported relocation types:** **0**.

### Symbol Resolution Statistics
- **Total Unique Import Names Across All 4 Modules:** 423
- **Total Available Runtime Shims:** 631
- **Newly Added Target Shims:**
  1. `asprintf`: standard GNU libc implementation via newlib.
  2. `fchown`: safe no-op on FAT32/exFAT Horizon OS SD filesystem.
  3. `fseeko64`: mapped to 64-bit `fseeko`.
  4. `ftello64`: mapped to 64-bit `ftello`.
  5. `mremap`: fail-safe fallback reporting `ENOSYS` / `MAP_FAILED` (triggers standard allocator / non-mmap fallback).
  6. `remainderf`: standard C99/POSIX float math.
- **Unresolved Strong Data Symbols:** **0 (FATAL_MISSING = 0)**
- **Poison Pointers (`*ptr = r_offset`):** **0 (COMPLETELY ELIMINATED)**
- **Weak Undefined Symbols:** Correctly resolved to `NULL` (`0`) per ELF specification.
- **Fail-Stop Thunk Subsystem:** Pool of 64 static callable AAPCS64 thunks initialized. In standard Durak 25.0 configuration, all 423 imports resolve cleanly.

---

## 5. Constructor Discovery & Guest Code Execution Barrier

Constructor information was recovered directly from `PT_DYNAMIC` tags (`DT_INIT_ARRAY`, `DT_INIT_ARRAYSZ`, `DT_INIT`):

| Module | `DT_INIT` | `DT_INIT_ARRAY` VADDR | `DT_INIT_ARRAYSZ` (bytes) | Discovered Constructors | Execution Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `libsqlite3.so` | None | None | 0 | 0 | None |
| `libmain.so` | None | None | 0 | 0 | None |
| `libunity.so` | None | `0x14500d0` | 4,048 | 506 | **INHIBITED** |
| `libil2cpp.so` | None | `0x1bd9d28` | 176 | 22 | **INHIBITED** |
| **Total** | | | | **528** | **0 EXECUTED** |

### Execution Barrier Verification
- `so_execute_init_array` body explicitly replaced with execution inhibition logger.
- No `JNI_OnLoad` calls executed.
- No `initJni` calls executed.
- No `nativeRender` frames executed.
- **Guest code execution count:** **0**.

---

## 6. Neutralization of Unverified Donor Patches

In accordance with user rules and Codex feedback:
1. **Stack-Canary Blanket NOP Patching:** Neutralized (`so_patch_stack_canaries` converted to a no-op with diagnostic logging). No blanket NOPs applied without specific target crash evidence.
2. **Layton-Specific Gameplay & DLC Patches:** Completely removed from `main.c`.
3. **Choreographer / FMOD / Payment Patches:** Removed.

---

## 7. Review Findings Resolution (Codex Step 2 Review)

The four findings identified during Codex review were resolved and verified:

### Finding 1 (HIGH — Runtime audit false-positive & permission check)
- **Problem:** `svcQueryMemory` leaving `perm = 0` on failure was not failing the audit, and actual permissions were not checked against expected ELF segment permissions (allowing inaccessible pages or writable RELRO to pass).
- **Resolution:**
  - Added strict per-page comparison of actual permissions against expected permissions derived from `PT_LOAD` and `PT_GNU_RELRO`.
  - Any query failure immediately marks `sum.audit_passed = 0` and logs the address and Result code.
  - Inaccessible pages (`perm == 0`) fail the audit.
  - Writable RELRO pages (`is_relro && (perm & Perm_W)`) fail the audit with explicit diagnostic markers.
  - RWX violations or unexpected permissions fail the audit.
  - Pluggable memory query hook (`durak_set_query_memory_hook`) added to verify all negative paths in automated tests.

### Finding 2 (HIGH — Logger clobbering & handle desynchronization)
- **Problem:** `main.c` opened `LOG_NAME` in `"w"` mode while `debugPrintf` opened a separate handle in `"a"` mode without synchronization, risking file position desync and overwritten log segments.
- **Resolution:**
  - Created a unified logger in `util.h` and `util.c`: `durak_log_init`, `durak_log_printf`, `durak_log_vprintf`, `durak_log_flush`, and `durak_log_close`.
  - Protected with mutex serialization (`Mutex` on Switch, `pthread_mutex_t` on host).
  - Truncating open mode `"w"` on start, with durable flush (`fflush` + `fsync`) ensuring all log lines and crash tails survive.
  - `debugPrintf`, `durak_run_pre_entry_audit`, and `fatal_error` route through `durak_log_printf`. No duplicate handles or competing writers exist.

### Finding 3 (MEDIUM — Resolver error handling & fail-closed lifecycle)
- **Problem:** `crx_resolve_imports` was `void` and ignored `so_resolve` return values, failing to abort loading before `so_finalize`, and `main` exited 0 even after audit failures.
- **Resolution:**
  - `crx_resolve_imports` now returns `int` error status from `so_relocate` and `so_resolve`.
  - `locate_and_load_module` immediately aborts upon import resolution failure without executing `so_finalize`.
  - `main` checks `audit_rc == 0 && audit_summary.audit_passed` and exits with code `1` if audit fails.

### Finding 4 (MEDIUM — Active native C linker tests & verification)
- **Problem:** Existing tests were Python mock simulations and target hash checks, lacking a native C test harness executing active `so_load`/`so_relocate`/`so_resolve` and inspecting relocated pointers in memory.
- **Resolution:**
  - Implemented `tests/test_loader_linker_native.c`.
  - Performs active loading, relocation, and symbol resolution on real Durak 25.0 ELF (`extracted_durak/libmain.so`).
  - Actively inspects relocated memory pointers (`*ptr`), verifying that all 12 undefined function imports match exact target shim addresses.
  - Verifies fail-stop thunk binding when strong function imports are omitted.
  - Verifies negative resolution when a strong data symbol is unresolved (`so_resolve` returns `-1`).
  - Verifies pre-entry audit gates across 4 negative failure cases: memory query failure (`0xD801`), inaccessible page (`perm=0`), writable RELRO violation, and RWX page violation.
  - Added to automated build and verification pipeline in `build_nro.ps1`.

---

## 8. Step 2 Gate Verdict

| Gate Criterion | Status | Notes |
| :--- | :--- | :--- |
| Target SHA-256 / Build-ID verified | **PASS** | 4/4 modules cryptographically validated |
| 64 KiB alignment enforced | **PASS** | `libsqlite3.so` allocated with `0x10000` alignment |
| Strict W^X compliance | **PASS** | 0 RWX pages across all modules |
| Writable RELRO prevented | **PASS** | 0 writable RELRO pages post-reloc |
| Memory query failure handling | **PASS** | Fail-closed on query failure and inaccessible pages |
| 0 Poison pointers emitted | **PASS** | Eliminated; replaced with ELF weak NULL & fail-stop thunks |
| Unresolved strong data imports | **PASS** | 0 missing data symbols; negative test verified fail-closed |
| Discovered constructors | **PASS** | 528 constructors indexed from `PT_DYNAMIC` |
| Guest code execution barrier | **PASS** | 0 constructors / 0 guest instructions executed |
| Unified diagnostic logger | **PASS** | Single mutexed handle with durable fsync flushing |
| Native C test harnesses | **PASS** | `test_target_verify_native` & `test_loader_linker_native` passed |
| Host Python test suite | **PASS** | 8/8 tests passed in `test_step2_loader_harness.py` |
| Clean compilation & artifacts | **PASS** | `durak_nx.nro` built with pinned devkitA64 container |

**Overall Gate Status:** **`PASS` for Step 2**. Changes are clean, self-contained within ``, and ready for Codex review.
