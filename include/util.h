/* util.h -- misc utility functions
 *
 * Copyright (C) 2021 fgsfds, Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

// Unified diagnostic logger API
int  durak_log_init(const char *path);
int  durak_log_is_open(void);
int  durak_log_has_error(void);
int  durak_log_get_error_count(void);
void durak_log_printf(const char *fmt, ...);
void durak_log_vprintf(const char *fmt, va_list args);
/* Publish buffered log bytes; normal durable syncs are coalesced at 1s.
 * Use flush_critical for fatal/watchdog reports requiring immediate fsync. */
int  durak_log_flush(void);
/* Explicit/periodic durable syncs; excludes final close. Thread-safe snapshot. */
void durak_log_sync_stats(uint64_t *count, uint64_t *milliseconds);
void durak_log_close(void);
void durak_log_set_file_only(int enable);
int  durak_log_is_file_only(void);

int debugPrintf(char *text, ...);

unsigned cpu_boost(int on);
void durak_log_startup_batch(int enable);
int durak_log_flush_critical(void);

int ret0(void);
int retm1(void);

/* Point TPIDR_EL0 at a zeroed per-thread block so the engine's stack-protector
 * prologues (which read the canary from TPIDR_EL0+0x28) have a valid, stable
 * bionic TLS. `buf` must outlive the thread. libnx keeps its own thread state in
 * TPIDR_RO_EL0, so commandeering TPIDR_EL0 is safe. EACH THREAD NEEDS ITS OWN
 * BLOCK -- sharing one corrupts the guard slot across threads. */
#define BIONIC_TLS_SIZE 0x400
#define BIONIC_TLS_TP_OFFSET 0x200   /* tp points into the block: headroom for any negative bionic TLS slots */
void install_bionic_tls(void *buf);

#ifdef __aarch64__
static inline void* armGetTlsRw(void) {
  void* ret;
  __asm__ ("mrs %x[data], s3_3_c13_c0_2" : [data] "=r" (ret));
  return ret;
}

static inline void armSetTlsRw(void *addr) {
  __asm__  ("msr s3_3_c13_c0_2, %0" : : "r"(addr));
}
#endif

static inline uint64_t umin(uint64_t a, uint64_t b) {
  return (a < b) ? a : b;
}

#endif
