/* util.c -- misc utility functions
 *
 * Copyright (C) 2021 fgsfds, Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdatomic.h>
#include "boot_measure.h"

#ifdef __SWITCH__
#include <switch.h>
static Mutex g_log_mutex;
#define LOG_LOCK() mutexLock(&g_log_mutex)
#define LOG_UNLOCK() mutexUnlock(&g_log_mutex)
#else
#include <pthread.h>
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
#define LOG_LOCK() pthread_mutex_lock(&g_log_mutex)
#define LOG_UNLOCK() pthread_mutex_unlock(&g_log_mutex)
#endif

#include "util.h"
#include "config.h"

#ifdef __SWITCH__
static Mutex g_boot_metric_lock;
#define BOOT_LOCK() mutexLock(&g_boot_metric_lock)
#define BOOT_UNLOCK() mutexUnlock(&g_boot_metric_lock)
#else
static pthread_mutex_t g_boot_metric_lock=PTHREAD_MUTEX_INITIALIZER;
#define BOOT_LOCK() pthread_mutex_lock(&g_boot_metric_lock)
#define BOOT_UNLOCK() pthread_mutex_unlock(&g_boot_metric_lock)
#endif
static atomic_int g_boot_measuring;
static uint64_t g_boot_measure_origin;
typedef struct { uint64_t calls, total, maximum, bytes, first, last; } BootMetric;
static BootMetric g_boot_metrics[BOOT_METRIC_COUNT];
static const char *g_boot_metric_names[BOOT_METRIC_COUNT]={
  "nativeRender", "asset_cache_fill", "sqlite_open", "sqlite_prepare",
  "sqlite_step", "inventory_grant", "sd_commit_on_close", "guest_fsync",
  "sqlite_export_miss", "host_stat", "asset_reopen_reuse"
};
static uint64_t boot_clock_ns(void) {
  int saved=errno;
#ifdef __SWITCH__
  uint64_t ticks=armGetSystemTick(),freq=armGetSystemTickFreq();
  uint64_t ns=(ticks/freq)*1000000000ULL+(ticks%freq)*1000000000ULL/freq;
#else
  struct timespec ts;
  uint64_t ns=clock_gettime(CLOCK_MONOTONIC,&ts)==0 ?
    (uint64_t)ts.tv_sec*1000000000ULL+ts.tv_nsec : 0;
#endif
  errno=saved; return ns;
}
void durak_boot_measure_begin(void) {
  int saved=errno;
  BOOT_LOCK();
  g_boot_measure_origin=boot_clock_ns();
  memset(g_boot_metrics,0,sizeof(g_boot_metrics));
  atomic_store(&g_boot_measuring,g_boot_measure_origin!=0);
  BOOT_UNLOCK(); errno=saved;
}
uint64_t durak_boot_measure_now(void) {
  return atomic_load(&g_boot_measuring) ? boot_clock_ns() : 0;
}
void durak_boot_measure_span(DurakBootMetric metric,uint64_t begin,uint64_t bytes) {
  if(!begin || (unsigned)metric>=BOOT_METRIC_COUNT) return;
  int saved=errno;
  uint64_t end=durak_boot_measure_now();
  if(end>=begin && end) {
    BOOT_LOCK();
    if(atomic_load(&g_boot_measuring) && begin>=g_boot_measure_origin) {
      BootMetric *m=&g_boot_metrics[metric];
      uint64_t duration=end-begin;
      ++m->calls; m->total+=duration; m->bytes+=bytes;
      if(duration>m->maximum) m->maximum=duration;
      if(m->calls==1 || begin<m->first) m->first=begin;
      if(end>m->last) m->last=end;
    }
    BOOT_UNLOCK();
  }
  errno=saved;
}
void durak_boot_measure_phase(const char *phase,const char *detail,uint64_t begin) {
  int saved=errno;
  uint64_t end=durak_boot_measure_now(),origin=g_boot_measure_origin;
  if(begin && end>=begin && begin>=origin && durak_log_is_open())
    durak_log_printf("[BOOT PROFILE] phase=%s detail=%s start_us=%llu end_us=%llu duration_us=%llu\n",
      phase,detail ? detail : "",(unsigned long long)((begin-origin)/1000),
      (unsigned long long)((end-origin)/1000),(unsigned long long)((end-begin)/1000));
  errno=saved;
}
void durak_boot_measure_finish(const char *reason) {
  if(!atomic_load(&g_boot_measuring)) return;
  int saved=errno;
  BootMetric snapshot[BOOT_METRIC_COUNT];
  BOOT_LOCK();
  if(!atomic_exchange(&g_boot_measuring,0)) { BOOT_UNLOCK(); errno=saved; return; }
  uint64_t end=boot_clock_ns(),origin=g_boot_measure_origin;
  memcpy(snapshot,g_boot_metrics,sizeof(snapshot));
  BOOT_UNLOCK();
  if(durak_log_is_open()) {
    uint64_t syncs,sync_ms; durak_log_sync_stats(&syncs,&sync_ms);
    durak_log_startup_batch(0);
    durak_log_printf("[BOOT PROFILE] summary reason=%s main_to_summary_us=%llu; inclusive wall durations overlap; in-flight calls excluded; click-to-main unmeasured\n",
      reason,(unsigned long long)(end>=origin ? (end-origin)/1000 : 0));
    for(int i=0;i<BOOT_METRIC_COUNT;++i) {
      BootMetric *m=&snapshot[i];
      durak_log_printf("[BOOT PROFILE] metric=%s calls=%llu total_us=%llu max_us=%llu bytes=%llu first_us=%llu last_us=%llu\n",
        g_boot_metric_names[i],(unsigned long long)m->calls,(unsigned long long)(m->total/1000),
        (unsigned long long)(m->maximum/1000),(unsigned long long)m->bytes,
        (unsigned long long)(m->calls ? (m->first-origin)/1000 : 0),
        (unsigned long long)(m->calls ? (m->last-origin)/1000 : 0));
    }
    durak_log_printf("[BOOT PROFILE] logger_syncs=%llu logger_sync_ms=%llu (snapshot before summary output)\n",
      (unsigned long long)syncs,(unsigned long long)sync_ms);
    durak_log_flush();
  }
  errno=saved;
}

// Unified diagnostic logger handle
static FILE *g_durak_log_file = NULL;
static int   g_durak_log_open_failed = 0;
static int   g_durak_log_write_errors = 0;
static int   g_durak_log_file_only = 0;
static char  g_durak_log_buffer[16384];
static uint64_t g_durak_log_last_sync_ms;
static uint64_t g_durak_log_sync_count;
static uint64_t g_durak_log_sync_time_ms;
static int g_startup_log_batch;

static uint64_t log_monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
  return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

/* Caller holds the logger mutex. Critical reports explicitly force durability. */
static int log_sync_locked(void) {
  uint64_t start = log_monotonic_ms();
  int rc = 0;
  if (fflush(g_durak_log_file) != 0) {
    g_durak_log_write_errors++;
    rc = -1;
  }
#ifndef _WIN32
  if (fsync(fileno(g_durak_log_file)) != 0) {
    g_durak_log_write_errors++;
    rc = -1;
  }
#endif
  g_durak_log_last_sync_ms = log_monotonic_ms();
  ++g_durak_log_sync_count;
  if (start && g_durak_log_last_sync_ms >= start)
    g_durak_log_sync_time_ms += g_durak_log_last_sync_ms - start;
  return rc;
}

void durak_log_sync_stats(uint64_t *count, uint64_t *milliseconds) {
  LOG_LOCK();
  if (count) *count = g_durak_log_sync_count;
  if (milliseconds) *milliseconds = g_durak_log_sync_time_ms;
  LOG_UNLOCK();
}

void durak_log_set_file_only(int enable) {
  LOG_LOCK();
  g_durak_log_file_only = enable ? 1 : 0;
  LOG_UNLOCK();
}

int durak_log_is_file_only(void) {
  LOG_LOCK();
  int res = g_durak_log_file_only;
  LOG_UNLOCK();
  return res;
}

int durak_log_init(const char *path) {
  LOG_LOCK();
  g_durak_log_write_errors = 0;
  if (g_durak_log_file) {
    fflush(g_durak_log_file);
#ifndef _WIN32
    fsync(fileno(g_durak_log_file));
#endif
    fclose(g_durak_log_file);
    g_durak_log_file = NULL;
  }
  if (path) {
    g_durak_log_file = fopen(path, "w");
    g_durak_log_open_failed = (g_durak_log_file == NULL) ? 1 : 0;
    if (g_durak_log_file)
      setvbuf(g_durak_log_file, g_durak_log_buffer, _IOFBF, sizeof(g_durak_log_buffer));
    g_durak_log_last_sync_ms = log_monotonic_ms();
  } else {
    g_durak_log_open_failed = 0;
  }
  int rc = (g_durak_log_file != NULL || path == NULL) ? 0 : -1;
  LOG_UNLOCK();
  return rc;
}

int durak_log_is_open(void) {
  LOG_LOCK();
  int is_open = (g_durak_log_file != NULL);
  LOG_UNLOCK();
  return is_open;
}

int durak_log_has_error(void) {
  LOG_LOCK();
  int err = g_durak_log_open_failed || (g_durak_log_write_errors > 0);
  if (g_durak_log_file && ferror(g_durak_log_file)) {
    err = 1;
  }
  LOG_UNLOCK();
  return err;
}

int durak_log_get_error_count(void) {
  LOG_LOCK();
  int cnt = g_durak_log_write_errors + (g_durak_log_open_failed ? 1 : 0);
  LOG_UNLOCK();
  return cnt;
}

void durak_log_vprintf(const char *fmt, va_list args) {
  if (!fmt) return;

  LOG_LOCK();
  if (!g_durak_log_file_only) {
    va_list copy;
    va_copy(copy, args);
    vprintf(fmt, copy);
    va_end(copy);
  }

  if (g_durak_log_file) {
    int w = vfprintf(g_durak_log_file, fmt, args);
    if (w < 0 || ferror(g_durak_log_file)) {
      g_durak_log_write_errors++;
      clearerr(g_durak_log_file);
    } else {
      uint64_t now = log_monotonic_ms();
      if (!now || now - g_durak_log_last_sync_ms >= 1000u)
        log_sync_locked();
    }
  } else if (g_durak_log_open_failed) {
    g_durak_log_write_errors++;
  }
  LOG_UNLOCK();
}

void durak_log_printf(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  durak_log_vprintf(fmt, args);
  va_end(args);
}

int durak_log_flush(void) {
  int rc = 0;
  LOG_LOCK();
  if (g_durak_log_file) {
    /* Runtime render/input checkpoints can arrive in bursts during a UI
     * transition. Publish bytes immediately, but coalesce SD syncs just as
     * during startup. Fatal/watchdog reports use flush_critical instead. */
    uint64_t now=log_monotonic_ms();
    rc = !g_startup_log_batch && (!now || now-g_durak_log_last_sync_ms>=1000u) ?
      log_sync_locked() : fflush(g_durak_log_file);
    if (ferror(g_durak_log_file)) {
      g_durak_log_write_errors++;
      rc = -1;
    }
  } else if (g_durak_log_open_failed) {
    rc = -1;
  }
  if (!g_durak_log_file_only) {
    fflush(stdout);
  }
  LOG_UNLOCK();
  return rc;
}

void durak_log_close(void) {
  LOG_LOCK();
  if (g_durak_log_file) {
    fflush(g_durak_log_file);
#ifndef _WIN32
    fsync(fileno(g_durak_log_file));
#endif
    fclose(g_durak_log_file);
    g_durak_log_file = NULL;
  }
  LOG_UNLOCK();
}

void durak_log_startup_batch(int enable) {
  LOG_LOCK(); g_startup_log_batch=enable!=0; LOG_UNLOCK();
}
int durak_log_flush_critical(void) {
  int rc=0;
  LOG_LOCK();
  if(g_durak_log_file) rc=log_sync_locked();
  else if(g_durak_log_open_failed) rc=-1;
  LOG_UNLOCK(); return rc;
}

#if DEBUG_LOG
static int log_is_noisy(const char *t) {
  return !strncmp(t, "dlsym", 5) || !strncmp(t, "dlopen", 6) ||
         !strncmp(t, "JNI ", 4)  || !strncmp(t, "JNI:", 4) || !strncmp(t, "[jni]", 5);
}
#endif

int debugPrintf(char *text, ...) {
#if DEBUG_LOG
  if (log_is_noisy(text)) return 0;
  va_list list;
  va_start(list, text);
  durak_log_vprintf(text, list);
  va_end(list);
#else
  (void)text;
#endif
  return 0;
}

// Per-thread bionic TLS. The engine reads its stack canary from tpidr_el0+0x28;
// every thread that runs engine code needs its OWN zeroed block here. A single
// shared block races: one thread's TLS writes (including the guard slot) corrupt
// another thread's in-flight canary, tripping a false __stack_chk_fail. `buf`
// must outlive the thread (TPIDR_EL0 points into it until the thread exits).
void install_bionic_tls(void *buf) {
  memset(buf, 0, BIONIC_TLS_SIZE);
  void **tls = (void **)((uint8_t *)buf + BIONIC_TLS_TP_OFFSET);
  tls[0] = (void *)tls; // TLS_SLOT_SELF (slot 0 points to self)
#ifdef __aarch64__
  armSetTlsRw(tls);
#endif
}

// boost the CPU to 1785MHz while loading
unsigned cpu_boost(int on) {
#ifdef __SWITCH__
  static atomic_int active;
  if(!on && !atomic_load(&active)) return 0;
  unsigned rc=appletSetCpuBoostMode(on ? ApmCpuBoostMode_FastLoad : ApmCpuBoostMode_Normal);
  if(!on && durak_log_is_open())
    durak_log_printf("[STARTUP FAST] CPU normal restore result=0x%x\n",rc);
  if(!rc) atomic_store(&active,on!=0);
  return rc;
#else
  (void)on;
  return 0;
#endif
}

int ret0(void) { return 0; }

int retm1(void) { return -1; }
