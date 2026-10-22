/* frame_pacer.c -- Coherent 60 Hz VSync frame pacer for Durak NX
 *
 * Drives Unity 6's internal OnVsync event handler (RVA 0x00e724a0 in libunity.so)
 * at a rock-solid 60.0 Hz cadence (16.666 ms) with nanosecond monotonic timestamps.
 *
 * This delivers authentic vsync pulses, increments g_vsync_frame_counter (0x1557220),
 * and broadcasts g_vsync_cond (0x15571ec), unblocking WaitForVsyncFrame (0x00e72440).
 */

#include "frame_pacer.h"
#include "util.h"
#include <time.h>
#include <stdio.h>
#include <string.h>

#ifdef __SWITCH__
#include <switch.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

static fn_unity_on_vsync g_on_vsync = NULL;
static volatile uint64_t *g_counter_ptr = NULL;
static volatile uint64_t *g_ts_cur_ptr = NULL;
static volatile uint64_t *g_ts_prev_ptr = NULL;

static volatile int g_pacer_running = 0;
static int g_pacer_inited = 0;

#ifdef __SWITCH__
static Thread g_pacer_thread;
#else
static pthread_t g_pacer_thread;
#endif

static inline uint64_t get_monotonic_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#ifdef __SWITCH__
static void pacer_thread_func(void *arg) {
  (void)arg;
  static uint8_t pacer_tls[BIONIC_TLS_SIZE] __attribute__((aligned(16)));
  install_bionic_tls(pacer_tls);

  durak_log_printf("[PACER] VSync pacer background thread started on core %d\n", svcGetCurrentProcessorNumber());
  durak_log_flush();

  const uint64_t tick_interval_ns = 16666667ULL; // 60.0 Hz (16.666 ms)
  uint64_t next_deadline_ns = get_monotonic_ns() + tick_interval_ns;
  uint64_t tick_count = 0;

  while (g_pacer_running) {
    uint64_t now_ns = get_monotonic_ns();
    if (now_ns < next_deadline_ns) {
      uint64_t sleep_ns = next_deadline_ns - now_ns;
      svcSleepThread(sleep_ns);
    }

    now_ns = get_monotonic_ns();
    next_deadline_ns += tick_interval_ns;
    // Drift compensation: if we fell more than 1 frame behind, reset deadline
    if (now_ns > next_deadline_ns + tick_interval_ns) {
      next_deadline_ns = now_ns + tick_interval_ns;
    }

    if (g_on_vsync) {
      g_on_vsync(now_ns);
      tick_count++;

    }
  }

  durak_log_printf("[PACER] VSync pacer background thread exiting (total ticks: %llu)\n",
                   (unsigned long long)tick_count);
  durak_log_flush();
}
#else
static void *pacer_thread_func(void *arg) {
  (void)arg;
  const uint64_t tick_interval_ns = 16666667ULL;
  uint64_t next_deadline_ns = get_monotonic_ns() + tick_interval_ns;
  uint64_t tick_count = 0;

  while (g_pacer_running) {
    uint64_t now_ns = get_monotonic_ns();
    if (now_ns < next_deadline_ns) {
      struct timespec req;
      uint64_t sleep_ns = next_deadline_ns - now_ns;
      req.tv_sec = (time_t)(sleep_ns / 1000000000ULL);
      req.tv_nsec = (long)(sleep_ns % 1000000000ULL);
      nanosleep(&req, NULL);
    }

    now_ns = get_monotonic_ns();
    next_deadline_ns += tick_interval_ns;
    if (now_ns > next_deadline_ns + tick_interval_ns) {
      next_deadline_ns = now_ns + tick_interval_ns;
    }

    if (g_on_vsync) {
      g_on_vsync(now_ns);
      tick_count++;
    }
  }
  return NULL;
}
#endif

int durak_frame_pacer_init(void *libunity_virtbase) {
  if (!libunity_virtbase) return -1;

  g_on_vsync = (fn_unity_on_vsync)((uintptr_t)libunity_virtbase + UNITY_ON_VSYNC_RVA);
  g_counter_ptr = (volatile uint64_t *)((uintptr_t)libunity_virtbase + UNITY_VSYNC_COUNTER_RVA);
  g_ts_cur_ptr = (volatile uint64_t *)((uintptr_t)libunity_virtbase + UNITY_VSYNC_TS_CUR_RVA);
  g_ts_prev_ptr = (volatile uint64_t *)((uintptr_t)libunity_virtbase + UNITY_VSYNC_TS_PREV_RVA);

  durak_log_printf("[PACER] Initialized Switch VSync pacer:\n"
                   "  - OnVsync entrypoint: %p (RVA 0x%x)\n"
                   "  - Counter ptr:        %p (RVA 0x%x, initial val=%llu)\n"
                   "  - Timestamp ptr:      %p (RVA 0x%x)\n",
                   (void *)g_on_vsync, UNITY_ON_VSYNC_RVA,
                   (void *)g_counter_ptr, UNITY_VSYNC_COUNTER_RVA,
                   g_counter_ptr ? (unsigned long long)*g_counter_ptr : 0ULL,
                   (void *)g_ts_cur_ptr, UNITY_VSYNC_TS_CUR_RVA);
  durak_log_flush();

  // Prime with two initial pulses spaced by 16.6ms so dt is pre-calibrated to 16.6ms
  uint64_t t0 = get_monotonic_ns();
  g_on_vsync(t0 - 16666667ULL);
  g_on_vsync(t0);

  durak_log_printf("[PACER] Primed initial vsync frames: counter=%llu\n",
                   g_counter_ptr ? (unsigned long long)*g_counter_ptr : 0ULL);
  durak_log_flush();

  g_pacer_inited = 1;
  return 0;
}

int durak_frame_pacer_start(void) {
  if (!g_pacer_inited || g_pacer_running) return -1;
  g_pacer_running = 1;

#ifdef __SWITCH__
  // Priority 0x2B is slightly higher than main thread (0x2C) for minimal tick jitter
  Result rc = threadCreate(&g_pacer_thread, pacer_thread_func, NULL, NULL, 0x4000, 0x2B, -2);
  if (R_FAILED(rc) || R_FAILED(threadStart(&g_pacer_thread))) {
    durak_log_printf("[PACER ERROR] Failed to start VSync pacer thread: rc=0x%08x\n", (unsigned int)rc);
    durak_log_flush();
    g_pacer_running = 0;
    return -1;
  }
#else
  if (pthread_create(&g_pacer_thread, NULL, pacer_thread_func, NULL) != 0) {
    g_pacer_running = 0;
    return -1;
  }
#endif

  durak_log_printf("[PACER] VSync pacer thread started successfully (60 Hz cadence)\n");
  durak_log_flush();
  return 0;
}

void durak_frame_pacer_stop(void) {
  if (!g_pacer_running) return;
  g_pacer_running = 0;

  // Pulse once to ensure any blocked wait wakes up immediately
  if (g_on_vsync) {
    g_on_vsync(get_monotonic_ns());
  }

#ifdef __SWITCH__
  threadWaitForExit(&g_pacer_thread);
  threadClose(&g_pacer_thread);
#else
  pthread_join(g_pacer_thread, NULL);
#endif

  durak_log_printf("[PACER] VSync pacer thread stopped\n");
  durak_log_flush();
}

void durak_frame_pacer_pulse(void) {
  if (g_on_vsync) {
    g_on_vsync(get_monotonic_ns());
  }
}

uint64_t durak_frame_pacer_get_counter(void) {
  return g_counter_ptr ? *g_counter_ptr : 0ULL;
}

void durak_frame_pacer_set_handler_for_test(fn_unity_on_vsync handler,
                                            volatile uint64_t *counter,
                                            volatile uint64_t *ts_cur,
                                            volatile uint64_t *ts_prev) {
  g_on_vsync = handler;
  g_counter_ptr = counter;
  g_ts_cur_ptr = ts_cur;
  g_ts_prev_ptr = ts_prev;
  g_pacer_inited = 1;
}
