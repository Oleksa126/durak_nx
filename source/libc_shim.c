/* libc_shim.c -- bionic-compatible libc wrappers for libcrx.so + libc++_shared
 *
 * The Android engine and its C++ runtime are linked against bionic. Where the
 * bionic and newlib ABIs differ (struct layouts, flag values, missing
 * functions) we provide converting wrappers here; everything that matches is
 * passed straight through from imports.c. Online/IPC functionality (sockets,
 * fork/exec, dlopen of system libs) is dead on Switch and stubbed to fail
 * cleanly so the engine falls back to offline behaviour.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license. See the LICENSE file for details.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <malloc.h>
#include <wchar.h>
#include <wctype.h>
#include <time.h>
#include <sys/stat.h>
#include <switch.h>
#include <EGL/egl.h>     /* eglGetProcAddress: resolve the full GLES API for dlsym */

#include "config.h"
#include "boot_measure.h"
#include "read_ahead.h"
#include "asset_stat.h"
#include "sqlite_exports.h"
#include "case_probe_cleanup.h"
#include "util.h"
#include "cosmetics_inventory.h"
#include "sqlite_probe_cache.h"
#include "error.h"
#include "imports.h"   /* dynlib_find_export (dlsym shim lookup) */
#include "so_util.h"
#include "libc_shim.h"
#include "android_native_unity.h"
#include "diag.h"

// ---------------------------------------------------------------------------
// fortify (_chk) wrappers: ignore the object-size argument
// ---------------------------------------------------------------------------

void *__memcpy_chk_fake(void *dst, const void *src, size_t n, size_t dstlen) { (void)dstlen; return memcpy(dst, src, n); }
void *__memmove_chk_fake(void *dst, const void *src, size_t n, size_t dstlen) { (void)dstlen; return memmove(dst, src, n); }
void *__memset_chk_fake(void *dst, int c, size_t n, size_t dstlen) { (void)dstlen; return memset(dst, c, n); }
char *__strcat_chk_fake(char *dst, const char *src, size_t dstlen) { (void)dstlen; return strcat(dst, src); }
char *__strchr_chk_fake(const char *s, int c, size_t slen) { (void)slen; return strchr(s, c); }
char *__strcpy_chk_fake(char *dst, const char *src, size_t dstlen) { (void)dstlen; return strcpy(dst, src); }
size_t __strlen_chk_fake(const char *s, size_t slen) { (void)slen; return strlen(s); }
char *__strncat_chk_fake(char *dst, const char *src, size_t n, size_t dstlen) { (void)dstlen; return strncat(dst, src, n); }
char *__strncpy_chk_fake(char *dst, const char *src, size_t n, size_t dstlen) { (void)dstlen; return strncpy(dst, src, n); }
char *__strncpy_chk2_fake(char *dst, const char *src, size_t n, size_t dstlen, size_t srclen) { (void)dstlen; (void)srclen; return strncpy(dst, src, n); }
char *__strrchr_chk_fake(const char *s, int c, size_t slen) { (void)slen; return strrchr(s, c); }
int __vsnprintf_chk_fake(char *s, size_t maxlen, int flag, size_t slen, const char *fmt, va_list va) { (void)flag; (void)slen; return vsnprintf(s, maxlen, fmt, va); }
int __vsprintf_chk_fake(char *s, int flag, size_t slen, const char *fmt, va_list va) { (void)flag; (void)slen; return vsprintf(s, fmt, va); }

int __snprintf_chk_fake(char *s, size_t maxlen, int flag, size_t slen, const char *fmt, ...) {
  (void)flag; (void)slen;
  va_list va; va_start(va, fmt);
  int r = vsnprintf(s, maxlen, fmt, va);
  va_end(va);
  return r;
}
int __sprintf_chk_fake(char *s, int flag, size_t slen, const char *fmt, ...) {
  (void)flag; (void)slen;
  va_list va; va_start(va, fmt);
  int r = vsprintf(s, fmt, va);
  va_end(va);
  return r;
}

// fortified read helpers ignore the buffer-size guard
int   __open_2_fake(const char *path, int flags) { return open_fake(path, flags); }
long  __read_chk_fake(int fd, void *buf, size_t count, size_t buflen) { (void)buflen; return read_fake(fd, buf, count); }
long  __pread_chk_fake(int fd, void *buf, size_t count, long off, size_t buflen) {
  (void)buflen;
  long cached;
  if(durak_ra_pread(fd,buf,count,off,&cached)) return cached;
  long cur = lseek(fd, 0, SEEK_CUR);
  if (cur < 0 || lseek(fd, off, SEEK_SET) < 0) return -1;
  long r = read(fd, buf, count);
  lseek(fd, cur, SEEK_SET);
  return r;
}
void  __FD_SET_chk_fake(int fd, void *set, size_t setlen) { (void)setlen; if (set && fd >= 0 && fd < 1024) ((unsigned long *)set)[fd / (8 * sizeof(long))] |= (1ul << (fd % (8 * sizeof(long)))); }
int   __FD_ISSET_chk_fake(int fd, const void *set, size_t setlen) { (void)setlen; if (set && fd >= 0 && fd < 1024) return (((const unsigned long *)set)[fd / (8 * sizeof(long))] >> (fd % (8 * sizeof(long)))) & 1; return 0; }

// ---------------------------------------------------------------------------
// misc bionic functions
// ---------------------------------------------------------------------------

// Native twin of the android.os.Build.* JNI fields. libunity calls this to
// detect API level / ABI / device; returning "" (the old stub) made it
// mis-detect the platform. Hand back Switch-sane values for the keys engines
// actually query; everything else stays empty (= property unset, the normal
// Android case). Return value is the value length, per bionic contract.
int __system_property_get_fake(const char *name, char *value) {
  if (!value) return 0;
  const char *v = "";
  if (name) {
    if      (!strcmp(name, "ro.build.version.sdk"))        v = "33";
    else if (!strcmp(name, "ro.build.version.release"))    v = "13";
    else if (!strcmp(name, "ro.build.version.codename"))   v = "REL";
    else if (!strcmp(name, "ro.product.cpu.abi"))          v = "arm64-v8a";
    else if (!strcmp(name, "ro.product.cpu.abilist"))      v = "arm64-v8a";
    else if (!strcmp(name, "ro.product.cpu.abilist64"))    v = "arm64-v8a";
    else if (!strcmp(name, "ro.product.cpu.abi2"))         v = "";
    else if (!strcmp(name, "ro.product.model"))            v = "Switch";
    else if (!strcmp(name, "ro.product.manufacturer"))     v = "Nintendo";
    else if (!strcmp(name, "ro.product.brand"))            v = "Nintendo";
    else if (!strcmp(name, "ro.product.name"))             v = "Switch";
    else if (!strcmp(name, "ro.product.device"))           v = "Switch";
    else if (!strcmp(name, "ro.product.board"))            v = "nx";
    else if (!strcmp(name, "ro.hardware"))                 v = "nx";
    else if (!strcmp(name, "ro.board.platform"))           v = "nx";
    else if (!strcmp(name, "ro.build.fingerprint"))        v = "Nintendo/Switch/Switch:13/REL/10007:user/release-keys";
    else if (!strcmp(name, "ro.build.characteristics"))    v = "default";
    else if (!strcmp(name, "ro.build.type"))               v = "user";
    else if (!strcmp(name, "ro.build.tags"))               v = "release-keys";
    else if (!strcmp(name, "ro.debuggable"))               v = "0";
    else if (!strcmp(name, "ro.secure"))                   v = "1";
    else if (!strcmp(name, "ro.kernel.qemu"))              v = "0";
    else if (!strcmp(name, "ro.opengles.version"))         v = "196610"; /* GLES 3.2 */
    else if (!strcmp(name, "dalvik.vm.heapsize"))          v = "512m";
    else if (!strcmp(name, "persist.sys.timezone"))        v = "UTC";
  }
  size_t n = strlen(v);
  if (n > 91) n = 91;            /* PROP_VALUE_MAX-1 */
  memcpy(value, v, n); value[n] = '\0';
  return (int)n;
}
unsigned long getauxval_fake(unsigned long type) { (void)type; return 0; }

int gettid_fake(void) {
  u64 tid = 1;
  if (R_SUCCEEDED(svcGetThreadId(&tid, CUR_THREAD_HANDLE)) && tid)
    return (int)(tid & 0x7fffffff);
  return 1;
}

#define ARM64_SYS_GETTID            178
#define ARM64_SYS_FUTEX             98
#define ARM64_SYS_SCHED_SETAFFINITY 122
#define ARM64_SYS_PROCESS_VM_READV  270
#define ARM64_SYS_PROCESS_VM_WRITEV 271

// futex(2) emulation over libnx mutex+condvar. The il2cpp runtime synchronizes
// its GC, thread pool and locks with raw futex; returning ENOSYS made every
// waiter spin forever (the syscall(98) -> ENOSYS flood) and threading never made
// progress. Wait queues are hashed by uaddr into a bucket array; FUTEX_WAKE wakes
// the whole bucket (waiters re-check *uaddr, so over-broad wakes are harmless).
// The bucket mutex serializes compare-and-sleep against wakers so no wake is lost.
// Infinite waits are capped at 16ms and return as if woken: under load a wake can
// be missed (the Unity Job System / GC otherwise deadlock), and a bounded re-poll
// recovers it safely since the waiter re-checks *uaddr before proceeding.
#define FUTEX_WAIT        0
#define FUTEX_WAKE        1
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_CMD_MASK    0x7f  // strip FUTEX_PRIVATE_FLAG(128)/CLOCK_REALTIME(256)
#define FUTEX_BUCKETS     256

static Mutex   futex_lock[FUTEX_BUCKETS];   // libnx Mutex/CondVar are u32; 0 == ready
static CondVar futex_cond[FUTEX_BUCKETS];

static long futex_impl(volatile int32_t *uaddr, int op, int val, const struct timespec *to) {
  const int cmd = op & FUTEX_CMD_MASK;
  const unsigned h = (unsigned)(((uintptr_t)uaddr >> 4) & (FUTEX_BUCKETS - 1));
  if (cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET) {
    long ret = 0;
    mutexLock(&futex_lock[h]);
    if (*uaddr != val) {
      errno = EAGAIN; ret = -1;
    } else if (to) {
      const u64 ns = (u64)to->tv_sec * 1000000000ULL + (u64)to->tv_nsec;
      if (R_FAILED(condvarWaitTimeout(&futex_cond[h], &futex_lock[h], ns))) {
        errno = ETIMEDOUT; ret = -1;
      }
    } else {
      diag_futex_spin(uaddr); // beacon: alive-but-spinning if value never flips
      condvarWaitTimeout(&futex_cond[h], &futex_lock[h], 16000000ULL); // capped infinite wait
    }
    mutexUnlock(&futex_lock[h]);
    return ret;
  }
  if (cmd == FUTEX_WAKE || cmd == FUTEX_WAKE_BITSET) {
    mutexLock(&futex_lock[h]);
    condvarWakeAll(&futex_cond[h]);
    mutexUnlock(&futex_lock[h]);
    return val > 0 ? val : 0; // approximate count woken
  }
  errno = ENOSYS;
  return -1;
}

/* newlib has no <sys/uio.h>; the kernel iovec layout is just {ptr, len}. */
struct nx_iovec { void *iov_base; size_t iov_len; };

/* Validate that [addr, addr+len) is mapped and readable via svcQueryMemory, so a
 * self process_vm_readv can copy safely instead of risking a fault. */
static int nx_addr_readable(uintptr_t addr, size_t len) {
  uintptr_t a = addr, end = addr + len;
  while (a < end) {
    MemoryInfo mi; u32 pi;
    if (R_FAILED(svcQueryMemory(&mi, &pi, a))) return 0;
    if (mi.type == 0) return 0;                 /* MemType_Unmapped */
    if ((mi.perm & Perm_R) == 0) return 0;      /* not readable */
    uintptr_t be = (uintptr_t)mi.addr + mi.size;
    if (be <= a) return 0;
    a = be;
  }
  return 1;
}

long syscall_fake(long number, ...) {
  switch (number) {
    case ARM64_SYS_GETTID: return gettid_fake();
    case ARM64_SYS_FUTEX: {
      va_list va; va_start(va, number);
      volatile int32_t *uaddr = va_arg(va, volatile int32_t *);
      const int op  = va_arg(va, int);
      const int val = va_arg(va, int);
      const struct timespec *to = va_arg(va, const struct timespec *);
      va_end(va);
      return futex_impl(uaddr, op, val, to);
    }
    case ARM64_SYS_SCHED_SETAFFINITY:
      return 0; // affinity hints are advisory; pretend success
    case ARM64_SYS_PROCESS_VM_READV:
    case ARM64_SYS_PROCESS_VM_WRITEV: {
      /* Self memory copy used as a fault-safe read/write probe. Stubbing it to
       * ENOSYS made the caller spin once per frame (a process_vm_readv flood),
       * wedging the boot path. Implement it for the own-process case: validate
       * each remote range with svcQueryMemory, then copy the readable parts. */
      va_list va; va_start(va, number);
      long pid                   = va_arg(va, long); (void)pid;
      const struct nx_iovec *liov   = va_arg(va, const struct nx_iovec *);
      unsigned long lcnt         = va_arg(va, unsigned long);
      const struct nx_iovec *riov   = va_arg(va, const struct nx_iovec *);
      unsigned long rcnt         = va_arg(va, unsigned long);
      va_end(va);
      int writing = (number == ARM64_SYS_PROCESS_VM_WRITEV);
      static int dbg = 0;
      if (dbg < 5) {
        dbg++;
        debugPrintf("[sys%ld] %s lcnt=%lu rcnt=%lu remote0=%p rlen0=%zu caller=%p\n",
                    number, writing ? "vm_writev" : "vm_readv", lcnt, rcnt,
                    rcnt ? riov[0].iov_base : NULL, rcnt ? riov[0].iov_len : 0,
                    __builtin_return_address(0));
      }
      ssize_t total = 0;
      unsigned long li = 0, ri = 0; size_t lo = 0, ro = 0;
      while (li < lcnt && ri < rcnt) {
        char *lp = (char *)liov[li].iov_base + lo;
        char *rp = (char *)riov[ri].iov_base + ro;
        size_t lrem = liov[li].iov_len - lo, rrem = riov[ri].iov_len - ro;
        size_t n = lrem < rrem ? lrem : rrem;
        char *probe = writing ? lp : rp;   /* the side being read-from must be readable */
        if (!nx_addr_readable((uintptr_t)probe, n)) {
          if (total == 0) { errno = EFAULT; return -1; }
          return total;
        }
        if (writing) memcpy(rp, lp, n); else memcpy(lp, rp, n);
        total += (ssize_t)n; lo += n; ro += n;
        if (lo == liov[li].iov_len) { li++; lo = 0; }
        if (ro == riov[ri].iov_len) { ri++; ro = 0; }
      }
      return total;
    }
  }
  debugPrintf("libc: syscall(%ld) -> ENOSYS\n", number);
  errno = ENOSYS;
  return -1;
}

void sincosf_fake(float x, float *s, float *c) { *s = sinf(x); *c = cosf(x); }
int sched_get_priority_max_fake(int policy) { (void)policy; return 0; }
int sched_get_priority_min_fake(int policy) { (void)policy; return 0; }
void android_set_abort_message_fake(const char *msg) { debugPrintf("abort message: %s\n", msg ? msg : "(null)"); }
size_t __ctype_get_mb_cur_max_fake(void) { return 1; }
int __register_atfork_fake(void) { return 0; }
int __cxa_thread_atexit_impl_fake(void (*fn)(void *), void *arg, void *dso) { (void)fn; (void)arg; (void)dso; return 0; }

#define BIONIC_SC_PAGESIZE 39
#define BIONIC_SC_PAGE_SIZE 40
#define BIONIC_SC_NPROCESSORS_CONF 96
#define BIONIC_SC_NPROCESSORS_ONLN 97
#define BIONIC_SC_PHYS_PAGES 98

long sysconf_fake(int name) {
  switch (name) {
    case BIONIC_SC_PAGESIZE:
    case BIONIC_SC_PAGE_SIZE: return 0x1000;
    case BIONIC_SC_NPROCESSORS_CONF:
    case BIONIC_SC_NPROCESSORS_ONLN: return 3;
    // Report 512 MB (matches synthetic /proc/meminfo MemTotal) to make Unity's
    // DynamicHeap reserve fewer 256MB regions; real backing (arena/OC) holds more.
    case BIONIC_SC_PHYS_PAGES: return (512ll * 1024 * 1024) / 0x1000;
    default: return -1;
  }
}
long pathconf_fake(const char *path, int name) { (void)path; (void)name; return -1; }

// ---------------------------------------------------------------------------
// open() flag translation (bionic/linux -> newlib)
// ---------------------------------------------------------------------------

#define LINUX_O_CREAT  0100
#define LINUX_O_EXCL   0200
#define LINUX_O_TRUNC  01000
#define LINUX_O_APPEND 02000

static int convert_open_flags(int flags) {
  int out = flags & 3;
  if (flags & LINUX_O_CREAT)  out |= O_CREAT;
  if (flags & LINUX_O_EXCL)   out |= O_EXCL;
  if (flags & LINUX_O_TRUNC)  out |= O_TRUNC;
  if (flags & LINUX_O_APPEND) out |= O_APPEND;
  return out;
}

static int durak_file_or_dir_exists(const char *p) {
  if (!p || !p[0]) return 0;
  struct stat st;
  if (stat(p, &st) == 0) return 1;
#ifndef __SWITCH__
  /* Host tests fallback: map sdmc:/switch/durak_nx to extracted_durak/sdmc/... */
  if (strncmp(p, "sdmc:/switch/durak_nx/", 22) == 0) {
    char host_alt[512];
    snprintf(host_alt, sizeof(host_alt), "extracted_durak/sdmc/switch/durak_nx/%s", p + 22);
    if (stat(host_alt, &st) == 0) return 1;
  }
#endif
  return 0;
}

// Structured guest path -> host path resolver. Resolves relative assets/... and
// /switch/... paths with canonical sdmc:/switch/durak_nx/assets/... and legacy
// game/assets/... fallback checks.
const char *durak_resolve_path(const char *in_path, char *buf, size_t bufsz, int for_write) {
  if (!in_path || !in_path[0] || !buf || bufsz < 32) return in_path;

  /* If opened for writing, construct canonical SD destination */
  if (for_write) {
    if (strncmp(in_path, "sdmc:", 5) == 0) {
      snprintf(buf, bufsz, "%s", in_path);
    } else if (strncmp(in_path, "/switch/", 8) == 0) {
      snprintf(buf, bufsz, "sdmc:%s", in_path);
    } else if (strncmp(in_path, "/data/data/ru.appscraft.durak/files/", 36) == 0) {
      snprintf(buf, bufsz, "%s/%s", GAME_HOME, in_path + 36);
    } else if (strncmp(in_path, "/data/data/ru.appscraft.durak/", 30) == 0) {
      snprintf(buf, bufsz, "%s/%s", GAME_HOME, in_path + 30);
    } else if (in_path[0] != '/' && !strchr(in_path, ':')) {
      snprintf(buf, bufsz, "%s/%s", GAME_HOME, in_path);
    } else {
      snprintf(buf, bufsz, "%s", in_path);
    }
    return buf;
  }

  /* Reading / Stat / Opendir: Check candidate paths in priority order */

  /* 1. Synthetic proc/sys or dev */
  if (strncmp(in_path, "/proc/", 6) == 0 || strncmp(in_path, "/sys/", 5) == 0 ||
      strcmp(in_path, "/dev/urandom") == 0 || strcmp(in_path, "/dev/random") == 0) {
    return in_path;
  }

  /* 2. Absolute guest path starting with /switch/durak_nx/ */
  if (strncmp(in_path, "/switch/durak_nx/", 17) == 0) {
    const char *rel = in_path + 17;
    snprintf(buf, bufsz, "sdmc:/switch/durak_nx/%s", rel);
    if (durak_file_or_dir_exists(buf)) return buf;

    if (strncmp(rel, "assets/", 7) == 0) {
      snprintf(buf, bufsz, "sdmc:/switch/durak_nx/game/%s", rel);
      if (durak_file_or_dir_exists(buf)) return buf;
    }
    if (strncmp(rel, "game/assets/", 12) == 0) {
      snprintf(buf, bufsz, "sdmc:/switch/durak_nx/%s", rel + 5);
      if (durak_file_or_dir_exists(buf)) return buf;
    }
    if (strncmp(rel, "bin/Data/", 9) == 0) {
      snprintf(buf, bufsz, "sdmc:/switch/durak_nx/assets/%s", rel);
      if (durak_file_or_dir_exists(buf)) return buf;
      snprintf(buf, bufsz, "sdmc:/switch/durak_nx/game/assets/%s", rel);
      if (durak_file_or_dir_exists(buf)) return buf;
    }
    snprintf(buf, bufsz, "sdmc:/switch/durak_nx/%s", rel);
    return buf;
  }

  /* 3. Absolute path starting with sdmc:/switch/durak_nx/ */
  if (strncmp(in_path, "sdmc:/switch/durak_nx/", 22) == 0) {
    if (durak_file_or_dir_exists(in_path)) {
      snprintf(buf, bufsz, "%s", in_path);
      return buf;
    }
    const char *rel = in_path + 22;
    if (strncmp(rel, "assets/", 7) == 0) {
      snprintf(buf, bufsz, "sdmc:/switch/durak_nx/game/%s", rel);
      if (durak_file_or_dir_exists(buf)) return buf;
    }
    if (strncmp(rel, "game/assets/", 12) == 0) {
      snprintf(buf, bufsz, "sdmc:/switch/durak_nx/%s", rel + 5);
      if (durak_file_or_dir_exists(buf)) return buf;
    }
    if (strncmp(rel, "bin/Data/", 9) == 0) {
      snprintf(buf, bufsz, "sdmc:/switch/durak_nx/assets/%s", rel);
      if (durak_file_or_dir_exists(buf)) return buf;
      snprintf(buf, bufsz, "sdmc:/switch/durak_nx/game/assets/%s", rel);
      if (durak_file_or_dir_exists(buf)) return buf;
    }
    snprintf(buf, bufsz, "%s", in_path);
    return buf;
  }

  /* 4. Relative path starting with assets/ */
  if (strncmp(in_path, "assets/", 7) == 0) {
    snprintf(buf, bufsz, "%s/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;

    snprintf(buf, bufsz, "%s/game/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;

    if (durak_file_or_dir_exists(in_path)) {
      snprintf(buf, bufsz, "%s", in_path);
      return buf;
    }
    snprintf(buf, bufsz, "%s/%s", GAME_HOME, in_path);
    return buf;
  }

  /* 5. Relative path starting with bin/Data/ */
  if (strncmp(in_path, "bin/Data/", 9) == 0) {
    snprintf(buf, bufsz, "%s/assets/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;

    snprintf(buf, bufsz, "%s/game/assets/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;

    snprintf(buf, bufsz, "%s/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;

    if (durak_file_or_dir_exists(in_path)) {
      snprintf(buf, bufsz, "%s", in_path);
      return buf;
    }
    snprintf(buf, bufsz, "%s/assets/%s", GAME_HOME, in_path);
    return buf;
  }

  /* 6. Absolute path starting with /switch/ */
  if (strncmp(in_path, "/switch/", 8) == 0) {
    snprintf(buf, bufsz, "sdmc:%s", in_path);
    return buf;
  }

  /* 7. Android app-internal storage paths */
  if (strncmp(in_path, "/data/data/ru.appscraft.durak/files/", 36) == 0) {
    const char *sub = in_path + 36;
    snprintf(buf, bufsz, "%s/%s", GAME_HOME, sub);
    if (durak_file_or_dir_exists(buf)) return buf;
    snprintf(buf, bufsz, "%s/game/%s", GAME_HOME, sub);
    if (durak_file_or_dir_exists(buf)) return buf;
    return buf;
  }
  if (strncmp(in_path, "/data/data/ru.appscraft.durak/", 30) == 0) {
    const char *sub = in_path + 30;
    snprintf(buf, bufsz, "%s/%s", GAME_HOME, sub);
    if (durak_file_or_dir_exists(buf)) return buf;
    return buf;
  }

  /* 8. Other relative paths (e.g. "unity_app_guid", "Managed", "prefs.kv", etc.) */
  if (in_path[0] != '/' && !strchr(in_path, ':')) {
    if (durak_file_or_dir_exists(in_path)) {
      snprintf(buf, bufsz, "%s", in_path);
      return buf;
    }
    snprintf(buf, bufsz, "%s/assets/bin/Data/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;

    snprintf(buf, bufsz, "%s/game/assets/bin/Data/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;

    snprintf(buf, bufsz, "%s/assets/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;

    snprintf(buf, bufsz, "%s/game/assets/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;

    snprintf(buf, bufsz, "%s/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;

    snprintf(buf, bufsz, "%s/game/%s", GAME_HOME, in_path);
    if (durak_file_or_dir_exists(buf)) return buf;
  }

  /* Default passthrough */
  snprintf(buf, bufsz, "%s", in_path);
  return buf;
}

// Last-resort fallback for stripped flat assets
static int basename_fallback(const char *path, char *out, size_t outsz) {
  const char *slash = strrchr(path, '/');
  if (!slash || !slash[1]) return 0;   // no subdir component to strip
  struct stat st;
  snprintf(out, outsz, "%s", slash + 1); // basename, resolved against the cwd
  return stat(out, &st) == 0;
}

// Create one directory, skipping paths newlib's mkdir() can't handle safely.
// A bare "device:" path (e.g. "sdmc:") makes newlib resolve to a device root
// with an empty in-device path and dereference a NULL devoptab -- a Data Abort
// reading devoptab->mkdir_r at +0x68. Refuse those (and null/empty).
static int safe_mkdir(const char *p) {
  if (!p || !*p) { errno = EINVAL; return -1; }
  const char *colon = strchr(p, ':');
  if (colon) {                       // has a "device:" prefix
    const char *in = colon + 1;      // the path inside the device
    while (*in == '/') in++;
    if (!*in) { errno = EEXIST; return 0; }  // "sdmc:" / "sdmc:/" -> root, skip
    // A single top-level component ("sdmc:/switch") also null-derefs newlib's
    // devoptab. Such dirs (the homebrew mount point) always pre-exist already.
    if (!strchr(in, '/')) { errno = EEXIST; return 0; }
  }
  return mkdir(p, 0777);
}

// mkdir -p: create `dir` and every missing parent. Save data lives in subdirs
// the engine only mkdir()s one level at a time, so a deeper missing parent left
// the whole chain (and the save write) failing.
//
// We must NOT try to create the game root or any ancestor of it ("sdmc:",
// "sdmc:/switch", "sdmc:/switch/zookeeper"): they already exist, they aren't
// ours, and newlib's mkdir() of a *top-level* path (one component under the
// device, e.g. "sdmc:/switch") null-derefs its devoptab -> Data Abort at the
// mkdir_r slot (+0x68). So begin the parent walk *after* GAME_HOME.
static void mkdir_p_dir(const char *dir) {
  if (!dir || !*dir) return;
  char tmp[512];
  if (snprintf(tmp, sizeof(tmp), "%s", dir) <= 0) return;
  size_t skip;
  const size_t glen = strlen(GAME_HOME);
  if (strncmp(tmp, GAME_HOME, glen) == 0 && (tmp[glen] == '/' || tmp[glen] == '\0')) {
    skip = glen;                                  // only create *under* the game root
  } else {
    const char *colon = strchr(tmp, ':');         // unknown base: at least skip "device:"
    skip = colon ? (size_t)(colon + 1 - tmp) : 0;
  }
  for (char *p = tmp + skip + 1; *p; p++)
    if (*p == '/') { *p = '\0'; safe_mkdir(tmp); *p = '/'; }
  if (tmp[skip]) safe_mkdir(tmp);
}
// create the parent directory chain of a file path
static void mkdir_parents(const char *filepath) {
  char tmp[512];
  snprintf(tmp, sizeof(tmp), "%s", filepath);
  char *last = strrchr(tmp, '/');
  if (!last || last == tmp) return;
  *last = '\0';
  mkdir_p_dir(tmp);
}

// mkdir wrapper: create the full chain and treat "already exists" as success
int mkdir_fake(const char *path, unsigned mode) {
  (void)mode;
  if (!path || !*path) { errno = EINVAL; return -1; }
  char resolved[512];
  const char *rpath = durak_resolve_path(path, resolved, sizeof(resolved), 1);
  if (!rpath) rpath = path;
  durak_sqlite_probe_mutation_begin(rpath,NULL);
  mkdir_p_dir(rpath);
  int r = safe_mkdir(rpath);
  durak_sqlite_probe_mutation_end();
  int err = (r != 0) ? errno : 0;
  if (r != 0 && errno == EEXIST) {
    r = 0;
    err = 0;
  }
  durak_log_printf("[io] mkdir(\"%s\" -> \"%s\") -> %d (errno=%d)\n", path, rpath, r, err);
  return r;
}

int rmdir_fake(const char *path) {
  if (!path || !*path) { errno = EINVAL; return -1; }
  char resolved[512];
  const char *rpath = durak_resolve_path(path, resolved, sizeof(resolved), 1);
  if (!rpath) rpath = path;
  durak_sqlite_probe_mutation_begin(rpath,NULL);
  int r = rmdir(rpath);
  durak_sqlite_probe_mutation_end();
  int err = (r != 0) ? errno : 0;
  durak_log_printf("[io] rmdir(\"%s\" -> \"%s\") -> %d (errno=%d)\n", path, rpath, r, err);
  return r;
}

int g_watch_fd = -1;   /* data.unity3d fd: trace its reads/seeks to debug header load */
void watch_dump(const char *tag, int fd, long a, long b, const void *buf, long got) {
  if (fd != g_watch_fd) return;
  char h[64]; int n = (got > 16 ? 16 : (got < 0 ? 0 : (int)got));
  int p = 0; for (int i = 0; i < n; i++) p += snprintf(h + p, sizeof(h) - p, "%02x ", ((const unsigned char *)buf)[i]);
  h[p] = 0;
  debugPrintf("[io] %s fd=%d a=%ld b=%ld -> %ld  [%s]\n", tag, fd, a, b, got, h);
}

/* ---- read-ahead cache for big archive files (data.unity3d, sharedassets) ----
 * Unity deserializes archives with THOUSANDS of tiny read()s (2-8 bytes each,
 * field by field). On Android the archive sits in the OS page cache so these are
 * memory-fast; on Switch there is no page cache, so every tiny read is a direct
 * SD access (~ms) and boot crawls (8000+ reads just for the header). We buffer
 * each big read-only fd through a 1MB window filled by one large read, and
 * virtualize the logical file position -- turning ~250k tiny SD reads per MB into
 * a single one. Keyed by fd; the real fd position is used only as our scratch. */
/* ARM64 off_t/long are 64-bit; both lseek imports use the same cursor. */
long z_lseek(int fd, long off, int whence) {
  long result;
  if(durak_ra_seek(fd,off,whence,&result)) return result;
  return lseek(fd,off,whence);
}

/* File-map copies are positional too: share the cache lock/cursor discipline
 * with read and pread when using a cached immutable descriptor. */
static long read_map_at(int fd,void *buf,size_t count,long offset) {
  long got=0,cached;
  if(durak_ra_pread(fd,buf,count,offset,&cached)) return cached<0 ? 0 : cached;
  long cur=lseek(fd,0,SEEK_CUR);
  if(lseek(fd,offset,SEEK_SET)>=0)
    while((size_t)got<count) { long r=read(fd,(char *)buf+got,count-(size_t)got); if(r<=0) break; got+=r; }
  if(cur>=0) lseek(fd,cur,SEEK_SET);
  return got;
}

static const char *synthetic_proc(const char *path);  /* defined below */

// Serve /proc and /sys reads that arrive through raw open() (e.g.
// /proc/self/maps, which the engine opens to enumerate memory mappings).
// newlib's open() can't be memory-backed, so materialize the synthetic content
// into a small file under the game dir and hand back a real fd. Returns an fd,
// or -1 if `path` isn't a node we synthesize (caller proceeds normally).
static int synth_proc_open(const char *path) {
  if (!path) return -1;
  if (strncmp(path, "/proc/", 6) && strncmp(path, "/sys/", 5)) return -1;
  static char buf[16384];
  int len;
  if (!strcmp(path, "/proc/self/maps") || !strcmp(path, "/proc/self/smaps")) {
    len = so_dump_maps(buf, sizeof buf);
  } else {
    const char *s = synthetic_proc(path);
    if (!s) return -1;                                   // not /proc or /sys
    len = (int)strlen(s);
    if (len > (int)sizeof buf) len = (int)sizeof buf;
    memcpy(buf, s, (size_t)len);
  }
  char safe[160]; size_t j = 0;
  for (const char *p = path; *p && j < sizeof safe - 1; p++) safe[j++] = (*p == '/') ? '_' : *p;
  safe[j] = '\0';
  char tf[256];
  snprintf(tf, sizeof tf, "%s/.synth%s", GAME_HOME, safe);
  int wfd = open(tf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (wfd >= 0) { if (write(wfd, buf, (size_t)len) < 0) { /* best effort */ } close(wfd); }
  return open(tf, O_RDONLY);
}

// ---------------------------------------------------------------------------
// Synthetic inode numbers. libnx's fsdev returns st_ino==0 for EVERY file, but
// il2cpp's System.IO share layer keys its open-file table on (st_dev,st_ino):
// with every file colliding on inode 0 it treats UNRELATED files as the same
// one, so Easy Save's concurrent SaveData.es3.tmp (write) + SaveData.es3 (read)
// looks like an incompatible double-open of one file and throws "IOException:
// Sharing violation on path SaveData.es3" every frame on the menu -- and each of
// those exception backtraces mmaps libunity/libil2cpp, leaking us to OOM/exit.
// Give each distinct path a stable, non-zero inode (only when the real one is 0,
// so a genuine inode from a future fsdev is preserved). fstat() has no path, so a
// small fd->inode map is filled at open() time and mirrors stat(path)'s value.
#define FD_INO_MAX 4096
static uint64_t g_fd_ino[FD_INO_MAX];
static uint64_t path_ino(const char *path) {
  uint64_t h = 1469598103934665603ULL;               // FNV-1a 64 offset basis
  for (const unsigned char *p = (const unsigned char *)path; *p; p++) { h ^= *p; h *= 1099511628211ULL; }
  return h ? h : 1;                                   // 0 means "no inode" -- avoid it
}
static void fd_ino_set(int fd, const char *path) { if (fd >= 0 && fd < FD_INO_MAX) g_fd_ino[fd] = path_ino(path); }
static void fd_ino_clear(int fd) { if (fd >= 0 && fd < FD_INO_MAX) g_fd_ino[fd] = 0; }

// libnx buffers sdmc: writes -- they reach the physical card only on fsdevCommitDevice() or a
// clean unmount. Exiting via HOME kills the process (title override), so that commit never runs
// and saves written this session vanish on reboot. Track fds opened for writing and commit the
// card when they close, so a save persists the moment the game finishes writing it.
#define WFD_MAX 4096
static unsigned char g_write_fd[WFD_MAX];
int nx_sd_dirty = 0;   /* a file has been opened for writing since the last commit */
static void mark_write_fd(int fd)   { nx_sd_dirty = 1; if (fd >= 0 && fd < WFD_MAX) g_write_fd[fd] = 1; }
static void commit_write_fd(int fd) { if (fd >= 0 && fd < WFD_MAX && g_write_fd[fd]) {
                                        g_write_fd[fd] = 0; nx_sd_dirty = 0;
                                        uint64_t start=durak_boot_measure_now();
                                        fsdevCommitDevice("sdmc");
                                        durak_boot_measure_span(BOOT_SD_COMMIT,start,0); } }

/* Commit any pending writes to the physical card. Called periodically from the render loop and
 * after the game's save (nx_save_prefs), so the save survives a HOME-kill / reboot. */
void nx_sd_flush(void) {
  if (!nx_sd_dirty) return;
  nx_sd_dirty = 0;
  fsdevCommitDevice("sdmc");
}

int open_fake(const char *path, int flags, ...) {
  if (!path) { errno = EINVAL; return -1; }
  int mode = 0666;
  if (flags & LINUX_O_CREAT) { va_list va; va_start(va, flags); mode = va_arg(va, int); va_end(va); }
  const int cvt = convert_open_flags(flags);
  const int writing = (flags & 3) != 0 || (flags & LINUX_O_CREAT);
  if (!writing) {
    // /dev/urandom + /dev/random: Switch has no /dev node, but Mono/.NET (RNG
    // seeds, Guid.NewGuid, hashtable randomization) and asset crypto open these.
    // A failing open (-1) leaves those paths without entropy and can stall the
    // scene/asset load. Materialize a buffer of real CSPRNG bytes (libnx
    // randomGet) into a file and hand back a real fd so read() just works.
    if (!strcmp(path, "/dev/urandom") || !strcmp(path, "/dev/random")) {
      static char rbuf[65536];
      randomGet(rbuf, sizeof rbuf);
      char tf[256];
      snprintf(tf, sizeof tf, "%s/.synth_dev_random", GAME_HOME);
      int wfd = open(tf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (wfd >= 0) { if (write(wfd, rbuf, sizeof rbuf) < 0) { /* best effort */ } close(wfd); }
      int rfd = open(tf, O_RDONLY);
      fd_ino_set(rfd, path);
      durak_log_printf("[io] open(\"%s\", 0x%x) -> %d [urandom]\n", path, flags, rfd);
      return rfd;
    }
    // synthetic /proc, /sys (incl. self/maps)
    int sfd = synth_proc_open(path);
    if (sfd >= 0) {
      fd_ino_set(sfd, path);
      durak_log_printf("[io] open(\"%s\", 0x%x) -> %d [synthetic]\n", path, flags, sfd);
      return sfd;
    }
  }

  char resolved[512];
  char alt[320];
  const char *rpath = durak_resolve_path(path, resolved, sizeof(resolved), writing);
  if (!rpath) rpath = path;

  if (writing) { durak_sqlite_probe_mutation_begin(rpath,NULL);mkdir_parents(rpath); }

  int fd = open(rpath, cvt, mode);
  int err = errno;
  Result open_result = fd < 0 ? fsdevGetLastResult() : 0;
  if(writing) durak_sqlite_probe_mutation_end();

  if (fd < 0 && !writing && !(flags & LINUX_O_CREAT)) {
    if (basename_fallback(path, alt, sizeof(alt))) {
      fd = open(alt, cvt, mode);
      if (fd >= 0) {
        durak_log_printf("[io] open(\"%s\" -> \"%s\" [last-resort basename fallback], flags=0x%x) -> fd=%d\n",
                         path, alt, flags, fd);
        rpath = alt;
        err = 0;
      } else {
        err = errno;
      }
    }
  }

  if (fd >= 0) {
    fd_ino_set(fd, rpath);
    if (writing) mark_write_fd(fd);
    if (writing && (flags & LINUX_O_CREAT)) durak_probe_opened(fd, rpath, GAME_HOME);
    struct stat _st;
    if (fstat(fd, &_st) == 0) {
      durak_log_printf("[io] open(\"%s\" -> \"%s\", flags=0x%x) -> fd=%d (size=%lld)\n",
                       path, rpath, flags, fd, (long long)_st.st_size);
      /* Small immutable files retain whole contents across opens; large assets
       * keep bounded windows. Saves and SQLite databases are never eligible. */
      if (!writing && S_ISREG(_st.st_mode) && _st.st_size > 0 && durak_ra_asset_path(rpath,GAME_HOME)) {
        int attached=durak_ra_attach_path(fd,(long)_st.st_size,rpath);
        durak_log_printf("[ASSET CACHE] attach fd=%d size=%lld active=%d path=%s\n",fd,(long long)_st.st_size,attached,rpath);
      }
    } else {
      durak_log_printf("[io] open(\"%s\" -> \"%s\", flags=0x%x) -> fd=%d (size=?)\n",
                       path, rpath, flags, fd);
    }
  } else {
    durak_log_printf("[io] open(\"%s\" -> \"%s\", flags=0x%x) -> fd=-1 (errno=%d: %s)\n",
                     path, rpath, flags, err, strerror(err));
  }
  if (strstr(path, ".bytes") || strstr(path, ".db"))
    durak_log_printf("[io] open flags: path=%s guest=0x%x host=0x%x fd=%d errno=%d result=0x%x\n",
                     path, flags, cvt, fd, fd < 0 ? err : 0, open_result);
  errno = err;
  return fd;
}

int openat_fake(int dirfd, const char *path, int flags, ...) {
  (void)dirfd;
  int mode = 0666;
  if (flags & LINUX_O_CREAT) { va_list va; va_start(va, flags); mode = va_arg(va, int); va_end(va); }
  return open_fake(path, flags, mode);
}

int unlink_fake(const char *path) {
  if (!path) { errno = EINVAL; return -1; }
  char resolved[512];
  const char *rpath = durak_resolve_path(path, resolved, sizeof(resolved), 1);
  if (!rpath) rpath = path;
  durak_sqlite_probe_mutation_begin(rpath,NULL);
  int r = unlink(rpath);
  int err = errno;
  unsigned native = r < 0 ? fsdevGetLastResult() : 0;
  durak_sqlite_probe_mutation_end();
  durak_log_printf("[io] unlink(\"%s\" -> \"%s\") -> %d (errno=%d result=0x%x)\n", path, rpath, r, r < 0 ? err : 0, native);
  if (r < 0) durak_probe_unlink_failed(rpath, err, native);
  errno = err;
  return r;
}

int unlinkat_fake(int dirfd, const char *path, int flags) {
  (void)dirfd; (void)flags;
  return unlink_fake(path);
}

int remove_fake(const char *path) {
  return unlink_fake(path);
}

int rename_fake(const char *oldpath, const char *newpath) {
  if (!oldpath || !newpath) { errno = EINVAL; return -1; }
  char old_res[512], new_res[512];
  const char *rold = durak_resolve_path(oldpath, old_res, sizeof(old_res), 0);
  const char *rnew = durak_resolve_path(newpath, new_res, sizeof(new_res), 1);
  if (!rold) rold = oldpath;
  if (!rnew) rnew = newpath;
  durak_sqlite_probe_mutation_begin(rold,rnew);
  mkdir_parents(rnew);
  int r = rename(rold, rnew);
  durak_sqlite_probe_mutation_end();
  int err = (r != 0) ? errno : 0;
  durak_log_printf("[io] rename(\"%s\" -> \"%s\", \"%s\" -> \"%s\") -> %d (errno=%d)\n",
                   oldpath, rold, newpath, rnew, r, err);
  return r;
}

int access_fake(const char *path, int mode) {
  if (!path) { errno = EINVAL; return -1; }
  char resolved[512];
  const char *rpath = durak_resolve_path(path, resolved, sizeof(resolved), (mode & W_OK) != 0);
  if (!rpath) rpath = path;

  struct stat st;
  int r = (mode & W_OK) ? stat(rpath, &st) : durak_asset_stat(rpath,GAME_HOME,&st);
  int err = (r != 0) ? errno : 0;

  if (r != 0 && (mode & W_OK) == 0) {
    char alt[320];
    if (basename_fallback(path, alt, sizeof(alt))) {
      r = stat(alt, &st);
      if (r == 0) {
        durak_log_printf("[io] access(\"%s\" -> \"%s\" [last-resort basename fallback], mode=%d) -> 0\n",
                         path, alt, mode);
        rpath = alt;
        err = 0;
      } else {
        err = errno;
      }
    }
  }

  if (r == 0) {
    durak_log_printf("[io] access(\"%s\" -> \"%s\", mode=%d) -> 0\n", path, rpath, mode);
  } else {
    durak_log_printf("[io] access(\"%s\" -> \"%s\", mode=%d) -> -1 (errno=%d: %s)\n",
                     path, rpath, mode, err, strerror(err));
  }
  return (r == 0) ? 0 : -1;
}

void *opendir_fake(const char *name) {
  if (!name) { errno = EINVAL; return NULL; }
  char resolved[512];
  const char *rpath = durak_resolve_path(name, resolved, sizeof(resolved), 0);
  if (!rpath) rpath = name;

  DIR *d = opendir(rpath);
  int err = (d == NULL) ? errno : 0;

  if (!d) {
    char alt[320];
    if (basename_fallback(name, alt, sizeof(alt))) {
      d = opendir(alt);
      if (d) {
        durak_log_printf("[io] opendir(\"%s\" -> \"%s\" [last-resort basename fallback]) -> %p\n",
                         name, alt, (void *)d);
        rpath = alt;
        err = 0;
      } else {
        err = errno;
      }
    }
  }

  if (d) {
    durak_log_printf("[io] opendir(\"%s\" -> \"%s\") -> %p\n", name, rpath, (void *)d);
  } else {
    durak_log_printf("[io] opendir(\"%s\" -> \"%s\") -> NULL (errno=%d: %s)\n",
                     name, rpath, err, strerror(err));
  }
  return (void *)d;
}

// ---------------------------------------------------------------------------
// struct stat conversion (bionic aarch64 layout)
// ---------------------------------------------------------------------------

struct bionic_timespec { int64_t tv_sec; int64_t tv_nsec; };
struct bionic_stat {
  uint64_t st_dev; uint64_t st_ino; uint32_t st_mode; uint32_t st_nlink;
  uint32_t st_uid; uint32_t st_gid; uint64_t st_rdev; uint64_t __pad1;
  int64_t st_size; int32_t st_blksize; int32_t __pad2; int64_t st_blocks;
  struct bionic_timespec st_atim; struct bionic_timespec st_mtim; struct bionic_timespec st_ctim;
  uint32_t __unused4; uint32_t __unused5;
};

static void convert_stat(const struct stat *in, struct bionic_stat *out) {
  memset(out, 0, sizeof(*out));
  out->st_dev = in->st_dev; out->st_ino = in->st_ino; out->st_mode = in->st_mode;
  out->st_nlink = in->st_nlink; out->st_uid = in->st_uid; out->st_gid = in->st_gid;
  out->st_rdev = in->st_rdev; out->st_size = in->st_size; out->st_blksize = in->st_blksize;
  out->st_blocks = in->st_blocks;
  out->st_atim.tv_sec = in->st_atime; out->st_mtim.tv_sec = in->st_mtime; out->st_ctim.tv_sec = in->st_ctime;
}

static int sqlite_probe_native_stat(const char *path,struct stat *out,unsigned *native) {
  int rc=durak_asset_stat(path,GAME_HOME,out);
  *native=rc ? fsdevGetLastResult() : 0;return rc;
}
/* fsdev_stat opens a second read handle to obtain size. Horizon rejects that
 * while SQLite holds a write handle. Read the actual directory entry instead;
 * never substitute cached fd data for a path that may have disappeared. */
static int stat_directory_entry(const char *path, struct stat *st) {
  char native[FS_MAX_PATH];
  FsFileSystem *fs = NULL;
  if (fsdevTranslatePath(path, &fs, native) != 0) return -1;
  char *slash = strrchr(native, '/');
  if (!slash || !slash[1]) { errno = EINVAL; return -1; }
  char name[FS_MAX_PATH];
  snprintf(name, sizeof(name), "%s", slash + 1);
  if (slash == native) slash[1] = 0; else *slash = 0;
  FsDir dir;
  Result rc = fsFsOpenDirectory(fs, native, FsDirOpenMode_ReadFiles, &dir);
  if (R_FAILED(rc)) {
    durak_log_printf("[io] stat directory open failed: path=%s result=0x%x\n", path, rc);
    errno = EIO; return -1;
  }
  FsDirectoryEntry entry;
  s64 count = 0;
  int found = 0;
  while (R_SUCCEEDED(rc = fsDirRead(&dir, &count, 1, &entry)) && count) {
    if (strcmp(entry.name, name)) continue;
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0666;
    st->st_nlink = 1;
    st->st_size = entry.file_size;
    found = 1;
    break;
  }
  fsDirClose(&dir);
  if (R_FAILED(rc)) {
    durak_log_printf("[io] stat directory read failed: path=%s result=0x%x\n", path, rc);
    errno = EIO; return -1;
  }
  if (!found) { errno = ENOENT; return -1; }
  return 0;
}

int stat_fake(const char *path, struct bionic_stat *st) {
  if (!path || !st) { errno = EINVAL; return -1; }
  char resolved[512];
  const char *rpath = durak_resolve_path(path, resolved, sizeof(resolved), 0);
  if (!rpath) rpath = path;

  struct stat real;
  char alt[320];
  DurakProbeTrace probe_trace;
  int r=durak_sqlite_probe_stat(rpath,GAME_HOME,&real,&probe_trace,sqlite_probe_native_stat);
  int err = (r != 0) ? errno : 0;

  if (r != 0 && err == EIO && !strncmp(rpath, "sdmc:/", 6)) {
    Result native_error = fsdevGetLastResult();
    r = stat_directory_entry(rpath, &real);
    int fallback_error = r ? errno : 0;
    durak_log_printf("[io] stat metadata: path=%s errno=%d result=0x%x -> rc=%d errno=%d\n",
                     rpath, err, native_error, r, fallback_error);
    err = fallback_error;
  }

  if (r != 0 && !durak_sqlite_probe_path(rpath,GAME_HOME)) {
    if (basename_fallback(path, alt, sizeof(alt))) {
      r = stat(alt, &real);
      if (r == 0) {
        durak_log_printf("[io] stat(\"%s\" -> \"%s\" [last-resort basename fallback]) -> 0\n", path, alt);
        rpath = alt;
        err = 0;
      } else {
        err = errno;
      }
    }
  }

  if (r == 0) {
    convert_stat(&real, st);
    if (st->st_ino == 0) st->st_ino = path_ino(rpath);   // fsdev gives 0 -> synth
    durak_log_printf("[io] stat(\"%s\" -> \"%s\") -> 0 (size=%lld, mode=0%o)\n",
                     path, rpath, (long long)real.st_size, real.st_mode);
  } else {
    durak_log_printf("[io] stat(\"%s\" -> \"%s\") -> -1 (errno=%d: %s; cached_absence=%d observed_Result=0x%x)\n",
                     path, rpath, err, strerror(err),probe_trace.cached,probe_trace.observed_result);
  }
  if (r != 0) errno = err;
  return r;
}
int fstat_fake(int fd, struct bionic_stat *st) {
  struct stat real; const int r = fstat(fd, &real);
  if (r == 0) {
    convert_stat(&real, st);
    if (st->st_ino == 0) {                               // mirror stat(path)'s inode
      uint64_t ino = (fd >= 0 && fd < FD_INO_MAX) ? g_fd_ino[fd] : 0;
      st->st_ino = ino ? ino : ((uint64_t)(fd + 1) * 2654435761ULL) | 1;
    }
  }
  return r;
}
int lstat_fake(const char *path, struct bionic_stat *st) { return stat_fake(path, st); }

// ---------------------------------------------------------------------------
// dirent conversion (bionic dirent64 layout)
// ---------------------------------------------------------------------------

struct bionic_dirent {
  uint64_t d_ino; int64_t d_off; uint16_t d_reclen; uint8_t d_type; char d_name[256];
};

void *readdir_fake(void *dirp) {
  static struct bionic_dirent out; // not thread-safe (matches bionic readdir)
  struct dirent *e = readdir((DIR *)dirp);
  if (!e) return NULL;
  memset(&out, 0, sizeof(out));
  out.d_ino = e->d_ino;
  out.d_reclen = sizeof(out);
  out.d_type = e->d_type;
  snprintf(out.d_name, sizeof(out.d_name), "%s", e->d_name);
  return &out;
}

// ---------------------------------------------------------------------------
// locale: ignore the locale argument and use the C-locale versions
// ---------------------------------------------------------------------------

void *newlocale_fake(int mask, const char *locale, void *base) { (void)mask; (void)locale; (void)base; return (void *)1; }
void freelocale_fake(void *loc) { (void)loc; }
void *uselocale_fake(void *loc) { (void)loc; return (void *)1; }

#define WRAP_ISW_L(fn) int fn##_l_fake(int wc, void *loc) { (void)loc; return fn(wc); }
WRAP_ISW_L(iswalpha) WRAP_ISW_L(iswblank) WRAP_ISW_L(iswcntrl) WRAP_ISW_L(iswdigit)
WRAP_ISW_L(iswlower) WRAP_ISW_L(iswprint) WRAP_ISW_L(iswpunct) WRAP_ISW_L(iswspace)
WRAP_ISW_L(iswupper) WRAP_ISW_L(iswxdigit) WRAP_ISW_L(towlower) WRAP_ISW_L(towupper)

int strcoll_l_fake(const char *a, const char *b, void *loc) { (void)loc; return strcoll(a, b); }
size_t strxfrm_l_fake(char *dst, const char *src, size_t n, void *loc) { (void)loc; return strxfrm(dst, src, n); }
size_t strftime_l_fake(char *s, size_t max, const char *fmt, const void *tm, void *loc) { (void)loc; return strftime(s, max, fmt, (const struct tm *)tm); }
long double strtold_l_fake(const char *s, char **end, void *loc) { (void)loc; return strtold(s, end); }
long long strtoll_l_fake(const char *s, char **end, int base, void *loc) { (void)loc; return strtoll(s, end, base); }
unsigned long long strtoull_l_fake(const char *s, char **end, int base, void *loc) { (void)loc; return strtoull(s, end, base); }
int wcscoll_l_fake(const wchar_t *a, const wchar_t *b, void *loc) { (void)loc; return wcscoll(a, b); }
size_t wcsxfrm_l_fake(wchar_t *dst, const wchar_t *src, size_t n, void *loc) { (void)loc; return wcsxfrm(dst, src, n); }

size_t mbsnrtowcs_fake(wchar_t *dst, const char **src, size_t nms, size_t len, void *ps) {
  (void)ps;
  size_t i = 0; const char *s = *src;
  while (i < nms && s[i] && (!dst || i < len)) { if (dst) dst[i] = (unsigned char)s[i]; i++; }
  if (dst && i < len) { dst[i] = 0; *src = NULL; }
  return i;
}
size_t wcsnrtombs_fake(char *dst, const wchar_t **src, size_t nwc, size_t len, void *ps) {
  (void)ps;
  size_t i = 0; const wchar_t *s = *src;
  while (i < nwc && s[i] && (!dst || i < len)) { if (dst) dst[i] = (char)s[i]; i++; }
  if (dst && i < len) { dst[i] = 0; *src = NULL; }
  return i;
}

// ---------------------------------------------------------------------------
// memory
// ---------------------------------------------------------------------------

int posix_memalign_fake(void **out, size_t align, size_t size) {
  void *p = memalign(align, size);
  if (!p) return ENOMEM;
  *out = p;
  return 0;
}

// --- anonymous mmap arena (page-granular; supports sub-range munmap) ----------
//
// Switch has no mmap. Unity reserves big *256MB-aligned* pools by over-mmapping a
// larger region then munmapping the unaligned head/tail to keep an aligned middle.
// A plain malloc/free-per-mmap frees the WHOLE block when the head is trimmed (the
// trim's addr == the registered base) and the kept aligned middle is then reused
// out from under the engine -> the TLSF allocator's free block reads back zeroed
// (next_free == NULL) and faults. So we manage a dedicated arena (carved 256MB-
// aligned in __libnx_initheap) with a per-page used-bitmap: mmap = find a free run
// of pages and mark them; munmap = clear exactly the pages of the sub-range. Big
// requests are handed back 256MB-aligned so Unity only ever trims the tail.
// File-backed maps (Unity streams BGM/SE this way) are served from the same arena.
// ------------------------------------------------------------------------------
extern void  *g_mmap_arena_base;   // set by __libnx_initheap (main.c)
extern size_t g_mmap_arena_size;
extern int    g_overcommit;        // 1 = alias-region on-demand commit
extern u64    g_alias_base, g_alias_size;

#define BIONIC_MAP_ANONYMOUS 0x20
#define MMAP_PAGE       0x1000u
#define MMAP_BIG_ALIGN  MMAP_ARENA_ALIGN
#define MMAP_BIG_THRESH ((size_t)64 * 1024 * 1024)
#define BIONIC_PROT_NONE 0x0
#define BIONIC_PROT_WRITE 0x2
#define BIONIC_MADV_DONTNEED 4

static uint8_t *mmap_arena;    // 256MB-aligned usable base (published last)
static size_t   mmap_usable;   // usable bytes
static size_t   mmap_pages;    // usable / page
static uint8_t *mmap_used;     // 1 byte/page bitmap: reserved (address space)
static uint8_t *mmap_committed;// 1 byte/page bitmap: physically committed (overcommit only)
static size_t   g_committed_pages;   // running count of committed pages
static size_t   g_commit_peak;       // high-water mark (pages)
static Mutex    g_mmap_lock;   // zero-init == valid unlocked libnx mutex

// --- overcommit commit/decommit (caller holds g_mmap_lock) -------------------
// svcMapPhysicalMemory zero-fills and draws from the freed physical limit; it
// FAILS on already-mapped pages, so we only ever commit pages we track as
// uncommitted, in contiguous runs. Out-of-physical is logged, not fatal.
static void arena_commit_locked(size_t first, size_t cnt) {
  size_t i = 0;
  while (i < cnt) {
    if (mmap_committed[first + i]) { i++; continue; }
    size_t run = 0;
    while (i + run < cnt && !mmap_committed[first + i + run]) run++;
    u64 a = (u64)(uintptr_t)(mmap_arena + (first + i) * MMAP_PAGE);
    Result rc = svcMapPhysicalMemory((void *)a, (u64)run * MMAP_PAGE);
    if (R_SUCCEEDED(rc)) {
      for (size_t k = 0; k < run; k++) mmap_committed[first + i + k] = 1;
      g_committed_pages += run;
      if (g_committed_pages > g_commit_peak) {
        size_t prev = g_commit_peak;
        g_commit_peak = g_committed_pages;
        if ((g_commit_peak >> 16) != (prev >> 16))   // new 256MB high-water mark
          debugPrintf("[mmap] committed peak %u MB (live %u MB)\n",
                      (unsigned)((g_commit_peak * MMAP_PAGE) >> 20),
                      (unsigned)((g_committed_pages * MMAP_PAGE) >> 20));
      }
    } else {
      debugPrintf("[mmap] COMMIT FAIL %u KB @ 0x%lx rc=0x%x (committed %u MB peak %u MB)\n",
                  (unsigned)((run * MMAP_PAGE) >> 10), (unsigned long)a, rc,
                  (unsigned)((g_committed_pages * MMAP_PAGE) >> 20),
                  (unsigned)((g_commit_peak * MMAP_PAGE) >> 20));
    }
    i += run ? run : 1;
  }
}

static void arena_decommit_locked(size_t first, size_t cnt) {
  size_t i = 0;
  while (i < cnt) {
    if (!mmap_committed[first + i]) { i++; continue; }
    size_t run = 0;
    while (i + run < cnt && mmap_committed[first + i + run]) run++;
    u64 a = (u64)(uintptr_t)(mmap_arena + (first + i) * MMAP_PAGE);
    if (R_SUCCEEDED(svcUnmapPhysicalMemory((void *)a, (u64)run * MMAP_PAGE))) {
      for (size_t k = 0; k < run; k++) mmap_committed[first + i + k] = 0;
      g_committed_pages -= run;
    }
    i += run ? run : 1;
  }
}

// translate [addr,addr+len) to a clamped page range within the arena; returns 0 if
// outside the arena (e.g. a newlib-fallback pointer), else 1 with *first/*cnt set.
static int arena_page_range(void *addr, size_t len, size_t *first, size_t *cnt) {
  if (!mmap_arena || (uint8_t *)addr < mmap_arena) return 0;
  size_t off = (uint8_t *)addr - mmap_arena;
  if (off >= mmap_usable) return 0;
  size_t f = off / MMAP_PAGE;
  size_t c = (len + MMAP_PAGE - 1) / MMAP_PAGE;
  if (f + c > mmap_pages) c = mmap_pages - f;
  *first = f; *cnt = c;
  return 1;
}

// commit [addr,len) on demand (mprotect RW / anon mmap). no-op if not overcommit.
static void arena_commit_range(void *addr, size_t len) {
  if (!g_overcommit) return;
  size_t first, cnt;
  mutexLock(&g_mmap_lock);
  if (arena_page_range(addr, len, &first, &cnt)) arena_commit_locked(first, cnt);
  mutexUnlock(&g_mmap_lock);
}

// decommit [addr,len) (mprotect PROT_NONE / munmap). reclaims physical. Safe
// because re-use of a decommitted page goes through mprotect(RW) -> recommit.
static void arena_decommit_range(void *addr, size_t len) {
  if (!g_overcommit) return;
  size_t first, cnt;
  mutexLock(&g_mmap_lock);
  if (arena_page_range(addr, len, &first, &cnt)) arena_decommit_locked(first, cnt);
  mutexUnlock(&g_mmap_lock);
}

// madvise(MADV_DONTNEED): zero the committed pages but KEEP them committed. The
// Switch has no fault handler, so decommitting here would crash if the engine
// re-touches without an intervening mprotect(RW) (allowed on Linux). Zeroing
// preserves the "reads back as zero after DONTNEED" contract safely.
static void arena_dontneed_range(void *addr, size_t len) {
  if (!g_overcommit) return;
  size_t first, cnt;
  mutexLock(&g_mmap_lock);
  if (arena_page_range(addr, len, &first, &cnt)) {
    for (size_t i = 0; i < cnt; ) {
      if (!mmap_committed[first + i]) { i++; continue; }
      size_t run = 0;
      while (i + run < cnt && mmap_committed[first + i + run]) run++;
      memset(mmap_arena + (first + i) * MMAP_PAGE, 0, run * MMAP_PAGE);
      i += run;
    }
  }
  mutexUnlock(&g_mmap_lock);
}

// ===========================================================================
// Stack-region overcommit (OC) arena.
// Boot probe established: svcMapMemory can alias heap pages into the STACK
// region (the alias region is rejected, kernel err 0xdc01), and Unity reserves
// ~2.8GB of PROT_NONE blocks while committing only ~80MB via mprotect(RW) with
// ZERO decommits. So we satisfy the big PROT_NONE reservations from a cheap
// stack-region address window and alias a small bump-allocated heap commit-pool
// in on mprotect(RW). Tried BEFORE the heap-backed arena for big anon PROT_NONE
// maps; anything else (and overflow when the window fills) falls through to the
// heap-backed arena, so if OC setup fails the engine runs exactly as before.
// Because decommits are never observed, the pool is a no-reclaim bump allocator.
// ===========================================================================
static uint8_t *oc_base;        // stack-region window base (256MB-aligned)
static size_t   oc_pages;       // window size in pages (0 => OC disabled)
static uint8_t *oc_used;        // 1/page: address space reserved by an mmap
static uint8_t *oc_committed;   // 1/page: physically backed via svcMapMemory
static uint8_t *oc_pool;        // commit-pool base (heap, page-aligned)
static size_t   oc_pool_pages;  // pool capacity in pages
static size_t   oc_pool_bump;   // next free pool page (bump; no reclaim)
static size_t   oc_live_pages;  // committed pages (diagnostic)

// Called once from main() after the newlib heap exists. window = a reserved
// stack-region range; pool = a heap buffer. Returns 1 if OC is armed.
int oc_arena_init(void *window, size_t window_bytes, void *pool, size_t pool_bytes) {
  if (!window || !pool || !window_bytes || !pool_bytes) return 0;
  size_t wp = window_bytes / MMAP_PAGE;
  uint8_t *u = (uint8_t *)calloc(wp, 1);
  uint8_t *c = (uint8_t *)calloc(wp, 1);
  if (!u || !c) { free(u); free(c); return 0; }
  mutexLock(&g_mmap_lock);
  oc_base = (uint8_t *)window; oc_pages = wp; oc_used = u; oc_committed = c;
  oc_pool = (uint8_t *)pool; oc_pool_pages = pool_bytes / MMAP_PAGE;
  oc_pool_bump = 0; oc_live_pages = 0;
  mutexUnlock(&g_mmap_lock);
  return 1;
}

static int oc_contains(void *addr) {
  return oc_pages && (uint8_t *)addr >= oc_base &&
         (uint8_t *)addr < oc_base + oc_pages * MMAP_PAGE;
}

// A thread stack (e.g. an audio worker's) can get mapped by libnx INSIDE the OC
// window after arm time -- the boot hole-scan can't see stacks created later, and
// the virtmem reservation on the window doesn't reliably deflect them. Reserving
// such a range and later svcMapMemory'ing over it fails (0xd401 InvalidCurrentMemory)
// and leaves Unity's allocation unbacked -> the engine faults. So before handing out
// a candidate, confirm every page is still Unmapped; if a mapped span is found, mark
// its OC pages used so the scan permanently routes around it. caller holds g_mmap_lock.
static int oc_range_occupied(size_t i, size_t need) {
  uint64_t a   = (uint64_t)(uintptr_t)(oc_base + i * MMAP_PAGE);
  uint64_t end = a + (uint64_t)need * MMAP_PAGE;
  int occ = 0;
  while (a < end) {
    MemoryInfo mi; u32 pi;
    if (R_FAILED(svcQueryMemory(&mi, &pi, a))) { occ = 1; break; }
    uint64_t span_end = mi.addr + mi.size;
    if (span_end <= a) { occ = 1; break; }
    if (mi.type != MemType_Unmapped) {
      occ = 1;
      uint64_t s = mi.addr > (uint64_t)(uintptr_t)oc_base ? mi.addr
                                                          : (uint64_t)(uintptr_t)oc_base;
      size_t p0 = (size_t)((s - (uint64_t)(uintptr_t)oc_base) / MMAP_PAGE);
      size_t p1 = (size_t)((span_end - (uint64_t)(uintptr_t)oc_base + MMAP_PAGE - 1) / MMAP_PAGE);
      for (size_t k = p0; k < p1 && k < oc_pages; k++) oc_used[k] = 1;
      durak_log_printf("[oc] window range 0x%llx has mapped span 0x%llx..0x%llx (type=0x%x) -> routing around\n",
                  (unsigned long long)s, (unsigned long long)mi.addr,
                  (unsigned long long)span_end, mi.type);
      durak_log_flush();
    }
    a = span_end;
  }
  return occ;
}

// Reserve address space in the OC window. Mirrors mmap_arena_alloc_locked's
// 256MB-aligned tail-overflow so Unity's 511MB over-map nets one 256MB slot.
// caller holds g_mmap_lock.
static void *oc_alloc_locked(size_t len, size_t *got) {
  *got = 0;
  if (!oc_pages) return NULL;
  size_t need = (len + MMAP_PAGE - 1) / MMAP_PAGE; if (!need) need = 1;
  const size_t step = MMAP_BIG_ALIGN / MMAP_PAGE;
  size_t kept = need > step ? need - step : need;
  for (size_t i = 0; i + need <= oc_pages; i += step) {        // pass 1: full over-map fits
    size_t run = 0; while (run < need && !oc_used[i + run]) run++;
    if (run == need) {
      if (oc_range_occupied(i, need)) continue;   // a thread stack landed here -> skip
      for (size_t k = 0; k < need; k++) oc_used[i + k] = 1;
      *got = need * MMAP_PAGE; return oc_base + i * MMAP_PAGE;
    }
  }
  for (size_t i = 0; i < oc_pages; i += step) {                // pass 2: tail slot
    if (i + need <= oc_pages) continue;
    size_t avail = oc_pages - i; if (avail < kept) continue;
    size_t run = 0; while (run < avail && !oc_used[i + run]) run++;
    if (run == avail) {
      if (oc_range_occupied(i, avail)) continue;  // a thread stack landed here -> skip
      for (size_t k = 0; k < avail; k++) oc_used[i + k] = 1;
      *got = avail * MMAP_PAGE; return oc_base + i * MMAP_PAGE;
    }
  }
  return NULL;
}

// Commit [addr,len): alias contiguous bump-pool runs into the reserved OC range
// via svcMapMemory (which remaps the pool source away -- we only access via the
// OC address). Already-committed pages are skipped. caller holds g_mmap_lock.
// Returns 0 on success, -1 on failure (with errno set).
static int oc_commit_locked(void *addr, size_t len) {
  if (!oc_pages || !oc_base) {
    errno = ENOMEM;
    return -1;
  }
  if ((uint8_t *)addr < oc_base) {
    durak_log_printf("[oc ERROR] commit address underflow: addr=%p < oc_base=%p\n", addr, oc_base);
    durak_log_flush();
    errno = ENOMEM;
    return -1;
  }
  size_t first = ((uint8_t *)addr - oc_base) / MMAP_PAGE;
  size_t cnt   = (len + MMAP_PAGE - 1) / MMAP_PAGE;
  if (first >= oc_pages) {
    durak_log_printf("[oc ERROR] commit address overflow: first=%zu >= oc_pages=%zu\n", first, oc_pages);
    durak_log_flush();
    errno = ENOMEM;
    return -1;
  }
  if (first + cnt > oc_pages) {
    durak_log_printf("[oc WARN] commit length clamped to window: first=%zu cnt=%zu -> clamped to %zu\n",
                     first, cnt, oc_pages - first);
    cnt = oc_pages - first;
  }

  size_t i = 0;
  while (i < cnt) {
    // Skip already-committed pages (handles repeat commit gracefully)
    if (oc_committed[first + i]) { i++; continue; }
    size_t run = 0;
    while (i + run < cnt && !oc_committed[first + i + run]) run++;
    if (run == 0) break;

    // Check pool capacity
    if (oc_pool_bump + run > oc_pool_pages) {
      durak_log_printf("================================================================================\n");
      durak_log_printf("[oc ERROR] commit-pool EXHAUSTED: need %zu pages (%llu bytes), %zu left\n",
                       run, (unsigned long long)run * MMAP_PAGE,
                       (oc_pool_pages > oc_pool_bump) ? oc_pool_pages - oc_pool_bump : 0);
      durak_log_printf("  pool bump=%zu, limit=%zu, live=%zu MB, total pool=%zu MB\n",
                       oc_pool_bump, oc_pool_pages,
                       (oc_live_pages * MMAP_PAGE) >> 20, (oc_pool_pages * MMAP_PAGE) >> 20);
      durak_log_printf("================================================================================\n");
      durak_log_flush();
      errno = ENOMEM;
      return -1;
    }

    void *dst = oc_base + (first + i) * MMAP_PAGE;
    void *src = oc_pool + oc_pool_bump * MMAP_PAGE;
    u64 size_bytes = (u64)run * MMAP_PAGE;

    // Check reservation status in bitmap for this run
    size_t used_pages = 0;
    size_t committed_pages = 0;
    for (size_t k = 0; k < run; k++) {
      if (oc_used[first + i + k]) used_pages++;
      if (oc_committed[first + i + k]) committed_pages++;
    }

#ifdef __SWITCH__
    // Query source and destination memory state before syscall
    MemoryInfo mi_dst = {0}, mi_src = {0};
    u32 pi_dst = 0, pi_src = 0;
    Result qrc_dst = svcQueryMemory(&mi_dst, &pi_dst, (u64)(uintptr_t)dst);
    Result qrc_src = svcQueryMemory(&mi_src, &pi_src, (u64)(uintptr_t)src);

    int dst_occupied = (R_SUCCEEDED(qrc_dst) && mi_dst.type != MemType_Unmapped);
    int src_unsuitable = (R_SUCCEEDED(qrc_src) && (mi_src.type != MemType_Heap || (mi_src.perm & Perm_Rw) != Perm_Rw || mi_src.attr != 0));

    if (dst_occupied || src_unsuitable) {
      durak_log_printf("================================================================================\n");
      durak_log_printf("[oc WARN] Pre-mapping check detected potential conflict before svcMapMemory:\n");
      durak_log_printf("  dst: %p (size=%llu bytes, %zu pages): query_rc=0x%08x base=%p size=0x%llx type=0x%x perm=0x%x attr=0x%x\n",
                       dst, (unsigned long long)size_bytes, run, (unsigned int)qrc_dst,
                       (void *)mi_dst.addr, (unsigned long long)mi_dst.size,
                       mi_dst.type, mi_dst.perm, mi_dst.attr);
      if (dst_occupied) {
        durak_log_printf("  [CHECK] Destination %p is ALREADY OCCUPIED (state/type=0x%x, expected MemType_Unmapped=0x0)!\n",
                         dst, mi_dst.type);
      }
      durak_log_printf("  src: %p (size=%llu bytes, %zu pages): query_rc=0x%08x base=%p size=0x%llx type=0x%x perm=0x%x attr=0x%x\n",
                       src, (unsigned long long)size_bytes, run, (unsigned int)qrc_src,
                       (void *)mi_src.addr, (unsigned long long)mi_src.size,
                       mi_src.type, mi_src.perm, mi_src.attr);
      if (src_unsuitable) {
        durak_log_printf("  [CHECK] Source %p is UNSUITABLE (type=0x%x [expected MemType_Heap=0x5], perm=0x%x [expected RW=0x3], attr=0x%x [expected 0x0])!\n",
                         src, mi_src.type, mi_src.perm, mi_src.attr);
      }
      durak_log_printf("================================================================================\n");
      durak_log_flush();
    }
#endif

    Result rc = svcMapMemory(dst, src, size_bytes);
    if (R_FAILED(rc)) {
#ifdef __SWITCH__
      MemoryInfo fail_mi_dst = {0}, fail_mi_src = {0};
      u32 fail_pi_dst = 0, fail_pi_src = 0;
      Result fail_qrc_dst = svcQueryMemory(&fail_mi_dst, &fail_pi_dst, (u64)(uintptr_t)dst);
      Result fail_qrc_src = svcQueryMemory(&fail_mi_src, &fail_pi_src, (u64)(uintptr_t)src);

      durak_log_printf("================================================================================\n");
      durak_log_printf("[oc ERROR] svcMapMemory FAILED! rc=0x%08x\n", (unsigned int)rc);
      durak_log_printf("  src: %p, dst: %p, size: %llu bytes (%zu pages)\n",
                       src, dst, (unsigned long long)size_bytes, run);
      durak_log_printf("  pool: bump=%zu pages (%zu MB), limit=%zu pages (%zu MB), remaining=%zu pages\n",
                       oc_pool_bump, (oc_pool_bump * MMAP_PAGE) >> 20,
                       oc_pool_pages, (oc_pool_pages * MMAP_PAGE) >> 20,
                       (oc_pool_pages > oc_pool_bump) ? oc_pool_pages - oc_pool_bump : 0);
      durak_log_printf("  live: %zu MB (%zu pages)\n",
                       (oc_live_pages * MMAP_PAGE) >> 20, oc_live_pages);
      durak_log_printf("  bitmap [range first=%zu..%zu]: oc_used: %zu/%zu, oc_committed: %zu/%zu\n",
                       first + i, first + i + run - 1, used_pages, run, committed_pages, run);
      durak_log_printf("  dst svcQueryMemory (rc=0x%08x):\n", (unsigned int)fail_qrc_dst);
      durak_log_printf("    base=%p, size=0x%llx, state/type=0x%x, perm=0x%x, attr=0x%x, ipc_ref=%u, dev_ref=%u\n",
                       (void *)fail_mi_dst.addr, (unsigned long long)fail_mi_dst.size,
                       fail_mi_dst.type, fail_mi_dst.perm, fail_mi_dst.attr,
                       fail_mi_dst.ipc_refcount, fail_mi_dst.device_refcount);
      durak_log_printf("  src svcQueryMemory (rc=0x%08x):\n", (unsigned int)fail_qrc_src);
      durak_log_printf("    base=%p, size=0x%llx, state/type=0x%x, perm=0x%x, attr=0x%x, ipc_ref=%u, dev_ref=%u\n",
                       (void *)fail_mi_src.addr, (unsigned long long)fail_mi_src.size,
                       fail_mi_src.type, fail_mi_src.perm, fail_mi_src.attr,
                       fail_mi_src.ipc_refcount, fail_mi_src.device_refcount);

      // Explicit diagnostics
      if (fail_mi_dst.type != MemType_Unmapped) {
        durak_log_printf("  [DIAGNOSIS: OCCUPIED DESTINATION] dst %p has state/type=0x%x != MemType_Unmapped(0x0)\n",
                         dst, fail_mi_dst.type);
      }
      if (fail_mi_dst.type == MemType_MappedMemory) {
        durak_log_printf("  [DIAGNOSIS: REPEAT COMMIT] dst %p is already MemType_MappedMemory(0x0B)!\n", dst);
      }
      if (fail_mi_src.type != MemType_Heap) {
        durak_log_printf("  [DIAGNOSIS: UNSUITABLE SOURCE] src %p has state/type=0x%x != MemType_Heap(0x5)\n",
                         src, fail_mi_src.type);
      }
      if ((fail_mi_src.perm & Perm_Rw) != Perm_Rw) {
        durak_log_printf("  [DIAGNOSIS: UNSUITABLE SOURCE] src %p permissions 0x%x do not include Perm_Rw(0x3)\n",
                         src, fail_mi_src.perm);
      }
      if (fail_mi_src.attr != 0) {
        durak_log_printf("  [DIAGNOSIS: UNSUITABLE SOURCE] src %p has attributes=0x%x (expected 0x0)\n",
                         src, fail_mi_src.attr);
      }
      durak_log_printf("================================================================================\n");
#else
      durak_log_printf("[oc ERROR] svcMapMemory FAIL dst=%p src=%p size=%llu bytes rc=0x%x\n",
                       dst, src, (unsigned long long)size_bytes, rc);
#endif
      durak_log_flush();

      // Ensure failed pages remain uncommitted!
      // Do NOT set oc_committed!
      // Do NOT advance oc_pool_bump or oc_live_pages!
      errno = (rc == 0xd401) ? EFAULT : ENOMEM;
      return -1;
    }

    // Success: zero freshly committed anon memory, mark bitmap, advance bump
    memset(dst, 0, run * MMAP_PAGE);
    for (size_t k = 0; k < run; k++) oc_committed[first + i + k] = 1;
    oc_pool_bump += run;
    oc_live_pages += run;
    durak_log_printf("[oc:COMMIT] committed %zu KB @ %p (live %zu MB, pool %zu/%zu MB)\n",
                     (run * MMAP_PAGE) >> 10, dst,
                     (oc_live_pages * MMAP_PAGE) >> 20,
                     (oc_pool_bump * MMAP_PAGE) >> 20, (oc_pool_pages * MMAP_PAGE) >> 20);
    durak_log_flush();
    i += run;
  }
  return 0;
}

// munmap of an OC range: reclaim only UNCOMMITTED pages (the tail-overflow slack
// Unity trims after each over-map). Committed pages stay reserved+mapped (a small
// bounded leak) so a later reservation can't collide with a live alias.
static void oc_free_locked(void *addr, size_t len) {
  if ((uint8_t *)addr < oc_base) return;
  size_t first = ((uint8_t *)addr - oc_base) / MMAP_PAGE;
  size_t cnt   = (len + MMAP_PAGE - 1) / MMAP_PAGE;
  if (first >= oc_pages) return;
  if (first + cnt > oc_pages) cnt = oc_pages - first;
  for (size_t i = 0; i < cnt; i++)
    if (!oc_committed[first + i]) oc_used[first + i] = 0;
}

// caller holds g_mmap_lock
static void mmap_arena_init_locked(void) {
  if (mmap_arena) return;
  uint8_t *base; size_t usable;
  if (g_mmap_arena_base) {
    base   = (uint8_t *)g_mmap_arena_base;   // dedicated, already 256MB-aligned
    usable = g_mmap_arena_size;
  } else {
    // fallback (small heap / applet): memalign a modest arena (< 2GB newlib limit)
    const size_t want = (size_t)768 * 1024 * 1024 + MMAP_BIG_ALIGN;
    uint8_t *raw = memalign(MMAP_PAGE, want);
    if (!raw) fatal_error("mmap arena alloc (%u MB) failed", (unsigned)(want >> 20));
    base   = (uint8_t *)(((uintptr_t)raw + (MMAP_BIG_ALIGN - 1)) & ~(MMAP_BIG_ALIGN - 1));
    usable = (size_t)768 * 1024 * 1024;
  }
  size_t pages  = usable / MMAP_PAGE;
  uint8_t *used = (uint8_t *)calloc(pages, 1);
  if (!used) fatal_error("mmap bitmap alloc failed");
  if (g_overcommit) {
    mmap_committed = (uint8_t *)calloc(pages, 1);
    if (!mmap_committed) fatal_error("mmap commit-bitmap alloc failed");
  }
  mmap_usable = usable; mmap_pages = pages; mmap_used = used;
  mmap_arena  = base;   // publish last (alloc/free key off this)
  debugPrintf("[mmap] arena: %u MB %s at %p\n", (unsigned)(usable >> 20),
              g_overcommit ? "virtual (alias, on-demand commit)" : "256MB-aligned heap-backed",
              base);
}

// caller holds g_mmap_lock.
// Returns the mapped base and writes the number of bytes ACTUALLY reserved
// (in-arena) to *got. For big alignment over-maps (Unity reserves block+align,
// then munmaps the unaligned head/tail), the request is much larger than the
// ~256MB block Unity actually keeps. Normally we reserve the whole over-map and
// let the tail-munmap give it back. But for the LAST 256MB slot the full over-map
// runs past the arena end, so a plain "need contiguous pages" search fails even
// though the kept block fits. In that case we reserve only [slot, arena_end) -- the
// kept block lives there; Unity's tail-munmap targets addresses beyond our arena
// and is a harmless no-op. This removes the transient peak so each block costs
// exactly its 256MB slot (floor(arena/256MB) blocks fit, no 2x headroom needed).
static void *mmap_arena_alloc_locked(size_t len, size_t *got) {
  size_t need = (len + MMAP_PAGE - 1) / MMAP_PAGE;
  if (!need) need = 1;
  if (len >= MMAP_BIG_THRESH) {
    const size_t step = MMAP_BIG_ALIGN / MMAP_PAGE;   // 256MB in pages
    size_t kept = need > step ? need - step : need;   // pages Unity actually keeps
    // pass 1: full over-map fits within the arena (normal case for all but the last slot)
    for (size_t i = 0; i + need <= mmap_pages; i += step) {
      size_t run = 0;
      while (run < need && !mmap_used[i + run]) run++;
      if (run == need) {
        for (size_t k = 0; k < need; k++) mmap_used[i + k] = 1;
        *got = need * MMAP_PAGE;
        return mmap_arena + i * MMAP_PAGE;
      }
    }
    // pass 2: tail slot -- the over-map would spill past the arena end, but the kept
    // block fits in [slot, arena_end). Reserve only that; the spill is trimmed away.
    for (size_t i = 0; i < mmap_pages; i += step) {
      if (i + need <= mmap_pages) continue;          // handled by pass 1
      size_t avail = mmap_pages - i;
      if (avail < kept) continue;                    // kept block wouldn't fit
      size_t run = 0;
      while (run < avail && !mmap_used[i + run]) run++;
      if (run == avail) {
        for (size_t k = 0; k < avail; k++) mmap_used[i + k] = 1;
        *got = avail * MMAP_PAGE;                     // only the in-arena portion
        return mmap_arena + i * MMAP_PAGE;
      }
    }
  } else {
    for (size_t i = 0; i + need <= mmap_pages; ) {
      size_t run = 0;
      while (run < need && !mmap_used[i + run]) run++;
      if (run == need) {
        for (size_t k = 0; k < need; k++) mmap_used[i + k] = 1;
        *got = need * MMAP_PAGE;
        return mmap_arena + i * MMAP_PAGE;
      }
      i += run + 1;
    }
  }
  *got = 0;
  return NULL;
}

static void mmap_arena_free(void *addr, size_t len) {
  if (!mmap_arena || (uint8_t *)addr < mmap_arena) return;
  size_t off = (uint8_t *)addr - mmap_arena;
  if (off >= mmap_usable) return;
  size_t first = off / MMAP_PAGE;
  size_t cnt   = (len + MMAP_PAGE - 1) / MMAP_PAGE;
  mutexLock(&g_mmap_lock);
  for (size_t k = 0; k < cnt && first + k < mmap_pages; k++)
    mmap_used[first + k] = 0;
  mutexUnlock(&g_mmap_lock);
}

// Stopgap: when the 256MB-block arena is exhausted by Unity's 9 pools, small
// (sub-threshold) il2cpp/GC mmaps still need to land somewhere. Serve them from
// newlib's free heap via memalign and track each so munmap can free it. This is
// not real overcommit (it consumes physical newlib heap), but it unblocks the
// sub-1MB il2cpp allocations that were failing and surfaces il2cpp's true mmap
// appetite in the log to size the proper fix.
#define MMAP_FALLBACK_MAX 4096
static struct { void *ptr; size_t len; } g_fb[MMAP_FALLBACK_MAX];
static int   g_fb_n = 0;
static size_t g_fb_bytes = 0;
static Mutex g_fb_lock;

static void *mmap_fallback(size_t length, int prot, int flags, int fd, long offset) {
  /* Big anonymous reservations are Unity Dynamic-Heap pools: its allocator masks
   * pointers down to a large-aligned pool base to derive block indices, so a
   * 4KB-aligned block makes that math walk off into unmapped memory (the
   * libunity+0xdce75c Data Abort). Hand big anon maps a MMAP_BIG_ALIGN-aligned
   * base so the index math lands correctly even out here in the newlib overflow. */
  size_t align = (length >= MMAP_BIG_THRESH && (flags & BIONIC_MAP_ANONYMOUS))
                   ? MMAP_BIG_ALIGN : MMAP_PAGE;
  void *q = memalign(align, length);
  if (!q) return NULL;
  long got = 0;
  if (flags & BIONIC_MAP_ANONYMOUS) {
    if (prot != BIONIC_PROT_NONE) {
      memset(q, 0, length);
    }
  } else {
    if (fd >= 0) {
      got=read_map_at(fd,q,length,offset);
    }
    if ((size_t)got < length) memset((char *)q + got, 0, length - got);
  }
  mutexLock(&g_fb_lock);
  if (g_fb_n < MMAP_FALLBACK_MAX) { g_fb[g_fb_n].ptr = q; g_fb[g_fb_n].len = length; g_fb_n++; g_fb_bytes += length; }
  const size_t total = g_fb_bytes;
  mutexUnlock(&g_fb_lock);
  durak_log_printf("[mmap:FALLBACK] fallback %u KB -> %p  prot=0x%x anon=%d fd=%d off=0x%lx got=%ld (total %u MB)\n",
                   (unsigned)(length >> 10), q, prot, !!(flags & BIONIC_MAP_ANONYMOUS), fd, offset, got,
                   (unsigned)(total >> 20));
  durak_log_flush();
  return q;
}

// returns 1 and frees if addr was a fallback allocation
static int mmap_fallback_free(void *addr) {
  mutexLock(&g_fb_lock);
  for (int i = 0; i < g_fb_n; i++) {
    if (g_fb[i].ptr == addr) {
      free(addr);
      g_fb_bytes -= g_fb[i].len;
      g_fb[i] = g_fb[--g_fb_n];
      mutexUnlock(&g_fb_lock);
      return 1;
    }
  }
  mutexUnlock(&g_fb_lock);
  return 0;
}

// ---- read-only file-map dedup cache ---------------------------------------
// il2cpp builds a stack trace for every thrown managed exception (even caught
// ones -- GPG login retries, etc.), and the symbolizer mmaps libil2cpp.so
// (~40MB) + libunity.so (~25MB) read-only EACH TIME, never munmapping. Over a
// play session that is dozens of fresh copies (~1.4GB) that exhaust newlib ->
// the "arena FULL / out of RAM" self-exit. Dedup: hand back one shared, pinned
// buffer per (file inode, offset, length). Safe -- these maps are read-only.
#define MAPC_N 24
static struct { uint64_t ino; long off; size_t len; void *ptr; } g_mapc[MAPC_N];
static int g_mapc_n = 0;
static void *mapcache_get(uint64_t ino, long off, size_t len) {
  void *r = NULL;
  mutexLock(&g_fb_lock);
  for (int i = 0; i < g_mapc_n; i++)
    if (g_mapc[i].ino == ino && g_mapc[i].off == off && g_mapc[i].len == len) { r = g_mapc[i].ptr; break; }
  mutexUnlock(&g_fb_lock);
  return r;
}
static void mapcache_put(uint64_t ino, long off, size_t len, void *ptr) {
  mutexLock(&g_fb_lock);
  for (int i = 0; i < g_fb_n; i++)          // pin: drop from fallback free-list
    if (g_fb[i].ptr == ptr) { g_fb_bytes -= g_fb[i].len; g_fb[i] = g_fb[--g_fb_n]; break; }
  if (g_mapc_n < MAPC_N) { g_mapc[g_mapc_n].ino = ino; g_mapc[g_mapc_n].off = off;
                           g_mapc[g_mapc_n].len = len; g_mapc[g_mapc_n].ptr = ptr; g_mapc_n++; }
  mutexUnlock(&g_fb_lock);
}

void *mmap_fake(void *addr, size_t length, int prot, int flags, int fd, long offset) {
  (void)addr;
  if (length == 0) length = 1;

  // Big anonymous PROT_NONE reservations -> stack-region OC arena: cheap address
  // space now, physical aliased in on the later mprotect(RW). On a full window we
  // fall through to the heap-backed arena below (no behaviour change there).
  if (oc_pages && length >= MMAP_BIG_THRESH &&
      (flags & BIONIC_MAP_ANONYMOUS) && prot == BIONIC_PROT_NONE) {
    size_t ocres = 0;
    mutexLock(&g_mmap_lock);
    void *op = oc_alloc_locked(length, &ocres);
    mutexUnlock(&g_mmap_lock);
    if (op) {
      durak_log_printf("[mmap:OC] RESERVATION %u MB (prot=0x0 anon=1) -> %p  [OC reserve %u MB, live %u MB / pool %u MB]\n",
                       (unsigned)(length >> 20), op, (unsigned)(ocres >> 20),
                       (unsigned)((oc_live_pages * MMAP_PAGE) >> 20),
                       (unsigned)((oc_pool_pages * MMAP_PAGE) >> 20));
      durak_log_flush();
      return op;   // reserved-only; committed lazily via mprotect_fake
    }
    durak_log_printf("[mmap:OC] OC window full for %u MB -> heap-backed arena\n",
                     (unsigned)(length >> 20));
    durak_log_flush();
  }

  size_t reserved = 0;
  mutexLock(&g_mmap_lock);
  mmap_arena_init_locked();
  void *p = mmap_arena_alloc_locked(length, &reserved);
  mutexUnlock(&g_mmap_lock);
  if (length >= MMAP_BIG_THRESH || (p && prot == BIONIC_PROT_NONE)) {
    durak_log_printf("[mmap:ARENA] RESERVATION %u MB (prot=0x%x anon=%d) -> %p  [reserved %u MB]\n",
                     (unsigned)(length >> 20), prot, !!(flags & BIONIC_MAP_ANONYMOUS), p,
                     (unsigned)(reserved >> 20));
    durak_log_flush();
  }
  /* A file-backed map must be contiguous and fully readable. When the arena can
   * only give a tail-overflow reservation (reserved < length) we'd read just
   * `fill` bytes and leave the tail unfilled -- silently truncating the file in
   * RAM. For global-metadata.dat that nulls out System.Object (Class::Init NULL).
   * Hand any short-reserved file map to newlib, which backs the whole length. */
  if (p && !(flags & BIONIC_MAP_ANONYMOUS) && fd >= 0 && reserved < length) {
    mutexLock(&g_mmap_lock);
    mmap_arena_free(p, length);
    mutexUnlock(&g_mmap_lock);
    debugPrintf("[mmap] file fd=%d len=%zu: arena tail-overflow (reserved=%zu) -> newlib\n",
                fd, length, reserved);
    p = NULL;
  }
  if (!p) {
    // Arena exhausted (Unity's pools fill it). Route the request to newlib's free
    // heap regardless of size -- il2cpp's resource-extraction maps can exceed 64MB,
    // and rejecting them is what NULL-derefs the engine. Only a genuinely huge map
    // (> newlib free) will fail, and we log that distinctly.
    // Read-only file maps get deduped (backtrace .so symbolication leak, see above).
    int ro_file = fd >= 0 && !(flags & BIONIC_MAP_ANONYMOUS) && !(prot & BIONIC_PROT_WRITE);
    uint64_t mino = (ro_file && fd < FD_INO_MAX) ? g_fd_ino[fd] : 0;
    if (mino) { void *hit = mapcache_get(mino, offset, length); if (hit) return hit; }
    void *q = mmap_fallback(length, prot, flags, fd, offset);
    if (q) { if (mino) mapcache_put(mino, offset, length, q); return q; }
    durak_log_printf("[mmap] arena FULL and newlib fallback FAILED for %u MB (out of RAM)\n",
                     (unsigned)(length >> 20));
    durak_log_flush();
    errno = ENOMEM; return (void *)-1;
  }

  // Never touch beyond what we actually reserved in-arena (tail over-maps reserve
  // less than the requested length; the spill lives past the arena and is trimmed).
  size_t fill = length < reserved ? length : reserved;

  if (g_overcommit) {
    // PROT_NONE reservation: address space only, no physical -- the whole point.
    // The engine commits the sub-ranges it uses later via mprotect(RW).
    if (prot == BIONIC_PROT_NONE) return p;
    // Otherwise commit now (anon RW, file maps): svcMapPhysicalMemory zero-fills,
    // so anon needs no memset; file maps read their contents over the zeros.
    arena_commit_range(p, fill);
    if (!(flags & BIONIC_MAP_ANONYMOUS) && fd >= 0) {
      read_map_at(fd,p,fill,offset);
    }
    return p;
  }

  if (flags & BIONIC_MAP_ANONYMOUS) {
    if (prot != BIONIC_PROT_NONE) {
      memset(p, 0, fill);   // anonymous accessible memory must read back as zero
    }
  } else {
    // File-backed mapping: pull [offset, offset+fill) into RAM (no real mmap).
    long got = 0;
    if (fd >= 0) {
      got=read_map_at(fd,p,fill,offset);
    }
    if ((size_t)got < fill) memset((char *)p + got, 0, fill - (size_t)got);
    if (fd >= 0)
      debugPrintf("[mmap] file map fd=%d len=%zu reserved=%zu fill=%zu got=%ld%s\n",
                  fd, length, reserved, fill, got,
                  ((size_t)got < length) ? "  *** TRUNCATED ***" : "");
  }
  return p;
}

int munmap_fake(void *addr, size_t length) {
  if (mmap_fallback_free(addr)) {
    durak_log_printf("[munmap:FALLBACK] free %zu KB @ %p\n", length >> 10, addr);
    durak_log_flush();
    return 0;   // newlib fallback allocation
  }
  if (oc_contains(addr)) {                   // stack-region OC reservation
    mutexLock(&g_mmap_lock);
    oc_free_locked(addr, length);
    mutexUnlock(&g_mmap_lock);
    durak_log_printf("[munmap:OC] free %zu KB @ %p\n", length >> 10, addr);
    durak_log_flush();
    return 0;
  }
  arena_decommit_range(addr, length);       // reclaim physical (overcommit only)
  mmap_arena_free(addr, length);            // unreserve address space
  return 0;
}

// In overcommit mode mprotect drives commit/decommit: RW/R commits physical at
// the alias address, PROT_NONE decommits it (safe -- reuse re-mprotects to RW).
// In heap-backed mode the arena is always RW so this is a no-op.
int mprotect_fake(void *addr, size_t len, int prot) {
  /* Diagnostic (fires even heap-backed): measure Unity's commit pattern so we can
   * confirm it commits PROT_NONE reservations via mprotect(RW) and size the
   * overcommit commit-pool. Tracks cumulative RW-commit vs PROT_NONE-decommit
   * bytes that fall inside the mmap arena (= Unity's live committed footprint). */
  {
    static size_t rw_b = 0, none_b = 0;
    static unsigned rw_n = 0, none_n = 0, oth_n = 0;
    int in_arena = g_mmap_arena_base &&
                   (uint8_t *)addr >= (uint8_t *)g_mmap_arena_base &&
                   (uint8_t *)addr <  (uint8_t *)g_mmap_arena_base + g_mmap_arena_size;
    if (prot == BIONIC_PROT_NONE)       { none_n++; if (in_arena) none_b += len; }
    else if (prot & BIONIC_PROT_WRITE)  { rw_n++;   if (in_arena) rw_b   += len; }
    else                                  oth_n++;
    if (len >= 4u * 1024 * 1024 || ((rw_n + none_n) & 0x7F) == 0) {
      durak_log_printf("[mprot] addr=%p len=%zuKB prot=0x%x arena=%d oc=%d | RW %u/%zuMB NONE %u/%zuMB oth %u  net=%zdMB\n",
                       addr, len >> 10, prot, in_arena, oc_contains(addr), rw_n, rw_b >> 20, none_n, none_b >> 20, oth_n,
                       (ssize_t)(rw_b - none_b) >> 20);
      durak_log_flush();
    }
  }
  if (oc_contains(addr)) {
    // OC reservation being committed/decommitted. Unity only ever commits (RW);
    // decommits aren't observed, so PROT_NONE here is left mapped (cheap + safe).
    if (prot != BIONIC_PROT_NONE) {
      mutexLock(&g_mmap_lock);
      int oc_rc = oc_commit_locked(addr, len);
      mutexUnlock(&g_mmap_lock);
      if (oc_rc != 0) {
        durak_log_printf("[mprotect:OC ERROR] failed to commit addr=%p len=%zu (errno=%d)\n",
                         addr, len, errno);
        durak_log_flush();
        return -1;
      }
    }
    return 0;
  }
  if (!g_overcommit) return 0;
  if (prot == BIONIC_PROT_NONE) arena_decommit_range(addr, len);
  else                          arena_commit_range(addr, len);
  return 0;
}
// madvise(MADV_DONTNEED): overcommit zeroes-but-keeps (see arena_dontneed_range);
// heap-backed leaves pages as-is (always RW-backed).
int madvise_fake(void *addr, size_t len, int advice) {
  if (g_overcommit && advice == BIONIC_MADV_DONTNEED) arena_dontneed_range(addr, len);
  return 0;
}

// ---------------------------------------------------------------------------
// filesystem odds and ends
// ---------------------------------------------------------------------------

char *realpath_fake(const char *path, char *resolved) {
  if (!path) { errno = EINVAL; return NULL; }
  char res_buf[512];
  const char *rpath = durak_resolve_path(path, res_buf, sizeof(res_buf), 0);
  if (!rpath) rpath = path;
  if (!resolved) resolved = malloc(0x1000);
  if (resolved) {
    snprintf(resolved, 0x1000, "%s", rpath);
    durak_log_printf("[io] realpath(\"%s\" -> \"%s\")\n", path, resolved);
  }
  return resolved;
}
int strerror_r_fake(int err, char *buf, size_t len) { snprintf(buf, len, "%s", strerror(err)); return 0; }
int statvfs_fake(const char *path, void *buf) { (void)path; memset(buf, 0, 0x70); return 0; }
int statfs_fake(const char *path, void *buf) { (void)path; memset(buf, 0, 0x78); return 0; }

// Synthetic /proc and /sys files. Unity reads /proc/meminfo (MemTotal) to size
// its allocator reservations and /proc/cpuinfo + /sys cpu range to count cores
// for the job system. We report ~1 GB (NOT the real ~3 GB) so the engine's big
// 256MB-block dynamic-heap reservations stay within our mmap arena -- the arena
// is the real backing and has headroom, but Unity must not try to reserve 3 GB
// of address space up front. 3 cores (homebrew gets 0-2).
static const char *synthetic_proc(const char *path) {
  if (!path) return NULL;
  if (!strcmp(path, "/proc/meminfo"))
    return "MemTotal:        524288 kB\n"
           "MemFree:         393216 kB\n"
           "MemAvailable:    393216 kB\n"
           "Buffers:              0 kB\n"
           "Cached:               0 kB\n"
           "SwapTotal:            0 kB\n"
           "SwapFree:             0 kB\n";
  if (!strcmp(path, "/proc/cpuinfo"))
    return "processor\t: 0\nprocessor\t: 1\nprocessor\t: 2\n"
           "Features\t: fp asimd aes pmull sha1 sha2 crc32\n"
           "CPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x1\n"
           "CPU part\t: 0xd07\nCPU revision\t: 1\n";
  if (strstr(path, "cpu_capacity")) return "1024\n";
  if (strstr(path, "cpuinfo_max_freq") || strstr(path, "scaling_max_freq")) return "1785000\n";
  if (strstr(path, "cpuinfo_min_freq") || strstr(path, "scaling_min_freq")) return "1020000\n";
  if (strstr(path, "/cpu/possible") || strstr(path, "/cpu/present") || strstr(path, "/cpu/online"))
    return "0-2\n";
  if (!strncmp(path, "/proc/", 6) || !strncmp(path, "/sys/", 5)) return ""; // empty for the rest
  return NULL;
}

FILE *fopen_fake(const char *path, const char *mode) {
  if (!path) { errno = EINVAL; return NULL; }
  const char *synth = synthetic_proc(path);
  if (synth) {
    size_t n = strlen(synth);
    return fmemopen((void *)strdup(synth), n ? n : 1, "r");
  }
  const int writing = mode && strpbrk(mode, "wa+") != NULL;

  char resolved[512];
  const char *rpath = durak_resolve_path(path, resolved, sizeof(resolved), writing);
  if (!rpath) rpath = path;

  if (writing) { durak_sqlite_probe_mutation_begin(rpath,NULL);mkdir_parents(rpath); }

  FILE *f = fopen(rpath, mode);
  if(writing) durak_sqlite_probe_mutation_end();
  int err = (f == NULL) ? errno : 0;

  if (!f && !writing && mode && strchr(mode, 'r')) {
    char alt[320];
    if (basename_fallback(path, alt, sizeof(alt))) {
      f = fopen(alt, mode);
      if (f) {
        durak_log_printf("[io] fopen(\"%s\" -> \"%s\" [last-resort basename fallback], mode=\"%s\") -> %p\n",
                         path, alt, mode ? mode : "", (void *)f);
        rpath = alt;
        err = 0;
      } else {
        err = errno;
      }
    }
  }

  if (f) {
    if (writing) mark_write_fd(fileno(f));
    durak_log_printf("[io] fopen(\"%s\" -> \"%s\", mode=\"%s\") -> %p\n",
                     path, rpath, mode ? mode : "", (void *)f);
    if (mode && strchr(mode, 'r')) {
      const char *ext = strrchr(rpath, '.');
      if (ext && (strcasecmp(ext, ".mvgl") == 0 || strcasecmp(ext, ".unity3d") == 0))
        setvbuf(f, NULL, _IOFBF, 256 * 1024);
    }
  } else {
    durak_log_printf("[io] fopen(\"%s\" -> \"%s\", mode=\"%s\") -> NULL (errno=%d: %s)\n",
                     path, rpath, mode ? mode : "", err, strerror(err));
  }
  return f;
}

// ---------------------------------------------------------------------------
// stdio over the fake bionic __sF (stdin/stdout/stderr). libc++_shared wires
// std::cout/cerr/cin to &__sF[1]/[2]/[0]; these wrappers absorb writes to those
// fake FILEs and forward everything else to newlib.
// ---------------------------------------------------------------------------

uint8_t fake_sF[3][0x100]; // referenced by imports.c (__sF / std{in,out,err})

static int is_fake_file(const void *f) {
  const uint8_t *p = f;
  const uint8_t *base = (const uint8_t *)fake_sF;
  return p >= base && p < base + sizeof(fake_sF);
}

size_t fwrite_fake(const void *ptr, size_t size, size_t n, FILE *f) {
  if (is_fake_file(f)) {
#if DEBUG_LOG
    static char buf[0x400];
    const size_t total = size * n < sizeof(buf) - 1 ? size * n : sizeof(buf) - 1;
    memcpy(buf, ptr, total); buf[total] = '\0';
    debugPrintf("stdio: %s", buf);
#endif
    return n;
  }
  return fwrite(ptr, size, n, f);
}
size_t fread_fake(void *ptr, size_t size, size_t n, FILE *f) {
  if (is_fake_file(f)) return 0;
  return fread(ptr, size, n, f);
}
int fputc_fake(int c, FILE *f) { if (is_fake_file(f)) return c; return fputc(c, f); }
int fputs_fake(const char *s, FILE *f) { if (is_fake_file(f)) { debugPrintf("stdio: %s", s); return 0; } return fputs(s, f); }
int fflush_fake(FILE *f) { if (is_fake_file(f) || f == NULL) return 0; return fflush(f); }
int fclose_fake(FILE *f) { if (is_fake_file(f)) return 0;
  int fd = fileno(f);
  durak_ra_detach(fd);
  DurakProbeClose state;
  durak_probe_before_close(fd, &state);
  int r = fclose(f), err = errno;
  unsigned native = r < 0 ? fsdevGetLastResult() : 0;
  durak_probe_after_close(&state, r, err, native);
  commit_write_fd(fd); errno = err; return r; }
int ferror_fake(FILE *f) { if (is_fake_file(f)) return 0; return ferror(f); }
int feof_fake(FILE *f) { if (is_fake_file(f)) return 1; return feof(f); }
int fileno_fake(FILE *f) { if (is_fake_file(f)) return ((const uint8_t *)f - &fake_sF[0][0]) / 0x100; return fileno(f); }
int fseek_fake(FILE *f, long off, int whence) { if (is_fake_file(f)) return -1; return fseek(f, off, whence); }
long ftell_fake(FILE *f) { if (is_fake_file(f)) return -1; return ftell(f); }
int getc_fake(FILE *f) { if (is_fake_file(f)) return -1; return getc(f); }
int fgetc_fake(FILE *f) { if (is_fake_file(f)) return -1; return fgetc(f); }
char *fgets_fake(char *s, int n, FILE *f) { if (is_fake_file(f)) return NULL; return fgets(s, n, f); }
int ungetc_fake(int c, FILE *f) { if (is_fake_file(f)) return -1; return ungetc(c, f); }
void setbuf_fake(FILE *f, char *buf) { if (is_fake_file(f)) return; setbuf(f, buf); }

int fprintf_fake(FILE *f, const char *fmt, ...) {
  va_list va; va_start(va, fmt);
  int ret;
  if (is_fake_file(f)) {
#if DEBUG_LOG
    static char buf[0x400];
    ret = vsnprintf(buf, sizeof(buf), fmt, va);
    debugPrintf("stdio: %s", buf);
#else
    ret = 0;
#endif
  } else {
    ret = vfprintf(f, fmt, va);
  }
  va_end(va);
  return ret;
}
int vfprintf_fake(FILE *f, const char *fmt, va_list va) {
  if (is_fake_file(f)) {
#if DEBUG_LOG
    static char buf[0x400];
    int ret = vsnprintf(buf, sizeof(buf), fmt, va);
    debugPrintf("stdio: %s", buf);
    return ret;
#else
    return 0;
#endif
  }
  return vfprintf(f, fmt, va);
}

// ---------------------------------------------------------------------------
// fd routing: the native_app_glue command pipe lives in the fake-fd layer
// (android_native.c). Real files (small fds from open()) pass through to newlib.
// ---------------------------------------------------------------------------

long read_fake(int fd, void *buf, size_t count) {
  if (fakefd_is_fake(fd)) return fakefd_read(fd, buf, count);
  { long result; if(durak_ra_read(fd,buf,count,&result)) return result; }
  /* fsdev can return fewer bytes than requested for a large read; il2cpp's
   * global-metadata.dat loader (and others) assume a single read() fills the
   * buffer. Loop until `count` is satisfied or we hit EOF/error so the metadata
   * is never silently truncated (a short read leaves System.Object et al.
   * unresolvable -> Class::Init(NULL)). */
  size_t total = 0;
  while (total < count) {
    long r = read(fd, (char *)buf + total, count - total);
    if (r < 0) {
      int saved_errno = errno;
      Result native_error = fsdevGetLastResult();
      long position = lseek(fd, 0, SEEK_CUR);
      struct stat st;
      int metadata_ok = fstat(fd, &st) == 0;
      /* Horizon DryRead rejects offset > file size. POSIX read must return
       * EOF there; SQLite probes the next journal header past its current end.
       * Recover only this proven range case, never an in-range storage error. */
      int eof = saved_errno == EIO && position >= 0 && metadata_ok &&
                S_ISREG(st.st_mode) && position > st.st_size;
      durak_log_printf("[io] read %s: fd=%d offset=%ld count=%zu size=%lld errno=%d result=0x%x caller=%p\n",
                       eof ? "past EOF" : "FAILED", fd, position, count - total,
                       metadata_ok ? (long long)st.st_size : -1LL,
                       saved_errno, native_error, __builtin_return_address(0));
      errno = saved_errno;
      if (eof || total) return (long)total;
      return -1;
    }
    if (r == 0) break; /* EOF */
    total += (size_t)r;
  }
  if (count >= (1u << 20))
    debugPrintf("[io] read(fd=%d, %zu) -> %zu%s\n", fd, count, total,
                total < count ? "  *** SHORT READ ***" : "");
  watch_dump("read", fd, (long)count, 0, buf, (long)total);
  return (long)total;
}
long write_fake(int fd, const void *buf, size_t count) {
  if (fakefd_is_fake(fd)) return fakefd_write(fd, buf, count);
  return write(fd, buf, count);
}
int close_fake(int fd) {
  durak_ra_detach(fd);
  fd_ino_clear(fd);
  if (fakefd_is_fake(fd)) return fakefd_close(fd);
  DurakProbeClose state;
  durak_probe_before_close(fd, &state);
  int r = close(fd);
  int err = errno;
  unsigned native = r < 0 ? fsdevGetLastResult() : 0;
  durak_probe_after_close(&state, r, err, native);
  commit_write_fd(fd);   /* flush a just-written save to the physical SD */
  errno = err;
  return r;
}
int pipe_fake(int fds[2]) { return fakefd_pipe(fds); }
int poll_fake(void *fds, unsigned long nfds, int timeout) { (void)fds; (void)nfds; (void)timeout; return 0; }
int select_fake(int n, void *r, void *w, void *e, void *t) { (void)n; (void)r; (void)w; (void)e; (void)t; return 0; }

// ---------------------------------------------------------------------------
// networking: online play (Mobage / Silicon Studio servers) is dead. Stub the
// socket layer so connections fail and the engine stays in offline mode.
// ---------------------------------------------------------------------------

int socket_fake(int d, int t, int p) { (void)d; (void)t; (void)p; errno = EAFNOSUPPORT; return -1; }
int connect_fake(int s, const void *a, unsigned l) { (void)s; (void)a; (void)l; errno = ECONNREFUSED; return -1; }
int bind_fake(int s, const void *a, unsigned l) { (void)s; (void)a; (void)l; errno = EACCES; return -1; }
int listen_fake(int s, int b) { (void)s; (void)b; return -1; }
int accept_fake(int s, void *a, void *l) { (void)s; (void)a; (void)l; errno = EINVAL; return -1; }
long send_fake(int s, const void *b, size_t l, int f) { (void)s; (void)b; (void)l; (void)f; errno = EPIPE; return -1; }
long recv_fake(int s, void *b, size_t l, int f) { (void)s; (void)b; (void)l; (void)f; return 0; }
long sendto_fake(int s, const void *b, size_t l, int f, const void *a, unsigned al) { (void)s; (void)b; (void)l; (void)f; (void)a; (void)al; errno = EPIPE; return -1; }
long recvfrom_fake(int s, void *b, size_t l, int f, void *a, void *al) { (void)s; (void)b; (void)l; (void)f; (void)a; (void)al; return 0; }
int shutdown_fake(int s, int how) { (void)s; (void)how; return 0; }
int setsockopt_fake(int s, int lv, int n, const void *v, unsigned l) { (void)s; (void)lv; (void)n; (void)v; (void)l; return 0; }
int getsockopt_fake(int s, int lv, int n, void *v, void *l) { (void)s; (void)lv; (void)n; (void)v; (void)l; return -1; }
int getsockname_fake(int s, void *a, void *l) { (void)s; (void)a; (void)l; return -1; }
int getpeername_fake(int s, void *a, void *l) { (void)s; (void)a; (void)l; return -1; }
int getaddrinfo_fake(const char *node, const char *svc, const void *hints, void **res) { (void)node; (void)svc; (void)hints; if (res) *res = NULL; return -2 /* EAI_NONAME */; }
void freeaddrinfo_fake(void *res) { (void)res; }
int getnameinfo_fake(const void *a, unsigned al, char *h, unsigned hl, char *s, unsigned sl, int f) { (void)a; (void)al; (void)f; if (h && hl) h[0] = 0; if (s && sl) s[0] = 0; return -1; }
int gethostname_fake(char *name, size_t len) { if (name && len) snprintf(name, len, "switch"); return 0; }
void *getservbyname_fake(const char *n, const char *p) { (void)n; (void)p; return NULL; }
unsigned if_nametoindex_fake(const char *n) { (void)n; return 0; }
char *if_indextoname_fake(unsigned i, char *buf) { (void)i; if (buf) buf[0] = 0; return buf; }
static volatile int g_h_errno = 0;
int *__get_h_errno_fake(void) { return (int *)&g_h_errno; }

// ---------------------------------------------------------------------------
// process control: fork/exec/etc. are unavailable; report failure.
// ---------------------------------------------------------------------------

int fork_fake(void) { errno = ENOSYS; return -1; }
int execvp_fake(const char *f, char *const argv[]) { (void)f; (void)argv; errno = ENOSYS; return -1; }
int waitpid_fake(int pid, int *status, int opts) { (void)pid; (void)opts; if (status) *status = 0; errno = ECHILD; return -1; }
int kill_fake(int pid, int sig) { (void)pid; (void)sig; return 0; }
int getpid_fake(void) { return 1; }
int sched_yield_fake(void) { svcSleepThread(0); return 0; }
// bionic struct passwd layout (pw_dir at +0x20, as the engine derefs).
struct bionic_passwd {
  char *pw_name;     /* 0x00 */
  char *pw_passwd;   /* 0x08 */
  uint32_t pw_uid;   /* 0x10 */
  uint32_t pw_gid;   /* 0x14 */
  char *pw_gecos;    /* 0x18 */
  char *pw_dir;      /* 0x20 */
  char *pw_shell;    /* 0x28 */
};
void *getpwuid_fake(int uid) {
  (void)uid;
  static struct bionic_passwd pw;
  static char nm[] = "switch", dir[] = GAME_HOME, sh[] = "/bin/sh", empty[] = "";
  pw.pw_name = nm; pw.pw_passwd = empty; pw.pw_uid = 0; pw.pw_gid = 0;
  pw.pw_gecos = empty; pw.pw_dir = dir; pw.pw_shell = sh;
  return &pw;
}

// Unity computes its home/cache dir via getenv("HOME") (then getpwuid fallback).
// Serve the writable game root for HOME/TMPDIR; delegate everything else to newlib.
const char *managed_path(const char *p) {
  if (!p) return p;
  const char *c = strchr(p, ':');
  return (c && c[1] == '/') ? c + 1 : p;     // "sdmc:/switch/.." -> "/switch/.."
}
char *getenv_fake(const char *name) {
  if (name) {
    if (!strcmp(name, "HOME"))   return (char *)managed_path(GAME_HOME);
    if (!strcmp(name, "TMPDIR")) return (char *)managed_path(GAME_HOME);
  }
  return getenv(name);
}
// Report a Unix-rooted cwd ("/switch/zookeeper", no "sdmc:") so managed Path
// APIs don't treat it as relative in Path.Combine. newlib's *internal* cwd is
// unchanged, so relative file resolution still works via the default device.
char *getcwd_fake(char *buf, size_t size) {
  char *r = getcwd(buf, size);
  if (!r) return r;
  const char *c = strchr(r, ':');
  if (c && c[1] == '/') memmove(r, c + 1, strlen(c + 1) + 1);  // drop "sdmc:"
  return r;
}
int getrusage_fake(int who, void *usage) { (void)who; if (usage) memset(usage, 0, 144); return 0; }

// ---------------------------------------------------------------------------
// dlopen/dlsym over the already-loaded modules (no real dynamic loading).
// dlsym lets the engine look up its own exports / our shims.
// ---------------------------------------------------------------------------

void *dlopen_fake(const char *name, int flags) {
  (void)flags; debugPrintf("dlopen(%s)\n", name ? name : "(self)");
  return (void *)0x1;
}
int dlclose_fake(void *h) { (void)h; return 0; }
const char *dlerror_fake(void) { return NULL; }

/* Observe managed SQLite P/Invokes at their exported C ABI. Preserve original
 * errors and DB configuration; successful inventory reads grant local items
 * before their first step. Inventory write failures are logged and returned. */
static void *sqlite_export(const char *name) {
  void *address=durak_sqlite_export(name,so_resolve_external);
  if(!address) fatal_error("Required SQLite export missing: %s",name);
  return address;
}
static void sqlite_diagnostic(void *db, const char *operation, const char *sql, int rc, int saved_errno) {
  int (*extended)(void *) = sqlite_export("sqlite3_extended_errcode");
  const char *(*message)(void *) = sqlite_export("sqlite3_errmsg");
  const char *(*filename)(void *, const char *) = sqlite_export("sqlite3_db_filename");
  durak_log_printf("[sqlite] %s db=%p file=%s rc=%d extended=%d errno=%d message=%s sql=%.512s\n",
                   operation, db, db && filename ? filename(db, "main") : "?", rc,
                   db && extended ? extended(db) : rc, saved_errno,
                   db && message ? message(db) : "?", sql ? sql : "");
  errno = saved_errno;
}
static int sqlite_open_diag(const char *path, void **db) {
  int (*fn)(const char *, void **) = sqlite_export("sqlite3_open");
  uint64_t start=durak_boot_measure_now();
  int rc = fn(path, db), saved = errno;
  durak_boot_measure_span(BOOT_SQL_OPEN,start,0);
  sqlite_diagnostic(db ? *db : NULL, "open", path, rc, saved);
  return rc;
}
static int sqlite_open_v2_diag(const char *path, void **db, int flags, const char *vfs) {
  int (*fn)(const char *, void **, int, const char *) = sqlite_export("sqlite3_open_v2");
  uint64_t start=durak_boot_measure_now();
  int rc = fn(path, db, flags, vfs), saved = errno;
  durak_boot_measure_span(BOOT_SQL_OPEN,start,0);
  durak_log_printf("[sqlite] open_v2 flags=0x%x vfs=%s\n", flags, vfs ? vfs : "default");
  sqlite_diagnostic(db ? *db : NULL, "open_v2", path, rc, saved);
  return rc;
}
static int sqlite_prepare_v2_diag(void *db, const char *sql, int len, void **stmt, const char **tail) {
  int (*fn)(void *, const char *, int, void **, const char **) = sqlite_export("sqlite3_prepare_v2");
  uint64_t start=durak_boot_measure_now();
  int rc = fn(db, sql, len, stmt, tail), saved = errno;
  durak_boot_measure_span(BOOT_SQL_PREPARE,start,0);
  /* Preserve the original prepare error. Grant only after a valid inventory
   * SELECT is prepared, but before its first step creates the read snapshot. */
  if(!rc && stmt && *stmt) {
    start=durak_boot_measure_now();
    rc=durak_inventory_before_query(db,sql,len,sqlite_export);
    saved=errno;
    durak_boot_measure_span(BOOT_INVENTORY,start,0);
    if(rc) {
      int (*finalize)(void *)=sqlite_export("sqlite3_finalize");
      int cleanup=finalize(*stmt);
      if(cleanup) sqlite_diagnostic(db,"inventory finalize",NULL,cleanup,errno);
      *stmt=NULL;
    }
  }
  if (rc) {
    char query[513];
    size_t limit = len < 0 ? 512 : (len < 512 ? (size_t)len : 512);
    size_t n = sql ? strnlen(sql, limit) : 0;
    if (n) memcpy(query, sql, n);
    query[n] = 0;
    sqlite_diagnostic(db, "prepare_v2", query, rc, saved);
  }
  errno = saved;
  return rc;
}
static int sqlite_step_diag(void *stmt) {
  int (*fn)(void *) = sqlite_export("sqlite3_step");
  void *(*handle)(void *) = sqlite_export("sqlite3_db_handle");
  const char *(*sql_fn)(void *) = sqlite_export("sqlite3_sql");
  uint64_t start=durak_boot_measure_now();
  int rc = fn(stmt), saved = errno;
  durak_boot_measure_span(BOOT_SQL_STEP,start,0);
  const char *sql = sql_fn ? sql_fn(stmt) : NULL;
  if ((rc != 100 && rc != 101) || (sql && !strncasecmp(sql, "create", 6)))
    sqlite_diagnostic(handle ? handle(stmt) : NULL, "step", sql, rc, saved);
  errno = saved;
  return rc;
}
void *dlsym_fake(void *handle, const char *symbol) {
  (void)handle;
  if (!symbol) return NULL;
  /* Firebase SWIG stub resolver (firebase_stub.c) -- see step 2b below. */
  extern void *firebase_stub_lookup(const char *symbol);
  /* 1) a real export from a loaded module (il2cpp/unity/main) */
  void *p = so_resolve_external(symbol);
  if (p) {
    if (!strcmp(symbol, "sqlite3_open")) return (void *)&sqlite_open_diag;
    if (!strcmp(symbol, "sqlite3_open_v2")) return (void *)&sqlite_open_v2_diag;
    if (!strcmp(symbol, "sqlite3_prepare_v2")) return (void *)&sqlite_prepare_v2_diag;
    if (!strcmp(symbol, "sqlite3_step")) return (void *)&sqlite_step_diag;
    return p;
  }
  /* 2) one of our libc/GLES/EGL shims (the engine dlopen()s libGLESv2.so etc.
   *    and dlsym()s glGetString/glGetIntegerv, which are shims, not exports) */
  uintptr_t shim = dynlib_find_export(symbol);
  if (shim) { debugPrintf("dlsym(%s) -> %p [shim]\n", symbol, (void *)shim); return (void *)shim; }
  /* 2b) Firebase SWIG P/Invokes. The real Firebase .so files are intentionally
   *     NOT loaded (they crash our loader at boot and, lacking Play Services,
   *     could never report DependencyStatus.Available on a Switch anyway). We
   *     answer the managed SDK's native lookups with trivial stubs so the
   *     dependency check resolves to Available(0) and the bootstrap advances. */
  void *fb = firebase_stub_lookup(symbol);
  if (fb) return fb;
  /* 3) the full GLES/EGL API (~150 entry points) lives in mesa, beyond our
   *    static table -- resolve any gl or egl symbol via eglGetProcAddress. */
  if (!strncmp(symbol, "gl", 2) || !strncmp(symbol, "egl", 3)) {
    p = (void *)eglGetProcAddress(symbol);
    if (p) { debugPrintf("dlsym(%s) -> %p [egl]\n", symbol, p); return p; }
  }
  debugPrintf("dlsym(%s) -> NULL\n", symbol);
  return NULL;
}

// ---------------------------------------------------------------------------
// pthread extras: rwlocks, semaphores, timed locks
// ---------------------------------------------------------------------------

typedef struct { RwLock lock; } FakeRwLock;

static FakeRwLock *get_rwlock(void **storage) {
  if (!*storage) { FakeRwLock *l = calloc(1, sizeof(*l)); rwlockInit(&l->lock); *storage = l; }
  return *storage;
}
int pthread_rwlock_rdlock_fake(void **rw) { RwLock *l=&get_rwlock(rw)->lock; diag_wait_enter(DIAG_W_RWLOCK,l); rwlockReadLock(l); diag_wait_exit(); return 0; }
int pthread_rwlock_wrlock_fake(void **rw) { RwLock *l=&get_rwlock(rw)->lock; diag_wait_enter(DIAG_W_RWLOCK,l); rwlockWriteLock(l); diag_wait_exit(); return 0; }
int pthread_rwlock_unlock_fake(void **rw) {
  FakeRwLock *l = get_rwlock(rw);
  if (rwlockIsWriteLockHeldByCurrentThread(&l->lock)) rwlockWriteUnlock(&l->lock);
  else rwlockReadUnlock(&l->lock);
  return 0;
}

typedef struct { Semaphore sem; } FakeSem;
int sem_init_fake(void **s, int pshared, unsigned int value) { (void)pshared; FakeSem *fs = calloc(1, sizeof(*fs)); semaphoreInit(&fs->sem, value); *s = fs; return 0; }
int sem_destroy_fake(void **s) { if (s && *s) { free(*s); *s = NULL; } return 0; }
int sem_post_fake(void **s) { if (s && *s) semaphoreSignal(&((FakeSem *)*s)->sem); return 0; }
int sem_wait_fake(void **s) { if (s && *s) { Semaphore *sm=&((FakeSem *)*s)->sem; diag_wait_enter(DIAG_W_SEM,sm); semaphoreWait(sm); diag_wait_exit(); } return 0; }
int sem_trywait_fake(void **s) { if (s && *s && semaphoreTryWait(&((FakeSem *)*s)->sem)) return 0; errno = EAGAIN; return -1; }
int sem_getvalue_fake(void **s, int *val) { if (s && *s) *val = (int)((FakeSem *)*s)->sem.count; else *val = 0; return 0; }
// no native timed wait on libnx Semaphore; poll with a short backoff to the
// deadline. The engine uses it as a yield-with-timeout in its task scheduler.
int sem_timedwait_fake(void **s, const struct timespec *abs) {
  (void)abs;
  for (int i = 0; i < 1000; i++) {
    if (sem_trywait_fake(s) == 0) return 0;
    svcSleepThread(1000000ull); // 1 ms
  }
  errno = ETIMEDOUT;
  return -1;
}

/* --- Boehm GC stop-the-world bridge -------------------------------------
 * In Unity/IL2CPP, Boehm GC implements stop-the-world synchronization using
 * POSIX signals (pthread_kill with GC_suspend_sig and GC_restart_sig).
 * On Linux/Android, each signaled thread enters its signal handler, saves its
 * stack context, posts an acknowledgement to GC_suspend_ack_sem, and suspends
 * in sigsuspend(). GC_stop_world loops calling sem_wait on those acks.
 *
 * Horizon OS / Atmosphère has no kernel-level POSIX signal delivery. Signals sent
 * via standard pthread_kill are never delivered and their handlers never run.
 * If pthread_kill is a blind stub returning success (0) without posting an ack,
 * GC_stop_world enters an unrecoverable infinite hang on sem_wait during the very
 * first garbage collection.
 *
 * ARCHITECTURAL JUSTIFICATION FOR COOPERATIVE ACK WITHOUT HARD SUSPENSION:
 * 1. Why not svcSetThreadActivity(ThreadActivity_Paused)?
 *    Pausing arbitrary threads asynchronously from userspace carries severe deadlock risk:
 *    if a thread is paused while holding any runtime lock (e.g. malloc_lock, newlib
 *    reentrant locks, logging mutexes, or IPC channels), and the GC collector thread
 *    subsequently attempts to acquire that lock, the system deadlocks immediately.
 *    POSIX signals avoid this because they execute in the target thread's own execution
 *    context at safe userspace boundaries, whereas svcSetThreadActivity is an external stop.
 * 2. Why is cooperative acking safe for Unity/IL2CPP in Durak?
 *    In Unity's runtime architecture, managed C# execution is fundamentally single-threaded
 *    on the MainEngine thread during initialization and frame execution (Update/Render).
 *    Auxiliary engine worker threads (Job.Worker*, AsyncReadManager) are native threads
 *    that spend idle time parked inside libc synchronization primitives (semaphoreWait,
 *    pthread_cond_timedwait, diag_wait_enter). When parked in our shim, their call stacks
 *    are stationary and they cannot concurrently mutate managed object references.
 *    Therefore, having pthread_kill post the ack directly satisfies the GC handshake
 *    contract without introducing external deadlock hazards.
 *
 * DEFENSIVE FAIL-SAFES:
 * 1. Module bounds guard: verifies offsets are within mapped libil2cpp memory.
 * 2. Instruction word guards: matches 8 ARM64 instructions at the exact call and
 *    data sites in libil2cpp to prevent execution against stale/foreign binaries.
 * 3. Signal sanity validation: verifies signal numbers are positive and valid (SIGPWR=30, SIGXCPU=24).
 * If any guard fails, the bridge fails closed safely with diagnostic logs rather than faulting.
 */
uintptr_t g_il2cpp_base = 0;

/* Offsets recovered from Durak's actual libil2cpp.so (31,256,704 bytes, Unity 6000.0.23f1):
 *   0x0c5d200 GC_suspend_all:
 *     0x0c5d230: adrp x24, #0x1dda000
 *     0x0c5d26c: ldr  w1, [x24, #0x484] ; bl pthread_kill @0x0c5d270 -> 0x1dda484
 *   0x0c5d444 GC_restart_all:
 *     0x0c5d470: adrp x23, #0x1dda000
 *     0x0c5d474: adrp x24, #0x1dda000
 *     0x0c5d4b0: ldr  w8, [x23, #0x480] ; gate check                  -> 0x1dda480
 *     0x0c5d4cc: ldr  w1, [x24, #0x488] ; bl pthread_kill @0x0c5d4d0 -> 0x1dda488
 *   0x0c5d560 GC_stop_init:
 *     0x0c5d5a0: adrp x0, #0x1ff9000
 *     0x0c5d5a4: add  x0, x0, #0x188    ; bl sem_init @0x0c5d5b0      -> 0x1ff9188
 *   0x0c5d3d4 GC_wait_for_acks:
 *     0x0c5d3ec: adrp x20, #0x1ff9000
 *     0x0c5d3f0: add  x20, x20, #0x188   ; bl sem_wait @0x0c5d3f8     -> 0x1ff9188
 */
#define GC_START_ACK_OFF   0x1dda480   /* GC_retry_signals, restart-ack gate (int) -> 1  */
#define GC_SUSPEND_SIG_OFF 0x1dda484   /* GC_sig_suspend      (int)   -> 30 (SIGPWR)    */
#define GC_RESTART_SIG_OFF 0x1dda488   /* GC_sig_thr_restart  (int)   -> 24 (SIGXCPU)   */
#define GC_ACK_SEM_OFF     0x1ff9188   /* GC_suspend_ack_sem  (void*) (sem_t)           */

#define GC_MAX_OFF         (GC_ACK_SEM_OFF + sizeof(void *))

typedef struct { uint32_t off; uint32_t word; const char *what; } GcGuard;
static const GcGuard gc_guards[] = {
  { 0x0c5d230, 0xb0008bf8, "GC_suspend_all adrp x24, #0x1dda000" },
  { 0x0c5d26c, 0xb9448701, "GC_suspend_all ldr w1, [x24, #0x484]" },
  { 0x0c5d470, 0xb0008bf7, "GC_restart_all adrp x23, #0x1dda000" },
  { 0x0c5d474, 0xb0008bf8, "GC_restart_all adrp x24, #0x1dda000" },
  { 0x0c5d4b0, 0xb94482e8, "GC_restart_all ldr w8, [x23, #0x480]" },
  { 0x0c5d4cc, 0xb9448b01, "GC_restart_all ldr w1, [x24, #0x488]" },
  { 0x0c5d5a0, 0x90009ce0, "GC_stop_init adrp x0, #0x1ff9000"    },
  { 0x0c5d5a4, 0x91062000, "GC_stop_init add x0, x0, #0x188"      },
};

int pthread_kill_gc(pthread_t t, int sig) {
  (void)t;
  uintptr_t b = g_il2cpp_base;
  if (!b) return 0;

  /* FAIL-SAFE 1: Verify offsets remain within mapped module bounds */
  so_module *m = so_find_module_by_addr((const void *)b);
  if (m && m->load_size && GC_MAX_OFF > m->load_size) {
    static int logged_oob = 0;
    if (!logged_oob) {
      logged_oob = 1;
      durak_log_printf("[gc] BRIDGE DISABLED: offsets exceed libil2cpp size (max 0x%x > 0x%zx)\n",
                       (unsigned)GC_MAX_OFF, m->load_size);
      durak_log_flush();
    }
    return 0;
  }

  /* FAIL-SAFE 2: Verify all 8 instruction words before trusting memory layout */
  static int guards_state = 0; /* 0 = unchecked, 1 = pass, -1 = fail */
  if (guards_state == 0) {
    const unsigned n = (unsigned)(sizeof(gc_guards) / sizeof(gc_guards[0]));
    guards_state = 1;
    for (unsigned i = 0; i < n; i++) {
      uint32_t got = *(volatile uint32_t *)(b + gc_guards[i].off);
      if (got != gc_guards[i].word) {
        guards_state = -1;
        durak_log_printf("[gc] BRIDGE DISABLED: guard %u/%u failed at il2cpp+0x%x: expected %08x (%s), found %08x\n",
                         i + 1u, n, (unsigned)gc_guards[i].off,
                         (unsigned)gc_guards[i].word, gc_guards[i].what,
                         (unsigned)got);
        durak_log_flush();
        break;
      }
    }
    if (guards_state == 1) {
      durak_log_printf("[gc] bridge guards OK (%u instruction words verified)\n", n);
      durak_log_flush();
    }
  }
  if (guards_state < 0) return 0;

  if (sig) {
    int suspend_sig = *(volatile int *)(b + GC_SUSPEND_SIG_OFF);
    int restart_sig = *(volatile int *)(b + GC_RESTART_SIG_OFF);

    /* SANITY CHECK: Before GC_stop_init runs, values are -1 (SIGNAL_UNSET).
     * After GC_stop_init, expected values are SIGPWR(30) and SIGXCPU(24). */
    static int checked = 0;
    if (!checked && suspend_sig > 0 && restart_sig > 0) {
      checked = 1;
      int ok = (suspend_sig < 65 && restart_sig < 65 && suspend_sig != restart_sig);
      durak_log_printf("[gc] bridge offsets %s: suspend_sig=%d restart_sig=%d (il2cpp+0x%x / 0x%x)%s\n",
                       ok ? "VALID" : "INVALID",
                       suspend_sig, restart_sig,
                       (unsigned)GC_SUSPEND_SIG_OFF, (unsigned)GC_RESTART_SIG_OFF,
                       ok ? " (SIGPWR=30 / SIGXCPU=24)" : " (unexpected signal numbers)");
      durak_log_flush();
    }

    void **ack_sem = (void **)(b + GC_ACK_SEM_OFF);

    if (sig == suspend_sig) { /* stop-the-world: acknowledge suspend */
      static int logged_s = 0;
      if (!logged_s) {
        logged_s = 1;
        durak_log_printf("[gc] stop-world suspend sig=%d -> acking via sem@il2cpp+0x%x (first time)\n",
                         sig, (unsigned)GC_ACK_SEM_OFF);
        durak_log_flush();
      }
      sem_post_fake(ack_sem);
      return 0;
    }

    if (sig == restart_sig) { /* start-the-world: acknowledge restart if gate set */
      static int logged_r = 0;
      if (!logged_r) {
        logged_r = 1;
        durak_log_printf("[gc] start-world restart sig=%d gate=%d (first time)\n",
                         sig, *(volatile int *)(b + GC_START_ACK_OFF));
        durak_log_flush();
      }
      if (*(volatile int *)(b + GC_START_ACK_OFF)) {
        sem_post_fake(ack_sem);
      }
      return 0;
    }
  }

  return 0; /* any other signal: no-op */
}
