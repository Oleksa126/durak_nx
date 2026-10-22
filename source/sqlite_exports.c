#include "sqlite_exports.h"
#include "boot_measure.h"
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#ifdef __SWITCH__
#include <switch.h>
static Mutex lock;
#define LOCK() mutexLock(&lock)
#define UNLOCK() mutexUnlock(&lock)
#else
#include <pthread.h>
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
#define LOCK() pthread_mutex_lock(&lock)
#define UNLOCK() pthread_mutex_unlock(&lock)
#endif
static struct { const char *name; atomic_uintptr_t address; } exports[]={
  {"sqlite3_step",0}, {"sqlite3_db_handle",0}, {"sqlite3_sql",0},
  {"sqlite3_prepare_v2",0}, {"sqlite3_open",0}, {"sqlite3_open_v2",0},
  {"sqlite3_extended_errcode",0}, {"sqlite3_errmsg",0},
  {"sqlite3_db_filename",0}, {"sqlite3_finalize",0},
  {"sqlite3_column_text",0}, {"sqlite3_column_int",0}, {"sqlite3_exec",0}
};
void *durak_sqlite_export(const char *name,void *(*resolve)(const char *)) {
  if(!name || !resolve) return NULL;
  for(size_t i=0;i<sizeof(exports)/sizeof(exports[0]);++i) {
    if(strcmp(exports[i].name,name)) continue;
    uintptr_t address=atomic_load_explicit(&exports[i].address,memory_order_acquire);
    if(address) return (void *)address;
    int saved=errno;
    LOCK();
    address=atomic_load_explicit(&exports[i].address,memory_order_relaxed);
    if(!address) {
      uint64_t begin=durak_boot_measure_now();
      address=(uintptr_t)resolve(name);
      durak_boot_measure_span(BOOT_SQL_RESOLVE,begin,0);
      if(address) atomic_store_explicit(&exports[i].address,address,memory_order_release);
    }
    UNLOCK(); errno=saved;
    return (void *)address;
  }
  return resolve(name);
}
