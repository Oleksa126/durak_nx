#define _POSIX_C_SOURCE 200809L
#include "sqlite_exports.h"
#include "boot_measure.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static atomic_int calls;
static int step_address,handle_address,sql_address,open_address,open_available;
static void *resolve(const char *name) {
  atomic_fetch_add(&calls,1);
  errno=EIO;
  if(!strcmp(name,"sqlite3_step")) return &step_address;
  if(!strcmp(name,"sqlite3_db_handle")) return &handle_address;
  if(!strcmp(name,"sqlite3_sql")) return &sql_address;
  if(!strcmp(name,"sqlite3_open") && open_available) return &open_address;
  return NULL;
}
uint64_t durak_boot_measure_now(void) { return 1; }
void durak_boot_measure_span(DurakBootMetric k,uint64_t begin,uint64_t bytes) {
  (void)begin; (void)bytes; assert(k==BOOT_SQL_RESOLVE);
}
static void *worker(void *unused) {
  (void)unused;
  for(int i=0;i<1000;++i) {
    errno=ERANGE;
    assert(durak_sqlite_export("sqlite3_step",resolve)==&step_address);
    assert(durak_sqlite_export("sqlite3_db_handle",resolve)==&handle_address);
    assert(durak_sqlite_export("sqlite3_sql",resolve)==&sql_address);
    assert(errno==ERANGE);
  }
  return NULL;
}
int main(void) {
  pthread_t threads[4];
  for(int i=0;i<4;++i) assert(!pthread_create(&threads[i],NULL,worker,NULL));
  for(int i=0;i<4;++i) assert(!pthread_join(threads[i],NULL));
  assert(atomic_load(&calls)==3);
  errno=ERANGE;
  assert(!durak_sqlite_export("sqlite3_open",resolve) && errno==ERANGE);
  assert(!durak_sqlite_export("sqlite3_open",resolve));
  assert(atomic_load(&calls)==5); /* A missing export is never cached as success. */
  open_available=1;
  assert(durak_sqlite_export("sqlite3_open",resolve)==&open_address && errno==ERANGE);
  for(int i=0;i<100;++i) assert(durak_sqlite_export("sqlite3_open",resolve)==&open_address);
  assert(atomic_load(&calls)==6);
  assert(!durak_sqlite_export("outside_allowlist",resolve) && errno==EIO);
  assert(!durak_sqlite_export("outside_allowlist",resolve));
  assert(atomic_load(&calls)==8);
  assert(!durak_sqlite_export(NULL,resolve));
  puts("SQLite exports: PASS (one lookup per export, concurrent hits, errno, missing-export retry, unknown pass-through)");
  return 0;
}
