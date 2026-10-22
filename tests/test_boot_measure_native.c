#define _POSIX_C_SOURCE 200809L
#include "util.h"
#include "boot_measure.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static atomic_uint_fast64_t clock_ns=1000000000ULL;
int __wrap_clock_gettime(clockid_t clock,struct timespec *ts) {
  assert(clock==CLOCK_MONOTONIC);
  uint64_t ns=atomic_fetch_add(&clock_ns,1000000ULL);
  ts->tv_sec=ns/1000000000ULL; ts->tv_nsec=ns%1000000000ULL;
  errno=EDOM; return 0;
}
static void *worker(void *unused) {
  (void)unused;
  for(int i=0;i<100;++i) {
    errno=ERANGE; uint64_t start=durak_boot_measure_now();
    assert(errno==ERANGE);
    durak_boot_measure_span(BOOT_SQL_STEP,start,0); assert(errno==ERANGE);
  }
  return NULL;
}
int main(void) {
  assert(durak_boot_measure_now()==0);
  char path[]="/tmp/durak-boot-measure-XXXXXX";
  int fd=mkstemp(path); assert(fd>=0); assert(close(fd)==0);
  durak_log_set_file_only(1); assert(durak_log_init(path)==0);
  errno=ERANGE; durak_boot_measure_begin(); assert(errno==ERANGE);
  uint64_t start=durak_boot_measure_now();
  durak_boot_measure_span(BOOT_ASSET_FILL,start,4096); assert(errno==ERANGE);
  durak_boot_measure_span(BOOT_ASSET_FILL,0,999); /* disabled/missing sample */
  durak_boot_measure_span(BOOT_METRIC_COUNT,start,999); /* invalid category */
  durak_boot_measure_phase("test","detail",start); assert(errno==ERANGE);
  pthread_t threads[3];
  for(int i=0;i<3;++i) assert(pthread_create(&threads[i],NULL,worker,NULL)==0);
  for(int i=0;i<3;++i) assert(pthread_join(threads[i],NULL)==0);
  errno=ERANGE; durak_boot_measure_finish("menu_test"); assert(errno==ERANGE);
  assert(durak_boot_measure_now()==0);
  durak_boot_measure_span(BOOT_ASSET_FILL,start,999);
  durak_boot_measure_finish("must_not_repeat");
  durak_boot_measure_phase("must_not_repeat","",start);
  durak_log_close();
  FILE *f=fopen(path,"rb"); assert(f); char text[8192];
  size_t n=fread(text,1,sizeof(text)-1,f);text[n]=0;assert(fclose(f)==0);
  assert(strstr(text,"phase=test detail=detail"));
  assert(strstr(text,"metric=asset_cache_fill calls=1 total_us=1000 max_us=1000 bytes=4096"));
  assert(strstr(text,"metric=sqlite_step calls=300"));
  assert(strstr(text,"click-to-main unmeasured"));
  assert(!strstr(text,"must_not_repeat"));
  assert(unlink(path)==0);
  puts("boot measurement: PASS (monotonic durations, errno, concurrent counts, one file-only summary, frozen after menu)");
  return 0;
}
