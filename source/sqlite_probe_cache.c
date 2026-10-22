#include "sqlite_probe_cache.h"
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#ifdef __SWITCH__
#include <switch.h>
static Mutex lock;
#define LOCK() mutexLock(&lock)
#define UNLOCK() mutexUnlock(&lock)
static uint64_t now_ns(void) { uint64_t t=armGetSystemTick(),f=armGetSystemTickFreq();return (t/f)*1000000000ULL+(t%f)*1000000000ULL/f; }
#else
#include <pthread.h>
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
#define LOCK() pthread_mutex_lock(&lock)
#define UNLOCK() pthread_mutex_unlock(&lock)
static uint64_t now_ns(void) { struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec; }
#endif
static struct { char path[512];unsigned result;int missing; } entries[9];
static unsigned used,writers;
static uint64_t epoch;
static int active;
static DurakProbeStats totals;
int durak_sqlite_probe_path(const char *path,const char *root) {
  if(!path || !root || !*root) return 0;
  size_t n=strlen(root);
  if(strncmp(path,root,n) || path[n]!='/') return 0;
  const char *p=path+n+1;
  const char *db[]={"metrics.bytes","l10n.bytes","dict.bytes"};
  for(unsigned i=0;i<3;++i) {
    size_t len=strlen(db[i]);
    if(!strncmp(p,db[i],len) && (!strcmp(p+len,"-journal") || !strcmp(p+len,"-wal") || !strcmp(p+len,"-shm"))) return 1;
  }
  return 0;
}
static void expire_locked(void) { for(unsigned i=0;i<used;++i) entries[i].missing=0; }
void durak_sqlite_probe_frame_begin(void) { int saved=errno;LOCK();++epoch;expire_locked();active=1;UNLOCK();errno=saved; }
void durak_sqlite_probe_frame_end(void) { int saved=errno;LOCK();++epoch;expire_locked();active=0;UNLOCK();errno=saved; }
/* A path may be the exact file or a renamed/removed parent. Unknown relative
 * aliases invalidate everything rather than assume the current directory. */
static void invalidate_locked(const char *path) {
  if(!path) return;
  const char *colon=strchr(path,':');
  if(!*path || (path[0]!='/' && (!colon || colon[1]!='/')) || strstr(path,"//") || strstr(path,"/..") || strstr(path,"/./") ||
      (strlen(path)>=2 && !strcmp(path+strlen(path)-2,"/."))) { expire_locked();return; }
  size_t n=strlen(path);while(n>1 && path[n-1]=='/') --n;
  for(unsigned i=0;i<used;++i)
    if(!strncasecmp(path,entries[i].path,n) && (!entries[i].path[n] || entries[i].path[n]=='/')) entries[i].missing=0;
}
void durak_sqlite_probe_mutation_begin(const char *first,const char *second) {
  int saved=errno;LOCK();++writers;++epoch;invalidate_locked(first);invalidate_locked(second);UNLOCK();errno=saved;
}
void durak_sqlite_probe_mutation_end(void) { int saved=errno;LOCK();if(writers) --writers;++epoch;UNLOCK();errno=saved; }
void durak_sqlite_probe_stats(DurakProbeStats *out) { int saved=errno;LOCK();*out=totals;UNLOCK();errno=saved; }
int durak_sqlite_probe_stat(const char *path,const char *root,struct stat *out,
    DurakProbeTrace *trace,int (*probe)(const char *,struct stat *,unsigned *)) {
  *trace=(DurakProbeTrace){0};
  int eligible=out && durak_sqlite_probe_path(path,root) && strlen(path)<sizeof(entries[0].path);
  uint64_t before_epoch=0;
  if(eligible) {
    LOCK();before_epoch=epoch;
    if(active && !writers) for(unsigned i=0;i<used;++i) if(entries[i].missing && !strcmp(entries[i].path,path)) {
      ++totals.hits;*trace=(DurakProbeTrace){1,ENOENT,entries[i].result};
      UNLOCK();errno=ENOENT;return -1;
    }
    UNLOCK();
  }
  int saved=errno;
  uint64_t begin=eligible ? now_ns() : 0;
  errno=saved;
  unsigned result=0;
  int rc=probe(path,out,&result),error=errno;
  uint64_t end=eligible ? now_ns() : 0;
  *trace=(DurakProbeTrace){0,rc ? error : 0,result};
  if(eligible) {
    LOCK();++totals.probes;if(end>=begin) totals.probe_ns+=end-begin;
    if(rc==-1 && error==ENOENT && active && !writers && before_epoch==epoch) {
      unsigned i=0;while(i<used && strcmp(entries[i].path,path)) ++i;
      if(i<9) {
        strcpy(entries[i].path,path);entries[i].result=result;entries[i].missing=1;
        if(i==used) ++used;
      }
    }
    UNLOCK();
  }
  errno=error;return rc;
}
