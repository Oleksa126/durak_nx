#include "asset_stat.h"
#include "read_ahead.h"
#include "boot_measure.h"
#include <errno.h>
#include <string.h>
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
#define STAT_SLOTS 128
static struct { char path[512]; struct stat value; } entries[STAT_SLOTS];
static unsigned used;
int durak_asset_stat(const char *path,const char *root,struct stat *out) {
  int eligible=path && out && strlen(path)<sizeof(entries[0].path) &&
               durak_ra_asset_path(path,root);
  int saved=errno;
  if(eligible) {
    LOCK();
    for(unsigned i=0;i<used;++i) if(!strcmp(path,entries[i].path)) {
      *out=entries[i].value;
      UNLOCK(); errno=saved;
      return 0;
    }
    UNLOCK();
  }
  uint64_t begin=durak_boot_measure_now();
  int rc=stat(path,out),error=errno;
  durak_boot_measure_span(BOOT_HOST_STAT,begin,0);
  if(!rc && eligible && S_ISREG(out->st_mode)) {
    LOCK();
    unsigned i=0;
    while(i<used && strcmp(path,entries[i].path)) ++i;
    if(i<STAT_SLOTS) {
      strcpy(entries[i].path,path); entries[i].value=*out;
      if(i==used) ++used;
    }
    UNLOCK();
  }
  errno=error; return rc;
}
