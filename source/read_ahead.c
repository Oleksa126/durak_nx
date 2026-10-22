#include "read_ahead.h"
#include "boot_measure.h"
#include "util.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#ifdef __SWITCH__
#include <switch.h>
static Mutex lock;
#define LOCK() mutexLock(&lock)
#define UNLOCK() mutexUnlock(&lock)
static unsigned native_error(void) { return fsdevGetLastResult(); }
#else
#include <pthread.h>
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
#define LOCK() pthread_mutex_lock(&lock)
#define UNLOCK() pthread_mutex_unlock(&lock)
static unsigned native_error(void) { return 0; }
#endif
#define RA_WINDOW (1u<<20)
#define SMALL_LIMIT (4u<<20)
#define SMALL_BUDGET (16u<<20)
#define ARCHIVE_BUDGET (32u<<20)
typedef struct {
  char path[512]; long size,len; unsigned refs;
  unsigned long age; unsigned char *buf; int archive;
} SmallAsset;
static SmallAsset small_assets[8];
static size_t small_bytes;
static size_t archive_bytes;
#ifndef __SWITCH__
static struct {
  atomic_uint_fast64_t fills,fill_bytes,serves,served_bytes,reopens,evictions,resident_bytes;
} archive_stats;
#define ARCHIVE_COUNT(name,value) atomic_fetch_add_explicit(&archive_stats.name,value,memory_order_relaxed)
#define ARCHIVE_SET(name,value) atomic_store_explicit(&archive_stats.name,value,memory_order_relaxed)
#else
#define ARCHIVE_COUNT(name,value) ((void)0)
#define ARCHIVE_SET(name,value) ((void)0)
#endif
static unsigned long age;

/* Only the immutable packaged Unity archive gets the additional bounded budget.
 * Caller already verified read-only fd and absolute asset-path eligibility. */
static int archive_path(const char *path) {
  static const char suffix[]="/assets/bin/Data/data.unity3d";
  if(!path) return 0;
  size_t n=strlen(path),s=sizeof(suffix)-1;
  return n>=s && !strcmp(path+n-s,suffix);
}
typedef struct {
  int fd; long pos,size,base,len; unsigned char *buf; SmallAsset *shared;
} RaCache;
/* BSS zero is a valid descriptor, not an empty slot. */
static RaCache slots[8]={
  {.fd=-1},{.fd=-1},{.fd=-1},{.fd=-1},
  {.fd=-1},{.fd=-1},{.fd=-1},{.fd=-1}
};
static RaCache *find(int fd) {
  if(fd<0) return NULL;
  for(int i=0;i<8;++i) if(slots[i].fd==fd) return &slots[i];
  return NULL;
}
int durak_ra_asset_path(const char *path,const char *root) {
  if(!path || !root) return 0;
  size_t n=strlen(root);
  if(strncmp(path,root,n) || path[n]!='/') return 0;
  const char *p=path+n;
  size_t plen=strlen(p);
  if(strstr(p,"/../") || strstr(p,"/./") ||
     (plen>=3 && !strcmp(p+plen-3,"/..")) ||
     (plen>=2 && !strcmp(p+plen-2,"/."))) return 0;
  return !strncmp(p,"/assets/",8) || !strncmp(p,"/game/assets/",13) ||
         !strcmp(p,"/il2cpp/Metadata/global-metadata.dat");
}
/* Called with the cache lock held. Never evict content used by an open fd. */
static SmallAsset *small_attach(const char *path,long size) {
  int archive=size>SMALL_LIMIT && size<=ARCHIVE_BUDGET && archive_path(path);
  if(!path || !*path || strlen(path)>=sizeof(small_assets[0].path) ||
     size<=0 || (size>SMALL_LIMIT && !archive)) return NULL;
  size_t *used=archive ? &archive_bytes : &small_bytes;
  size_t budget=archive ? ARCHIVE_BUDGET : SMALL_BUDGET;
  for(int i=0;i<8;++i) {
    SmallAsset *s=&small_assets[i];
    if(s->buf && s->size==size && !strcmp(s->path,path)) {
      ++s->refs; s->age=++age;
      if(s->archive && s->len) ARCHIVE_COUNT(reopens,1);
      return s;
    }
  }
  SmallAsset *slot=NULL;
  for(int i=0;i<8;++i) if(!small_assets[i].buf) { slot=&small_assets[i]; break; }
  while(!slot || *used+(size_t)size>budget) {
    SmallAsset *old=NULL;
    for(int i=0;i<8;++i) {
      SmallAsset *s=&small_assets[i];
      /* Memory pressure evicts only its own budget; slot pressure may evict
       * another unpinned class. Open files are never evicted. */
      if(s->buf && !s->refs &&
         (*used+(size_t)size<=budget || s->archive==archive) &&
         (!old || s->age<old->age)) old=s;
    }
    if(!old) return NULL;
    if(old->archive) {
      archive_bytes-=(size_t)old->size;
      ARCHIVE_COUNT(evictions,1);
      ARCHIVE_SET(resident_bytes,archive_bytes);
    }
    else small_bytes-=(size_t)old->size;
    free(old->buf);
    memset(old,0,sizeof(*old));
    if(!slot) slot=old;
  }
  unsigned char *buf=malloc((size_t)size);
  if(!buf) return NULL;
  strcpy(slot->path,path); slot->size=size; slot->len=0;
  slot->buf=buf; slot->refs=1; slot->age=++age; slot->archive=archive; *used+=(size_t)size;
  if(archive) ARCHIVE_SET(resident_bytes,archive_bytes);
  return slot;
}
int durak_ra_attach_path(int fd,long size,const char *path) {
  if(fd<0 || size<0) return 0;
  int saved=errno,attached=0;
  LOCK();
  if(find(fd)) { UNLOCK(); errno=saved; return 1; }
  for(int i=0;i<8;++i) if(slots[i].fd<0) {
    long pos=lseek(fd,0,SEEK_CUR);
    if(pos<0) {
      int error=errno; unsigned native=native_error();
      durak_log_printf("[ASSET CACHE] attach seek failed fd=%d errno=%d result=0x%x; ordinary I/O retained\n",fd,error,native);
      break;
    }
    uint64_t reuse_begin=durak_boot_measure_now();
    SmallAsset *shared=small_attach(path,size);
    if(shared && shared->len)
      durak_boot_measure_span(BOOT_ASSET_REUSE,reuse_begin,(uint64_t)shared->len);
    if(!shared && !slots[i].buf) {
      slots[i].buf=malloc(RA_WINDOW);
      if(!slots[i].buf) {
        int error=errno;
        durak_log_printf("[ASSET CACHE] allocation failed fd=%d errno=%d; ordinary I/O retained\n",fd,error);
      }
    }
    if(shared || slots[i].buf) {
      slots[i].fd=fd; slots[i].pos=pos; slots[i].size=size;
      slots[i].base=0; slots[i].len=0; slots[i].shared=shared; attached=1;
    }
    break;
  }
  UNLOCK();
  /* No free slot/allocation failure leaves the ordinary reader intact. */
  errno=saved; return attached;
}
int durak_ra_attach(int fd,long size) { return durak_ra_attach_path(fd,size,NULL); }
void durak_ra_detach(int fd) {
  int saved=errno;
  LOCK(); RaCache *c=find(fd);
  if(c) {
    if(c->shared) { --c->shared->refs; c->shared->age=++age; }
    c->shared=NULL; c->fd=-1; c->len=0;
  }
  UNLOCK(); errno=saved;
}
int durak_ra_before_dup(int fd) {
  int saved=errno;
  LOCK(); RaCache *c=find(fd);
  if(c) {
    if(lseek(fd,c->pos,SEEK_SET)<0) {
      int error=errno; unsigned native=native_error();
      durak_log_printf("[ASSET CACHE] dup cursor sync failed fd=%d errno=%d result=0x%x\n",fd,error,native);
      UNLOCK(); errno=error; return -1;
    }
    if(c->shared) { --c->shared->refs; c->shared->age=++age; }
    c->shared=NULL; c->fd=-1; c->len=0;
  }
  UNLOCK(); errno=saved; return 0;
}
int durak_ra_seek(int fd,long offset,int whence,long *result) {
  int saved=errno;
  LOCK(); RaCache *c=find(fd);
  if(!c) { UNLOCK(); errno=saved; return 0; }
  long base=0,pos;
  int error=0;
  if(whence==SEEK_CUR) base=c->pos;
  else if(whence==SEEK_END) base=c->size;
  else if(whence!=SEEK_SET) error=EINVAL;
  if(!error && __builtin_add_overflow(base,offset,&pos)) error=EOVERFLOW;
  if(!error && pos<0) error=EINVAL;
  if(error) *result=-1;
  else { c->pos=pos; *result=pos; }
  UNLOCK(); errno=error ? error : saved; return 1;
}
static long read_locked(RaCache *c,void *buf,size_t count) {
  int saved=errno,error=0;
  size_t done=0;
  if(count>LONG_MAX) error=EINVAL;
  else if(count && !buf) error=EFAULT;
  while(!error && done<count && c->pos<c->size) {
    if(c->shared) {
      SmallAsset *s=c->shared;
      if(c->pos>=s->len) {
        uint64_t begin=durak_boot_measure_now();
        long r=-1;
        if(lseek(c->fd,s->len,SEEK_SET)>=0)
          r=read(c->fd,s->buf+s->len,(size_t)(s->size-s->len));
        if(r<0) {
          error=errno; unsigned native=native_error();
          durak_log_printf("[ASSET CACHE] small read failed fd=%d offset=%ld errno=%d result=0x%x\n",
                           c->fd,s->len,error,native);
        }
        durak_boot_measure_span(BOOT_ASSET_FILL,begin,r>0 ? (uint64_t)r : 0);
        if(s->archive) {
          ARCHIVE_COUNT(fills,1);
          if(r>0) ARCHIVE_COUNT(fill_bytes,(uint64_t)r);
        }
        if(r<=0) break;
        s->len+=r;
        if(c->pos>=s->len) continue;
      }
      size_t avail=(size_t)(s->len-c->pos);
      size_t n=count-done<avail ? count-done : avail;
      memcpy((char *)buf+done,s->buf+c->pos,n);
      if(s->archive) {
        ARCHIVE_COUNT(serves,1);
        ARCHIVE_COUNT(served_bytes,n);
        s->age=++age;
      }
      c->pos+=(long)n; done+=n; continue;
    }
    if(!c->len || c->pos<c->base || c->pos-c->base>=c->len) {
      uint64_t begin=durak_boot_measure_now();
      long r=-1;
      size_t want=(c->size-c->pos)<RA_WINDOW ? (size_t)(c->size-c->pos) : RA_WINDOW;
      if(lseek(c->fd,c->pos,SEEK_SET)>=0) r=read(c->fd,c->buf,want);
      if(r<0) {
        error=errno; unsigned native=native_error();
        durak_log_printf("[ASSET CACHE] read failed fd=%d offset=%ld errno=%d result=0x%x\n",c->fd,c->pos,error,native);
      }
      durak_boot_measure_span(BOOT_ASSET_FILL,begin,r>0 ? (uint64_t)r : 0);
      if(r<=0) break;
      c->base=c->pos; c->len=r; /* Positive short reads are valid cache windows. */
    }
    size_t avail=(size_t)(c->len-(c->pos-c->base));
    size_t n=count-done<avail ? count-done : avail;
    memcpy((char *)buf+done,c->buf+(c->pos-c->base),n);
    c->pos+=(long)n; done+=n;
  }
  errno=error ? error : saved; return error && !done ? -1 : (long)done;
}
int durak_ra_read(int fd,void *buf,size_t count,long *result) {
  int saved=errno;
  LOCK(); RaCache *c=find(fd);
  if(!c) { UNLOCK(); errno=saved; return 0; }
  *result=read_locked(c,buf,count); saved=errno;
  UNLOCK(); errno=saved; return 1;
}
int durak_ra_pread(int fd,void *buf,size_t count,long offset,long *result) {
  int saved=errno;
  LOCK(); RaCache *c=find(fd);
  if(!c) { UNLOCK(); errno=saved; return 0; }
  if(offset<0) { *result=-1; saved=EINVAL; }
  else {
    long original=c->pos; c->pos=offset;
    *result=read_locked(c,buf,count); saved=errno; c->pos=original;
  }
  UNLOCK(); errno=saved; return 1;
}
#ifndef __SWITCH__
void durak_ra_archive_stats(DurakArchiveCacheStats *out) {
  int saved=errno;
  /* Rendering must never wait behind a cold archive read just to sample its
   * diagnostics. Fields are independent monotonic snapshots across threads. */
  if(out) {
#define ARCHIVE_STAT(name) out->name=atomic_load_explicit(&archive_stats.name,memory_order_relaxed)
    ARCHIVE_STAT(fills); ARCHIVE_STAT(fill_bytes); ARCHIVE_STAT(serves);
    ARCHIVE_STAT(served_bytes); ARCHIVE_STAT(reopens); ARCHIVE_STAT(evictions);
    ARCHIVE_STAT(resident_bytes);
#undef ARCHIVE_STAT
  }
  errno=saved;
}

#endif
