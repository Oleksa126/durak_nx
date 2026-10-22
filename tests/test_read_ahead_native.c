#define _POSIX_C_SOURCE 200809L
#include "read_ahead.h"
#include "boot_measure.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define WIN (1u<<20)
static int reads,fail_at,short_limit,fail_seek;
static size_t fills;
static size_t last_requested;
long __real_read(int fd,void *buf,size_t n);
long __real_lseek(int fd,long offset,int whence);
long __wrap_lseek(int fd,long offset,int whence) {
  if(fail_seek) { errno=ESPIPE; return -1; }
  return __real_lseek(fd,offset,whence);
}
long __wrap_read(int fd,void *buf,size_t n) {
  /* Called with the production cache mutex held during a fill. Sampling must
   * work here without attempting to acquire that mutex or changing errno. */
  DurakArchiveCacheStats snapshot;
  int saved=errno; durak_ra_archive_stats(&snapshot);
  assert(errno==saved && snapshot.resident_bytes<=32*WIN);
  ++reads;
  last_requested=n;
  if(fail_at==reads) { errno=EIO; return -1; }
  if(short_limit && n>(size_t)short_limit) n=(size_t)short_limit;
  return __real_read(fd,buf,n);
}
void durak_log_printf(const char *fmt,...) { (void)fmt; errno=EDOM; }
uint64_t durak_boot_measure_now(void) { return 1; }
void durak_boot_measure_span(DurakBootMetric k,uint64_t start,uint64_t bytes) {
  (void)start;(void)bytes;assert(k==BOOT_ASSET_FILL || k==BOOT_ASSET_REUSE);
  if(k==BOOT_ASSET_FILL) ++fills;
}
static unsigned char expected(size_t i) { return (unsigned char)(i*17u+31u); }
static void seek_to(int fd,long p) {
  long result;assert(durak_ra_seek(fd,p,SEEK_SET,&result)==1 && result==p);
}
static void check_read(int fd,size_t n,size_t offset) {
  unsigned char *buf=malloc(n?n:1);assert(buf);long result;
  assert(durak_ra_read(fd,buf,n,&result)==1 && result==(long)n);
  for(size_t i=0;i<n;++i) assert(buf[i]==expected(offset+i));
  free(buf);
}
static void *worker(void *arg) {
  int fd=*(int *)arg;
  /* Shared descriptor reads must consume one serialized logical cursor. */
  for(int i=0;i<100;++i) {
    long r;unsigned char b;
    assert(durak_ra_pread(fd,&b,1,WIN+123,&r)==1 && r==1 && b==expected(WIN+123));
    assert(durak_ra_read(fd,&b,1,&r)==1 && r==1);
  }
  return NULL;
}
static void archive_test(void) {
  const char *key="sdmc:/switch/durak_nx/assets/bin/Data/data.unity3d";
  const char *alias_key="sdmc:/switch/durak_nx/game/assets/bin/Data/data.unity3d";
  char path[]="/tmp/durak-archive-XXXXXX";
  int writer=mkstemp(path); assert(writer>=0);
  size_t size=6*WIN+37;
  unsigned char *data=malloc(size); assert(data);
  for(size_t i=0;i<size;++i) data[i]=expected(i);
  assert(write(writer,data,size)==(long)size); free(data); assert(!close(writer));
  int fd=open(path,O_RDONLY); assert(fd>=0 && durak_ra_attach_path(fd,(long)size,key));
  unsigned char b; long r;
  fail_at=reads+1;
  assert(durak_ra_read(fd,&b,1,&r)==1 && r==-1 && errno==EIO);
  fail_at=0; short_limit=7; check_read(fd,20,0); short_limit=0;
  seek_to(fd,5*WIN+11); check_read(fd,30,5*WIN+11);
  int before=reads;
  /* Scatter below/above the original 1-MiB window: no second SD read. */
  for(int i=0;i<69;++i) {
    size_t offset=(i%6)*WIN+123;
    seek_to(fd,(long)offset); check_read(fd,20,offset);
  }
  assert(reads==before);
  int other=open(path,O_RDONLY); assert(other>=0 && durak_ra_attach_path(other,(long)size,key));
  assert(durak_ra_pread(other,&b,1,WIN+123,&r)==1 && r==1 && b==expected(WIN+123));
  assert(durak_ra_seek(other,0,SEEK_CUR,&r)==1 && r==0 && reads==before);
  seek_to(fd,0);
  pthread_t threads[3];
  for(int i=0;i<3;++i) assert(!pthread_create(&threads[i],NULL,worker,&fd));
  for(int i=0;i<3;++i) assert(!pthread_join(threads[i],NULL));
  assert(durak_ra_seek(fd,0,SEEK_CUR,&r)==1 && r==300 && reads==before);
  durak_ra_detach(fd); assert(!close(fd));
  fd=open(path,O_RDONLY); assert(fd>=0 && durak_ra_attach_path(fd,(long)size,key));
  check_read(fd,20,0); assert(reads==before);
  assert(!durak_ra_before_dup(fd));
  int alias=dup(fd); assert(alias>=0);
  assert(read(alias,&b,1)==1 && b==expected(20));
  assert(read(fd,&b,1)==1 && b==expected(21));
  assert(!close(alias) && !close(fd)); durak_ra_detach(other); assert(!close(other));
  /* Separate archive budget: two pinned 32-MiB aliases cannot double it.
   * The second falls back to the original window; the first remains cached. */
  writer=open(path,O_WRONLY|O_TRUNC); assert(writer>=0 && !ftruncate(writer,32*WIN) && !close(writer));
  fd=open(path,O_RDONLY); assert(fd>=0 && durak_ra_attach_path(fd,32*WIN,key));
  assert(durak_ra_read(fd,&b,1,&r)==1 && r==1 && b==0);
  other=open(path,O_RDONLY); assert(other>=0 && durak_ra_attach_path(other,32*WIN,alias_key));
  assert(durak_ra_read(other,&b,1,&r)==1 && r==1 && b==0);
  assert(last_requested<=WIN); /* fallback, not a second full 32-MiB cache */
  before=reads;
  assert(durak_ra_pread(fd,&b,1,5*WIN+11,&r)==1 && r==1 && b==0 && reads==before);
  durak_ra_detach(fd); durak_ra_detach(other); assert(!close(fd) && !close(other));
  assert(!unlink(path));
  puts("archive retention: PASS (69 scatter reads without I/O, reopen/concurrency/cursors, real errors/short reads, dup, pinned 32-MiB budget)");
}
int main(void) {
  long r=123;assert(durak_ra_read(0,NULL,0,&r)==0 && r==123);
  assert(durak_ra_asset_path("sdmc:/switch/durak_nx/assets/bin/Data/data.unity3d","sdmc:/switch/durak_nx"));
  assert(durak_ra_asset_path("sdmc:/switch/durak_nx/il2cpp/Metadata/global-metadata.dat","sdmc:/switch/durak_nx"));
  assert(!durak_ra_asset_path("sdmc:/switch/durak_nx/metrics.bytes","sdmc:/switch/durak_nx"));
  assert(!durak_ra_asset_path("sdmc:/switch/durak_nx/assets/../metrics.bytes","sdmc:/switch/durak_nx"));
  assert(!durak_ra_asset_path("sdmc:/switch/durak_nx/assets/..","sdmc:/switch/durak_nx"));
  assert(!durak_ra_asset_path("sdmc:/switch/durak_nx/assets/.","sdmc:/switch/durak_nx"));
  char path[]="/tmp/durak-read-ahead-XXXXXX";int writer=mkstemp(path);assert(writer>=0);
  size_t size=WIN*2+37;unsigned char *data=malloc(size);assert(data);
  for(size_t i=0;i<size;++i)data[i]=expected(i);
  assert(write(writer,data,size)==(long)size);free(data);assert(close(writer)==0);
  int fd=open(path,O_RDONLY);assert(fd>=0);
  errno=ERANGE;assert(durak_ra_attach(fd,(long)size)==1 && errno==ERANGE);
  assert(durak_ra_attach(fd,(long)size)==1); /* no duplicate slots/cursor reset */
  for(size_t i=0;i<100;++i)check_read(fd,1,i);
  assert(reads==1 && fills==1); /* tiny reads hit RAM */
  unsigned char b;
  seek_to(fd,WIN-9);check_read(fd,26,WIN-9);assert(reads==2);
  seek_to(fd,0);check_read(fd,19,0);
  assert(durak_ra_pread(fd,&b,1,WIN+123,&r)==1 && r==1 && b==expected(WIN+123));
  assert(durak_ra_seek(fd,0,SEEK_CUR,&r)==1 && r==19);
  assert(durak_ra_pread(fd,&b,1,-1,&r)==1 && r==-1 && errno==EINVAL);
  assert(durak_ra_seek(fd,0,SEEK_CUR,&r)==1 && r==19);
  assert(durak_ra_seek(fd,-10,SEEK_END,&r)==1 && r==(long)size-10);
  check_read(fd,10,size-10);
  assert(durak_ra_read(fd,&b,1,&r)==1 && r==0);
  seek_to(fd,(long)size+10);assert(durak_ra_read(fd,NULL,0,&r)==1 && r==0);
  assert(durak_ra_read(fd,&b,1,&r)==1 && r==0);
  assert(durak_ra_seek(fd,0,123,&r)==1 && r==-1 && errno==EINVAL);
  assert(durak_ra_seek(fd,-1,SEEK_SET,&r)==1 && r==-1 && errno==EINVAL);
  seek_to(fd,LONG_MAX);assert(durak_ra_seek(fd,1,SEEK_CUR,&r)==1 && r==-1 && errno==EOVERFLOW);
  assert(durak_ra_seek(fd,0,SEEK_CUR,&r)==1 && r==LONG_MAX);
  durak_ra_detach(fd);assert(close(fd)==0);
  fd=open(path,O_RDONLY);assert(fd>=0 && durak_ra_attach(fd,(long)size));
  fail_at=reads+1;assert(durak_ra_read(fd,&b,1,&r)==1 && r==-1 && errno==EIO);
  fail_at=0;short_limit=7;check_read(fd,30,0);short_limit=0;
  durak_ra_detach(fd);assert(close(fd)==0);
  fd=open(path,O_RDONLY);assert(fd>=0 && durak_ra_attach(fd,(long)size));
  fail_at=reads+2;
  unsigned char *large=malloc(WIN+1);assert(large);
  assert(durak_ra_read(fd,large,WIN+1,&r)==1 && r==WIN && errno==EIO);
  assert(durak_ra_seek(fd,0,SEEK_CUR,&r)==1 && r==WIN);
  free(large);fail_at=0;
  large=malloc(size);assert(large);
  assert(durak_ra_pread(fd,large,size,0,&r)==1 && r==(long)size);
  for(size_t i=0;i<size;++i)assert(large[i]==expected(i));
  assert(durak_ra_seek(fd,0,SEEK_CUR,&r)==1 && r==WIN);
  free(large);seek_to(fd,0);
  pthread_t threads[3];for(int i=0;i<3;++i)assert(pthread_create(&threads[i],NULL,worker,&fd)==0);
  for(int i=0;i<3;++i)assert(pthread_join(threads[i],NULL)==0);
  assert(durak_ra_seek(fd,0,SEEK_CUR,&r)==1 && r==300);
  durak_ra_detach(fd);assert(close(fd)==0);
  int fds[9];for(int i=0;i<9;++i) {
    fds[i]=open(path,O_RDONLY);assert(fds[i]>=0);
    assert(durak_ra_attach(fds[i],(long)size)==(i<8));
  }
  assert(durak_ra_read(fds[8],&b,1,&r)==0);
  for(int i=0;i<9;++i) { durak_ra_detach(fds[i]);assert(close(fds[i])==0); }
  fd=open(path,O_RDONLY);assert(fd>=0);assert(lseek(fd,17,SEEK_SET)==17);
  assert(durak_ra_attach(fd,(long)size));check_read(fd,10,17);
  fail_seek=1;
  assert(durak_ra_before_dup(fd)==-1 && errno==ESPIPE);
  assert(durak_ra_seek(fd,0,SEEK_CUR,&r)==1 && r==27);
  fail_seek=0;errno=ERANGE;
  assert(!durak_ra_before_dup(fd) && errno==ERANGE);
  int alias=dup(fd);assert(alias>=0);
  assert(read(alias,&b,1)==1 && b==expected(27));
  assert(read(fd,&b,1)==1 && b==expected(28));
  assert(durak_ra_read(fd,&b,1,&r)==0);
  assert(!close(alias));assert(!close(fd));
  /* Independent opens share immutable bytes, never their logical cursors. */
  int before=reads;
  fd=open(path,O_RDONLY);assert(fd>=0);
  assert(durak_ra_attach_path(fd,(long)size,path));check_read(fd,20,0);
  assert(reads==before+1);
  int other=open(path,O_RDONLY);assert(other>=0);
  assert(durak_ra_attach_path(other,(long)size,path));
  seek_to(other,123);check_read(other,50,123);
  assert(durak_ra_seek(fd,0,SEEK_CUR,&r)==1 && r==20);
  assert(durak_ra_pread(other,&b,1,WIN+123,&r)==1 && r==1 && b==expected(WIN+123));
  assert(durak_ra_seek(other,0,SEEK_CUR,&r)==1 && r==173);
  assert(reads==before+1);
  seek_to(fd,0);
  for(int i=0;i<3;++i)assert(pthread_create(&threads[i],NULL,worker,&fd)==0);
  for(int i=0;i<3;++i)assert(pthread_join(threads[i],NULL)==0);
  assert(durak_ra_seek(fd,0,SEEK_CUR,&r)==1 && r==300 && reads==before+1);
  durak_ra_detach(fd);assert(close(fd)==0);
  fd=open(path,O_RDONLY);assert(fd>=0);
  assert(durak_ra_attach_path(fd,(long)size,path));check_read(fd,20,0);
  assert(reads==before+1);
  assert(!durak_ra_before_dup(fd));
  alias=dup(fd);assert(alias>=0);
  assert(read(alias,&b,1)==1 && b==expected(20));
  assert(read(fd,&b,1)==1 && b==expected(21));
  assert(!close(alias));assert(close(fd)==0);
  durak_ra_detach(other);assert(close(other)==0);
  /* Same-size files must never collide merely because a descriptor is reused. */
  char second[]="/tmp/durak-small-asset-XXXXXX";
  writer=mkstemp(second);assert(writer>=0);
  assert(write(writer,"abcdef",6)==6);assert(close(writer)==0);
  fd=open(second,O_RDONLY);assert(fd>=0 && durak_ra_attach_path(fd,6,second));
  fail_at=reads+1;assert(durak_ra_read(fd,&b,1,&r)==1 && r==-1 && errno==EIO);
  fail_at=0;short_limit=2;
  char small[6];assert(durak_ra_read(fd,small,6,&r)==1 && r==6 && !memcmp(small,"abcdef",6));
  short_limit=0;assert(durak_ra_read(fd,&b,1,&r)==1 && r==0);
  durak_ra_detach(fd);assert(close(fd)==0);
  char third[]="/tmp/durak-small-other-XXXXXX";
  writer=mkstemp(third);assert(writer>=0);
  assert(write(writer,"ABCDEF",6)==6);assert(close(writer)==0);
  fd=open(third,O_RDONLY);assert(fd>=0 && durak_ra_attach_path(fd,6,third));
  assert(durak_ra_read(fd,small,6,&r)==1 && r==6 && !memcmp(small,"ABCDEF",6));
  durak_ra_detach(fd);assert(close(fd)==0);
  /* Budget pressure falls back to a window without evicting pinned content. */
  char pressure[5][64];int pinned[5];
  for(int i=0;i<5;++i) {
    strcpy(pressure[i],"/tmp/durak-small-pressure-XXXXXX");
    writer=mkstemp(pressure[i]);assert(writer>=0);
    assert(!ftruncate(writer,4*WIN));assert(!close(writer));
    pinned[i]=open(pressure[i],O_RDONLY);assert(pinned[i]>=0);
    assert(durak_ra_attach_path(pinned[i],4*WIN,pressure[i]));
    assert(durak_ra_read(pinned[i],&b,1,&r)==1 && r==1 && b==0);
  }
  before=reads;
  seek_to(pinned[0],0);
  assert(durak_ra_read(pinned[0],&b,1,&r)==1 && r==1 && b==0 && reads==before);
  for(int i=0;i<5;++i) {
    durak_ra_detach(pinned[i]);assert(!close(pinned[i]));assert(!unlink(pressure[i]));
  }
  assert(unlink(second)==0);assert(unlink(third)==0);assert(unlink(path)==0);
  archive_test();
  puts("read ahead: PASS (window/small-file reuse, independent and concurrent cursors, errors/short reads, budget pressure, fd/path identity, asset-only scope)");
  return 0;
}
