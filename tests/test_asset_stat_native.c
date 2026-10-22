#define _POSIX_C_SOURCE 200809L
#include "asset_stat.h"
#include "boot_measure.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static atomic_int calls;
static int inject;
int __real_stat(const char *,struct stat *);
int __wrap_stat(const char *path,struct stat *out) {
  atomic_fetch_add(&calls,1);
  if(inject) { errno=EIO; return -1; }
  return __real_stat(path,out);
}
void durak_log_printf(const char *fmt,...) { (void)fmt; }
uint64_t durak_boot_measure_now(void) { return 1; }
void durak_boot_measure_span(DurakBootMetric k,uint64_t begin,uint64_t bytes) {
  (void)begin; (void)bytes; assert(k==BOOT_HOST_STAT);
}
static char root[]="/tmp/durak-asset-stat-XXXXXX",asset[512];
static void *worker(void *unused) {
  (void)unused; struct stat st;
  for(int i=0;i<200;++i) {
    errno=ERANGE;
    assert(!durak_asset_stat(asset,root,&st) && st.st_size==3 && errno==ERANGE);
  }
  return NULL;
}
int main(void) {
  assert(mkdtemp(root));
  char dir[512],db[512],missing[512]; struct stat st,initial;
  snprintf(dir,sizeof(dir),"%s/assets",root); assert(!mkdir(dir,0700));
  snprintf(asset,sizeof(asset),"%s/assets/example",root);
  snprintf(db,sizeof(db),"%s/metrics.bytes",root);
  snprintf(missing,sizeof(missing),"%s/assets/missing",root);
  int fd=open(asset,O_CREAT|O_WRONLY,0600); assert(fd>=0);
  assert(write(fd,"abc",3)==3); assert(!close(fd));
  assert(!durak_asset_stat(asset,root,&initial)); assert(atomic_load(&calls)==1);
  inject=1; errno=ERANGE;
  assert(!durak_asset_stat(asset,root,&st) && errno==ERANGE);
  assert(st.st_mode==initial.st_mode && st.st_size==initial.st_size && st.st_ino==initial.st_ino);
  assert(durak_asset_stat(missing,root,&st)==-1 && errno==EIO);
  assert(durak_asset_stat(db,root,&st)==-1 && errno==EIO);
  inject=0;
  assert(durak_asset_stat(missing,root,&st)==-1 && errno==ENOENT);
  fd=open(missing,O_CREAT|O_WRONLY,0600); assert(fd>=0); assert(!close(fd));
  assert(!durak_asset_stat(missing,root,&st)); /* Negative results weren't retained. */
  int before=atomic_load(&calls);
  assert(!durak_asset_stat(dir,root,&st)); assert(!durak_asset_stat(dir,root,&st));
  assert(atomic_load(&calls)==before+2); /* Directories stay live. */
  fd=open(db,O_CREAT|O_WRONLY,0600); assert(fd>=0); assert(!close(fd));
  assert(!durak_asset_stat(db,root,&st) && st.st_size==0);
  fd=open(db,O_WRONLY,0600); assert(fd>=0); assert(write(fd,"changed",7)==7); assert(!close(fd));
  assert(!durak_asset_stat(db,root,&st) && st.st_size==7);
  before=atomic_load(&calls);
  pthread_t threads[3];
  for(int i=0;i<3;++i) assert(!pthread_create(&threads[i],NULL,worker,NULL));
  for(int i=0;i<3;++i) assert(!pthread_join(threads[i],NULL));
  assert(atomic_load(&calls)==before);
  assert(!unlink(asset)); assert(!unlink(missing)); assert(!unlink(db));
  assert(!rmdir(dir)); assert(!rmdir(root));
  puts("asset stat: PASS (positive immutable-file hits, live databases/directories, errno/errors, missing-file creation, concurrency)");
  return 0;
}
