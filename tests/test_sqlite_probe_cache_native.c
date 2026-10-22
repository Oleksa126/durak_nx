#define _POSIX_C_SOURCE 200809L
#include "sqlite_probe_cache.h"
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static char root[]="/tmp/durak-sqlite-probe-XXXXXX",journal[512],wal[512];
static atomic_uint calls;
static int injected,create_during_probe;
static int native_probe(const char *path,struct stat *st,unsigned *result) {
  atomic_fetch_add(&calls,1);
  if(injected) { errno=injected;*result=0xdead;return -1; }
  int rc=stat(path,st),saved=errno;*result=rc ? 0x202 : 0;
  if(rc && saved==ENOENT && create_during_probe) {
    create_during_probe=0;
    durak_sqlite_probe_mutation_begin(path,NULL);
    int fd=open(path,O_CREAT|O_WRONLY,0600);assert(fd>=0);assert(!close(fd));
    durak_sqlite_probe_mutation_end();
  }
  errno=saved;return rc;
}
static int probe(const char *path,DurakProbeTrace *trace,struct stat *st) {
  return durak_sqlite_probe_stat(path,root,st,trace,native_probe);
}
static void missing(const char *path,int expected_cached) {
  struct stat st;memset(&st,0xa5,sizeof(st));struct stat before=st;DurakProbeTrace trace;
  assert(probe(path,&trace,&st)==-1 && errno==ENOENT);
  assert(trace.cached==expected_cached && trace.observed_errno==ENOENT && trace.observed_result==0x202);
  assert(!memcmp(&st,&before,sizeof(st)) || !trace.cached); /* Cache never fabricates metadata. */
}
static void create(const char *path) {
  errno=ERANGE;durak_sqlite_probe_mutation_begin(path,NULL);assert(errno==ERANGE);
  int fd=open(path,O_CREAT|O_WRONLY,0600);assert(fd>=0);assert(!close(fd));
  durak_sqlite_probe_mutation_end();
}
static void erase(const char *path) {
  durak_sqlite_probe_mutation_begin(path,NULL);assert(!unlink(path));durak_sqlite_probe_mutation_end();
}
static void *reader(void *unused) {
  (void)unused;for(int i=0;i<200;++i) missing(journal,1);return NULL;
}
int main(void) {
  assert(mkdtemp(root));
  snprintf(journal,sizeof(journal),"%s/l10n.bytes-journal",root);
  snprintf(wal,sizeof(wal),"%s/l10n.bytes-wal",root);
  char db[512],other[512],parent[512];
  snprintf(db,sizeof(db),"%s/l10n.bytes",root);
  snprintf(other,sizeof(other),"%s/other.db-journal",root);
  snprintf(parent,sizeof(parent),"%s/../anything",root);
  assert(durak_sqlite_probe_path(journal,root));
  assert(!durak_sqlite_probe_path(db,root) && !durak_sqlite_probe_path(other,root));
  missing(journal,0);missing(journal,0); /* Outside nativeRender no absence cache. */
  durak_sqlite_probe_frame_begin();missing(journal,0);missing(wal,0);
  unsigned before=atomic_load(&calls);
  for(int i=0;i<1000;++i) { missing(journal,1);missing(wal,1); }
  assert(atomic_load(&calls)==before); /* 2000 checks require no new SD probes. */
  pthread_t readers[3];
  for(int i=0;i<3;++i) assert(!pthread_create(&readers[i],NULL,reader,NULL));
  for(int i=0;i<3;++i) assert(!pthread_join(readers[i],NULL));
  assert(atomic_load(&calls)==before);
  create(journal);
  struct stat st;DurakProbeTrace trace;
  assert(!probe(journal,&trace,&st) && !trace.cached && st.st_size==0);
  int writer_fd=open(journal,O_WRONLY);assert(writer_fd>=0);assert(write(writer_fd,"changed",7)==7);assert(!close(writer_fd));
  assert(!probe(journal,&trace,&st) && !trace.cached && st.st_size==7); /* Present file metadata stays live. */
  erase(journal);missing(journal,0);missing(journal,1);
  durak_sqlite_probe_mutation_begin(journal,NULL);
  missing(journal,0);missing(wal,0); /* No hits/publication while any mutation is in flight. */
  durak_sqlite_probe_mutation_end();missing(journal,0);
  durak_sqlite_probe_mutation_begin(other,journal); /* Rename destination must invalidate. */
  int fd=open(other,O_CREAT|O_WRONLY,0600);assert(fd>=0);assert(!close(fd));assert(!rename(other,journal));
  durak_sqlite_probe_mutation_end();assert(!probe(journal,&trace,&st));erase(journal);
  missing(journal,0);missing(journal,1);
  durak_sqlite_probe_mutation_begin(parent,NULL);durak_sqlite_probe_mutation_end();missing(journal,0);
  durak_sqlite_probe_mutation_begin(root,NULL);durak_sqlite_probe_mutation_end();missing(wal,0);
  durak_sqlite_probe_mutation_begin("l10n.bytes-journal",NULL);durak_sqlite_probe_mutation_end();missing(journal,0);
  char case_alias[512];strcpy(case_alias,journal);
  for(char *p=case_alias;*p;++p) *p=(char)toupper((unsigned char)*p);
  durak_sqlite_probe_mutation_begin(case_alias,NULL);durak_sqlite_probe_mutation_end();missing(journal,0);
  durak_sqlite_probe_mutation_begin(journal,NULL);durak_sqlite_probe_mutation_end();
  create_during_probe=1;missing(journal,0);
  assert(!probe(journal,&trace,&st)); /* Miss completing after a writer cannot publish stale absence. */
  erase(journal);
  injected=EIO;
  for(int i=0;i<2;++i) { assert(probe(journal,&trace,&st)==-1 && errno==EIO && !trace.cached && trace.observed_result==0xdead); }
  injected=EACCES;assert(probe(journal,&trace,&st)==-1 && errno==EACCES && !trace.cached);
  injected=0;missing(journal,0);missing(journal,1);
  durak_sqlite_probe_frame_end();missing(journal,0);
  durak_sqlite_probe_frame_begin();missing(journal,0);missing(journal,1);
  before=atomic_load(&calls);missing(db,0);missing(db,0);missing(other,0);missing(other,0);
  assert(atomic_load(&calls)==before+4); /* Bases and unrelated names/errors never cached. */
  DurakProbeStats stats;errno=ERANGE;durak_sqlite_probe_stats(&stats);assert(errno==ERANGE);
  assert(stats.hits>=2600 && stats.probes && stats.probe_ns);
  durak_sqlite_probe_frame_end();assert(!rmdir(root));
  puts("SQLite sidecar cache: PASS (frame scope, 2000 avoided probes, real files, mutation/rename/alias invalidation, stale-miss race, errno/Result and concurrency)");
}
