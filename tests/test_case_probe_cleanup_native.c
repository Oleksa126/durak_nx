#define _GNU_SOURCE
#include "case_probe_cleanup.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fault;
int __real_unlink(const char *path);
int __wrap_unlink(const char *path) {
  if(fault) { errno=fault; return -1; }
  return __real_unlink(path);
}
void durak_log_printf(const char *fmt, ...) { (void)fmt; errno=EDOM; }
static int create(const char *path, int nonempty) {
  int fd=open(path,O_CREAT|O_RDWR|O_TRUNC,0600); assert(fd>=0);
  if(nonempty) assert(write(fd,"x",1)==1);
  return fd;
}
static void finish(int fd) {
  DurakProbeClose state;
  durak_probe_before_close(fd,&state);
  int rc=close(fd); assert(rc==0);
  durak_probe_after_close(&state,rc,ERANGE,0);
  assert(errno==ERANGE);
}
int main(void) {
  char root[]="/tmp/durak-probe-XXXXXX"; assert(mkdtemp(root));
  char probe[256],data[256],other[256],dir[256],link[256];
  snprintf(probe,sizeof(probe),"%s/CASESENSITIVETEST0123456789abcdef0123456789abcdef",root);
  snprintf(data,sizeof(data),"%s/metrics.bytes",root);
  snprintf(other,sizeof(other),"%s/CASESENSITIVETESTinvalid",root);
  snprintf(dir,sizeof(dir),"%s/CASESENSITIVETEST11111111111111111111111111111111",root);
  snprintf(link,sizeof(link),"%s/CASESENSITIVETEST22222222222222222222222222222222",root);
  assert(close(create(data,1))==0); assert(close(create(other,0))==0);
  assert(mkdir(dir,0700)==0); assert(symlink(data,link)==0);
  assert(close(create(probe,1))==0);
  assert(durak_probe_cleanup_old(root)==0); assert(access(probe,F_OK)==0);
  assert(close(create(probe,0))==0);
  errno=ERANGE; assert(durak_probe_cleanup_old(root)==1); assert(errno==ERANGE);
  assert(access(data,F_OK)==0 && access(other,F_OK)==0 && access(dir,F_OK)==0 && access(link,F_OK)==0);
  assert(durak_probe_cleanup_old(root)==0);
  for(int failure=0;failure<3;++failure) {
    int fd=create(probe,0); durak_probe_opened(fd,probe,root);
    int fd2=open(probe,O_RDWR); assert(fd2>=0); durak_probe_opened(fd2,probe,root);
    fault=failure==0 ? EIO : failure==1 ? EBUSY : EACCES;
    assert(__wrap_unlink(probe)==-1); int saved=errno;
    durak_probe_unlink_failed(probe,saved,0xe02); assert(errno==saved);
    fault=0; finish(fd); assert(access(probe,F_OK)==0); finish(fd2);
    assert((access(probe,F_OK)==0)==(failure==2));
    if(failure==2) assert(__real_unlink(probe)==0);
  }
  int fd=create(probe,0); durak_probe_opened(fd,probe,root);
  durak_probe_unlink_failed(probe,EIO,0xe02);
  DurakProbeClose state; durak_probe_before_close(fd,&state);
  durak_probe_after_close(&state,-1,EIO,0xe02); assert(errno==EIO && access(probe,F_OK)==0);
  assert(close(fd)==0); assert(durak_probe_cleanup_old(root)==1);
  fd=create(probe,0); durak_probe_opened(fd,probe,"/tmp/unrelated");
  durak_probe_unlink_failed(probe,EIO,0xe02); finish(fd); assert(access(probe,F_OK)==0);
  assert(__real_unlink(probe)==0);
  assert(__real_unlink(link)==0); assert(rmdir(dir)==0);
  assert(__real_unlink(data)==0); assert(__real_unlink(other)==0); assert(rmdir(root)==0);
  puts("case probe cleanup: PASS (fault injection, errno, exact scope, multiple handles, failed close)");
  return 0;
}
