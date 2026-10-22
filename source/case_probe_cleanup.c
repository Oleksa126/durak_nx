/* Horizon cannot unlink an open FileStream DeleteOnClose probe. Keep its
 * real failure, then retry only this known empty temporary file after close. */
#include "case_probe_cleanup.h"
#include "util.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __SWITCH__
#include <switch.h>
static Mutex probe_lock;
#define LOCK() mutexLock(&probe_lock)
#define UNLOCK() mutexUnlock(&probe_lock)
static unsigned native_result(void) { return fsdevGetLastResult(); }
static unsigned commit(void) { return fsdevCommitDevice("sdmc"); }
#else
#include <pthread.h>
static pthread_mutex_t probe_lock=PTHREAD_MUTEX_INITIALIZER;
#define LOCK() pthread_mutex_lock(&probe_lock)
#define UNLOCK() pthread_mutex_unlock(&probe_lock)
static unsigned native_result(void) { return 0; }
static unsigned commit(void) { return 0; }
#endif

static DurakProbeClose probes[16]; /* only probe descriptors, never database FDs */
static int probe_name(const char *name) {
  const char *prefix="CASESENSITIVETEST";
  size_t n=strlen(prefix);
  if(strncmp(name,prefix,n) || strlen(name+n)!=32) return 0;
  for(int i=0;i<32;++i) if(!isxdigit((unsigned char)name[n+i])) return 0;
  return 1;
}
static int probe_path(const char *path,const char *root) {
  size_t n=strlen(root);
  return !strncmp(path,root,n) && path[n]=='/' && probe_name(path+n+1);
}
static int empty_regular(const char *path) {
  struct stat st;
#ifdef __SWITCH__
  /* sdmc (FAT/exFAT) has no symbolic links; avoid requiring newlib lstat. */
  int rc=stat(path,&st);
#else
  int rc=lstat(path,&st);
#endif
  if(rc<0) {
    int saved=errno; unsigned native=native_result();
    durak_log_printf("[CASE PROBE] stat failed: path=%s errno=%d result=0x%x\n",path,saved,native);
    errno=saved; return 0;
  }
  return S_ISREG(st.st_mode) && st.st_size==0;
}
static int remove_probe(const char *path) {
  if(!empty_regular(path)) return 0;
  int rc=unlink(path),saved=errno;
  unsigned native=rc<0 ? native_result() : 0;
  durak_log_printf("[CASE PROBE] cleanup path=%s rc=%d errno=%d result=0x%x\n",
                   path,rc,rc<0 ? saved : 0,native);
  errno=saved; return rc==0;
}
static void commit_cleanup(void) {
  unsigned rc=commit();
  if(rc) durak_log_printf("[CASE PROBE] cleanup commit failed: result=0x%x errno=%d\n",rc,errno);
}
void durak_probe_opened(int fd,const char *path,const char *root) {
  if(fd<0 || !path || !root || !probe_path(path,root) || strlen(path)>=sizeof(probes[0].path)) return;
  int saved=errno;
  struct stat st;
  if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size!=0) { errno=saved; return; }
  LOCK();
  int slot=-1;
  for(int i=0;i<16;++i) if(!probes[i].path[0]) { slot=i; break; }
  if(slot>=0) {
    probes[slot].fd=fd; probes[slot].pending=0;
    strcpy(probes[slot].path,path);
  }
  UNLOCK();
  if(slot<0) durak_log_printf("[CASE PROBE] tracking full; fd=%d retained for next startup cleanup\n",fd);
  errno=saved;
}
void durak_probe_unlink_failed(const char *path,int error,unsigned native) {
  if(!path || (error!=EIO && error!=EBUSY)) return;
  int saved=errno,matched=0;
  LOCK();
  for(int i=0;i<16;++i) if(probes[i].path[0] && !strcmp(probes[i].path,path)) {
    probes[i].pending=1; ++matched;
  }
  UNLOCK();
  if(matched) durak_log_printf("[CASE PROBE] retry after close: path=%s handles=%d errno=%d result=0x%x\n",
                               path,matched,error,native);
  errno=saved;
}
void durak_probe_before_close(int fd,DurakProbeClose *state) {
  int saved=errno;
  memset(state,0,sizeof(*state));
  LOCK();
  for(int i=0;i<16;++i) if(probes[i].path[0] && probes[i].fd==fd) {
    *state=probes[i]; memset(&probes[i],0,sizeof(probes[i])); break;
  }
  UNLOCK(); errno=saved;
}
void durak_probe_after_close(const DurakProbeClose *state,int result,int error,unsigned native) {
  if(!state->path[0]) { errno=error; return; }
  if(result<0) {
    durak_log_printf("[CASE PROBE] close failed: fd=%d errno=%d result=0x%x; no cleanup\n",
                     state->fd,error,native);
    errno=error; return;
  }
  if(state->pending) {
    int open_handles=0;
    LOCK();
    for(int i=0;i<16;++i) if(probes[i].path[0] && !strcmp(probes[i].path,state->path)) ++open_handles;
    if(!open_handles && remove_probe(state->path)) commit_cleanup();
    UNLOCK();
  }
  errno=error;
}

int durak_probe_cleanup_old(const char *root) {
  if(!root) return 0;
  int incoming=errno;
  DIR *dir=opendir(root);
  if(!dir) {
    int error=errno; unsigned native=native_result();
    durak_log_printf("[CASE PROBE] directory open failed: path=%s errno=%d result=0x%x\n",root,error,native);
    errno=incoming; return 0;
  }
  typedef struct OldProbe { struct OldProbe *next; char path[256]; } OldProbe;
  OldProbe *head=NULL;
  /* Enumerate first. Deleting during FsDirRead can invalidate its cursor. */
  while(1) {
    errno=0; struct dirent *entry=readdir(dir);
    if(!entry) {
      if(errno) {
        int error=errno; unsigned native=native_result();
        durak_log_printf("[CASE PROBE] directory read failed: errno=%d result=0x%x\n",error,native);
      }
      break;
    }
    if(!probe_name(entry->d_name)) continue;
    OldProbe *item=malloc(sizeof(*item));
    if(!item) { durak_log_printf("[CASE PROBE] allocation failed: errno=%d\n",errno); break; }
    int n=snprintf(item->path,sizeof(item->path),"%s/%s",root,entry->d_name);
    if(n<0 || (size_t)n>=sizeof(item->path)) { free(item); continue; }
    item->next=head; head=item;
  }
  int closed=closedir(dir),close_error=errno;
  unsigned close_native=closed<0 ? native_result() : 0;
  if(closed<0) durak_log_printf("[CASE PROBE] directory close failed: errno=%d result=0x%x\n",close_error,close_native);
  int removed=0;
  while(head) {
    OldProbe *next=head->next;
    if(closed==0) removed+=remove_probe(head->path);
    free(head); head=next;
  }
  if(removed) {
    commit_cleanup();
    durak_log_printf("[CASE PROBE] Removed %d old empty probes before Unity startup\n",removed);
  }
  errno=incoming; return removed;
}
