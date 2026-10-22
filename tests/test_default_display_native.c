#include "default_display.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
extern Result __wrap_viOpenDisplay(const char *,ViDisplay *);
static int opens,default_open;
Result __real_viOpenDisplay(const char *name,ViDisplay *out) {
  ++opens;memset(out,0,sizeof(*out));
  if(!strcmp(name,"Fail")) { errno=EIO;return 0xabc; }
  if(!strcmp(name,"Default") && default_open) { errno=EBUSY;return 0x1272; }
  out->display_id=!strcmp(name,"Default") ? 0xfeed : 0x1234;
  strcpy(out->display_name.data,name);out->initialized=true;
  if(!strcmp(name,"Default")) default_open=1;
  return 0;
}
int main(void) {
  ViDisplay out={.display_id=99},borrowed={0};
  assert(!durak_default_display_snapshot(&out) && out.display_id==99);
  assert(__wrap_viOpenDisplay("Fail",&out)==0xabc && errno==EIO);
  assert(!durak_default_display_snapshot(&borrowed));
  assert(!__wrap_viOpenDisplay("External",&out));
  assert(!durak_default_display_snapshot(&borrowed));
  errno=ERANGE;
  assert(!__wrap_viOpenDisplay("Default",&out) && errno==ERANGE);
  assert(durak_default_display_snapshot(&borrowed));
  assert(borrowed.display_id==0xfeed && borrowed.initialized && !strcmp(borrowed.display_name.data,"Default"));
  int before=opens;
  for(int i=0;i<1000;++i) {
    ViDisplay copy;assert(durak_default_display_snapshot(&copy));
    assert(copy.display_id==0xfeed && copy.initialized);
    copy.initialized=false; /* Borrowed copies cannot modify the SDK owner. */
  }
  assert(opens==before);
  assert(__wrap_viOpenDisplay("Default",&out)==0x1272 && errno==EBUSY);
  assert(durak_default_display_snapshot(&borrowed) && borrowed.display_id==0xfeed && borrowed.initialized);
  assert(!durak_default_display_snapshot(NULL));
  puts("Default display capture: PASS (first SDK success only, dynamic ID, no duplicate opens, error/errno preservation and owner isolation)");
  return 0;
}
