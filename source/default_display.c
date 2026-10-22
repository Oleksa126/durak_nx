#include "default_display.h"
#include <stdatomic.h>
#include <string.h>

static ViDisplay captured;
static atomic_int state; /* 0 empty, 1 writer, 2 published */
extern Result __real_viOpenDisplay(const char *name,ViDisplay *out);
/* GNU --wrap intercepts the SDK default_window.o call, before main. Keep the
 * real function's result/side effects; publish only its first successful Default
 * output. No logging, service calls or allocation during startup interception. */
Result __wrap_viOpenDisplay(const char *name,ViDisplay *out) {
  Result rc=__real_viOpenDisplay(name,out);
  if(!R_FAILED(rc) && name && out && out->initialized && !strcmp(name,"Default")) {
    int expected=0;
    if(atomic_compare_exchange_strong(&state,&expected,1)) {
      captured=*out;
      atomic_store_explicit(&state,2,memory_order_release);
    }
  }
  return rc;
}
int durak_default_display_snapshot(ViDisplay *out) {
  if(!out || atomic_load_explicit(&state,memory_order_acquire)!=2) return 0;
  *out=captured;return 1;
}
