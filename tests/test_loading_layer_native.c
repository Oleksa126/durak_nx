#include "loading_layer.h"
#include "default_display.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
u64 __nx_vi_layer_id=777;
static Service manager={true};
static Service system_display={true};
static int manager_visible,system_visible;
static int opaque,wrong_z;
static NWindow default_window={{42}};
static int operation,fail_at,duplicate,refs,owned,opened,windows,snapshot_available=1;
static char log_text[4096];
static Result result(void) { return ++operation==fail_at ? 0xabc : 0; }
static void check_layer(ViLayer *l) { assert(l->initialized && l->layer_id==333); }
void durak_log_printf(const char *fmt,...) {
  va_list args;va_start(args,fmt);
  size_t used=strlen(log_text);vsnprintf(log_text+used,sizeof(log_text)-used,fmt,args);
  va_end(args);
}
Service *viGetSession_IManagerDisplayService(void) { return &manager; }
Service *viGetSession_ISystemDisplayService(void) { return &system_display; }
u64 appletGetAppletResourceUserId(void) { return 12345; }
NWindow *nwindowGetDefault(void) { return &default_window; }
Result viInitialize(ViServiceType type) {
  assert(type==ViServiceType_Default);Result rc=result();if(!rc) ++refs;return rc;
}
void viExit(void) { assert(refs==1);--refs; }
Result viOpenDefaultDisplay(ViDisplay *d) {
  (void)d;assert(!"Default was already opened by the SDK; reopening returns 0x1272");return 0x1272;
}
Result viCloseDisplay(ViDisplay *d) {
  (void)d;assert(!"Must not close the SDK default display");return 0;
}
int durak_default_display_snapshot(ViDisplay *d) {
  if(!snapshot_available) return 0;
  *d=(ViDisplay){.display_id=0xfeed,.initialized=true};
  strcpy(d->display_name.data,"Default");return 1;
}
Result viCreateManagedLayer(const ViDisplay *d,ViLayerFlags flags,u64 aruid,u64 *id) {
  assert(d->initialized && d->display_id==0xfeed && flags==0 && aruid==0);
  Result rc=result();if(!rc) { *id=333;++owned;opaque=manager_visible=system_visible=0; } return rc;
}
Result viCreateLayer(const ViDisplay *d,ViLayer *l) {
  assert(d->initialized && __nx_vi_layer_id==333);
  Result rc=result();if(!rc) {
    l->initialized=true;l->layer_id=333;l->igbp_binder_obj_id=duplicate ? 42 : 43;++opened;
  }
  return rc;
}
Result viCloseLayer(ViLayer *l) {
  check_layer(l);assert(opened==1);--opened;memset(l,0,sizeof(*l));return 0;
}
Result viDestroyManagedLayer(ViLayer *l) {
  assert(l->layer_id==333 && owned==1 && !opened && !windows);--owned;return 0;
}
Result viSetLayerScalingMode(ViLayer *l,ViScalingMode mode) {
  check_layer(l);assert(mode==ViScalingMode_FitToLayer);return result();
}
Result viGetZOrderCountMax(ViDisplay *d,s32 *z) {
  assert(d->initialized);Result rc=result();if(!rc) *z=99;return rc;
}
Result viSetLayerZ(ViLayer *l,s32 z) { check_layer(l);assert(z==99);return result(); }
Result viSetLayerSize(ViLayer *l,s32 w,s32 h) {
  check_layer(l);assert(w==1920 && h==1080);return result();
}
Result viSetLayerPosition(ViLayer *l,float x,float y) {
  check_layer(l);assert(x==0 && y==0);return result();
}
Result nwindowCreateFromLayer(NWindow *w,const ViLayer *l) {
  assert(l->initialized && l->layer_id==333 && w!=&default_window);
  /* A successfully created/queued layer can still be hidden. Require both
   * explicit visibility gates before publishing the independent window. */
  assert(manager_visible && system_visible && opaque);
  Result rc=result();if(!rc) { w->bq.id=43;++windows; } return rc;
}
void nwindowClose(NWindow *w) { assert(w!=&default_window && windows==1);--windows; }
Result test_service_dispatch(Service *s,unsigned command,const void *data,size_t size) {
  assert(size==16);
  const unsigned char *bytes=data;u64 id;memcpy(&id,bytes+8,8);
  assert(id==333);
  if(command==6000) {
    u32 stack,pad;memcpy(&stack,bytes,4);memcpy(&pad,bytes+4,4);
    assert(s==&manager && stack<=1 && !pad);return result();
  }
  if(command==2209) {
    float alpha;u32 pad;memcpy(&alpha,bytes,4);memcpy(&pad,bytes+4,4);
    assert(s==&system_display && alpha==1.0f && !pad);
    Result rc=result();if(!rc) opaque=1;return rc;
  }
  assert((s==&manager && command==6002) || (s==&system_display && command==2207));
  assert(bytes[0]==1);
  for(unsigned i=1;i<8;++i) assert(bytes[i]==0);
  Result rc=result();
  if(!rc) { if(s==&manager) manager_visible=1;else system_visible=1; }
  return rc;
}
Result test_service_dispatch_inout(Service *s,unsigned command,const void *data,size_t size,void *out,size_t out_size) {
  u64 id;assert(s==&system_display && command==2204 && size==8 && out_size==8);
  memcpy(&id,data,8);assert(id==333);
  Result rc=result();if(!rc) { s64 z=wrong_z ? -5 : 99;memcpy(out,&z,8); }return rc;
}
static void clean(void) {
  loading_layer_end();loading_layer_end();
  assert(!refs && !owned && !opened && !windows);
  assert(__nx_vi_layer_id==777 && default_window.bq.id==42);
}
int main(void) {
  NWindow *window=loading_layer_begin();assert(window && window!=&default_window && operation==15);
  loading_layer_report();assert(strstr(log_text,"stage=ready Result=0x0"));
  assert(strstr(log_text,"visibility_enabled=1 manager_Result=0x0 system_Result=0x0"));clean();
  assert(strstr(log_text,"owner_aruid=0 requested_alpha=1 alpha_Result=0x0 requested_z=99 observed_z=99 z_read_Result=0x0"));
  for(fail_at=1;fail_at<=15;++fail_at) {
    operation=0;log_text[0]=0;
    assert(!loading_layer_begin());loading_layer_report();
    assert(strstr(log_text,"Result=0xabc"));clean();
    assert(strstr(log_text,"visibility_enabled=0"));
    if(fail_at==13) assert(strstr(log_text,"manager_Result=0xabc"));
    if(fail_at==14) assert(strstr(log_text,"system_Result=0xabc"));
  }
  fail_at=0;operation=0;manager.active=false;
  assert(!loading_layer_begin());clean();manager.active=true;
  operation=0;duplicate=1;assert(!loading_layer_begin());clean();
  operation=0;duplicate=0;wrong_z=1;assert(!loading_layer_begin());clean();wrong_z=0;
  operation=0;snapshot_available=0;assert(!loading_layer_begin());clean();
  puts("Loading layer: PASS (manager owner, opaque alpha, Z readback, borrowed display, wire layout, 15 failure cleanups)");
  return 0;
}
