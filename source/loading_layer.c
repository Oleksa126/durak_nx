#include "loading_layer.h"
#include "default_display.h"
#include "util.h"
#include <stddef.h>
#include <string.h>

extern u64 __nx_vi_layer_id;
static ViDisplay display;
static ViLayer layer;
static NWindow window;
static u64 owned_id;
static int vi_ref,window_open;
static const char *stage="not started";
static Result last_result;
static Result manager_visibility_result,system_visibility_result;
static int visibility_enabled;
static Result alpha_result,z_read_result;
static s32 requested_z;
static s64 observed_z;

/* Same IPC layout as libtesla's viAddToLayerStack helper. Only our own layer
 * is attached to the normal display and LCD stacks; no global display state. */
static Result add_stack(ViLayerStack stack) {
  const struct { u32 stack,pad; u64 layer_id; } request={stack,0,owned_id};
  _Static_assert(sizeof(request)==16,"VI AddToLayerStack request size");
  _Static_assert(offsetof(__typeof__(request),layer_id)==8,"VI layer ID offset");
  return serviceDispatchIn(viGetSession_IManagerDisplayService(),6000,request);
}
/* SwIPC describes both visibility requests as (b8, u64): the boolean is
 * first, followed by seven zero padding bytes and the owned layer ID. VI
 * creation/stack attachment alone do not explicitly enable either gate. */
static Result set_visible(Service *service,u32 command) {
  const struct { u8 visible,pad[7]; u64 layer_id; } request={1,{0},owned_id};
  _Static_assert(sizeof(request)==16,"VI visibility request size");
  _Static_assert(offsetof(__typeof__(request),layer_id)==8,"VI visibility ID offset");
  return serviceDispatchIn(service,command,request);
}
static Result set_opaque(void) {
  const struct { float alpha;u32 pad;u64 layer_id; } request={1.0f,0,owned_id};
  _Static_assert(sizeof(request)==16,"VI alpha request size");
  _Static_assert(offsetof(__typeof__(request),layer_id)==8,"VI alpha ID offset");
  return serviceDispatchIn(viGetSession_ISystemDisplayService(),2209,request);
}
static void cleanup_error(const char *operation,Result rc) {
  if(R_FAILED(rc)) durak_log_printf("[LOADING LAYER ERROR] cleanup %s Result=0x%x\n",operation,rc);
}
void loading_layer_end(void) {
  if(window_open) { nwindowClose(&window); window_open=0; }
  if(layer.initialized) cleanup_error("viCloseLayer",viCloseLayer(&layer));
  if(owned_id) {
    ViLayer owned={.layer_id=owned_id};
    cleanup_error("viDestroyManagedLayer",viDestroyManagedLayer(&owned));
    owned_id=0; memset(&layer,0,sizeof(layer));
  }
  /* This is the SDK default window's borrowed display, not one we opened. */
  memset(&display,0,sizeof(display));
  visibility_enabled=0;
  if(vi_ref) { viExit(); vi_ref=0; }
}
NWindow *loading_layer_begin(void) {
#define TRY(name,expression) do { stage=name; last_result=(expression); if(R_FAILED(last_result)) goto fail; } while(0)
  manager_visibility_result=system_visibility_result=MAKERESULT(Module_Libnx,LibnxError_NotInitialized);
  alpha_result=z_read_result=manager_visibility_result;requested_z=0;observed_z=0;
  TRY("viInitialize",viInitialize(ViServiceType_Default)); vi_ref=1;
  if(!serviceIsActive(viGetSession_IManagerDisplayService())) {
    stage="VI manager unavailable";
    last_result=MAKERESULT(Module_Libnx,LibnxError_NotInitialized); goto fail;
  }
  stage="borrow SDK Default display";
  if(!durak_default_display_snapshot(&display)) {
    last_result=MAKERESULT(Module_Libnx,LibnxError_NotInitialized);goto fail;
  }
  last_result=0;
  /* Match the libtesla overlay ownership contract: a VI-manager-owned layer,
   * not a second application layer that was never registered through AM. */
  TRY("viCreateManagedLayer",viCreateManagedLayer(&display,(ViLayerFlags)0,0,&owned_id));
  /* libnx viCreateLayer opens __nx_vi_layer_id when nonzero. Restore the loader's
   * original override on every outcome. Default NWindow already exists before
   * main; neither it nor Unity guest threads are being created concurrently. */
  u64 saved_layer=__nx_vi_layer_id;
  __nx_vi_layer_id=owned_id;
  stage="viCreateLayer"; last_result=viCreateLayer(&display,&layer);
  __nx_vi_layer_id=saved_layer;
  if(R_FAILED(last_result)) goto fail;
  if(layer.igbp_binder_obj_id==(u32)nwindowGetDefault()->bq.id) {
    stage="separate producer validation";
    last_result=MAKERESULT(Module_Libnx,LibnxError_BadInput); goto fail;
  }
  TRY("viSetLayerScalingMode",viSetLayerScalingMode(&layer,ViScalingMode_FitToLayer));
  s32 z=0;
  TRY("viGetZOrderCountMax",viGetZOrderCountMax(&display,&z));
  requested_z=z;
  if(z<=0) { stage="positive overlay Z validation";last_result=MAKERESULT(Module_Libnx,LibnxError_BadInput);goto fail; }
  TRY("viSetLayerZ",viSetLayerZ(&layer,z));
  TRY("read layer Z",z_read_result=serviceDispatchInOut(viGetSession_ISystemDisplayService(),2204,owned_id,observed_z));
  if(observed_z!=z) { stage="overlay Z readback validation";last_result=MAKERESULT(Module_Libnx,LibnxError_BadInput);goto fail; }
  TRY("attach default stack",add_stack(ViLayerStack_Default));
  TRY("attach LCD stack",add_stack(ViLayerStack_Lcd));
  /* VI's Default display logical size is 1920x1080 in handheld as well.
   * FitToLayer scales the fixed 1280x720 loading buffer in both modes. */
  TRY("viSetLayerSize",viSetLayerSize(&layer,1920,1080));
  TRY("viSetLayerPosition",viSetLayerPosition(&layer,0,0));
  TRY("opaque layer alpha",alpha_result=set_opaque());
  TRY("manager layer visibility",manager_visibility_result=set_visible(viGetSession_IManagerDisplayService(),6002));
  TRY("system layer visibility",system_visibility_result=set_visible(viGetSession_ISystemDisplayService(),2207));
  visibility_enabled=1;
  TRY("nwindowCreateFromLayer",nwindowCreateFromLayer(&window,&layer)); window_open=1;
  stage="ready"; return &window;
fail:
  durak_log_printf("[LOADING LAYER ERROR] %s Result=0x%x; same-image EGL fallback\n",stage,last_result);
  loading_layer_end(); return NULL;
#undef TRY
}
void loading_layer_report(void) {
  durak_log_printf("[LOADING LAYER] stage=%s Result=0x%x borrowed_display=%d display_id=%llu owned_id=%llu producer=%u default_producer=%d\n",
      stage,last_result,display.initialized,(unsigned long long)display.display_id,
      (unsigned long long)owned_id,layer.igbp_binder_obj_id,nwindowGetDefault()->bq.id);
  durak_log_printf("[LOADING LAYER] visibility_enabled=%d manager_Result=0x%x system_Result=0x%x\n",
      visibility_enabled,manager_visibility_result,system_visibility_result);
  durak_log_printf("[LOADING LAYER] owner_aruid=0 requested_alpha=1 alpha_Result=0x%x requested_z=%d observed_z=%lld z_read_Result=0x%x\n",
      alpha_result,requested_z,(long long)observed_z,z_read_result);
}
