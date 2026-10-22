#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef uint32_t u32,Result;
typedef uint8_t u8;
typedef uint64_t u64;
typedef int64_t s64;
typedef int32_t s32;
typedef struct { bool active; } Service;
typedef struct { char data[64]; } ViDisplayName;
typedef struct { u64 display_id;ViDisplayName display_name;bool initialized; } ViDisplay;
typedef struct { u64 layer_id;u32 igbp_binder_obj_id;bool initialized; } ViLayer;
typedef struct { struct { s32 id; } bq; } NWindow;
typedef enum { ViServiceType_Default=-1 } ViServiceType;
typedef enum { ViScalingMode_FitToLayer=2 } ViScalingMode;
typedef unsigned ViLayerFlags;
typedef enum { ViLayerStack_Default=0,ViLayerStack_Lcd=1 } ViLayerStack;
#define R_FAILED(rc) ((rc)!=0)
#define Module_Libnx 345
#define LibnxError_NotInitialized 5
#define LibnxError_BadInput 11
#define MAKERESULT(module,description) ((Result)((module)|((description)<<9)))
static inline bool serviceIsActive(Service *service) { return service->active; }
Service *viGetSession_IManagerDisplayService(void);
Service *viGetSession_ISystemDisplayService(void);
Result test_service_dispatch(Service *,unsigned,const void *,size_t);
#define serviceDispatchIn(s,cmd,in) test_service_dispatch(s,cmd,&(in),sizeof(in))
Result test_service_dispatch_inout(Service *,unsigned,const void *,size_t,void *,size_t);
#define serviceDispatchInOut(s,cmd,in,out) test_service_dispatch_inout(s,cmd,&(in),sizeof(in),&(out),sizeof(out))
Result viInitialize(ViServiceType);
void viExit(void);
Result viOpenDefaultDisplay(ViDisplay *);
Result viCloseDisplay(ViDisplay *);
Result viCreateManagedLayer(const ViDisplay *,ViLayerFlags,u64,u64 *);
Result viCreateLayer(const ViDisplay *,ViLayer *);
Result viCloseLayer(ViLayer *);
Result viDestroyManagedLayer(ViLayer *);
Result viSetLayerScalingMode(ViLayer *,ViScalingMode);
Result viGetZOrderCountMax(ViDisplay *,s32 *);
Result viSetLayerZ(ViLayer *,s32);
Result viSetLayerSize(ViLayer *,s32,s32);
Result viSetLayerPosition(ViLayer *,float,float);
u64 appletGetAppletResourceUserId(void);
NWindow *nwindowGetDefault(void);
Result nwindowCreateFromLayer(NWindow *,const ViLayer *);
void nwindowClose(NWindow *);
