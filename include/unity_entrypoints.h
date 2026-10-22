/* unity_entrypoints.h -- Unity native entrypoints and verified target RVAs
 * Target: ru.appscraft.durak v25.0 (Unity 6 / IL2CPP, arm64-v8a)
 */
#ifndef UNITY_ENTRYPOINTS_H
#define UNITY_ENTRYPOINTS_H

#include <stdint.h>
#include <stddef.h>
#include "so_util.h"

/* ---- Unity Lifecycle & JNI Natives (libunity.so) [CONFIRMED for Durak 25.0] ---- */
#define OFF_initJni                          0xe85c60 /* com/unity3d/player/UnityPlayer */
#define OFF_nativeInjectEvent                0xe8623c /* com/unity3d/player/UnityPlayer */
#define OFF_nativeApplicationUnload          0xe85e88 /* com/unity3d/player/UnityPlayer */
#define OFF_nativeRender                     0xe861dc /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativePause                      0xe85dc4 /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativeResume                     0xe85e28 /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativeFocusChanged               0xe85ed8 /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativeDone                       0xe85ce4 /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativeRecreateGfxState           0xe85f3c /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativeSendSurfaceChangedEvent    0xe85fa4 /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativeOnApplyWindowInsets        0xe85ff8 /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativeConfigurationChanged       0xe8614c /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativeMemoryUsageChanged         0xe85d70 /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativeGetNoWindowMode            0xe86e04 /* com/unity3d/player/UnityPlayerForActivityOrService */
#define OFF_nativeOrientationChanged         0xe86d50 /* com/unity3d/player/UnityPlayerForGameActivity */
#define OFF_nativeUnityPlayerSetRunning      0xe86db0 /* com/unity3d/player/UnityPlayerForGameActivity */
#define OFF_nativeSetLaunchURL               0xe86adc /* com/unity3d/player/UnityPlayer */
#define OFF_nativeHidePreservedContent       0xe86c98 /* com/unity3d/player/UnityPlayer */
#define OFF_nativeUnitySendMessage           0xe8684c /* com/unity3d/player/UnityPlayer */
#define OFF_nativeMuteMasterAudio            0xe86a78 /* com/unity3d/player/UnityPlayer */
#define OFF_nativeIsAutorotationOn           0xe86a18 /* com/unity3d/player/UnityPlayer */
#define OFF_nativeGetMainWindowIndex         0xe86e74 /* com/unity3d/player/UnityPlayer */
#define OFF_nativeCrashNow                   0xe86ecc /* com/unity3d/player/UnityPlayer */
#define OFF_permissionResponseToNative       0xe86c14 /* com/unity3d/player/UnityPlayer */

/* ---- FMOD Natives (libunity.so) [CONFIRMED for Durak 25.0] ---- */
#define OFF_fmodGetInfo                      0x108f264 /* org/fmod/FMODAudioDevice */
#define OFF_fmodProcess                      0x108f32c /* org/fmod/FMODAudioDevice */
#define OFF_fmodProcessMicData               0x108f3b8 /* org/fmod/FMODAudioDevice */

/* ---- TimeManager::Update (libunity.so) [CONFIRMED for Durak 25.0] ---- */
#define OFF_TimeManager_Update_entry         0xbbf058
#define OFF_TimeManager_Update_body          0xbbf07c
#define TM_FIELD_FRAMECOUNT                  0x160
#define TM_FIELD_AUX                         0x168
#define TM_FIELD_PAUSE                       0x1a8

/* ---- libmain.so exports & natives ---- */
#define OFF_MAIN_JNI_OnLoad                  0x4a80

/* ---- libil2cpp.so exports & JNI globals ---- */
#define OFF_IL2CPP_JNI_OnLoad                0xc0d5ec
#define OFF_IL2CPP_JavaVM_cache              0x1de50f8
#define OFF_IL2CPP_JNI_handler_slot          0x1de50d8
#define OFF_IL2CPP_JNI_handler_fn            0xc0d630

/* ---- JNI native signatures: ret (*)(JNIEnv*, jobject thiz, args...) ----
 * NOTE: Target DEX proof confirms initJni has 5 AAPCS64 arguments:
 * (env, thiz, context, contextType, cmdline).
 */
typedef void     (*fn_initJni)(void *env, void *thiz, void *context, int32_t context_type, void *cmdline);
typedef void     (*fn_gfxstate)(void *env, void *thiz, int32_t mode, void *surface);
typedef void     (*fn_v)(void *env, void *thiz);
typedef uint8_t  (*fn_z)(void *env, void *thiz);
typedef void     (*fn_vz)(void *env, void *thiz, int32_t val);
typedef uint8_t  (*fn_inject)(void *env, void *thiz, void *event, int32_t device_id);
typedef void     (*fn_orient)(void *env, void *thiz, int32_t orientation, int32_t rotation);

typedef struct {
  /* UnityPlayer */
  fn_initJni initJni;                        /* (env, thiz, context, contextType, cmdline) */
  fn_inject  nativeInjectEvent;              /* (env, thiz, event, [deviceId]) */
  fn_v       nativeApplicationUnload;        /* (env, thiz) */

  /* UnityPlayerForActivityOrService */
  fn_z        nativeRender;                  /* (env, thiz) -> jboolean */
  fn_z        nativePause;                   /* (env, thiz) -> jboolean */
  fn_v        nativeResume;                  /* (env, thiz) */
  fn_vz       nativeFocusChanged;            /* (env, thiz, hasFocus) */
  fn_z        nativeDone;                    /* (env, thiz) -> jboolean */
  fn_gfxstate nativeRecreateGfxState;        /* (env, thiz, mode, surface) */
  fn_v        nativeSendSurfaceChangedEvent; /* (env, thiz) */
  fn_z        nativeGetNoWindowMode;         /* (env, thiz) -> jboolean */

  /* UnityPlayerForGameActivity */
  fn_orient  nativeOrientationChanged;       /* (env, thiz, orientation, rotation) */
  fn_vz      nativeUnityPlayerSetRunning;    /* (env, thiz, isRunning) */

  /* FMOD Audio */
  void *fmodGetInfo;
  void *fmodProcess;
  void *fmodProcessMicData;

  /* NativeLoader (libmain) */
  void *nativeLoader_load;
  void *nativeLoader_unload;

  /* Registration Counters */
  size_t total_classes_registered;
  size_t total_methods_registered;
} DurakUnityNativeEntrypoints;

extern DurakUnityNativeEntrypoints g_unity_native;
extern void *fake_unityplayer_thiz;
extern void *fake_context_obj;
extern void *fake_surface_obj;

void unity_environment_init(const char *data_root);

#define UNITY_RESOLVE(mod, off) ((void*)((uintptr_t)(mod).load_virtbase + (off)))

#endif /* UNITY_ENTRYPOINTS_H */
