#!/usr/bin/env python3
"""
tools/generate_symbol_inventory.py - Canonical 362 Strong Symbol / 631 Relocation Site Inventory Generator.

Features:
- Fail-Closed direct ELF binary verification (size, SHA-256, and GNU Build-ID).
- Direct in-memory ELF parsing and linking via MultiModuleLoader (NO dependence on pre-baked JSON).
- Automatic .dynsym st_type (STT_FUNC / STT_OBJECT) verification for all 362 symbols.
- C ABI prototypes cataloged against Android NDK r26b (API 24+ AArch64 Bionic sysroot).
- Strict Wave 1 purity: only stateless, locale-independent leaf functions (27 symbols / 45 sites).
- Explicit unverified marking for constructor reachability until full static call-graph analysis.
- Parameterized output_dir and testable fail-closed validators.
"""

import os
import sys
import io
import json
import struct
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional
from elftools.elf.elffile import ELFFile

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
EXTRACTED_DIR = REPO_ROOT / "extracted_durak"

NDK_API_REFERENCE = "Android NDK r26b (API 24+ AArch64 Bionic sysroot)"

# Canonical expected libraries root of trust
EXPECTED_CORE_LIBRARIES = {
    "libsqlite3.so": {
        "size": 1797248,
        "sha256": "6df7a75d31c417cae7e877fd7c3d190e0ac47b1f104ae0ae5501d72491b1c32c",
        "build_id": "99495662cefa74605573c8dc36a53cb1f842764d"
    },
    "libmain.so": {
        "size": 6696,
        "sha256": "c11373dffa1bab427e8864a40313111de2a70367d052d87f33a9069ce8949d93",
        "build_id": "c5498ab8c791f1473a54c79a9d3c5b738ff6d941"
    },
    "libunity.so": {
        "size": 21388304,
        "sha256": "292f89210151ba0060f77d137cd6a00a52158dc5da760d4bf106158fc9309cef",
        "build_id": "bcc661ea2046416d"
    },
    "libil2cpp.so": {
        "size": 31256704,
        "sha256": "7bc9c2e7e20c741a511e6645589db16d0fa084d79bcfc12ba1fab78931e2271c",
        "build_id": "d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0"
    }
}

# Complete Database of Symbol Signatures, Headers, and Classifications
SYMBOL_METADATA: Dict[str, Dict[str, str]] = {
    "AAssetManager_fromJava": {
        "sig": "AAssetManager* AAssetManager_fromJava(JNIEnv* env, jobject assetManager);",
        "header": "<android/asset_manager_jni.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns native AAssetManager pointer from Java object."
    },
    "AAssetManager_open": {
        "sig": "AAsset* AAssetManager_open(AAssetManager* mgr, const char* filename, int mode);",
        "header": "<android/asset_manager.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Opens streaming asset file from SD/RomFS."
    },
    "AAsset_close": {
        "sig": "void AAsset_close(AAsset* asset);",
        "header": "<android/asset_manager.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Closes asset."
    },
    "AAsset_getBuffer": {
        "sig": "const void* AAsset_getBuffer(AAsset* asset);",
        "header": "<android/asset_manager.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns direct memory pointer to asset."
    },
    "AAsset_getLength": {
        "sig": "off_t AAsset_getLength(AAsset* asset);",
        "header": "<android/asset_manager.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns asset total length."
    },
    "AAsset_getLength64": {
        "sig": "off64_t AAsset_getLength64(AAsset* asset);",
        "header": "<android/asset_manager.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "64-bit asset total length."
    },
    "AAsset_getRemainingLength": {
        "sig": "off_t AAsset_getRemainingLength(AAsset* asset);",
        "header": "<android/asset_manager.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns remaining bytes in asset."
    },
    "AAsset_getRemainingLength64": {
        "sig": "off64_t AAsset_getRemainingLength64(AAsset* asset);",
        "header": "<android/asset_manager.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "64-bit remaining bytes in asset."
    },
    "AAsset_read": {
        "sig": "int AAsset_read(AAsset* asset, void* buf, size_t count);",
        "header": "<android/asset_manager.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reads bytes from asset."
    },
    "AAsset_seek": {
        "sig": "off_t AAsset_seek(AAsset* asset, off_t offset, int whence);",
        "header": "<android/asset_manager.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Repositions asset stream."
    },
    "AAsset_seek64": {
        "sig": "off64_t AAsset_seek64(AAsset* asset, off64_t offset, int whence);",
        "header": "<android/asset_manager.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "64-bit asset repositioning."
    },
    "AChoreographer_getInstance": {
        "sig": "AChoreographer* AChoreographer_getInstance(void);",
        "header": "<android/choreographer.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns singleton Choreographer instance for thread."
    },
    "AChoreographer_postFrameCallback": {
        "sig": "void AChoreographer_postFrameCallback(AChoreographer* choreographer, AChoreographer_frameCallback callback, void* data);",
        "header": "<android/choreographer.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Schedules frame callback on Vsync."
    },
    "AChoreographer_postFrameCallbackDelayed": {
        "sig": "void AChoreographer_postFrameCallbackDelayed(AChoreographer* choreographer, AChoreographer_frameCallback callback, void* data, long delayMillis);",
        "header": "<android/choreographer.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Schedules delayed frame callback."
    },
    "AConfiguration_delete": {
        "sig": "void AConfiguration_delete(AConfiguration* config);",
        "header": "<android/configuration.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Releases configuration object."
    },
    "AConfiguration_fromAssetManager": {
        "sig": "void AConfiguration_fromAssetManager(AConfiguration* out, AAssetManager* am);",
        "header": "<android/configuration.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initializes configuration from asset manager."
    },
    "AConfiguration_getCountry": {
        "sig": "void AConfiguration_getCountry(AConfiguration* config, char* outCountry);",
        "header": "<android/configuration.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns country code (e.g. 'UA', 'US')."
    },
    "AConfiguration_getDensity": {
        "sig": "int32_t AConfiguration_getDensity(AConfiguration* config);",
        "header": "<android/configuration.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns screen density (ACONFIGURATION_DENSITY_HIGH = 240)."
    },
    "AConfiguration_getLanguage": {
        "sig": "void AConfiguration_getLanguage(AConfiguration* config, char* outLanguage);",
        "header": "<android/configuration.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns language code (e.g. 'uk', 'en')."
    },
    "AConfiguration_getOrientation": {
        "sig": "int32_t AConfiguration_getOrientation(AConfiguration* config);",
        "header": "<android/configuration.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns screen orientation (ACONFIGURATION_ORIENTATION_LAND = 2)."
    },
    "AConfiguration_new": {
        "sig": "AConfiguration* AConfiguration_new(void);",
        "header": "<android/configuration.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates configuration object."
    },
    "ALooper_acquire": {
        "sig": "void ALooper_acquire(ALooper* looper);",
        "header": "<android/looper.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Increments looper reference count."
    },
    "ALooper_addFd": {
        "sig": "int ALooper_addFd(ALooper* looper, int fd, int ident, int events, ALooper_callbackFunc callback, void* data);",
        "header": "<android/looper.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Adds file descriptor to looper."
    },
    "ALooper_forThread": {
        "sig": "ALooper* ALooper_forThread(void);",
        "header": "<android/looper.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns looper associated with calling thread."
    },
    "ALooper_pollAll": {
        "sig": "int ALooper_pollAll(int timeoutMillis, int* outFd, int* outEvents, void** outData);",
        "header": "<android/looper.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Polls all file descriptors in looper repeatedly."
    },
    "ALooper_pollOnce": {
        "sig": "int ALooper_pollOnce(int timeoutMillis, int* outFd, int* outEvents, void** outData);",
        "header": "<android/looper.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Polls all file descriptors in looper."
    },
    "ALooper_prepare": {
        "sig": "ALooper* ALooper_prepare(int opts);",
        "header": "<android/looper.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Prepares looper for calling thread."
    },
    "ALooper_release": {
        "sig": "void ALooper_release(ALooper* looper);",
        "header": "<android/looper.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Decrements looper reference count."
    },
    "ALooper_removeFd": {
        "sig": "int ALooper_removeFd(ALooper* looper, int fd);",
        "header": "<android/looper.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Removes file descriptor from looper."
    },
    "ALooper_wake": {
        "sig": "void ALooper_wake(ALooper* looper);",
        "header": "<android/looper.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Wakes polling looper."
    },
    "ANativeWindow_acquire": {
        "sig": "void ANativeWindow_acquire(ANativeWindow* window);",
        "header": "<android/native_window.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Acquires reference on native window."
    },
    "ANativeWindow_fromSurface": {
        "sig": "ANativeWindow* ANativeWindow_fromSurface(JNIEnv* env, jobject surface);",
        "header": "<android/native_window_jni.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns native window backing Surface for Switch display."
    },
    "ANativeWindow_getFormat": {
        "sig": "int32_t ANativeWindow_getFormat(ANativeWindow* window);",
        "header": "<android/native_window.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns window pixel format (WINDOW_FORMAT_RGBA_8888 = 1)."
    },
    "ANativeWindow_getHeight": {
        "sig": "int32_t ANativeWindow_getHeight(ANativeWindow* window);",
        "header": "<android/native_window.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns window height (720)."
    },
    "ANativeWindow_getWidth": {
        "sig": "int32_t ANativeWindow_getWidth(ANativeWindow* window);",
        "header": "<android/native_window.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns window width (1280)."
    },
    "ANativeWindow_release": {
        "sig": "void ANativeWindow_release(ANativeWindow* window);",
        "header": "<android/native_window.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Releases reference on native window."
    },
    "ANativeWindow_setBuffersGeometry": {
        "sig": "int32_t ANativeWindow_setBuffersGeometry(ANativeWindow* window, int32_t width, int32_t height, int32_t format);",
        "header": "<android/native_window.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets display framebuffer resolution (1280x720 or 1920x1080)."
    },
    "ASensorEventQueue_disableSensor": {
        "sig": "int ASensorEventQueue_disableSensor(ASensorEventQueue* queue, ASensor const* sensor);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Disables hardware sensor events. Safe stub returning 0."
    },
    "ASensorEventQueue_enableSensor": {
        "sig": "int ASensorEventQueue_enableSensor(ASensorEventQueue* queue, ASensor const* sensor);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Enables hardware sensor events. Safe stub returning 0."
    },
    "ASensorEventQueue_getEvents": {
        "sig": "ssize_t ASensorEventQueue_getEvents(ASensorEventQueue* queue, ASensorEvent* events, size_t count);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Polls sensor events. Returns 0 events."
    },
    "ASensorEventQueue_hasEvents": {
        "sig": "int ASensorEventQueue_hasEvents(ASensorEventQueue* queue);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Checks if sensor events available. Returns 0."
    },
    "ASensorEventQueue_setEventRate": {
        "sig": "int ASensorEventQueue_setEventRate(ASensorEventQueue* queue, ASensor const* sensor, int32_t usec);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets sensor reporting rate. Returns 0."
    },
    "ASensorManager_createEventQueue": {
        "sig": "ASensorEventQueue* ASensorManager_createEventQueue(ASensorManager* manager, ALooper* looper, int ident, ALooper_callbackFunc callback, void* data);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates sensor event queue."
    },
    "ASensorManager_destroyEventQueue": {
        "sig": "int ASensorManager_destroyEventQueue(ASensorManager* manager, ASensorEventQueue* queue);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Destroys sensor event queue."
    },
    "ASensorManager_getDefaultSensor": {
        "sig": "ASensor const* ASensorManager_getDefaultSensor(ASensorManager* manager, int type);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Gets default sensor handle."
    },
    "ASensorManager_getInstance": {
        "sig": "ASensorManager* ASensorManager_getInstance(void);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns singleton sensor manager."
    },
    "ASensorManager_getSensorList": {
        "sig": "int ASensorManager_getSensorList(ASensorManager* manager, ASensorList* list);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns list of available sensors (0 sensors)."
    },
    "ASensor_getMinDelay": {
        "sig": "int ASensor_getMinDelay(ASensor const* sensor);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns sensor minimum delay."
    },
    "ASensor_getName": {
        "sig": "const char* ASensor_getName(ASensor const* sensor);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns sensor name string."
    },
    "ASensor_getResolution": {
        "sig": "float ASensor_getResolution(ASensor const* sensor);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns sensor resolution."
    },
    "ASensor_getType": {
        "sig": "int ASensor_getType(ASensor const* sensor);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns sensor type."
    },
    "ASensor_getVendor": {
        "sig": "const char* ASensor_getVendor(ASensor const* sensor);",
        "header": "<android/sensor.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns sensor vendor string."
    },
    "__FD_CLR_chk": {
        "sig": "void __FD_CLR_chk(int fd, fd_set* set, size_t set_size);",
        "header": "<sys/select.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Fortified bounds-checked FD_CLR."
    },
    "__FD_ISSET_chk": {
        "sig": "int __FD_ISSET_chk(int fd, const fd_set* set, size_t set_size);",
        "header": "<sys/select.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Fortified bounds-checked FD_ISSET."
    },
    "__FD_SET_chk": {
        "sig": "void __FD_SET_chk(int fd, fd_set* set, size_t set_size);",
        "header": "<sys/select.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Fortified bounds-checked FD_SET."
    },
    "__android_log_assert": {
        "sig": "void __android_log_assert(const char* cond, const char* tag, const char* fmt, ...) __attribute__((noreturn));",
        "header": "<android/log.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Android assert failure handler. Logs assert and aborts."
    },
    "__assert2": {
        "sig": "void __assert2(const char* file, int line, const char* function, const char* expression) __attribute__((noreturn));",
        "header": "<assert.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Bionic assert failure handler. Logs expression and aborts."
    },
    "__ctype_get_mb_cur_max": {
        "sig": "size_t __ctype_get_mb_cur_max(void);",
        "header": "<stdlib.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "__cxa_atexit": {
        "sig": "int __cxa_atexit(void (*func)(void*), void* arg, void* dso_handle);",
        "header": "<stdlib.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "C++ global destructor registration. Tracks functions to invoke on module unload."
    },
    "__cxa_finalize": {
        "sig": "void __cxa_finalize(void* dso_handle);",
        "header": "<stdlib.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Invokes registered C++ destructors for given DSO handle."
    },
    "__errno": {
        "sig": "int* __errno(void);",
        "header": "<errno.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Bionic TLS errno pointer. In single-thread, returns global errno."
    },
    "__gnu_strerror_r": {
        "sig": "char* __gnu_strerror_r(int errnum, char* buf, size_t buflen);",
        "header": "<string.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "GNU thread-safe strerror returning string pointer."
    },
    "__register_atfork": {
        "sig": "int __register_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void), void* dso_handle);",
        "header": "<pthread.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Registers fork handlers. On Horizon OS (no fork), no-op returning 0."
    },
    "__sF": {
        "sig": "extern FILE __sF[];",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_OBJECT",
        "safety": "Legacy BSD FILE array containing stdin (__sF[0]), stdout (__sF[1]), stderr (__sF[2])."
    },
    "__stack_chk_fail": {
        "sig": "void __stack_chk_fail(void) __attribute__((noreturn));",
        "header": "<stdlib.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Called when stack buffer overflow detected. Immediately logs error and aborts."
    },
    "__stack_chk_guard": {
        "sig": "extern uintptr_t __stack_chk_guard;",
        "header": "<stdint.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_OBJECT",
        "safety": "Global stack canary word. Initialized to random canary value at startup."
    },
    "__system_property_find": {
        "sig": "const prop_info* __system_property_find(const char* name);",
        "header": "<sys/system_properties.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Finds system property info pointer."
    },
    "__system_property_get": {
        "sig": "int __system_property_get(const char* name, char* value);",
        "header": "<sys/system_properties.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Retrieves Android system properties (ro.build.version.release='13', ro.product.model='Nintendo Switch', etc.)."
    },
    "__system_property_read": {
        "sig": "int __system_property_read(const prop_info* pi, char* name, char* value);",
        "header": "<sys/system_properties.h>",
        "wave": "Wave 8 (Android NDK & Properties)",
        "strategy": "ANDROID_NDK_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reads property name and value from prop_info."
    },
    "abort": {
        "sig": "void abort(void) __attribute__((noreturn));",
        "header": "<stdlib.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Abnormal program termination. Logs fatal diagnostic and halts safely."
    },
    "accept": {
        "sig": "int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Accepts connection on listening socket."
    },
    "access": {
        "sig": "int access(const char* pathname, int mode);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Checks file accessibility with path translation."
    },
    "android_set_abort_message": {
        "sig": "void android_set_abort_message(const char* msg);",
        "header": "<android/set_abort_message.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Stores abort message into crash buffer and logs via LOGE."
    },
    "asprintf": {
        "sig": "int asprintf(char** strp, const char* fmt, ...);",
        "header": "<stdio.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Allocating string formatting via malloc."
    },
    "basename": {
        "sig": "char* basename(const char* path);",
        "header": "<string.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_PATH_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Bionic basename(const char*) uses internal thread-local storage rather than in-place modification. Grouped with FS/path subsystem."
    },
    "bind": {
        "sig": "int bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Binds socket to local address."
    },
    "bsearch": {
        "sig": "void* bsearch(const void* key, const void* base, size_t nmemb, size_t size, int (*compar)(const void*, const void*));",
        "header": "<stdlib.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Pure algorithmic binary search over caller-provided buffer. Stateless, thread-safe, 0 heap allocations, safe anywhere."
    },
    "btowc": {
        "sig": "wint_t btowc(int c);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "chdir": {
        "sig": "int chdir(const char* path);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Changes current working directory."
    },
    "chmod": {
        "sig": "int chmod(const char* pathname, mode_t mode);",
        "header": "<sys/stat.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Change file permissions."
    },
    "clearerr": {
        "sig": "void clearerr(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Clears stream EOF and error indicators."
    },
    "clock": {
        "sig": "clock_t clock(void);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "CPU execution ticks since process startup."
    },
    "clock_getres": {
        "sig": "int clock_getres(clockid_t clk_id, struct timespec* res);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Clock resolution querying. Returns 1 ns resolution."
    },
    "clock_gettime": {
        "sig": "int clock_gettime(clockid_t clk_id, struct timespec* tp);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "POSIX monotonic and realtime clock querying via armGetSystemTick() and svcGetSystemTick()."
    },
    "close": {
        "sig": "int close(int fd);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Closes POSIX file descriptor."
    },
    "closedir": {
        "sig": "int closedir(DIR* dirp);",
        "header": "<dirent.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Closes directory stream."
    },
    "closelog": {
        "sig": "void closelog(void);",
        "header": "<syslog.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Closes connection to system logger."
    },
    "connect": {
        "sig": "int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initiates connection on a socket."
    },
    "difftime": {
        "sig": "double difftime(time_t time1, time_t time0);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Difference between two calendar times."
    },
    "div": {
        "sig": "div_t div(int numer, int denom);",
        "header": "<stdlib.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Integer quotient and remainder. Pure leaf math."
    },
    "dl_iterate_phdr": {
        "sig": "int dl_iterate_phdr(int (*callback)(struct dl_phdr_info* info, size_t size, void* data), void* data);",
        "header": "<link.h>",
        "wave": "Wave 7 (DL & Zlib)",
        "strategy": "DL_ZLIB_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Iterates through program headers of all loaded modules (used by unwinder/IL2CPP)."
    },
    "dladdr": {
        "sig": "int dladdr(const void* addr, Dl_info* info);",
        "header": "<dlfcn.h>",
        "wave": "Wave 7 (DL & Zlib)",
        "strategy": "DL_ZLIB_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Finds module and symbol containing virtual code address."
    },
    "dlclose": {
        "sig": "int dlclose(void* handle);",
        "header": "<dlfcn.h>",
        "wave": "Wave 7 (DL & Zlib)",
        "strategy": "DL_ZLIB_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Decrements module reference count."
    },
    "dlerror": {
        "sig": "char* dlerror(void);",
        "header": "<dlfcn.h>",
        "wave": "Wave 7 (DL & Zlib)",
        "strategy": "DL_ZLIB_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Returns last dynamic linker error message."
    },
    "dlopen": {
        "sig": "void* dlopen(const char* filename, int flags);",
        "header": "<dlfcn.h>",
        "wave": "Wave 7 (DL & Zlib)",
        "strategy": "DL_ZLIB_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Dynamic library loading. Maps known library handles (libunity, libmain, libsqlite3, libil2cpp)."
    },
    "dlsym": {
        "sig": "void* dlsym(void* handle, const char* symbol);",
        "header": "<dlfcn.h>",
        "wave": "Wave 7 (DL & Zlib)",
        "strategy": "DL_ZLIB_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Symbol lookup in loaded module export tables."
    },
    "dup": {
        "sig": "int dup(int oldfd);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Duplicates file descriptor."
    },
    "dup2": {
        "sig": "int dup2(int oldfd, int newfd);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Duplicates file descriptor to specific newfd."
    },
    "duplocale": {
        "sig": "locale_t duplocale(locale_t locobj);",
        "header": "<locale.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "eglChooseConfig": {
        "sig": "EGLBoolean eglChooseConfig(EGLDisplay dpy, const EGLint* attrib_list, EGLConfig* configs, EGLint config_size, EGLint* num_config);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Matches EGL framebuffer configuration."
    },
    "eglCreateContext": {
        "sig": "EGLContext eglCreateContext(EGLDisplay dpy, EGLConfig config, EGLContext share_context, const EGLint* attrib_list);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates OpenGL ES 3.2 rendering context."
    },
    "eglCreatePbufferSurface": {
        "sig": "EGLSurface eglCreatePbufferSurface(EGLDisplay dpy, EGLConfig config, const EGLint* attrib_list);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates off-screen pixel buffer surface."
    },
    "eglCreateWindowSurface": {
        "sig": "EGLSurface eglCreateWindowSurface(EGLDisplay dpy, EGLConfig config, EGLNativeWindowType win, const EGLint* attrib_list);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates on-screen EGL rendering surface bound to Switch native window."
    },
    "eglDestroyContext": {
        "sig": "EGLBoolean eglDestroyContext(EGLDisplay dpy, EGLContext ctx);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Destroys OpenGL ES rendering context."
    },
    "eglDestroySurface": {
        "sig": "EGLBoolean eglDestroySurface(EGLDisplay dpy, EGLSurface surface);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Destroys EGL rendering surface."
    },
    "eglGetConfigAttrib": {
        "sig": "EGLBoolean eglGetConfigAttrib(EGLDisplay dpy, EGLConfig config, EGLint attribute, EGLint* value);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Queries EGL configuration attribute."
    },
    "eglGetConfigs": {
        "sig": "EGLBoolean eglGetConfigs(EGLDisplay dpy, EGLConfig* configs, EGLint config_size, EGLint* num_config);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns all available EGL configurations."
    },
    "eglGetCurrentContext": {
        "sig": "EGLContext eglGetCurrentContext(void);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns current thread EGL context."
    },
    "eglGetCurrentSurface": {
        "sig": "EGLSurface eglGetCurrentSurface(EGLint readdraw);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns current thread draw/read surface."
    },
    "eglGetDisplay": {
        "sig": "EGLDisplay eglGetDisplay(EGLNativeDisplayType display_id);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Obtains EGL display connection. Returns native display handle."
    },
    "eglGetError": {
        "sig": "EGLint eglGetError(void);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns last EGL error code (EGL_SUCCESS = 0x3000)."
    },
    "eglGetProcAddress": {
        "sig": "void (*eglGetProcAddress(const char* procname))(void);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Extension function pointer resolver."
    },
    "eglInitialize": {
        "sig": "EGLBoolean eglInitialize(EGLDisplay dpy, EGLint* major, EGLint* minor);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initializes EGL display (version 1.5)."
    },
    "eglMakeCurrent": {
        "sig": "EGLBoolean eglMakeCurrent(EGLDisplay dpy, EGLSurface draw, EGLSurface read, EGLContext ctx);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Binds context to current rendering thread and surfaces."
    },
    "eglQueryContext": {
        "sig": "EGLBoolean eglQueryContext(EGLDisplay dpy, EGLContext ctx, EGLint attribute, EGLint* value);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Queries context attribute."
    },
    "eglQueryString": {
        "sig": "const char* eglQueryString(EGLDisplay dpy, EGLint name);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns EGL vendor, version, and extensions string."
    },
    "eglQuerySurface": {
        "sig": "EGLBoolean eglQuerySurface(EGLDisplay dpy, EGLSurface surface, EGLint attribute, EGLint* value);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Queries surface dimensions (width, height)."
    },
    "eglSurfaceAttrib": {
        "sig": "EGLBoolean eglSurfaceAttrib(EGLDisplay dpy, EGLSurface surface, EGLint attribute, EGLint value);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets EGL surface attribute."
    },
    "eglSwapBuffers": {
        "sig": "EGLBoolean eglSwapBuffers(EGLDisplay dpy, EGLSurface surface);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Presents rendered frame to display."
    },
    "eglSwapInterval": {
        "sig": "EGLBoolean eglSwapInterval(EGLDisplay dpy, EGLint interval);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets minimum number of video frames between buffer swaps (vsync)."
    },
    "eglTerminate": {
        "sig": "EGLBoolean eglTerminate(EGLDisplay dpy);",
        "header": "<EGL/egl.h>",
        "wave": "Wave 9 (EGL Graphics)",
        "strategy": "EGL_GRAPHICS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Terminates EGL display."
    },
    "exit": {
        "sig": "void exit(int status) __attribute__((noreturn));",
        "header": "<stdlib.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Terminates program cleanly. Calls __cxa_finalize, flushes log, exits loop."
    },
    "exp2": {
        "sig": "double exp2(double x);",
        "header": "<math.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Base-2 exponential. Pure math leaf."
    },
    "exp2f": {
        "sig": "float exp2f(float x);",
        "header": "<math.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Single-precision base-2 exponential. Pure math leaf."
    },
    "faccessat": {
        "sig": "int faccessat(int dirfd, const char* pathname, int mode, int flags);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Checks file accessibility relative to directory."
    },
    "fchmod": {
        "sig": "int fchmod(int fd, mode_t mode);",
        "header": "<sys/stat.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Change file permissions by descriptor."
    },
    "fchown": {
        "sig": "int fchown(int fd, uid_t owner, gid_t group);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Change file ownership (no-op on FAT32/exFAT SD)."
    },
    "fclose": {
        "sig": "int fclose(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Flushes and closes standard I/O stream."
    },
    "fcntl": {
        "sig": "int fcntl(int fd, int cmd, ...);",
        "header": "<fcntl.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "File descriptor control (F_GETFL, F_SETFL O_NONBLOCK)."
    },
    "fdatasync": {
        "sig": "int fdatasync(int fd);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Synchronizes file data to SD storage."
    },
    "fdopen": {
        "sig": "FILE* fdopen(int fd, const char* mode);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Associates stream with existing file descriptor."
    },
    "feof": {
        "sig": "int feof(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Checks stream end-of-file indicator."
    },
    "ferror": {
        "sig": "int ferror(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Checks stream error indicator."
    },
    "fflush": {
        "sig": "int fflush(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Flushes stream buffer to file."
    },
    "fgetc": {
        "sig": "int fgetc(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reads next character from stream."
    },
    "fgets": {
        "sig": "char* fgets(char* s, int size, FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reads line from stream."
    },
    "fileno": {
        "sig": "int fileno(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns integer descriptor associated with stream."
    },
    "flock": {
        "sig": "int flock(int fd, int operation);",
        "header": "<sys/file.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Apply or remove advisory lock on open file."
    },
    "fnmatch": {
        "sig": "int fnmatch(const char* pattern, const char* string, int flags);",
        "header": "<fnmatch.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Match filename or pathname against shell wildcard pattern."
    },
    "fopen": {
        "sig": "FILE* fopen(const char* pathname, const char* mode);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Opens standard I/O stream with path translation."
    },
    "fpathconf": {
        "sig": "long fpathconf(int fd, int name);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Get configuration values for file descriptor."
    },
    "fprintf": {
        "sig": "int fprintf(FILE* stream, const char* format, ...);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Formatted stream output."
    },
    "fputc": {
        "sig": "int fputc(int c, FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Writes character to stream."
    },
    "fputs": {
        "sig": "int fputs(const char* s, FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Writes string to stream."
    },
    "fread": {
        "sig": "size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Binary stream input."
    },
    "freeaddrinfo": {
        "sig": "void freeaddrinfo(struct addrinfo* res);",
        "header": "<netdb.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Frees addrinfo structure."
    },
    "freelocale": {
        "sig": "void freelocale(locale_t locobj);",
        "header": "<locale.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "fscanf": {
        "sig": "int fscanf(FILE* stream, const char* format, ...);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Formatted stream input."
    },
    "fseek": {
        "sig": "int fseek(FILE* stream, long offset, int whence);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Repositions stream."
    },
    "fseeko": {
        "sig": "int fseeko(FILE* stream, off_t offset, int whence);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Repositions stream with off_t offset."
    },
    "fstat": {
        "sig": "int fstat(int fd, struct stat* statbuf);",
        "header": "<sys/stat.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "File status by descriptor."
    },
    "fstat64": {
        "sig": "int fstat64(int fd, struct stat64* statbuf);",
        "header": "<sys/stat.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "64-bit file status by descriptor."
    },
    "fstatat": {
        "sig": "int fstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags);",
        "header": "<sys/stat.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "File status relative to dirfd."
    },
    "fstatfs": {
        "sig": "int fstatfs(int fd, struct statfs* buf);",
        "header": "<sys/vfs.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "File system statistics by descriptor."
    },
    "fsync": {
        "sig": "int fsync(int fd);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Synchronizes file data to SD storage."
    },
    "ftell": {
        "sig": "long ftell(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns current stream position."
    },
    "ftello": {
        "sig": "off_t ftello(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Obtains stream offset with off_t size."
    },
    "ftruncate": {
        "sig": "int ftruncate(int fd, off_t length);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Truncates file by descriptor."
    },
    "futimens": {
        "sig": "int futimens(int fd, const struct timespec times[2]);",
        "header": "<sys/stat.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Change file timestamps with nanosecond precision."
    },
    "fwrite": {
        "sig": "size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Binary stream output."
    },
    "gai_strerror": {
        "sig": "const char* gai_strerror(int errcode);",
        "header": "<netdb.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns error message for getaddrinfo error."
    },
    "getaddrinfo": {
        "sig": "int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res);",
        "header": "<netdb.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "DNS network address and service translation."
    },
    "getauxval": {
        "sig": "unsigned long getauxval(unsigned long type);",
        "header": "<sys/auxv.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Retrieves auxiliary vector value (AT_PAGESZ=4096, AT_HWCAP etc.)."
    },
    "getc": {
        "sig": "int getc(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reads next character from stream."
    },
    "getchar": {
        "sig": "int getchar(void);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reads character from stdin."
    },
    "getcwd": {
        "sig": "char* getcwd(char* buf, size_t size);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Gets current working directory ('sdmc:/switch/durak')."
    },
    "getegid": {
        "sig": "gid_t getegid(void);",
        "header": "<unistd.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns effective group ID (0 on Horizon OS)."
    },
    "getenv": {
        "sig": "char* getenv(const char* name);",
        "header": "<stdlib.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Environment variable lookup."
    },
    "geteuid": {
        "sig": "uid_t geteuid(void);",
        "header": "<unistd.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns effective user ID (0 on Horizon OS)."
    },
    "getgid": {
        "sig": "gid_t getgid(void);",
        "header": "<unistd.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns group ID (0 on Horizon OS)."
    },
    "gethostbyaddr": {
        "sig": "struct hostent* gethostbyaddr(const void* addr, socklen_t len, int type);",
        "header": "<netdb.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Legacy reverse DNS lookup."
    },
    "gethostbyname": {
        "sig": "struct hostent* gethostbyname(const char* name);",
        "header": "<netdb.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Legacy DNS host resolution."
    },
    "gethostname": {
        "sig": "int gethostname(char* name, size_t len);",
        "header": "<unistd.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns host name ('switch')."
    },
    "getnameinfo": {
        "sig": "int getnameinfo(const struct sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags);",
        "header": "<netdb.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Address-to-name translation."
    },
    "getpagesize": {
        "sig": "int getpagesize(void);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns page size (4096 on Horizon OS)."
    },
    "getpeername": {
        "sig": "int getpeername(int sockfd, struct sockaddr* addr, socklen_t* addrlen);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Retrieves peer connected socket address."
    },
    "getpid": {
        "sig": "pid_t getpid(void);",
        "header": "<unistd.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns process ID (1 on Horizon OS)."
    },
    "getppid": {
        "sig": "pid_t getppid(void);",
        "header": "<unistd.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns parent process ID (1 on Horizon OS)."
    },
    "getpriority": {
        "sig": "int getpriority(int which, id_t who);",
        "header": "<sys/resource.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Gets process scheduling priority."
    },
    "getpwuid": {
        "sig": "struct passwd* getpwuid(uid_t uid);",
        "header": "<pwd.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Password database entry by UID."
    },
    "getpwuid_r": {
        "sig": "int getpwuid_r(uid_t uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result);",
        "header": "<pwd.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reentrant password database entry."
    },
    "getsockname": {
        "sig": "int getsockname(int sockfd, struct sockaddr* addr, socklen_t* addrlen);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Retrieves locally bound socket address."
    },
    "getsockopt": {
        "sig": "int getsockopt(int sockfd, int level, int optname, void* optval, socklen_t* optlen);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Gets socket options."
    },
    "gettid": {
        "sig": "pid_t gettid(void);",
        "header": "<unistd.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns current thread ID from Bionic TLS slot."
    },
    "gettimeofday": {
        "sig": "int gettimeofday(struct timeval* tv, struct timezone* tz);",
        "header": "<sys/time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Returns current microsecond time via timeSystemGet() / epoch."
    },
    "getuid": {
        "sig": "uid_t getuid(void);",
        "header": "<unistd.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns user ID (0 on Horizon OS)."
    },
    "gmtime": {
        "sig": "struct tm* gmtime(const time_t* timep);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Converts epoch to UTC broken-down time."
    },
    "gmtime_r": {
        "sig": "struct tm* gmtime_r(const time_t* timep, struct tm* result);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Reentrant UTC time conversion."
    },
    "if_nametoindex": {
        "sig": "unsigned int if_nametoindex(const char* ifname);",
        "header": "<net/if.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Network interface name to index mapping."
    },
    "in6addr_any": {
        "sig": "extern const struct in6_addr in6addr_any;",
        "header": "<netinet/in.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_OBJECT",
        "safety": "Global IPv6 wildcard bind address (::)."
    },
    "inet_addr": {
        "sig": "in_addr_t inet_addr(const char* cp);",
        "header": "<arpa/inet.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Converts IPv4 dotted-decimal string to binary."
    },
    "inet_aton": {
        "sig": "int inet_aton(const char* cp, struct in_addr* inp);",
        "header": "<arpa/inet.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Converts IPv4 string to struct in_addr."
    },
    "inet_ntoa": {
        "sig": "char* inet_ntoa(struct in_addr in);",
        "header": "<arpa/inet.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Converts binary IPv4 address to dotted-decimal string."
    },
    "inet_ntop": {
        "sig": "const char* inet_ntop(int af, const void* src, char* dst, socklen_t size);",
        "header": "<arpa/inet.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Converts binary IPv4/IPv6 address to presentation text."
    },
    "inet_pton": {
        "sig": "int inet_pton(int af, const char* src, void* dst);",
        "header": "<arpa/inet.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Converts IPv4/IPv6 text to binary form."
    },
    "inflate": {
        "sig": "int inflate(z_streamp strm, int flush);",
        "header": "<zlib.h>",
        "wave": "Wave 7 (DL & Zlib)",
        "strategy": "DL_ZLIB_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Deflate decompression via standard zlib."
    },
    "inflateEnd": {
        "sig": "int inflateEnd(z_streamp strm);",
        "header": "<zlib.h>",
        "wave": "Wave 7 (DL & Zlib)",
        "strategy": "DL_ZLIB_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Decompression teardown."
    },
    "inflateInit2_": {
        "sig": "int inflateInit2_(z_streamp strm, int windowBits, const char* version, int stream_size);",
        "header": "<zlib.h>",
        "wave": "Wave 7 (DL & Zlib)",
        "strategy": "DL_ZLIB_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Decompression initialization."
    },
    "ioctl": {
        "sig": "int ioctl(int fd, unsigned long request, ...);",
        "header": "<sys/ioctl.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Device control ioctl."
    },
    "isatty": {
        "sig": "int isatty(int fd);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns 1 if fd is a TTY."
    },
    "islower": {
        "sig": "int islower(int c);",
        "header": "<ctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "isspace": {
        "sig": "int isspace(int c);",
        "header": "<ctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswalnum": {
        "sig": "int iswalnum(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswalnum_l": {
        "sig": "int iswalnum_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswalpha": {
        "sig": "int iswalpha(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswalpha_l": {
        "sig": "int iswalpha_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswblank_l": {
        "sig": "int iswblank_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswcntrl": {
        "sig": "int iswcntrl(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswcntrl_l": {
        "sig": "int iswcntrl_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswdigit": {
        "sig": "int iswdigit(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswdigit_l": {
        "sig": "int iswdigit_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswlower": {
        "sig": "int iswlower(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswlower_l": {
        "sig": "int iswlower_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswprint": {
        "sig": "int iswprint(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswprint_l": {
        "sig": "int iswprint_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswpunct": {
        "sig": "int iswpunct(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswpunct_l": {
        "sig": "int iswpunct_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswspace": {
        "sig": "int iswspace(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswspace_l": {
        "sig": "int iswspace_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswupper": {
        "sig": "int iswupper(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswupper_l": {
        "sig": "int iswupper_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswxdigit": {
        "sig": "int iswxdigit(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "iswxdigit_l": {
        "sig": "int iswxdigit_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "isxdigit": {
        "sig": "int isxdigit(int c);",
        "header": "<ctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "kill": {
        "sig": "int kill(pid_t pid, int sig);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sends signal to process."
    },
    "link": {
        "sig": "int link(const char* oldpath, const char* newpath);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Hard link creation."
    },
    "listen": {
        "sig": "int listen(int sockfd, int backlog);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Listens for incoming connections on socket."
    },
    "localeconv": {
        "sig": "struct lconv* localeconv(void);",
        "header": "<locale.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "localtime": {
        "sig": "struct tm* localtime(const time_t* timep);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Converts epoch to local broken-down time."
    },
    "localtime_r": {
        "sig": "struct tm* localtime_r(const time_t* timep, struct tm* result);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Reentrant local time conversion."
    },
    "logb": {
        "sig": "double logb(double x);",
        "header": "<math.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Radix-independent exponent. Pure math leaf."
    },
    "longjmp": {
        "sig": "void longjmp(jmp_buf env, int val) __attribute__((noreturn));",
        "header": "<setjmp.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Restores calling environment saved by setjmp."
    },
    "lrand48": {
        "sig": "long lrand48(void);",
        "header": "<stdlib.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "STATEFUL_RNG_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Stateful POSIX 48-bit linear congruential RNG sharing global seed state (__rand48_seed)."
    },
    "lseek": {
        "sig": "off_t lseek(int fd, off_t offset, int whence);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reposition read/write file offset."
    },
    "lseek64": {
        "sig": "off64_t lseek64(int fd, off64_t offset, int whence);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "64-bit reposition read/write file offset."
    },
    "lstat": {
        "sig": "int lstat(const char* pathname, struct stat* statbuf);",
        "header": "<sys/stat.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "File status without traversing symlinks."
    },
    "madvise": {
        "sig": "int madvise(void* addr, size_t length, int advice);",
        "header": "<sys/mman.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Gives memory advice (MADV_DONTNEED etc.). Safe stub returning 0."
    },
    "mbrlen": {
        "sig": "size_t mbrlen(const char* s, size_t n, mbstate_t* ps);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "mbrtowc": {
        "sig": "size_t mbrtowc(wchar_t* pwc, const char* s, size_t n, mbstate_t* ps);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "mbsnrtowcs": {
        "sig": "size_t mbsnrtowcs(wchar_t* dest, const char** src, size_t nms, size_t len, mbstate_t* ps);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "mbsrtowcs": {
        "sig": "size_t mbsrtowcs(wchar_t* dest, const char** src, size_t len, mbstate_t* ps);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "mbtowc": {
        "sig": "int mbtowc(wchar_t* pwc, const char* s, size_t n);",
        "header": "<stdlib.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "memchr": {
        "sig": "void* memchr(const void* s, int c, size_t n);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Standard memory search. Leaf function."
    },
    "memrchr": {
        "sig": "void* memrchr(const void* s, int c, size_t n);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Reverse memory search. Pure leaf function."
    },
    "mkdir": {
        "sig": "int mkdir(const char* pathname, mode_t mode);",
        "header": "<sys/stat.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates directory on SD card."
    },
    "mkdirat": {
        "sig": "int mkdirat(int dirfd, const char* pathname, mode_t mode);",
        "header": "<sys/stat.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates directory relative to dirfd."
    },
    "mktime": {
        "sig": "time_t mktime(struct tm* tm);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Converts broken-down time to epoch seconds."
    },
    "mmap": {
        "sig": "void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);",
        "header": "<sys/mman.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Memory mapping adapter (anonymous maps mapped to heap or code memory)."
    },
    "modf": {
        "sig": "double modf(double x, double* iptr);",
        "header": "<math.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Split into integral and fractional parts. Pure math leaf."
    },
    "modff": {
        "sig": "float modff(float x, float* iptr);",
        "header": "<math.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Single-precision split into integral and fractional parts. Pure math leaf."
    },
    "mprotect": {
        "sig": "int mprotect(void* addr, size_t len, int prot);",
        "header": "<sys/mman.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets memory protection respecting Horizon OS W^X policy."
    },
    "mremap": {
        "sig": "void* mremap(void* old_address, size_t old_size, size_t new_size, int flags, ...);",
        "header": "<sys/mman.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Remaps virtual memory address space."
    },
    "munmap": {
        "sig": "int munmap(void* addr, size_t length);",
        "header": "<sys/mman.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Unmaps memory range."
    },
    "nanosleep": {
        "sig": "int nanosleep(const struct timespec* req, struct timespec* rem);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "High-resolution thread sleep via svcSleepThread()."
    },
    "newlocale": {
        "sig": "locale_t newlocale(int category_mask, const char* locale, locale_t base);",
        "header": "<locale.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "nl_langinfo": {
        "sig": "char* nl_langinfo(nl_item item);",
        "header": "<langinfo.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Language information lookup (e.g. CODESET -> 'UTF-8')."
    },
    "nl_langinfo_l": {
        "sig": "char* nl_langinfo_l(nl_item item, locale_t locale);",
        "header": "<langinfo.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Locale-aware language information lookup."
    },
    "open": {
        "sig": "int open(const char* pathname, int flags, ...);",
        "header": "<fcntl.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Opens file descriptor with path translation from /data/data to sdmc:/switch/durak."
    },
    "openat": {
        "sig": "int openat(int dirfd, const char* pathname, int flags, ...);",
        "header": "<fcntl.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Opens file descriptor relative to dirfd."
    },
    "opendir": {
        "sig": "DIR* opendir(const char* name);",
        "header": "<dirent.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Opens directory stream with path translation."
    },
    "openlog": {
        "sig": "void openlog(const char* ident, int option, int facility);",
        "header": "<syslog.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Opens connection to system logger."
    },
    "pathconf": {
        "sig": "long pathconf(const char* path, int name);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Get configuration values for files."
    },
    "pipe": {
        "sig": "int pipe(int pipefd[2]);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates unidirectional pipe channel."
    },
    "pipe2": {
        "sig": "int pipe2(int pipefd[2], int flags);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates pipe with O_CLOEXEC / O_NONBLOCK flags."
    },
    "poll": {
        "sig": "int poll(struct pollfd* fds, nfds_t nfds, int timeout);",
        "header": "<poll.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Waits for events on file descriptors."
    },
    "posix_memalign": {
        "sig": "int posix_memalign(void** memptr, size_t alignment, size_t size);",
        "header": "<stdlib.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Aligned memory allocation via memalign()."
    },
    "prctl": {
        "sig": "int prctl(int option, ...);",
        "header": "<sys/prctl.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Process control (PR_SET_NAME etc.)."
    },
    "pread64": {
        "sig": "ssize_t pread64(int fd, void* buf, size_t count, off64_t offset);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Positional read at 64-bit file offset without modifying file pointer."
    },
    "printf": {
        "sig": "int printf(const char* format, ...);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Formatted output to stdout."
    },
    "process_vm_readv": {
        "sig": "ssize_t process_vm_readv(pid_t pid, const struct iovec* local_iov, unsigned long liovcnt, const struct iovec* remote_iov, unsigned long riovcnt, unsigned long flags);",
        "header": "<sys/uio.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Process memory reading. Returns EPERM or copies directly if pid == getpid()."
    },
    "pselect": {
        "sig": "int pselect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* timeout, const sigset_t* sigmask);",
        "header": "<sys/select.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Synchronous I/O multiplexing with signal mask."
    },
    "pthread_attr_destroy": {
        "sig": "int pthread_attr_destroy(pthread_attr_t* attr);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Destroys thread attributes."
    },
    "pthread_attr_getschedparam": {
        "sig": "int pthread_attr_getschedparam(const pthread_attr_t* attr, struct sched_param* param);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Gets thread scheduling parameters."
    },
    "pthread_attr_getstack": {
        "sig": "int pthread_attr_getstack(const pthread_attr_t* attr, void** stackaddr, size_t* stacksize);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Retrieves thread stack bounds."
    },
    "pthread_attr_init": {
        "sig": "int pthread_attr_init(pthread_attr_t* attr);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initializes thread attributes."
    },
    "pthread_attr_setdetachstate": {
        "sig": "int pthread_attr_setdetachstate(pthread_attr_t* attr, int detachstate);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets thread detach state."
    },
    "pthread_attr_setschedparam": {
        "sig": "int pthread_attr_setschedparam(pthread_attr_t* attr, const struct sched_param* param);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets thread scheduling parameters."
    },
    "pthread_attr_setschedpolicy": {
        "sig": "int pthread_attr_setschedpolicy(pthread_attr_t* attr, int policy);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets thread scheduling policy."
    },
    "pthread_attr_setstacksize": {
        "sig": "int pthread_attr_setstacksize(pthread_attr_t* attr, size_t stacksize);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets requested thread stack size."
    },
    "pthread_cond_broadcast": {
        "sig": "int pthread_cond_broadcast(pthread_cond_t* cond);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Wakes all threads waiting on cond."
    },
    "pthread_cond_destroy": {
        "sig": "int pthread_cond_destroy(pthread_cond_t* cond);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Destroys condition variable."
    },
    "pthread_cond_init": {
        "sig": "int pthread_cond_init(pthread_cond_t* cond, const pthread_condattr_t* attr);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initializes condition variable."
    },
    "pthread_cond_signal": {
        "sig": "int pthread_cond_signal(pthread_cond_t* cond);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Wakes one thread waiting on cond."
    },
    "pthread_cond_timedwait": {
        "sig": "int pthread_cond_timedwait(pthread_cond_t* cond, pthread_mutex_t* mutex, const struct timespec* abstime);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Waits on cond with timeout."
    },
    "pthread_cond_wait": {
        "sig": "int pthread_cond_wait(pthread_cond_t* cond, pthread_mutex_t* mutex);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Atomically releases mutex and waits on cond."
    },
    "pthread_condattr_destroy": {
        "sig": "int pthread_condattr_destroy(pthread_condattr_t* attr);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Destroys condition variable attributes."
    },
    "pthread_condattr_init": {
        "sig": "int pthread_condattr_init(pthread_condattr_t* attr);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initializes condition variable attributes."
    },
    "pthread_condattr_setclock": {
        "sig": "int pthread_condattr_setclock(pthread_condattr_t* attr, clockid_t clock_id);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets clock used by condition variable."
    },
    "pthread_create": {
        "sig": "int pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start_routine)(void*), void* arg);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates thread mapped to libnx Thread with TLS initialization."
    },
    "pthread_detach": {
        "sig": "int pthread_detach(pthread_t thread);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Detaches thread."
    },
    "pthread_equal": {
        "sig": "int pthread_equal(pthread_t t1, pthread_t t2);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Compares thread handles for equality."
    },
    "pthread_exit": {
        "sig": "void pthread_exit(void* retval) __attribute__((noreturn));",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Terminates calling thread."
    },
    "pthread_getattr_np": {
        "sig": "int pthread_getattr_np(pthread_t thread, pthread_attr_t* attr);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Retrieves attributes of running thread (stack base, size)."
    },
    "pthread_getname_np": {
        "sig": "int pthread_getname_np(pthread_t thread, char* name, size_t len);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Retrieves thread name."
    },
    "pthread_getspecific": {
        "sig": "void* pthread_getspecific(pthread_key_t key);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Retrieves thread-specific value."
    },
    "pthread_join": {
        "sig": "int pthread_join(pthread_t thread, void** retval);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Waits for thread termination."
    },
    "pthread_key_create": {
        "sig": "int pthread_key_create(pthread_key_t* key, void (*destructor)(void*));",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Allocates thread-specific data key."
    },
    "pthread_key_delete": {
        "sig": "int pthread_key_delete(pthread_key_t key);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Releases thread-specific data key."
    },
    "pthread_kill": {
        "sig": "int pthread_kill(pthread_t thread, int sig);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sends signal to thread."
    },
    "pthread_mutex_destroy": {
        "sig": "int pthread_mutex_destroy(pthread_mutex_t* mutex);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Destroys mutex."
    },
    "pthread_mutex_init": {
        "sig": "int pthread_mutex_init(pthread_mutex_t* mutex, const pthread_mutexattr_t* attr);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initializes mutex using Bionic layout."
    },
    "pthread_mutex_lock": {
        "sig": "int pthread_mutex_lock(pthread_mutex_t* mutex);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Acquires mutex lock."
    },
    "pthread_mutex_trylock": {
        "sig": "int pthread_mutex_trylock(pthread_mutex_t* mutex);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Non-blocking mutex acquisition."
    },
    "pthread_mutex_unlock": {
        "sig": "int pthread_mutex_unlock(pthread_mutex_t* mutex);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Releases mutex lock."
    },
    "pthread_mutexattr_destroy": {
        "sig": "int pthread_mutexattr_destroy(pthread_mutexattr_t* attr);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Destroys mutex attributes."
    },
    "pthread_mutexattr_init": {
        "sig": "int pthread_mutexattr_init(pthread_mutexattr_t* attr);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initializes mutex attributes."
    },
    "pthread_mutexattr_settype": {
        "sig": "int pthread_mutexattr_settype(pthread_mutexattr_t* attr, int type);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets mutex type (NORMAL, RECURSIVE, ERRORCHECK)."
    },
    "pthread_once": {
        "sig": "int pthread_once(pthread_once_t* once_control, void (*init_routine)(void));",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Atomic once-initialization routine."
    },
    "pthread_rwlock_destroy": {
        "sig": "int pthread_rwlock_destroy(pthread_rwlock_t* rwlock);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Destroys read-write lock."
    },
    "pthread_rwlock_init": {
        "sig": "int pthread_rwlock_init(pthread_rwlock_t* rwlock, const pthread_rwlockattr_t* attr);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initializes read-write lock."
    },
    "pthread_rwlock_rdlock": {
        "sig": "int pthread_rwlock_rdlock(pthread_rwlock_t* rwlock);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Acquires read lock on rwlock."
    },
    "pthread_rwlock_tryrdlock": {
        "sig": "int pthread_rwlock_tryrdlock(pthread_rwlock_t* rwlock);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Non-blocking read lock acquisition."
    },
    "pthread_rwlock_trywrlock": {
        "sig": "int pthread_rwlock_trywrlock(pthread_rwlock_t* rwlock);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Non-blocking write lock acquisition."
    },
    "pthread_rwlock_unlock": {
        "sig": "int pthread_rwlock_unlock(pthread_rwlock_t* rwlock);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Releases read/write lock on rwlock."
    },
    "pthread_rwlock_wrlock": {
        "sig": "int pthread_rwlock_wrlock(pthread_rwlock_t* rwlock);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Acquires write lock on rwlock."
    },
    "pthread_self": {
        "sig": "pthread_t pthread_self(void);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Returns current thread handle from TLS."
    },
    "pthread_setname_np": {
        "sig": "int pthread_setname_np(pthread_t thread, const char* name);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Assigns thread name for diagnostics/profiling."
    },
    "pthread_setspecific": {
        "sig": "int pthread_setspecific(pthread_key_t key, const void* value);",
        "header": "<pthread.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Assigns thread-specific value."
    },
    "pthread_sigmask": {
        "sig": "int pthread_sigmask(int how, const sigset_t* set, sigset_t* oldset);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Examines and changes thread signal mask."
    },
    "ptrace": {
        "sig": "long ptrace(int request, pid_t pid, void* addr, void* data);",
        "header": "<sys/ptrace.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Process trace. Fail-closed returning EPERM / -1."
    },
    "putc": {
        "sig": "int putc(int c, FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Writes character to stream."
    },
    "putchar": {
        "sig": "int putchar(int c);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Writes character to stdout."
    },
    "puts": {
        "sig": "int puts(const char* s);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Writes string and newline to stdout."
    },
    "pwrite64": {
        "sig": "ssize_t pwrite64(int fd, const void* buf, size_t count, off64_t offset);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Positional write at 64-bit file offset without modifying file pointer."
    },
    "qsort": {
        "sig": "void qsort(void* base, size_t nmemb, size_t size, int (*compar)(const void*, const void*));",
        "header": "<stdlib.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Standard in-place sorting algorithm. Stateless, thread-safe, standard libc."
    },
    "raise": {
        "sig": "int raise(int sig);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sends signal to caller process."
    },
    "rawmemchr": {
        "sig": "void* rawmemchr(const void* s, int c);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "GNU memory search without length check. Pure leaf function."
    },
    "read": {
        "sig": "ssize_t read(int fd, void* buf, size_t count);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reads data from file descriptor."
    },
    "readdir": {
        "sig": "struct dirent* readdir(DIR* dirp);",
        "header": "<dirent.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reads next entry in directory stream."
    },
    "readdir_r": {
        "sig": "int readdir_r(DIR* dirp, struct dirent* entry, struct dirent** result);",
        "header": "<dirent.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reentrant read of directory entry."
    },
    "readlink": {
        "sig": "ssize_t readlink(const char* pathname, char* buf, size_t bufsiz);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reads value of symbolic link (handles /proc/self/exe)."
    },
    "realpath": {
        "sig": "char* realpath(const char* path, char* resolved_path);",
        "header": "<stdlib.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Canonicalizes absolute path."
    },
    "recv": {
        "sig": "ssize_t recv(int sockfd, void* buf, size_t len, int flags);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Receives message from socket."
    },
    "recvfrom": {
        "sig": "ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Receives message and source address from socket."
    },
    "recvmsg": {
        "sig": "ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Receives scatter/gather message from socket."
    },
    "remove": {
        "sig": "int remove(const char* pathname);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Removes file or directory."
    },
    "rename": {
        "sig": "int rename(const char* oldpath, const char* newpath);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Renames file with path translation."
    },
    "rewind": {
        "sig": "void rewind(FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Resets stream position to beginning."
    },
    "rewinddir": {
        "sig": "void rewinddir(DIR* dirp);",
        "header": "<dirent.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Resets directory stream position."
    },
    "rmdir": {
        "sig": "int rmdir(const char* pathname);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Removes directory."
    },
    "scalbn": {
        "sig": "double scalbn(double x, int n);",
        "header": "<math.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Scale by radix power. Pure math leaf."
    },
    "sched_get_priority_max": {
        "sig": "int sched_get_priority_max(int policy);",
        "header": "<sched.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Maximum scheduling priority (99)."
    },
    "sched_get_priority_min": {
        "sig": "int sched_get_priority_min(int policy);",
        "header": "<sched.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Minimum scheduling priority (1)."
    },
    "sched_yield": {
        "sig": "int sched_yield(void);",
        "header": "<sched.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Yields CPU time slice via svcSleepThread(0)."
    },
    "select": {
        "sig": "int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout);",
        "header": "<sys/select.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Synchronous I/O multiplexing."
    },
    "sem_destroy": {
        "sig": "int sem_destroy(sem_t* sem);",
        "header": "<semaphore.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Destroys POSIX semaphore."
    },
    "sem_getvalue": {
        "sig": "int sem_getvalue(sem_t* sem, int* sval);",
        "header": "<semaphore.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Reads current semaphore value."
    },
    "sem_init": {
        "sig": "int sem_init(sem_t* sem, int pshared, unsigned int value);",
        "header": "<semaphore.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initializes POSIX semaphore."
    },
    "sem_post": {
        "sig": "int sem_post(sem_t* sem);",
        "header": "<semaphore.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Increments semaphore."
    },
    "sem_timedwait": {
        "sig": "int sem_timedwait(sem_t* sem, const struct timespec* abs_timeout);",
        "header": "<semaphore.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Timed semaphore decrement."
    },
    "sem_trywait": {
        "sig": "int sem_trywait(sem_t* sem);",
        "header": "<semaphore.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Non-blocking semaphore decrement."
    },
    "sem_wait": {
        "sig": "int sem_wait(sem_t* sem);",
        "header": "<semaphore.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Locks semaphore."
    },
    "send": {
        "sig": "ssize_t send(int sockfd, const void* buf, size_t len, int flags);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sends message on connected socket."
    },
    "sendfile": {
        "sig": "ssize_t sendfile(int out_fd, int in_fd, off_t* offset, size_t count);",
        "header": "<sys/sendfile.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Zero-copy file descriptor transfer."
    },
    "sendmsg": {
        "sig": "ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sends scatter/gather message on socket."
    },
    "sendto": {
        "sig": "ssize_t sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sends message to specific destination address."
    },
    "setbuf": {
        "sig": "void setbuf(FILE* stream, char* buf);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Controls stream buffering."
    },
    "setenv": {
        "sig": "int setenv(const char* name, const char* value, int overwrite);",
        "header": "<stdlib.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Environment variable assignment."
    },
    "setjmp": {
        "sig": "int setjmp(jmp_buf env);",
        "header": "<setjmp.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Saves calling environment for longjmp. Direct AAPCS64 implementation."
    },
    "setlocale": {
        "sig": "char* setlocale(int category, const char* locale);",
        "header": "<locale.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "setpriority": {
        "sig": "int setpriority(int which, id_t who, int prio);",
        "header": "<sys/resource.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets process scheduling priority."
    },
    "setsockopt": {
        "sig": "int setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets socket options (SO_REUSEADDR, TCP_NODELAY, SO_SNDBUF, SO_RCVBUF)."
    },
    "setvbuf": {
        "sig": "int setvbuf(FILE* stream, char* buf, int mode, size_t size);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Controls stream buffering."
    },
    "shutdown": {
        "sig": "int shutdown(int sockfd, int how);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Shuts down full-duplex connection."
    },
    "sigaction": {
        "sig": "int sigaction(int signum, const struct sigaction* act, struct sigaction* oldact);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Examines and changes a signal action."
    },
    "sigaddset": {
        "sig": "int sigaddset(sigset_t* set, int signum);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Adds signal to signal set."
    },
    "sigaltstack": {
        "sig": "int sigaltstack(const stack_t* ss, stack_t* old_ss);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets or gets signal stack context."
    },
    "sigdelset": {
        "sig": "int sigdelset(sigset_t* set, int signum);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Removes signal from signal set."
    },
    "sigemptyset": {
        "sig": "int sigemptyset(sigset_t* set);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Initializes empty signal set."
    },
    "sigfillset": {
        "sig": "int sigfillset(sigset_t* set);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Fills signal set with all signals."
    },
    "sigismember": {
        "sig": "int sigismember(const sigset_t* set, int signum);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Tests if signal is member of signal set."
    },
    "siglongjmp": {
        "sig": "void siglongjmp(sigjmp_buf env, int val) __attribute__((noreturn));",
        "header": "<setjmp.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Restores environment and signal mask."
    },
    "signal": {
        "sig": "sighandler_t signal(int signum, sighandler_t handler);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Sets signal handler."
    },
    "sigprocmask": {
        "sig": "int sigprocmask(int how, const sigset_t* set, sigset_t* oldset);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Examines and changes blocked signals."
    },
    "sigsetjmp": {
        "sig": "int sigsetjmp(sigjmp_buf env, int savesigs);",
        "header": "<setjmp.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Saves calling environment and signal mask."
    },
    "sigsuspend": {
        "sig": "int sigsuspend(const sigset_t* mask);",
        "header": "<signal.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Waits for signal."
    },
    "sincos": {
        "sig": "void sincos(double x, double* sin, double* cos);",
        "header": "<math.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Standard GNU math leaf function. Computes both sin and cos in single pass."
    },
    "sincosf": {
        "sig": "void sincosf(float x, float* sin, float* cos);",
        "header": "<math.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Single-precision sincos. Pure math leaf function."
    },
    "snprintf": {
        "sig": "int snprintf(char* str, size_t size, const char* format, ...);",
        "header": "<stdio.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Standard bounded string formatting. Requires AAPCS64 variadic ABI."
    },
    "socket": {
        "sig": "int socket(int domain, int type, int protocol);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates socket endpoint for communication via BSD socket layer."
    },
    "socketpair": {
        "sig": "int socketpair(int domain, int type, int protocol, int sv[2]);",
        "header": "<sys/socket.h>",
        "wave": "Wave 10 (Sockets & Networking)",
        "strategy": "SOCKETS_NET_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Creates pair of connected sockets."
    },
    "sprintf": {
        "sig": "int sprintf(char* str, const char* format, ...);",
        "header": "<stdio.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Standard string formatting."
    },
    "srand48": {
        "sig": "void srand48(long seedval);",
        "header": "<stdlib.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "STATEFUL_RNG_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Stateful POSIX 48-bit linear congruential RNG sharing global seed state (__rand48_seed)."
    },
    "sscanf": {
        "sig": "int sscanf(const char* str, const char* format, ...);",
        "header": "<stdio.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "String parsing against format string."
    },
    "stat": {
        "sig": "int stat(const char* pathname, struct stat* statbuf);",
        "header": "<sys/stat.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "File status by pathname with path translation."
    },
    "statfs": {
        "sig": "int statfs(const char* path, struct statfs* buf);",
        "header": "<sys/vfs.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "File system statistics (SD free space query)."
    },
    "stderr": {
        "sig": "extern FILE* stderr;",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_OBJECT",
        "safety": "Standard error stream pointer."
    },
    "stdin": {
        "sig": "extern FILE* stdin;",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_OBJECT",
        "safety": "Standard input stream pointer."
    },
    "stdout": {
        "sig": "extern FILE* stdout;",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_OBJECT",
        "safety": "Standard output stream pointer."
    },
    "strcasecmp": {
        "sig": "int strcasecmp(const char* s1, const char* s2);",
        "header": "<strings.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "strcasestr": {
        "sig": "char* strcasestr(const char* haystack, const char* needle);",
        "header": "<string.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "strcat": {
        "sig": "char* strcat(char* dest, const char* src);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Standard string concatenation. Pure leaf function."
    },
    "strchr": {
        "sig": "char* strchr(const char* s, int c);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Standard string search. Pure leaf function."
    },
    "strcoll_l": {
        "sig": "int strcoll_l(const char* s1, const char* s2, locale_t locale);",
        "header": "<string.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "strcspn": {
        "sig": "size_t strcspn(const char* s, const char* reject);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Complementary string span search. Pure leaf function."
    },
    "strdup": {
        "sig": "char* strdup(const char* s);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Heap string duplication via malloc and memcpy."
    },
    "strerror": {
        "sig": "char* strerror(int errnum);",
        "header": "<string.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Standard error string lookup."
    },
    "strerror_r": {
        "sig": "int strerror_r(int errnum, char* buf, size_t buflen);",
        "header": "<string.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "POSIX thread-safe strerror into buffer."
    },
    "strftime": {
        "sig": "size_t strftime(char* s, size_t max, const char* format, const struct tm* tm);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Formats broken-down time into string."
    },
    "strftime_l": {
        "sig": "size_t strftime_l(char* s, size_t max, const char* format, const struct tm* tm, locale_t locale);",
        "header": "<time.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "strlcpy": {
        "sig": "size_t strlcpy(char* dst, const char* src, size_t size);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "BSD-safe string copy. Guarantees null-termination. Pure leaf function."
    },
    "strncasecmp": {
        "sig": "int strncasecmp(const char* s1, const char* s2, size_t n);",
        "header": "<strings.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "strncat": {
        "sig": "char* strncat(char* dest, const char* src, size_t n);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Bounded string concatenation. Pure leaf function."
    },
    "strndup": {
        "sig": "char* strndup(const char* s, size_t n);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Bounded heap string duplication."
    },
    "strpbrk": {
        "sig": "char* strpbrk(const char* s, const char* accept);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Pointer to first occurrence in accept. Pure leaf function."
    },
    "strrchr": {
        "sig": "char* strrchr(const char* s, int c);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Reverse string search. Pure leaf function."
    },
    "strspn": {
        "sig": "size_t strspn(const char* s, const char* accept);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "String span search. Pure leaf function."
    },
    "strstr": {
        "sig": "char* strstr(const char* haystack, const char* needle);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Substring search. Pure leaf function."
    },
    "strtok_r": {
        "sig": "char* strtok_r(char* str, const char* delim, char** saveptr);",
        "header": "<string.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Reentrant string tokenizer using caller-provided saveptr."
    },
    "strtold": {
        "sig": "long double strtold(const char* nptr, char** endptr);",
        "header": "<stdlib.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "strtold_l": {
        "sig": "long double strtold_l(const char* nptr, char** endptr, locale_t locale);",
        "header": "<stdlib.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "strtoll_l": {
        "sig": "long long strtoll_l(const char* nptr, char** endptr, int base, locale_t locale);",
        "header": "<stdlib.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "strtoull_l": {
        "sig": "unsigned long long strtoull_l(const char* nptr, char** endptr, int base, locale_t locale);",
        "header": "<stdlib.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "strxfrm_l": {
        "sig": "size_t strxfrm_l(char* dest, const char* src, size_t n, locale_t locale);",
        "header": "<string.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "swprintf": {
        "sig": "int swprintf(wchar_t* wcs, size_t maxlen, const wchar_t* format, ...);",
        "header": "<wchar.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Wide character string formatting."
    },
    "symlink": {
        "sig": "int symlink(const char* target, const char* linkpath);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Symbolic link creation."
    },
    "syscall": {
        "sig": "long syscall(long number, ...);",
        "header": "<unistd.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Direct Linux syscall invocation. Maps known numbers (gettid, futex) to Switch equivalents."
    },
    "sysconf": {
        "sig": "long sysconf(int name);",
        "header": "<unistd.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "System configuration query (_SC_PAGE_SIZE = 4096, _SC_NPROCESSORS_ONLN = 3)."
    },
    "syslog": {
        "sig": "void syslog(int priority, const char* format, ...);",
        "header": "<syslog.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "System log message. Formatted and redirected to Durak log_write."
    },
    "tanhf": {
        "sig": "float tanhf(float x);",
        "header": "<math.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Single-precision hyperbolic tangent. Pure math leaf function."
    },
    "time": {
        "sig": "time_t time(time_t* tloc);",
        "header": "<time.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Current Unix epoch seconds via timeCurrentTime()."
    },
    "towlower": {
        "sig": "wint_t towlower(wint_t wc);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "towlower_l": {
        "sig": "wint_t towlower_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "towupper_l": {
        "sig": "wint_t towupper_l(wint_t wc, locale_t locale);",
        "header": "<wctype.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "truncate": {
        "sig": "int truncate(const char* path, off_t length);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Truncates file by path."
    },
    "uname": {
        "sig": "int uname(struct utsname* buf);",
        "header": "<sys/utsname.h>",
        "wave": "Wave 6 (Pthreads, TLS & Process)",
        "strategy": "PTHREAD_TLS_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "System name ('Linux', '4.9.0', 'aarch64')."
    },
    "ungetc": {
        "sig": "int ungetc(int c, FILE* stream);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Pushes character back into input stream."
    },
    "unlink": {
        "sig": "int unlink(const char* pathname);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Deletes file with path translation."
    },
    "unlinkat": {
        "sig": "int unlinkat(int dirfd, const char* pathname, int flags);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Deletes file relative to directory."
    },
    "unsetenv": {
        "sig": "int unsetenv(const char* name);",
        "header": "<stdlib.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Environment variable removal."
    },
    "uselocale": {
        "sig": "locale_t uselocale(locale_t newloc);",
        "header": "<locale.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "usleep": {
        "sig": "int usleep(useconds_t usec);",
        "header": "<unistd.h>",
        "wave": "Wave 3 (Time, Clock, Env & Stateful RNG)",
        "strategy": "TIME_ENV_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Microsecond thread sleep via svcSleepThread()."
    },
    "utime": {
        "sig": "int utime(const char* filename, const struct utimbuf* times);",
        "header": "<utime.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Change file access/modification times."
    },
    "utimes": {
        "sig": "int utimes(const char* filename, const struct timeval times[2]);",
        "header": "<sys/time.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Change file access/modification times with microsecond precision."
    },
    "vasprintf": {
        "sig": "int vasprintf(char** strp, const char* fmt, va_list ap);",
        "header": "<stdio.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Allocating string formatting with va_list."
    },
    "vfprintf": {
        "sig": "int vfprintf(FILE* stream, const char* format, va_list ap);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Formatted stream output with va_list."
    },
    "vprintf": {
        "sig": "int vprintf(const char* format, va_list ap);",
        "header": "<stdio.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Formatted output to stdout with va_list."
    },
    "vsnprintf": {
        "sig": "int vsnprintf(char* str, size_t size, const char* format, va_list ap);",
        "header": "<stdio.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Standard bounded string formatting with va_list."
    },
    "vsprintf": {
        "sig": "int vsprintf(char* str, const char* format, va_list ap);",
        "header": "<stdio.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Standard string formatting with va_list."
    },
    "vsscanf": {
        "sig": "int vsscanf(const char* str, const char* format, va_list ap);",
        "header": "<stdio.h>",
        "wave": "Wave 2 (Format, Error, Guard & Lifecycle)",
        "strategy": "FORMAT_GUARD_ADAPTER",
        "type": "STT_FUNC",
        "safety": "String parsing with va_list."
    },
    "wcrtomb": {
        "sig": "size_t wcrtomb(char* s, wchar_t wc, mbstate_t* ps);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wcscoll_l": {
        "sig": "int wcscoll_l(const wchar_t* ws1, const wchar_t* ws2, locale_t locale);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wcslen": {
        "sig": "size_t wcslen(const wchar_t* s);",
        "header": "<wchar.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Wide character string length. Pure leaf."
    },
    "wcsnrtombs": {
        "sig": "size_t wcsnrtombs(char* dest, const wchar_t** src, size_t nwc, size_t len, mbstate_t* ps);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wcstod": {
        "sig": "double wcstod(const wchar_t* nptr, wchar_t** endptr);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wcstof": {
        "sig": "float wcstof(const wchar_t* nptr, wchar_t** endptr);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wcstol": {
        "sig": "long wcstol(const wchar_t* nptr, wchar_t** endptr, int base);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wcstold": {
        "sig": "long double wcstold(const wchar_t* nptr, wchar_t** endptr);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wcstoll": {
        "sig": "long long wcstoll(const wchar_t* nptr, wchar_t** endptr, int base);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wcstoul": {
        "sig": "unsigned long wcstoul(const wchar_t* nptr, wchar_t** endptr, int base);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wcstoull": {
        "sig": "unsigned long long wcstoull(const wchar_t* nptr, wchar_t** endptr, int base);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wcsxfrm_l": {
        "sig": "size_t wcsxfrm_l(wchar_t* dest, const wchar_t* src, size_t n, locale_t locale);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wctob": {
        "sig": "int wctob(wint_t c);",
        "header": "<wchar.h>",
        "wave": "Wave 4 (Locale & Multibyte Subsystem)",
        "strategy": "LOCALE_MB_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Explicit (locale_t/mbstate_t) or implicit (LC_CTYPE/LC_NUMERIC) locale-sensitive function. Must not blindly pass to newlib without C-locale pinning or Bionic-to-newlib state translation."
    },
    "wmemchr": {
        "sig": "wchar_t* wmemchr(const wchar_t* s, wchar_t c, size_t n);",
        "header": "<wchar.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Wide memory character search. Pure leaf."
    },
    "wmemcmp": {
        "sig": "int wmemcmp(const wchar_t* s1, const wchar_t* s2, size_t n);",
        "header": "<wchar.h>",
        "wave": "Wave 1 (Safe Leaf Libc & Math)",
        "strategy": "SAFE_LEAF_ADAPTER",
        "type": "STT_FUNC",
        "safety": "Wide memory comparison. Pure leaf."
    },
    "write": {
        "sig": "ssize_t write(int fd, const void* buf, size_t count);",
        "header": "<unistd.h>",
        "wave": "Wave 5 (FS, Stdio & Memory)",
        "strategy": "FS_STDIO_SUBSYSTEM",
        "type": "STT_FUNC",
        "safety": "Writes data to file descriptor."
    },
}


def get_elf_build_id(elf_data: bytes) -> Optional[str]:
    """Extract GNU build ID from an ELF binary (.note.gnu.build-id)."""
    try:
        elf = ELFFile(io.BytesIO(elf_data))
        for s in elf.iter_sections():
            if s.name == '.note.gnu.build-id':
                for note in s.iter_notes():
                    if 'n_desc' in note:
                        return note['n_desc']
                    elif hasattr(note, 'desc'):
                        return note.desc
    except Exception:
        pass
    return None


def verify_target_binaries(extracted_dir: Path = EXTRACTED_DIR):
    """Fail-closed validation of library existence, exact size, SHA-256, and GNU Build-ID."""
    for name, exp in EXPECTED_CORE_LIBRARIES.items():
        p = extracted_dir / name
        if not p.is_file():
            print(f"[FAIL] Missing target library: {p}", file=sys.stderr)
            sys.exit(1)
        data = p.read_bytes()
        if len(data) != exp["size"]:
            print(f"[FAIL] Size mismatch for {name}: {len(data)} != {exp['size']}", file=sys.stderr)
            sys.exit(1)
        sha = hashlib.sha256(data).hexdigest()
        if sha != exp["sha256"]:
            print(f"[FAIL] SHA-256 mismatch for {name}: {sha} != {exp['sha256']}", file=sys.stderr)
            sys.exit(1)
        actual_bid = get_elf_build_id(data)
        if actual_bid != exp["build_id"]:
            print(f"[FAIL] Build ID mismatch for {name}: have {actual_bid}, expected {exp['build_id']}", file=sys.stderr)
            sys.exit(1)


def compute_unresolved_relocations_from_elf(
    extracted_dir: Path = EXTRACTED_DIR
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, str]]:
    """
    Directly loads and resolves ELF modules in memory using MultiModuleLoader.
    Returns (unresolved_strong, unresolved_weak, sym_elf_types).
    """
    from tools.elf_loader import MultiModuleLoader, resolve_baseline_android_shim, verify_durak_default_environment

    module_paths = verify_durak_default_environment(str(extracted_dir))
    loader = MultiModuleLoader(0x7000000000)
    for mp in module_paths:
        loader.load_module(mp)

    loader.relocate_all(strict=False, external_resolver=resolve_baseline_android_shim)

    # Extract actual ELF .dynsym st_type for every unresolved strong symbol
    sym_elf_types: Dict[str, str] = {}
    for mod in loader.modules.values():
        for rel in mod.relocations:
            if not rel.resolved and not rel.is_weak and rel.symbol:
                st_val = rel.symbol.st_type
                st_str = "STT_OBJECT" if st_val == 1 else ("STT_FUNC" if st_val == 2 else f"STT_OTHER({st_val})")
                if rel.symbol.name in sym_elf_types and sym_elf_types[rel.symbol.name] != st_str:
                    print(
                        f"[FATAL] Conflicting ELF st_type across modules for {rel.symbol.name}: "
                        f"{sym_elf_types[rel.symbol.name]} vs {st_str} [FAIL-CLOSED]",
                        file=sys.stderr
                    )
                    sys.exit(1)
                sym_elf_types[rel.symbol.name] = st_str

    return loader.unresolved_strong, loader.unresolved_weak, sym_elf_types


def verify_against_reference_json(strong_details: List[Dict[str, Any]], json_path: Path) -> None:
    """Fail-closed cross-check of in-memory relocations against a reference JSON report."""
    if not json_path.is_file():
        print(f"[FATAL] Reference JSON file not found: {json_path} [FAIL-CLOSED]", file=sys.stderr)
        sys.exit(1)
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            disk_data = json.load(f)
    except Exception as e:
        print(f"[FATAL] Failed to parse reference JSON {json_path}: {e} [FAIL-CLOSED]", file=sys.stderr)
        sys.exit(1)

    disk_strong = disk_data.get("unresolved_strong_details", [])
    calc_tuples = [(x["module"], x["symbol"], x["r_type"], x["r_offset"]) for x in strong_details]
    disk_tuples = [(x.get("module"), x.get("symbol"), x.get("r_type"), x.get("r_offset")) for x in disk_strong]
    if calc_tuples != disk_tuples:
        print(
            "[FATAL] Discrepancy between in-memory calculated relocations and reference JSON! [FAIL-CLOSED]",
            file=sys.stderr
        )
        sys.exit(1)


def validate_and_filter_metadata(
    sym_groups: Dict[str, List[Dict[str, Any]]],
    sym_elf_types: Dict[str, str],
    metadata_db: Dict[str, Dict[str, str]] = SYMBOL_METADATA
) -> Dict[str, Dict[str, str]]:
    """
    Fail-closed validation of metadata completeness and .dynsym STT_FUNC / STT_OBJECT agreement.
    """
    active_metadata = {k: v for k, v in metadata_db.items() if k in sym_groups}
    missing_meta = set(sym_groups.keys()) - set(active_metadata.keys())
    if missing_meta:
        print(f"[FATAL] Missing metadata definitions for {len(missing_meta)} symbols: {missing_meta} [FAIL-CLOSED]", file=sys.stderr)
        sys.exit(1)
    if len(active_metadata) != 362:
        print(f"[FATAL] Expected exactly 362 active metadata entries, got {len(active_metadata)} [FAIL-CLOSED]", file=sys.stderr)
        sys.exit(1)

    # Verify symbol type against ELF .dynsym st_type
    for sym, meta in active_metadata.items():
        expected_type = meta.get("type")
        actual_elf_type = sym_elf_types.get(sym)
        if expected_type != actual_elf_type:
            print(
                f"[FATAL] Symbol type mismatch for '{sym}': metadata has '{expected_type}', "
                f"but ELF .dynsym has '{actual_elf_type}'! [FAIL-CLOSED]",
                file=sys.stderr
            )
            sys.exit(1)

    return active_metadata


def parse_elf_relocations_and_ctors(elf_path: Path):
    data = elf_path.read_bytes()
    phoff = struct.unpack("<Q", data[32:40])[0]
    phentsz = struct.unpack("<H", data[54:56])[0]
    phnum = struct.unpack("<H", data[56:58])[0]

    dyn_offset = None
    dyn_filesz = None
    load_segs = []

    for i in range(phnum):
        ph = data[phoff + i * phentsz : phoff + (i + 1) * phentsz]
        ptype, pflags, poff, pvaddr, ppaddr, pfilesz, pmemsz, palign = struct.unpack("<IIQQQQQQ", ph)
        if ptype == 1:  # PT_LOAD
            load_segs.append((poff, pvaddr, pfilesz, pmemsz))
        elif ptype == 2:  # PT_DYNAMIC
            dyn_offset = poff
            dyn_filesz = pfilesz

    def vaddr_to_off(vaddr):
        for poff, pvaddr, pfilesz, pmemsz in load_segs:
            if pvaddr <= vaddr < pvaddr + pmemsz:
                return poff + (vaddr - pvaddr)
        return None

    # Parse dynamic tags
    init_array_vaddr = None
    init_array_sz = 0
    pos = dyn_offset
    while pos < dyn_offset + dyn_filesz:
        d_tag, d_val = struct.unpack("<Qq", data[pos : pos + 16])
        pos += 16
        if d_tag == 0:
            break
        elif d_tag == 25:  # DT_INIT_ARRAY
            init_array_vaddr = d_val
        elif d_tag == 27:  # DT_INIT_ARRAYSZ
            init_array_sz = d_val

    ctors = []
    if init_array_vaddr and init_array_sz:
        init_arr_off = vaddr_to_off(init_array_vaddr)
        count = init_array_sz // 8
        for i in range(count):
            ctor_vaddr = struct.unpack("<Q", data[init_arr_off + i*8 : init_arr_off + (i+1)*8])[0]
            ctors.append(ctor_vaddr)

    return ctors


def wave_sort_key(wave_name: str) -> int:
    try:
        return int(wave_name.split()[1])
    except Exception:
        return 999


def generate_inventory(
    extracted_dir: Path = EXTRACTED_DIR,
    output_dir: Path = REPO_ROOT / "docs" / "analysis",
    reference_json_path: Optional[Path] = REPO_ROOT / "docs" / "analysis" / "durak_unresolved_imports.json",
    metadata_db: Dict[str, Dict[str, str]] = SYMBOL_METADATA
) -> Dict[str, Any]:
    """
    Executes the full fail-closed inventory calculation and writes JSON and Markdown outputs to output_dir.
    """
    print("[*] Verifying target binaries fail-closed against canonical root of trust...")
    verify_target_binaries(extracted_dir)
    print("    -> All 4 target binaries confirmed 100% genuine (SHA-256 and Build-ID verified).")

    print("[*] Performing direct in-memory ELF loading and cross-module link resolution...")
    strong_details, weak_details, sym_elf_types = compute_unresolved_relocations_from_elf(extracted_dir)

    if reference_json_path is not None and reference_json_path.is_file():
        verify_against_reference_json(strong_details, reference_json_path)
        print(f"    -> Cross-check against {reference_json_path.name}: 100% exact match.")

    print(f"[*] Processing {len(strong_details)} strong sites and {len(weak_details)} weak sites...")

    # Group strong relocations by symbol
    sym_groups: Dict[str, List[Dict[str, Any]]] = {}
    for d in strong_details:
        sym = d["symbol"]
        sym_groups.setdefault(sym, []).append(d)

    unique_strong_count = len(sym_groups)
    total_strong_sites = len(strong_details)

    if unique_strong_count != 362 or total_strong_sites != 631:
        print(
            f"[FATAL] Inventory count mismatch: have {unique_strong_count} unique / {total_strong_sites} sites, "
            f"expected exactly 362 unique / 631 sites! [FAIL-CLOSED]",
            file=sys.stderr
        )
        sys.exit(1)

    print(f"    -> Confirmed: exactly {unique_strong_count} unique strong symbols across {total_strong_sites} sites.")

    active_metadata = validate_and_filter_metadata(sym_groups, sym_elf_types, metadata_db)
    print("    -> Verified all 362 symbols against metadata and ELF .dynsym st_type (359 STT_FUNC, 3 STT_OBJECT).")

    # Parse constructors from modules
    unity_ctors = parse_elf_relocations_and_ctors(extracted_dir / "libunity.so")
    il2cpp_ctors = parse_elf_relocations_and_ctors(extracted_dir / "libil2cpp.so")
    print(f"[*] Constructors: libunity.so has {len(unity_ctors)} ctors, libil2cpp.so has {len(il2cpp_ctors)} ctors.")

    # Build canonical records for all 362 symbols
    canonical_records = []
    wave_stats: Dict[str, Dict[str, Any]] = {}

    for sym in sorted(sym_groups.keys()):
        sites = sym_groups[sym]
        meta = active_metadata[sym]
        consumers = {}
        r_types = set()
        r_offsets = []
        for s in sites:
            consumers[s["module"]] = consumers.get(s["module"], 0) + 1
            r_types.add(s["r_type"])
            r_offsets.append(s["r_offset"])

        wave = meta["wave"]
        if wave not in wave_stats:
            wave_stats[wave] = {
                "symbols_count": 0,
                "sites_count": 0,
                "symbols": []
            }
        wave_stats[wave]["symbols_count"] += 1
        wave_stats[wave]["sites_count"] += len(sites)
        wave_stats[wave]["symbols"].append(sym)

        record = {
            "symbol": sym,
            "total_sites": len(sites),
            "consumers": consumers,
            "relocation_types": sorted(list(r_types)),
            "offsets": r_offsets,
            "symbol_type": meta["type"],
            "dynsym_verified": True,
            "signature": meta["sig"],
            "header": meta["header"],
            "ndk_api_reference": NDK_API_REFERENCE,
            "wave": meta["wave"],
            "strategy": meta["strategy"],
            "safety_rationale": meta["safety"],
            "constructor_reachability": "unverified"
        }
        canonical_records.append(record)

    # Sort waves numerically
    sorted_wave_names = sorted(wave_stats.keys(), key=wave_sort_key)

    # 1. Output JSON database
    output_dir.mkdir(parents=True, exist_ok=True)
    json_out_path = output_dir / "durak_362_unresolved_inventory.json"
    full_inventory = {
        "metadata": {
            "schema_version": "1.2.0",
            "source": "Durak 25.0 AArch64 Production Modules",
            "ndk_api_reference": NDK_API_REFERENCE,
            "prototype_verification_status": "dynsym_st_type_verified_manual_c_prototype_catalog",
            "total_unique_strong_symbols": unique_strong_count,
            "total_strong_relocation_sites": total_strong_sites,
            "total_unique_weak_symbols": len(set(x["symbol"] for x in weak_details)),
            "total_weak_relocation_sites": len(weak_details),
            "waves_count": len(wave_stats),
            "waves_summary": {k: {"symbols": wave_stats[k]["symbols_count"], "sites": wave_stats[k]["sites_count"]} for k in sorted_wave_names},
            "constructor_reachability_status": "unverified_static_analysis"
        },
        "weak_symbols": weak_details,
        "symbols": canonical_records
    }

    with open(json_out_path, "w", encoding="utf-8") as f:
        json.dump(full_inventory, f, indent=2)
    print(f"[OK] Wrote machine-readable database: {json_out_path}")

    # 2. Output Markdown report
    md_out_path = output_dir / "durak_362_unresolved_inventory.md"
    with open(md_out_path, "w", encoding="utf-8") as f:
        f.write("# Durak NX — Канонічний інвентар 362 Strong Symbols / 631 Relocation Sites\n\n")
        f.write("Цей документ є машинно згенерованою специфікацією всіх зовнішніх символів Android Bionic, ")
        f.write("необхідних для повного зв'язування чотирьох модулів Durak 25.0 (`libsqlite3.so`, `libmain.so`, ")
        f.write("`libunity.so`, `libil2cpp.so`) перед переходом до запуску конструкторів (E06b).\n\n")
        f.write("> **Методологія та верифікація:**\n")
        f.write("> - Обчислення інвентарю виконано безпосередньо з перевірених у пам'яті ELF-модулів (`MultiModuleLoader`) із перевіркою розмірів, SHA-256 та GNU Build-ID.\n")
        f.write("> - Типи символів (`STT_FUNC` / `STT_OBJECT`) автоматично звірені з `.dynsym` кожного ELF-модуля (359 функцій, 3 об'єкти даних: `__sF`, `stderr`, `stdout`).\n")
        f.write(f"> - Прототипи C ABI каталогізовані за заголовками **{NDK_API_REFERENCE}** і підлягають похвильовій компіляційній перевірці під час реалізації.\n")
        f.write("> - **Wave 1 (Safe Leaf Libc & Math)** очищена від усіх явних (`locale_t`, `mbstate_t`) та неявних (`LC_CTYPE`, `LC_NUMERIC`) locale-залежностей, а також від stateful RNG (`lrand48`/`srand48`) та буферизованих Bionic-функцій (`basename`).\n")
        f.write("> - Досяжність із конструкторів (`constructor_reachability`) має статус `unverified` до побудови статичного графа викликів (E06b).\n\n")

        f.write("## 1. Загальний підсумок розподілу за хвилями (Waves Roadmap)\n\n")
        f.write("| Хвиля | Призначення | Унікальних символів | Relocation Sites | Відсоток покриття |\n")
        f.write("|---|---|:---:|:---:|:---:|\n")

        running_sites = 0
        for wave_name in sorted_wave_names:
            st = wave_stats[wave_name]
            running_sites += st["sites_count"]
            pct = (st["sites_count"] / total_strong_sites) * 100.0
            cum_pct = (running_sites / total_strong_sites) * 100.0
            f.write(f"| **{wave_name}** | {wave_name.split('(')[1].rstrip(')')} | {st['symbols_count']} | {st['sites_count']} | {pct:.1f}% (cum: {cum_pct:.1f}%) |\n")
        f.write(f"| **РАЗОМ** | **Усі 10 хвиль закриття** | **{unique_strong_count}** | **{total_strong_sites}** | **100.0%** |\n\n")

        f.write("## 2. Слабкі імпорти (Weak Symbols, 4 relocation sites)\n\n")
        f.write("Слабкі символи дозволяють резолв у `NULL`, якщо відповідна підсистема ще не зареєстрована:\n\n")
        f.write("| Символ | Модуль | Тип релокації | Offset | Призначення / Поведінка |\n")
        f.write("|---|---|---|---|---|\n")
        for w in weak_details:
            f.write(f"| `{w['symbol']}` | `{w['module']}` | `{w['r_type']}` | `{w['r_offset']}` | Дозволений `NULL` за специфікацією ELF64 |\n")
        f.write("\n---\n\n")

        f.write("## 3. Детальний реєстр символів за хвилями\n\n")
        for wave_name in sorted_wave_names:
            st = wave_stats[wave_name]
            f.write(f"### {wave_name} ({st['symbols_count']} символів, {st['sites_count']} сайтів)\n\n")
            f.write("| Символ | Тип | Сайти | Модулі-споживачі | Сигнатура (ABI) / Заголовок | Стратегія / Доказ безпеки |\n")
            f.write("|---|:---:|:---:|---|---|---|\n")
            wave_syms = [r for r in canonical_records if r["wave"] == wave_name]
            for r in wave_syms:
                mod_str = "<br>".join(f"`{m}` ({c})" for m, c in sorted(r["consumers"].items()))
                sig_fmt = f"`{r['signature']}`<br>*{r['header']}*"
                f.write(f"| `{r['symbol']}` | `{r['symbol_type']}` | {r['total_sites']} | {mod_str} | {sig_fmt} | **{r['strategy']}**:<br>{r['safety_rationale']} |\n")
            f.write("\n")

    print(f"[OK] Wrote human-readable report: {md_out_path}")
    print("[PASS] Canonical inventory generation completed successfully.")
    return full_inventory


def main(output_dir: Path = REPO_ROOT / "docs" / "analysis"):
    generate_inventory(extracted_dir=EXTRACTED_DIR, output_dir=output_dir)


if __name__ == "__main__":
    main()
