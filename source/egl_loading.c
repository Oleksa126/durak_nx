/* Keep static imports and dynamically resolved EGL calls on the same path. */
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include "egl_loading.h"
#include "imports.h"
#include "config.h"
#include "util.h"

EGLBoolean nx_egl_query_surface(EGLDisplay d, EGLSurface s, EGLint attribute, EGLint *value) {
  EGLBoolean result=eglQuerySurface(d,s,attribute,value);
  if(value && *value<=0 && (attribute==EGL_WIDTH || attribute==EGL_HEIGHT)) {
    int raw=*value;
    *value=attribute==EGL_WIDTH ? screen_width : screen_height;
    result=EGL_TRUE; /* Existing Switch Mesa dimension fix, now shared by overlay. */
    static atomic_uint reported;
    unsigned bit=attribute==EGL_WIDTH ? 1u : 2u;
    if(!(atomic_fetch_or(&reported,bit)&bit))
      durak_log_printf("[LOADING] EGL dimension 0x%x corrected %d -> %d\n",attribute,raw,*value);
  }
  return result;
}

__eglMustCastToProperFunctionPointerType nx_egl_get_proc_address(const char *name) {
  if(!name) return NULL;
  if(!strncmp(name,"egl",3)) {
    uintptr_t shim=dynlib_find_export(name);
    if(shim) return (__eglMustCastToProperFunctionPointerType)shim;
  }
  return eglGetProcAddress(name);
}
