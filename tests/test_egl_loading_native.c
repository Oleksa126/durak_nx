#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "egl_loading.h"
int screen_width=1280,screen_height=720;
static int raw_size, native_calls;
static void shim(void) {}
static void native(void) {}
void durak_log_printf(const char *fmt,...) { (void)fmt; }
EGLBoolean eglQuerySurface(EGLDisplay d,EGLSurface s,EGLint attribute,EGLint *value) {
  (void)d; (void)s;
  if(value) *value=raw_size;
  return attribute==EGL_WIDTH || attribute==EGL_HEIGHT;
}
uintptr_t dynlib_find_export(const char *name) {
  return !strcmp(name,"eglMakeCurrent") || !strcmp(name,"eglSwapBuffers") ||
         !strcmp(name,"eglQuerySurface") ? (uintptr_t)shim : 0;
}
__eglMustCastToProperFunctionPointerType eglGetProcAddress(const char *name) {
  assert(name); ++native_calls; return native;
}
int main(void) {
  EGLint width=0,height=0;
  assert(nx_egl_query_surface(NULL,NULL,EGL_WIDTH,&width));
  assert(nx_egl_query_surface(NULL,NULL,EGL_HEIGHT,&height));
  assert(width==1280 && height==720); /* Mesa's 0x0 must not suppress draw. */
  raw_size=1920;
  assert(nx_egl_query_surface(NULL,NULL,EGL_WIDTH,&width) && width==1920);
  assert(!nx_egl_query_surface(NULL,NULL,0x1234,&width) && width==1920);
  assert(nx_egl_get_proc_address("eglMakeCurrent")==shim);
  assert(nx_egl_get_proc_address("eglSwapBuffers")==shim);
  assert(nx_egl_get_proc_address("eglQuerySurface")==shim);
  assert(native_calls==0);
  assert(nx_egl_get_proc_address("eglUnknownExtension")==native);
  assert(nx_egl_get_proc_address("glDrawArrays")==native);
  assert(native_calls==2 && nx_egl_get_proc_address(NULL)==NULL);
  puts("[PASS] Loading EGL: 0x0 extent repair, valid extent/error preservation, proc routing");
}
