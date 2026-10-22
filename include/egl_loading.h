#ifndef DURAK_EGL_LOADING_H
#define DURAK_EGL_LOADING_H
#include <EGL/egl.h>
EGLBoolean nx_egl_query_surface(EGLDisplay display, EGLSurface surface, EGLint attribute, EGLint *value);
__eglMustCastToProperFunctionPointerType nx_egl_get_proc_address(const char *name);
#endif
