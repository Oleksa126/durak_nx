#pragma once
typedef void *EGLDisplay;
typedef void *EGLSurface;
typedef int EGLint;
typedef unsigned EGLBoolean;
typedef void (*__eglMustCastToProperFunctionPointerType)(void);
#define EGL_TRUE 1
#define EGL_FALSE 0
#define EGL_WIDTH 0x3057
#define EGL_HEIGHT 0x3056
EGLBoolean eglQuerySurface(EGLDisplay,EGLSurface,EGLint,EGLint *);
__eglMustCastToProperFunctionPointerType eglGetProcAddress(const char *);
