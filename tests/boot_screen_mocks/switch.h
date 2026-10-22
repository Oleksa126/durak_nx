#pragma once
#include <stdint.h>
typedef uint32_t u32;
typedef uint32_t Result;
typedef struct { int unused; } NWindow;
typedef struct { NWindow *win;unsigned char *pixels; } Framebuffer;
typedef struct { int locked; } Mutex;
typedef struct { int unused; } Thread;
Result threadCreate(Thread *, void (*)(void *), void *, void *, unsigned long, int, int);
Result threadStart(Thread *);
Result threadWaitForExit(Thread *);
Result threadClose(Thread *);
Result svcSleepThread(int64_t);
void mutexLock(Mutex *);
void mutexUnlock(Mutex *);
#define R_FAILED(rc) ((rc) != 0)
#define PIXEL_FORMAT_RGBA_8888 1
uint64_t armGetSystemTick(void);
uint64_t armGetSystemTickFreq(void);
NWindow *nwindowGetDefault(void);
Result framebufferCreate(Framebuffer *, NWindow *, u32, u32, u32, u32);
Result framebufferMakeLinear(Framebuffer *);
void *framebufferBegin(Framebuffer *, u32 *);
void framebufferEnd(Framebuffer *);
void framebufferClose(Framebuffer *);
