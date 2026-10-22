#define _POSIX_C_SOURCE 200809L
#include <switch.h>
#include "boot_screen.h"
#include "loading_layer.h"
#include <zlib.h>
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
static NWindow loading_window,default_window;
static pthread_t worker;
static void (*worker_entry)(void *);
static atomic_uint frames,fb_closes,layer_closes;
static atomic_uint default_frames,default_closes;
static unsigned joins;
#ifdef LOADING_GL_NATIVE_TEST
unsigned loading_gl_draws(void);
#endif
static void pause_ms(unsigned ms) {
  struct timespec delay={ms/1000,(long)(ms%1000)*1000000};nanosleep(&delay,NULL);
}
void mutexLock(Mutex *m) { while(__sync_lock_test_and_set(&m->locked,1)) sched_yield(); }
void mutexUnlock(Mutex *m) { __sync_lock_release(&m->locked); }
uint64_t armGetSystemTick(void) {
  struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
  return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;
}
uint64_t armGetSystemTickFreq(void) { return 1000000000; }
Result svcSleepThread(int64_t ns) { assert(ns==50000000);pause_ms(50);return 0; }
NWindow *nwindowGetDefault(void) { return &default_window; }
NWindow *loading_layer_begin(void) { return &loading_window; }
void loading_layer_report(void) {}
void loading_layer_end(void) { atomic_fetch_add(&layer_closes,1); }
unsigned cpu_boost(int on) { assert(!on);return 0; }
void durak_log_printf(const char *fmt,...) { (void)fmt; }
static void *run_worker(void *unused) { worker_entry(unused);return NULL; }
Result threadCreate(Thread *t,void (*entry)(void *),void *arg,void *stack,unsigned long size,int priority,int core) {
  (void)t;(void)arg;(void)stack;(void)priority;(void)core;assert(size==0x4000);worker_entry=entry;return 0;
}
Result threadStart(Thread *t) { (void)t;return pthread_create(&worker,NULL,run_worker,NULL); }
Result threadWaitForExit(Thread *t) { (void)t;assert(!boot_screen_framebuffer_active());++joins;return pthread_join(worker,NULL); }
Result threadClose(Thread *t) { (void)t;return 0; }
int uncompress(unsigned char *dst,uLongf *len,const unsigned char *src,unsigned long size) {
  (void)src;assert(size && *len==1280*720*4);memset(dst,255,*len);return Z_OK;
}
Result framebufferCreate(Framebuffer *f,NWindow *w,u32 width,u32 height,u32 format,u32 count) {
  assert((w==&loading_window || w==&default_window) && width==1280 && height==720 && format==PIXEL_FORMAT_RGBA_8888 && count==2);
  f->win=w;f->pixels=malloc((1280*4+32)*720);assert(f->pixels);return 0;
}
Result framebufferMakeLinear(Framebuffer *f) { (void)f;return 0; }
void *framebufferBegin(Framebuffer *f,u32 *stride) { assert(f->pixels);*stride=1280*4+32;return f->pixels; }
void framebufferEnd(Framebuffer *f) {
  assert(f->pixels);
  atomic_fetch_add(f->win==&default_window ? &default_frames : &frames,1);
}
void framebufferClose(Framebuffer *f) {
  free(f->pixels);f->pixels=NULL;
  atomic_fetch_add(f->win==&default_window ? &default_closes : &fb_closes,1);
}
int main(void) {
  boot_screen_begin(armGetSystemTick());
  assert(boot_screen_independent() && boot_screen_framebuffer_active() && boot_screen_blocks_default_window());
  assert(atomic_load(&default_frames)==1); /* Visible SDK window gets the same art even if the private layer is hidden. */
  boot_screen_disconnect(); /* Unity EGL acquisition must not stop the worker. */
  assert(atomic_load(&default_closes)==1 && !boot_screen_blocks_default_window() && !atomic_load(&fb_closes));
  unsigned before=atomic_load(&frames);
  pause_ms(300); /* Main/Unity thread makes no rendering calls during this stall. */
  assert(atomic_load(&frames)>=before+3 && boot_screen_waiting());
#ifdef LOADING_GL_NATIVE_TEST
  before=atomic_load(&frames);
  assert(boot_screen_independent() && boot_screen_draw(1280,720));
  assert(loading_gl_draws()==1); /* Success of the private layer cannot skip a real default-window GL draw. */
  assert(atomic_load(&frames)>=before+2); /* Blocking GL call never holds the CPU worker mutex. */
  puts("[PASS] Real EGL loading path draws with independent=1; CPU worker advances during a 250ms GL driver stall");
#endif
  boot_screen_menu_ready();boot_screen_presented();
  assert(boot_screen_waiting() && boot_screen_framebuffer_active());
  boot_screen_presented();
  assert(!boot_screen_waiting() && !boot_screen_framebuffer_active());
#ifdef LOADING_GL_NATIVE_TEST
  assert(!boot_screen_draw(1280,720) && loading_gl_draws()==1);
  boot_screen_context_destroyed((void *)(uintptr_t)1);
#endif
  unsigned after=atomic_load(&frames);pause_ms(150);assert(atomic_load(&frames)==after);
  boot_screen_shutdown();boot_screen_shutdown();
  assert(atomic_load(&fb_closes)==1 && atomic_load(&default_closes)==1 && atomic_load(&layer_closes)==1 && joins==1);
  puts("Async loading: PASS (real worker advances during blocked main/Unity, survives EGL handoff, stops only at menu, joins before free)");
  return 0;
}
