#include <switch.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "boot_screen.h"
#include "loading_style.h"
#include "loading_layer.h"

static unsigned char *buffer;
static int fail_create, fail_linear, closes, queues;
static int fail_decode;
static uint64_t tick=1234;
static void (*animation_entry)(void *);
static int sleeps, thread_closes, fail_thread_start, fail_thread_create;
static unsigned char initial_logo_pixel;
static int fail_layer,layer_closes;
static int fail_default_create,fail_default_linear,fail_private_create,fail_private_linear;
static unsigned first_phase;
static int first_sample,changed_sample;
static NWindow private_window;
NWindow *loading_layer_begin(void) { return fail_layer ? NULL : &private_window; }
void loading_layer_end(void) { ++layer_closes; }
void loading_layer_report(void) {}
Result threadCreate(Thread *t,void (*entry)(void *),void *arg,void *stack,unsigned long size,int priority,int core) {
  (void)t; (void)arg; (void)stack; (void)priority; (void)core;
  assert(size==0x4000); animation_entry=entry; return fail_thread_create ? 0xabc : 0;
}
Result threadStart(Thread *t) { (void)t; return fail_thread_start ? 0x789 : 0; }
Result threadWaitForExit(Thread *t) { (void)t; assert(!boot_screen_framebuffer_active()); return 0; }
Result threadClose(Thread *t) { (void)t; ++thread_closes; return 0; }
Result svcSleepThread(int64_t ns) {
  assert(ns==50000000); tick+=250;
  if (++sleeps==2) boot_screen_disconnect();
  if(!fail_layer && sleeps==5) {
    assert(boot_screen_framebuffer_active() && boot_screen_waiting());
    boot_screen_menu_ready();boot_screen_presented();
    assert(boot_screen_framebuffer_active());
    boot_screen_presented();
  }
  return 0;
}
int uncompress(unsigned char *dst, uLongf *len, const unsigned char *src, unsigned long size) {
  (void)src; assert(size>0 && *len==1280*720*4);
  if(fail_decode) return Z_DATA_ERROR;
  for(unsigned y=0;y<LOADING_HEIGHT;++y) for(unsigned x=0;x<LOADING_WIDTH;++x) {
    unsigned char *p=dst+(y*LOADING_WIDTH+x)*4;
    int art=x>=LOADING_LOGO_X && x<LOADING_LOGO_X+LOADING_LOGO_SIZE &&
            y>=LOADING_LOGO_Y && y<LOADING_LOGO_Y+LOADING_LOGO_SIZE;
    p[0]=art ? (unsigned char)(x-LOADING_LOGO_X) : 10;
    p[1]=art ? (unsigned char)(y-LOADING_LOGO_Y) : 10;
    p[2]=art ? 60 : 15; p[3]=255;
  }
  return Z_OK;
}
static unsigned stride = 1280*4 + 32;
unsigned cpu_boost(int on) { assert(on==0); return 0; }
void mutexLock(Mutex *m) { assert(!m->locked); m->locked = 1; }
void mutexUnlock(Mutex *m) { assert(m->locked); m->locked = 0; }
uint64_t armGetSystemTick(void) { return tick; }
uint64_t armGetSystemTickFreq(void) { return 1000; }
NWindow *nwindowGetDefault(void) { static NWindow window; return &window; }
void durak_log_printf(const char *fmt, ...) { (void)fmt; }
Result framebufferCreate(Framebuffer *f, NWindow *w, u32 width, u32 height, u32 format, u32 count) {
  assert((w==nwindowGetDefault() || (!fail_layer && w==&private_window)) && width==1280 && height==720);
  assert(format==PIXEL_FORMAT_RGBA_8888 && count==2);
  f->win=w;
  return fail_create || (w==nwindowGetDefault() ? fail_default_create : fail_private_create) ? 0x123 : 0;
}
Result framebufferMakeLinear(Framebuffer *f) { return fail_linear || (f->win==nwindowGetDefault() ? fail_default_linear : fail_private_linear) ? 0x456 : 0; }
void *framebufferBegin(Framebuffer *f, u32 *out) {
  free(f->pixels);f->pixels=malloc(stride*720);buffer=f->pixels;assert(buffer);
  memset(buffer,0xa5,stride*720); *out=stride; return buffer;
}
void framebufferEnd(Framebuffer *f) {
  (void)f; ++queues;
  for(unsigned y=0;y<720;++y) for(unsigned x=1280*4;x<stride;++x)
    assert(buffer[y*stride+x]==0xa5);
  assert(buffer[3]==255); /* Image has an opaque background. */
  /* Check the actual transformed picture against the gtasa cosine formula,
   * including an expanding edge and background outside the logo. */
  unsigned phase=(unsigned)((tick-1000)/50%40);
  float scale=1.0f+0.04f*(1.0f-cosf(phase*6.28318530718f/40));
  const int positions[][2]={{500,280},{437,360},{640,155},{30,30},{640,650}};
  for(unsigned i=0;i<sizeof(positions)/sizeof(positions[0]);++i) {
    int x=positions[i][0],y=positions[i][1];
    int art=fabsf(x+0.5f-640)<200*scale && fabsf(y+0.5f-360)<200*scale;
    unsigned char red=10,green=10;
    if(art) {
      int sx=(int)((x+0.5f-640)/scale+640);
      int sy=(int)((y+0.5f-360)/scale+360);
      red=(unsigned char)(sx-440);green=(unsigned char)(sy-160);
    }
    assert(buffer[y*stride+x*4]==red && buffer[y*stride+x*4+1]==green);
    assert(buffer[y*stride+x*4+2]==(art ? 60 : 15));
  }
  unsigned char current=buffer[280*stride+500*4];
  if(!first_sample) { initial_logo_pixel=current;first_phase=phase;first_sample=1; }
  else if(!changed_sample && phase!=first_phase) { assert(current!=initial_logo_pixel);changed_sample=1; }
}
void framebufferClose(Framebuffer *f) { ++closes;if(buffer==f->pixels) buffer=NULL;free(f->pixels);f->pixels=NULL; }
int main(int argc,char **argv) {
  assert(durak_loading_phase(0)==0 && durak_loading_phase(2000)==0);
  assert(fabsf(durak_loading_scale(0)-1.0f)<0.00001f);
  assert(fabsf(durak_loading_scale(20)-1.08f)<0.00001f);
  if(argc>1 && !strcmp(argv[1],"create")) fail_create=1;
  if(argc>1 && !strcmp(argv[1],"linear")) fail_linear=1;
  if(argc>1 && !strcmp(argv[1],"decode")) fail_decode=1;
  if(argc>1 && !strcmp(argv[1],"thread")) fail_thread_start=1;
  if(argc>1 && !strcmp(argv[1],"thread-create")) fail_thread_create=1;
  if(argc>1 && !strcmp(argv[1],"layer")) fail_layer=1;
  if(argc>1 && !strcmp(argv[1],"default-create")) fail_default_create=1;
  if(argc>1 && !strcmp(argv[1],"default-linear")) fail_default_linear=1;
  if(argc>1 && !strcmp(argv[1],"private-create")) fail_private_create=1;
  if(argc>1 && !strcmp(argv[1],"private-linear")) fail_private_linear=1;
  boot_screen_begin(1000);
  if(fail_decode) {
    assert(!boot_screen_waiting() && !boot_screen_framebuffer_active() && !queues);
    boot_screen_shutdown(); boot_screen_shutdown();
    assert(!closes); puts("[PASS] Loading decode failure leaves no display ownership"); return 0;
  }
  assert(boot_screen_waiting()); /* EGL can still use the art if CPU FB failed. */
  int default_created=!fail_create && !fail_default_create;
  int default_good=default_created && !fail_linear && !fail_default_linear;
  int private_created=!fail_layer && !fail_create && !fail_private_create;
  int private_good=private_created && !fail_linear && !fail_private_linear;
  int fb_good=default_good || private_good;
  int expected_closes=default_created+private_created;
  assert(queues==default_good+fb_good);
  int independent=private_good && !fail_thread_start && !fail_thread_create;
  assert(boot_screen_independent()==independent);
  assert(boot_screen_blocks_default_window()==default_good);
  for(int i=0;i<200;++i) boot_screen_presented();
  assert(boot_screen_waiting()); /* No timer/frame count can dismiss pre-menu. */
  if(independent) {
    boot_screen_disconnect();boot_screen_disconnect();
    assert(boot_screen_framebuffer_active() && closes==default_created && !layer_closes);
  }
  if (fb_good && !fail_thread_start && !fail_thread_create) {
    animation_entry(NULL);
    assert(queues==default_good+(independent ? 5 : 2) && sleeps==(independent ? 5 : 2) && closes==expected_closes);
    if(independent) assert(!boot_screen_waiting());
  }
  boot_screen_disconnect(); boot_screen_disconnect();
  assert(!boot_screen_framebuffer_active() && closes==expected_closes);
  if(!independent) {
    boot_screen_menu_ready(); boot_screen_presented();
    assert(boot_screen_waiting());
    boot_screen_presented(); assert(!boot_screen_waiting());
  }
  boot_screen_shutdown(); boot_screen_shutdown();
  assert(closes==expected_closes && !buffer);
  assert(thread_closes==(fb_good && !fail_thread_create));
  assert(layer_closes==!fail_layer);
  puts("[PASS] Loading: independent pulse survives EGL acquisition and absent Unity presents; menu gate, fallback, cleanup and padded pixels");
}
