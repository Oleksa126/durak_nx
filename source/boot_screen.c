/* Independent CPU layer until menu; same-image EGL fallback on VI failure. */
#include <switch.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <zlib.h>
#include "loading_screen_bin.h"
#include "boot_screen.h"
#include "loading_style.h"
#include "loading_layer.h"
#include "util.h"
#ifndef BOOT_SCREEN_NATIVE_TEST
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#endif

static Framebuffer fb,default_fb;
static Mutex lock,graphics_lock;
static atomic_int fb_active, finished, menu_ready, image_ready;
static atomic_int private_layer,independent;
static atomic_int default_fb_active;
static Result default_create_result,default_linear_result;
static unsigned long long default_queued_ms;
static unsigned ready_presents;
static unsigned char *image;
static uint64_t start_tick;
static int decode_result;
static Result create_result, linear_result;
static unsigned long long queued_ms;
static Thread animation_thread;
static int animation_started;
static const char *animation_stage="not attempted";
static Result animation_result;
static unsigned cpu_frames;
static unsigned long long last_queue_ms,max_queue_gap_ms;

static unsigned long long elapsed(void) {
  return (armGetSystemTick()-start_tick)*1000/armGetSystemTickFreq();
}
static unsigned animation_phase(void) { return durak_loading_phase(elapsed()); }

/* Caller owns lock, or runs before the animation thread starts. */
static void queue_frame(Framebuffer *target,unsigned phase) {
  u32 stride;
  unsigned char *pixels = framebufferBegin(target, &stride);
  for (unsigned y=0; y<720; ++y)
    memcpy(pixels+y*stride, image+y*1280*4, 1280*4);
  float scale=durak_loading_scale(phase);
  float half=LOADING_LOGO_SIZE * 0.5f * scale;
  int left=(int)ceilf(LOADING_CENTER_X-half-0.5f);
  int right=(int)ceilf(LOADING_CENTER_X+half-0.5f);
  int top=(int)ceilf(LOADING_CENTER_Y-half-0.5f);
  int bottom=(int)ceilf(LOADING_CENTER_Y+half-0.5f);
  unsigned source_x[LOADING_LOGO_SIZE*108/100+2];
  for(int x=left;x<right;++x)
    source_x[x-left]=(unsigned)((x+0.5f-LOADING_CENTER_X)/scale+LOADING_CENTER_X);
  for(int y=top;y<bottom;++y) {
    unsigned sy=(unsigned)((y+0.5f-LOADING_CENTER_Y)/scale+LOADING_CENTER_Y);
    for(int x=left;x<right;++x)
      memcpy(pixels+y*stride+x*4,image+(sy*LOADING_WIDTH+source_x[x-left])*4,4);
  }
  framebufferEnd(target);
}
static void queue_cpu_frame(unsigned phase) {
  queue_frame(&fb,phase);
  unsigned long long now=elapsed();
  if(cpu_frames && now-last_queue_ms>max_queue_gap_ms) max_queue_gap_ms=now-last_queue_ms;
  last_queue_ms=now;
  ++cpu_frames;
}
static void animate_cpu(void *unused) {
  (void)unused;
  unsigned previous=animation_phase();
  unsigned long long heartbeat=elapsed();
  while (atomic_load(&fb_active)) {
    svcSleepThread(LOADING_FRAME_MS*1000000LL);
    mutexLock(&lock);
    unsigned phase=animation_phase();
    if (atomic_load(&fb_active) && phase!=previous) {
      queue_cpu_frame(phase);
      previous=phase;
      unsigned long long now=elapsed();
      if(atomic_load(&independent) && now-heartbeat>=2000) {
        durak_log_printf("[LOADING] Pulse heartbeat: cpu_frames=%u max_queue_gap_ms=%llu\n",cpu_frames,max_queue_gap_ms);
        heartbeat=now;
      }
    }
    mutexUnlock(&lock);
  }
}
int boot_screen_waiting(void) { return atomic_load(&image_ready) && !atomic_load(&finished); }
int boot_screen_framebuffer_active(void) { return atomic_load(&fb_active); }
int boot_screen_independent(void) { return atomic_load(&independent); }
int boot_screen_blocks_default_window(void) {
  return atomic_load(&default_fb_active) || (atomic_load(&fb_active) && !atomic_load(&private_layer));
}
void boot_screen_report(void) {
  durak_log_printf("[LOADING] Early image: zlib=%d create_Result=0x%x linear_Result=0x%x queued=%llu ms active=%d\n",
                   decode_result,create_result,linear_result,queued_ms,boot_screen_framebuffer_active());
  loading_layer_report();
  durak_log_printf("[LOADING] Default window image: create_Result=0x%x linear_Result=0x%x queued=%llu ms active=%d\n",
      default_create_result,default_linear_result,default_queued_ms,atomic_load(&default_fb_active));
  durak_log_printf("[LOADING] independent=%d default_window_blocked=%d\n",
                  atomic_load(&independent),boot_screen_blocks_default_window());
  durak_log_printf("[LOADING] animation_thread=%s Result=0x%x\n",animation_stage,animation_result);
}

/* Caller owns lock; worker and release cannot access the framebuffer together. */
static void close_cpu_locked(void) {
  if(atomic_exchange(&default_fb_active,0)) framebufferClose(&default_fb);
  if(atomic_exchange(&fb_active,0)) framebufferClose(&fb);
  if(atomic_exchange(&private_layer,0)) loading_layer_end();
  atomic_store(&independent,0);
}

void boot_screen_disconnect(void) {
  unsigned boost_rc=cpu_boost(0);
  if(boost_rc) durak_log_printf("[STARTUP FAST] CPU normal restore failed result=0x%x\n",boost_rc);
  mutexLock(&lock);
  /* Release the default CPU producer before Mesa connects its EGL swapchain,
   * even while the independent worker keeps its own producer alive. */
  if(atomic_exchange(&default_fb_active,0)) {
    framebufferClose(&default_fb);
    durak_log_printf("[LOADING] Default CPU image released for EGL at %llu ms\n",elapsed());
  }
  if(atomic_load(&independent)) { mutexUnlock(&lock);return; }
  if (atomic_load(&fb_active) || atomic_load(&private_layer)) {
    close_cpu_locked();
    durak_log_printf("[LOADING] CPU framebuffer disconnected for EGL at %llu ms\n", elapsed());
  }
  mutexUnlock(&lock);
}
static int adopt_default_framebuffer(void) {
  if(!atomic_exchange(&default_fb_active,0)) return 0;
  fb=default_fb;memset(&default_fb,0,sizeof(default_fb));
  atomic_store(&fb_active,1);return 1;
}
void boot_screen_begin(uint64_t tick) {
  start_tick = tick;
  image = malloc(1280*720*4);
  uLongf size = 1280*720*4;
  int zrc = image ? uncompress(image, &size, loading_screen_bin, loading_screen_bin_size) : Z_MEM_ERROR;
  decode_result=zrc;
  if (zrc != Z_OK || size != 1280*720*4) {
    durak_log_printf("[LOADING ERROR] Image decode: zlib=%d bytes=%lu\n", zrc, size);
    free(image); image = NULL;
    return;
  }
  atomic_store(&image_ready, 1);
  /* The SDK window is already known to display this image on hardware. Never
   * make its early content depend on an unverified additional VI layer. */
  default_create_result=framebufferCreate(&default_fb,nwindowGetDefault(),1280,720,PIXEL_FORMAT_RGBA_8888,2);
  default_linear_result=default_create_result;
  if(!R_FAILED(default_create_result)) {
    atomic_store(&default_fb_active,1);
    default_linear_result=framebufferMakeLinear(&default_fb);
    if(R_FAILED(default_linear_result)) {
      framebufferClose(&default_fb);atomic_store(&default_fb_active,0);
    } else {
      queue_frame(&default_fb,animation_phase());default_queued_ms=elapsed();
    }
  }
  NWindow *loading_window=loading_layer_begin();
  atomic_store(&private_layer,loading_window!=NULL);
  Result rc;
  if(loading_window) {
    rc=framebufferCreate(&fb,loading_window,1280,720,PIXEL_FORMAT_RGBA_8888,2);
    create_result=rc;linear_result=rc;
    if(!R_FAILED(rc)) {
      atomic_store(&fb_active,1);rc=framebufferMakeLinear(&fb);linear_result=rc;
    }
    if(R_FAILED(rc)) {
      durak_log_printf("[LOADING ERROR] Private framebuffer create=0x%x linear=0x%x; retaining default image\n",create_result,linear_result);
      if(atomic_exchange(&fb_active,0)) framebufferClose(&fb);
      loading_layer_end();atomic_store(&private_layer,0);
      if(!adopt_default_framebuffer()) return;
    }
  } else {
    create_result=default_create_result;linear_result=default_linear_result;
    if(!adopt_default_framebuffer()) return;
  }
  queue_cpu_frame(animation_phase());
  queued_ms=elapsed();
  durak_log_printf("[LOADING] Shared image queued at %llu ms\n", elapsed());
  animation_stage="threadCreate";
  rc=threadCreate(&animation_thread,animate_cpu,NULL,NULL,0x4000,0x2C,-2);
  animation_result=rc;
  if (R_FAILED(rc)) {
    durak_log_printf("[LOADING ERROR] Animation threadCreate Result=0x%x\n",rc);
    return;
  }
  animation_stage="threadStart";
  rc=threadStart(&animation_thread);
  animation_result=rc;
  if (R_FAILED(rc)) {
    durak_log_printf("[LOADING ERROR] Animation threadStart Result=0x%x\n",rc);
    threadClose(&animation_thread);
    return;
  }
  animation_started=1;
  animation_stage="running";
  atomic_store(&independent,atomic_load(&private_layer));
  durak_log_printf("[LOADING] Logo pulse started at %llu ms (period=2000ms scale=1.00..1.08)\n",elapsed());
}
void boot_screen_menu_ready(void) {
  if (!atomic_exchange(&menu_ready, 1))
    durak_log_printf("[LOADING] Active MainMenu detected at %llu ms; awaiting menu presents\n", elapsed());
}
void boot_screen_presented(void) {
  static int first_present;
  mutexLock(&lock);
  if (!first_present) {
    first_present=1;
    durak_log_printf("[LOADING] First Unity window present at %llu ms; independent=%d\n",elapsed(),atomic_load(&independent));
  }
  /* Only successful presents count, and never release on a startup timer. */
  if (!atomic_load(&finished) && atomic_load(&menu_ready) && ++ready_presents >= 2) {
    atomic_store(&finished, 1);
    if(atomic_load(&independent)) {
      close_cpu_locked();
      durak_log_printf("[LOADING] Independent layer removed after %u CPU frames at %llu ms; max_queue_gap_ms=%llu\n",
                      cpu_frames,elapsed(),max_queue_gap_ms);
    }
    durak_log_printf("[LOADING] Menu handoff after two accepted presents at %llu ms\n", elapsed());
  }
  mutexUnlock(&lock);
}
void boot_screen_shutdown(void) {
  cpu_boost(0);
  mutexLock(&lock);
  close_cpu_locked();
  atomic_store(&finished,1);
  mutexUnlock(&lock);
  if (animation_started) {
    threadWaitForExit(&animation_thread);
    threadClose(&animation_thread);
    animation_started=0;
  }
  mutexLock(&graphics_lock);
  atomic_store(&finished, 1);
  free(image); image = NULL;
  mutexUnlock(&graphics_lock);
}

#ifndef BOOT_SCREEN_NATIVE_TEST
typedef struct { EGLContext context; GLuint program, texture; int failed; } LoadingGL;
static LoadingGL contexts[4];
void boot_screen_context_destroyed(void *context) {
  mutexLock(&graphics_lock);
  for(int i=0;i<4;++i) if(contexts[i].context==context) memset(&contexts[i],0,sizeof(contexts[i]));
  mutexUnlock(&graphics_lock);
}

static GLuint compile_shader(GLenum type, const char *source) {
  GLuint shader = glCreateShader(type);
  glShaderSource(shader, 1, &source, NULL);
  glCompileShader(shader);
  GLint ok;
  glGetShaderiv(shader, GL_COMPILE_STATUS, &ok);
  if (!ok) {
    char log[512]; glGetShaderInfoLog(shader, sizeof(log), NULL, log);
    durak_log_printf("[LOADING ERROR] Shader compile: %s\n", log);
    glDeleteShader(shader); return 0;
  }
  return shader;
}
static int create_gl(LoadingGL *slot) {
  GLuint vs = compile_shader(GL_VERTEX_SHADER,
      "#version 300 es\n precision highp float; out highp vec2 uv;"
      "void main(){vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2));"
      "uv=vec2(p.x,1.0-p.y);gl_Position=vec4(p*2.0-1.0,0.0,1.0);}");
  GLuint fs = compile_shader(GL_FRAGMENT_SHADER,
      "#version 300 es\n precision highp float; in highp vec2 uv; uniform sampler2D art;"
      "uniform float pulse; uniform vec4 logo; out vec4 color; void main(){"
      "vec2 d=uv*vec2(1280.0,720.0)-logo.xy;"
      "if(all(lessThan(abs(d),logo.zw*pulse)))"
      "color=texture(art,(logo.xy+d/pulse)/vec2(1280.0,720.0));"
      "else color=texture(art,uv);}");
  if (!vs || !fs) { if(vs) glDeleteShader(vs); if(fs) glDeleteShader(fs); return 0; }
  slot->program = glCreateProgram();
  glAttachShader(slot->program, vs); glAttachShader(slot->program, fs);
  glLinkProgram(slot->program);
  glDeleteShader(vs); glDeleteShader(fs);
  GLint ok;
  glGetProgramiv(slot->program, GL_LINK_STATUS, &ok);
  if (!ok) {
    char log[512]; glGetProgramInfoLog(slot->program, sizeof(log), NULL, log);
    durak_log_printf("[LOADING ERROR] Program link: %s\n", log);
    glDeleteProgram(slot->program); slot->program=0; return 0;
  }
  glGenTextures(1, &slot->texture);
  glBindTexture(GL_TEXTURE_2D, slot->texture);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  GLint unpack[5];
  const GLenum names[] = {GL_UNPACK_ALIGNMENT,GL_UNPACK_ROW_LENGTH,GL_UNPACK_SKIP_ROWS,
                          GL_UNPACK_SKIP_PIXELS,GL_PIXEL_UNPACK_BUFFER_BINDING};
  for(int i=0;i<5;++i) glGetIntegerv(names[i], &unpack[i]);
  glBindBuffer(GL_PIXEL_UNPACK_BUFFER, 0);
  glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
  glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
  glPixelStorei(GL_UNPACK_SKIP_ROWS, 0); glPixelStorei(GL_UNPACK_SKIP_PIXELS, 0);
  glTexStorage2D(GL_TEXTURE_2D,1,GL_RGBA8,1280,720);
  glTexSubImage2D(GL_TEXTURE_2D,0,0,0,1280,720,GL_RGBA,GL_UNSIGNED_BYTE,image);
  for(int i=0;i<4;++i) glPixelStorei(names[i],unpack[i]);
  glBindBuffer(GL_PIXEL_UNPACK_BUFFER,unpack[4]);
  GLint immutable=0;
  glGetTexParameteriv(GL_TEXTURE_2D,GL_TEXTURE_IMMUTABLE_FORMAT,&immutable);
  if(!immutable) {
    durak_log_printf("[LOADING ERROR] Texture storage failed: GL error=0x%x\n",glGetError());
    glDeleteTextures(1,&slot->texture); glDeleteProgram(slot->program);
    slot->texture=slot->program=0; return 0;
  }
  return 1;
}
int boot_screen_draw(int width, int height) {
  /* Driver compilation/uploads/presents must not hold the CPU worker mutex. */
  mutexLock(&graphics_lock);
  if (!boot_screen_waiting() || width<=0 || height<=0) { mutexUnlock(&graphics_lock); return 0; }
  EGLContext context=eglGetCurrentContext();
  if(context==EGL_NO_CONTEXT) {
    static int reported;
    if(!reported++) durak_log_printf("[LOADING ERROR] Overlay has no current EGL context\n");
    mutexUnlock(&graphics_lock); return 0;
  }
  LoadingGL *slot=NULL;
  for(int i=0;i<4;++i) if(contexts[i].context==context) { slot=&contexts[i]; break; }
  if(!slot) for(int i=0;i<4;++i) if(!contexts[i].context) {
    slot=&contexts[i]; slot->context=context; break;
  }
  if(!slot) {
    durak_log_printf("[LOADING ERROR] Unexpected number of EGL contexts\n");
    mutexUnlock(&graphics_lock); return 0;
  }
  GLint program, fbo, vao, viewport[4], active, texture, sampler, draw_buffer;
  GLboolean mask[4];
  GLboolean feedback, paused;
  glGetBooleanv(GL_TRANSFORM_FEEDBACK_ACTIVE,&feedback);
  glGetBooleanv(GL_TRANSFORM_FEEDBACK_PAUSED,&paused);
  if(feedback && !paused) glPauseTransformFeedback();
  glGetIntegerv(GL_CURRENT_PROGRAM,&program); glGetIntegerv(GL_DRAW_FRAMEBUFFER_BINDING,&fbo);
  glGetIntegerv(GL_VERTEX_ARRAY_BINDING,&vao); glGetIntegerv(GL_VIEWPORT,viewport);
  glGetBooleanv(GL_COLOR_WRITEMASK,mask); glGetIntegerv(GL_ACTIVE_TEXTURE,&active);
  glActiveTexture(GL_TEXTURE0); glGetIntegerv(GL_TEXTURE_BINDING_2D,&texture);
  glGetIntegerv(GL_SAMPLER_BINDING,&sampler);
  const GLenum caps[]={GL_BLEND,GL_DEPTH_TEST,GL_STENCIL_TEST,GL_SCISSOR_TEST,GL_CULL_FACE,
                       GL_RASTERIZER_DISCARD,GL_SAMPLE_ALPHA_TO_COVERAGE,GL_SAMPLE_COVERAGE};
  GLboolean enabled[8];
  for(int i=0;i<8;++i) { enabled[i]=glIsEnabled(caps[i]); glDisable(caps[i]); }
  if(!slot->program && !slot->failed && !create_gl(slot)) slot->failed=1;
  int ok=slot->program != 0;
  if(ok) {
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER,0);
    glGetIntegerv(GL_DRAW_BUFFER0,&draw_buffer);
    GLenum back=GL_BACK; glDrawBuffers(1,&back);
    glViewport(0,0,width,height); glColorMask(GL_TRUE,GL_TRUE,GL_TRUE,GL_TRUE);
    glBindVertexArray(0); glUseProgram(slot->program);
    glBindTexture(GL_TEXTURE_2D,slot->texture); glBindSampler(0,0);
    glUniform1i(glGetUniformLocation(slot->program,"art"),0);
    glUniform1f(glGetUniformLocation(slot->program,"pulse"),durak_loading_scale(animation_phase()));
    glUniform4f(glGetUniformLocation(slot->program,"logo"),LOADING_CENTER_X,LOADING_CENTER_Y,
                LOADING_LOGO_SIZE*0.5f,LOADING_LOGO_SIZE*0.5f);
    glDrawArrays(GL_TRIANGLES,0,3);
    static int first_draw;
    if(!first_draw++)
      durak_log_printf("[LOADING] First overlay draw: context=%p viewport=%dx%d program=%u texture=%u\n",
                       context,width,height,slot->program,slot->texture);
    GLenum previous=(GLenum)draw_buffer; glDrawBuffers(1,&previous);
  }
  glBindSampler(0,sampler); glBindTexture(GL_TEXTURE_2D,texture); glActiveTexture(active);
  glUseProgram(program); glBindVertexArray(vao); glBindFramebuffer(GL_DRAW_FRAMEBUFFER,fbo);
  glViewport(viewport[0],viewport[1],viewport[2],viewport[3]);
  glColorMask(mask[0],mask[1],mask[2],mask[3]);
  for(int i=0;i<8;++i) if(enabled[i]) glEnable(caps[i]);
  if(feedback && !paused) glResumeTransformFeedback();
  mutexUnlock(&graphics_lock);
  return ok;
}
#endif
