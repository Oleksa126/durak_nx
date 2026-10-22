/* Host driver boundary for the real boot_screen.c EGL drawing path. */
#define _POSIX_C_SOURCE 200809L
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
static atomic_uint draws;
unsigned loading_gl_draws(void) { return atomic_load(&draws); }
EGLContext eglGetCurrentContext(void) { return (EGLContext)(uintptr_t)1; }
GLuint glCreateShader(GLenum type) { assert(type==GL_VERTEX_SHADER || type==GL_FRAGMENT_SHADER);return 1; }
void glShaderSource(GLuint s,GLsizei n,const GLchar *const *text,const GLint *length) { (void)s;(void)length;assert(n==1 && text && *text); }
void glCompileShader(GLuint s) { (void)s; }
void glGetShaderiv(GLuint s,GLenum p,GLint *out) { (void)s;assert(p==GL_COMPILE_STATUS);*out=1; }
void glGetShaderInfoLog(GLuint s,GLsizei n,GLsizei *length,GLchar *out) { (void)s;if(length) *length=0;if(n) *out=0; }
void glDeleteShader(GLuint s) { (void)s; }
GLuint glCreateProgram(void) { return 2; }
void glAttachShader(GLuint p,GLuint s) { (void)p;(void)s; }
void glLinkProgram(GLuint p) { (void)p; }
void glGetProgramiv(GLuint p,GLenum name,GLint *out) { (void)p;assert(name==GL_LINK_STATUS);*out=1; }
void glGetProgramInfoLog(GLuint p,GLsizei n,GLsizei *length,GLchar *out) { (void)p;if(length) *length=0;if(n) *out=0; }
void glDeleteProgram(GLuint p) { (void)p; }
void glGenTextures(GLsizei n,GLuint *out) { assert(n==1);*out=3; }
void glDeleteTextures(GLsizei n,const GLuint *out) { (void)n;(void)out; }
void glBindTexture(GLenum target,GLuint texture) { (void)target;(void)texture; }
void glTexParameteri(GLenum target,GLenum name,GLint value) { (void)target;(void)name;(void)value; }
void glGetIntegerv(GLenum name,GLint *out) {
  if(name==GL_VIEWPORT) { const GLint viewport[4]={0,0,1280,720};memcpy(out,viewport,sizeof(viewport)); }
  else *out=name==GL_ACTIVE_TEXTURE ? GL_TEXTURE0 : name==GL_DRAW_BUFFER0 ? GL_BACK : 0;
}
void glGetBooleanv(GLenum name,GLboolean *out) { memset(out,0,name==GL_COLOR_WRITEMASK ? 4 : 1); }
void glBindBuffer(GLenum target,GLuint b) { (void)target;(void)b; }
void glPixelStorei(GLenum name,GLint value) { (void)name;(void)value; }
void glTexStorage2D(GLenum target,GLsizei levels,GLenum format,GLsizei w,GLsizei h) {
  assert(target==GL_TEXTURE_2D && levels==1 && format==GL_RGBA8 && w==1280 && h==720);
}
void glTexSubImage2D(GLenum target,GLint level,GLint x,GLint y,GLsizei w,GLsizei h,GLenum format,GLenum type,const void *data) {
  assert(target==GL_TEXTURE_2D && !level && !x && !y && w==1280 && h==720 && format==GL_RGBA && type==GL_UNSIGNED_BYTE);
  const unsigned char *bytes=data;assert(bytes && bytes[0]==255 && bytes[1280*720*4-1]==255);
}
void glGetTexParameteriv(GLenum target,GLenum name,GLint *out) { assert(target==GL_TEXTURE_2D && name==GL_TEXTURE_IMMUTABLE_FORMAT);*out=1; }
GLenum glGetError(void) { return GL_NO_ERROR; }
void glPauseTransformFeedback(void) {}
void glResumeTransformFeedback(void) {}
void glActiveTexture(GLenum texture) { (void)texture; }
GLboolean glIsEnabled(GLenum cap) { (void)cap;return GL_FALSE; }
void glDisable(GLenum cap) { (void)cap; }
void glEnable(GLenum cap) { (void)cap; }
void glBindFramebuffer(GLenum target,GLuint fb) { (void)target;(void)fb; }
void glDrawBuffers(GLsizei n,const GLenum *buffers) { assert(n==1 && buffers); }
void glViewport(GLint x,GLint y,GLsizei w,GLsizei h) { assert(!x && !y && w==1280 && h==720); }
void glColorMask(GLboolean r,GLboolean g,GLboolean b,GLboolean a) { (void)r;(void)g;(void)b;(void)a; }
void glBindVertexArray(GLuint vao) { (void)vao; }
void glUseProgram(GLuint p) { (void)p; }
void glBindSampler(GLuint unit,GLuint sampler) { (void)unit;(void)sampler; }
GLint glGetUniformLocation(GLuint p,const GLchar *name) { (void)p;assert(name);return 1; }
void glUniform1i(GLint location,GLint value) { (void)location;assert(!value); }
void glUniform1f(GLint location,GLfloat value) { (void)location;assert(value>=1 && value<=1.08f); }
void glUniform4f(GLint location,GLfloat x,GLfloat y,GLfloat w,GLfloat h) { (void)location;assert(x==640 && y==360 && w==200 && h==200); }
void glDrawArrays(GLenum mode,GLint first,GLsizei count) {
  assert(mode==GL_TRIANGLES && !first && count==3);
  atomic_fetch_add(&draws,1);
  /* A blocking graphics driver call must not freeze the CPU pulse worker. */
  struct timespec delay={0,250000000};nanosleep(&delay,NULL);
}
