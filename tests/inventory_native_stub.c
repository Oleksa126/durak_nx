#include <stdarg.h>
#include <stdio.h>
void durak_log_printf(const char *format, ...) {
  va_list args; va_start(args,format); vfprintf(stderr,format,args); va_end(args);
}
int durak_log_flush(void) { return 0; }
