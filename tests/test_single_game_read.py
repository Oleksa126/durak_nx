"""Exercise the real read shim with Horizon-style range errors and I/O faults."""
import pathlib
import subprocess
import tempfile
import unittest


class ReadEOFTest(unittest.TestCase):
    def test_eof_and_errors(self):
        source = pathlib.Path('source/libc_shim.c').read_text()
        start = source.index('long read_fake(')
        function = source[start:source.index('\nlong write_fake(', start)]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
typedef unsigned Result;
struct RaCache { int unused; };
static long position, file_size;
static int read_calls, fault, metadata_fault, seek_fault, logs;
static int fakefd_is_fake(int fd) { (void)fd; return 0; }
static long fakefd_read(int fd, void *p, size_t n) { return -1; }
static struct RaCache *ra_find(int fd) { return NULL; }
static long ra_read(struct RaCache *c, int fd, void *p, size_t n) { return -1; }
static Result fsdevGetLastResult(void) { return 0xBAD002; }
static void durak_log_printf(const char *fmt, ...) { logs++; errno = EDOM; }
static void debugPrintf(const char *fmt, ...) { errno = EDOM; }
static void watch_dump(const char *s, int fd, long n, long a, void *p, long r) {}
static long test_seek(int fd, long p, int w) {
  assert(w == SEEK_CUR && p == 0);
  if (seek_fault) { errno = ESPIPE; return -1; }
  return position;
}
static int test_stat(int fd, struct stat *s) {
  if (metadata_fault) { errno = EBADF; return -1; }
  memset(s, 0, sizeof(*s)); s->st_size = file_size;
  s->st_mode = S_IFREG; return 0;
}
static long test_read(int fd, void *p, size_t n) {
  read_calls++;
  if (fault == 3) { errno = EBADF; return -1; }
  if (fault == 1 || (fault == 2 && read_calls == 2) || position > file_size) {
    errno = EIO; return -1;
  }
  if ((long)n > file_size - position) n = file_size - position;
  if (fault == 2 && n > 2) n = 2;
  memset(p, 0x5a, n); position += n; return n;
}
#define read test_read
#define lseek test_seek
#define fstat test_stat
'''
        main = r'''
static void reset(long p) {
  position = p; file_size = 512;
  read_calls = fault = metadata_fault = seek_fault = logs = 0;
}
int main(void) {
  char data[8];
  /* The SQLite next-journal-header probe: beyond EOF is a short read,
   * while real in-range EIO must remain an error. */
  reset(4096);
  memset(data, 0x55, sizeof(data));
  assert(read_fake(11, data, 8) == 0 && position == 4096 && logs == 1);
  assert(data[0] == 0x55 && data[7] == 0x55);
  reset(0); fault = 1;
  assert(read_fake(11, data, 8) == -1 && errno == EIO && logs == 1);
  reset(4096); fault = 3;
  assert(read_fake(11, data, 8) == -1 && errno == EBADF);
  reset(4096); metadata_fault = 1;
  assert(read_fake(11, data, 8) == -1 && errno == EIO);
  reset(4096); seek_fault = 1;
  assert(read_fake(11, data, 8) == -1 && errno == EIO);
  reset(510);
  assert(read_fake(11, data, 8) == 2 && position == 512);
  reset(512);
  assert(read_fake(11, data, 8) == 0 && logs == 0);
  reset(0); fault = 2;
  assert(read_fake(11, data, 8) == 2 && errno == EIO && logs == 1);
  reset(0);
  assert(read_fake(11, data, 8) == 8 && data[0] == 0x5a && data[7] == 0x5a);
  reset(0);
  assert(read_fake(11, data, 0) == 0 && read_calls == 0);
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            c = pathlib.Path(tmp) / 'read_test.c'
            exe = pathlib.Path(tmp) / 'read_test'
            c.write_text(harness + function + main)
            subprocess.run(['cc', '-Wall', '-Wextra', '-Wno-unused-parameter',
                            str(c), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)
