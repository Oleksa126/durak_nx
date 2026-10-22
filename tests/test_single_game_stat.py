"""Compile the production metadata lookup against fault-injected Horizon calls.

Run on Linux with: python3 -m unittest tests.test_single_game_stat
No SD files or user databases are modified.
"""
import pathlib
import subprocess
import tempfile
import unittest


class DirectoryStatTest(unittest.TestCase):
    def test_metadata_and_failures(self):
        source = pathlib.Path('source/libc_shim.c').read_text()
        start = source.index('static int stat_directory_entry(')
        helper = source[start:source.index('\nint stat_fake(', start)]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
typedef unsigned Result;
typedef long long s64;
typedef struct { int dummy; } FsFileSystem;
typedef struct { int dummy; } FsDir;
typedef struct { char name[256]; s64 file_size; } FsDirectoryEntry;
#define FS_MAX_PATH 768
#define FsDirOpenMode_ReadFiles 2
#define R_FAILED(x) ((x) != 0)
#define R_SUCCEEDED(x) ((x) == 0)
static int scenario, reads, closes;
static char parent[768];
static FsFileSystem fs;
static void durak_log_printf(const char *fmt, ...) { errno = EDOM; }
static int fsdevTranslatePath(const char *p, FsFileSystem **f, char *out) {
  if (scenario == 4) { errno = ENODEV; return -1; }
  *f = &fs; strcpy(out, p + 5); return 0;
}
static Result fsFsOpenDirectory(FsFileSystem *f, const char *p, int mode, FsDir *d) {
  assert(f == &fs && mode == 2); strcpy(parent, p);
  return scenario == 1 ? 0xe02 : 0;
}
static Result fsDirRead(FsDir *d, s64 *count, int n, FsDirectoryEntry *e) {
  assert(n == 1);
  if (scenario == 2) return 0xe02;
  *count = reads++ < 2;
  strcpy(e->name, reads == 1 ? "unrelated.bytes" : "metrics.bytes");
  if (scenario == 3) strcpy(e->name, "missing.bytes");
  e->file_size = 24576; return 0;
}
static void fsDirClose(FsDir *d) { closes++; errno = EDOM; }
'''
        main = r'''
int main(void) {
  struct stat st;
  assert(stat_directory_entry("sdmc:/switch/durak_nx/metrics.bytes", &st) == 0);
  assert(st.st_size == 24576 && S_ISREG(st.st_mode) && st.st_nlink == 1);
  assert(!strcmp(parent, "/switch/durak_nx") && closes == 1);
  for (scenario = 1; scenario <= 4; scenario++) {
    reads = closes = 0;
    assert(stat_directory_entry("sdmc:/metrics.bytes", &st) == -1);
    assert(errno == (scenario == 3 ? ENOENT : scenario == 4 ? ENODEV : EIO));
    assert(closes == (scenario == 2 || scenario == 3));
    if (scenario != 4) assert(!strcmp(parent, "/"));
  }
  scenario = reads = closes = 0;
  assert(stat_directory_entry("sdmc:/", &st) == -1 && errno == EINVAL);
  assert(closes == 0);
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            c = pathlib.Path(tmp) / 'stat_test.c'
            exe = pathlib.Path(tmp) / 'stat_test'
            c.write_text(harness + helper + main)
            subprocess.run(['cc', '-Wall', '-Wextra', '-Wno-unused-parameter',
                            str(c), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)
