#pragma once

typedef struct {
  int fd, pending;
  char path[256];
} DurakProbeClose;

void durak_probe_opened(int fd, const char *path, const char *root);
void durak_probe_unlink_failed(const char *path, int error, unsigned native_result);
void durak_probe_before_close(int fd, DurakProbeClose *state);
void durak_probe_after_close(const DurakProbeClose *state, int result, int error,
                            unsigned native_result);
int durak_probe_cleanup_old(const char *root);
