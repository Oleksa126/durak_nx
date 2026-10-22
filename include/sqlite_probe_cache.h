#pragma once
#include <stdint.h>
#include <sys/stat.h>
typedef struct { int cached,observed_errno;unsigned observed_result; } DurakProbeTrace;
typedef struct { uint64_t hits,probes,probe_ns; } DurakProbeStats;
/* Frame-scoped absence only for the three known DBs' journal/WAL/SHM paths.
 * All namespace mutations must be bracketed, including failed operations. */
int durak_sqlite_probe_path(const char *path,const char *root);
int durak_sqlite_probe_stat(const char *path,const char *root,struct stat *out,
    DurakProbeTrace *trace,int (*probe)(const char *,struct stat *,unsigned *));
void durak_sqlite_probe_frame_begin(void);
void durak_sqlite_probe_frame_end(void);
void durak_sqlite_probe_mutation_begin(const char *first,const char *second);
void durak_sqlite_probe_mutation_end(void);
void durak_sqlite_probe_stats(DurakProbeStats *out);
