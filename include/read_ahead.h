#pragma once
#include <stddef.h>
#include <stdint.h>
/* Only immutable read-only assets may be attached. Native pread remains
 * positional; sequential read/lseek must both use these adapters. */
int durak_ra_asset_path(const char *path,const char *root);
int durak_ra_attach(int fd,long size);
/* Retain small assets and the bounded packaged data.unity3d archive across independent handles.
 * The caller has verified read-only access and an eligible absolute path. */
int durak_ra_attach_path(int fd,long size,const char *path);
void durak_ra_detach(int fd);
/* Synchronize a buffered cursor and release the adapter before native dup(),
 * whose handles share one kernel cursor. Failure leaves the adapter attached. */
int durak_ra_before_dup(int fd);
int durak_ra_read(int fd,void *buf,size_t count,long *result);
int durak_ra_pread(int fd,void *buf,size_t count,long offset,long *result);
int durak_ra_seek(int fd,long offset,int whence,long *result);
#ifndef __SWITCH__
/* Archive-specific all-thread totals; RAM serves can include a just-filled read.
 * fill_bytes is actual native I/O, never inferred from requested bytes. */
typedef struct {
  uint64_t fills,fill_bytes,serves,served_bytes,reopens,evictions,resident_bytes;
} DurakArchiveCacheStats;
void durak_ra_archive_stats(DurakArchiveCacheStats *out);
#endif
