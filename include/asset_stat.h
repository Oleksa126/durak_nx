#pragma once
#include <sys/stat.h>
/* Cache successful regular-file metadata only inside the immutable asset tree.
 * Directories, saves, missing files and errors always use the host filesystem. */
int durak_asset_stat(const char *path,const char *root,struct stat *out);
