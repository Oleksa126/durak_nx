#pragma once
#include <stdint.h>
typedef enum {
  BOOT_RENDER, BOOT_ASSET_FILL, BOOT_SQL_OPEN, BOOT_SQL_PREPARE,
  BOOT_SQL_STEP, BOOT_INVENTORY, BOOT_SD_COMMIT, BOOT_GUEST_FSYNC,
  BOOT_SQL_RESOLVE, BOOT_HOST_STAT, BOOT_ASSET_REUSE,
  BOOT_METRIC_COUNT
} DurakBootMetric;
/* Monotonic nanoseconds, not CPU time. Zero means profiling is inactive.
 * All helpers preserve errno. Summary/phase output goes only to the log file. */
void durak_boot_measure_begin(void);
uint64_t durak_boot_measure_now(void);
void durak_boot_measure_span(DurakBootMetric metric, uint64_t begin, uint64_t bytes);
void durak_boot_measure_phase(const char *phase, const char *detail, uint64_t begin);
void durak_boot_measure_finish(const char *reason);
