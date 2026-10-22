/* Count actual logger sync calls with a deterministic monotonic clock. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "util.h"

static long clock_ms = 1000;
static int sync_count;
static int fail_sync;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    ++sync_count;
    clock_ms += 5; /* Simulated SD latency measured by the logger. */
    if(fail_sync) { errno=ENOSPC;return -1; }
    return __real_fsync(fd);
}
int __wrap_clock_gettime(clockid_t clock, struct timespec *now) {
    assert(clock == CLOCK_MONOTONIC);
    now->tv_sec = clock_ms / 1000;
    now->tv_nsec = (clock_ms % 1000) * 1000000;
    return 0;
}

int main(void) {
    const char *path = "tests/test_log_batch.log";
    durak_log_set_file_only(1);
    assert(durak_log_init(path) == 0);
    for (int i = 0; i < 1000; ++i) durak_log_printf("record %d\n", i);
    assert(sync_count == 0); /* No per-message SD syncs. */
    clock_ms += 999;
    durak_log_printf("before interval\n");
    assert(sync_count == 0);
    ++clock_ms;
    durak_log_printf("interval\n");
    assert(sync_count == 1);
    durak_log_printf("checkpoint\n");
    assert(durak_log_flush() == 0);
    assert(sync_count == 1); /* A routine checkpoint only publishes bytes. */
    uint64_t counted, duration;
    durak_log_sync_stats(&counted, &duration);
    assert(counted == 1 && duration == 5);
    FILE *reader = fopen(path, "r");
    assert(reader);
    char line[80], expected[80];
    for (int i = 0; i < 1000; ++i) {
        assert(fgets(line, sizeof(line), reader));
        snprintf(expected, sizeof(expected), "record %d\n", i);
        assert(!strcmp(line, expected));
    }
    assert(fgets(line, sizeof(line), reader) && !strcmp(line, "before interval\n"));
    assert(fgets(line, sizeof(line), reader) && !strcmp(line, "interval\n"));
    assert(fgets(line, sizeof(line), reader) && !strcmp(line, "checkpoint\n"));
    assert(!fgets(line, sizeof(line), reader));
    fclose(reader);
    durak_log_startup_batch(1);
    durak_log_printf("batched checkpoint\n");
    assert(durak_log_flush()==0 && sync_count==1);
    clock_ms+=999;durak_log_printf("batched interval before\n");
    assert(sync_count==1);
    ++clock_ms;durak_log_printf("batched interval reached\n");
    assert(sync_count==2);
    assert(durak_log_flush_critical()==0 && sync_count==3);
    durak_log_startup_batch(0);
    /* Reproduce the actual boot-to-menu policy switch, then repeated input,
     * render and modal-opening checkpoints without restarting the logger. */
    for(int i=0;i<1000;++i) {
      durak_log_printf("runtime checkpoint %d\n",i);
      assert(durak_log_flush()==0);
    }
    assert(sync_count==3);
    clock_ms+=1000;
    assert(durak_log_flush()==0 && sync_count==4);
    fail_sync=1;
    assert(durak_log_flush_critical()==-1 && sync_count==5);
    assert(durak_log_has_error() && durak_log_get_error_count()>0);
    fail_sync=0;
    durak_log_close();
    assert(sync_count == 6);
    remove(path);
    puts("[PASS] Startup and 1000 runtime checkpoints: interval syncs only, bytes published, critical errors reported, close durable");
    return 0;
}
