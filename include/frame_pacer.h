#ifndef DURAK_FRAME_PACER_H
#define DURAK_FRAME_PACER_H

#include <stdint.h>
#include <stddef.h>

/* RVAs in Durak libunity.so (Build-ID bcc661ea2046416d) */
#define UNITY_ON_VSYNC_RVA       0x00e724a0
#define UNITY_VSYNC_COUNTER_RVA  0x01557220
#define UNITY_VSYNC_TS_CUR_RVA   0x01557228
#define UNITY_VSYNC_TS_PREV_RVA  0x01557230
#define UNITY_VSYNC_MUTEX_RVA    0x015571c4
#define UNITY_VSYNC_COND_RVA     0x015571ec

typedef void (*fn_unity_on_vsync)(uint64_t timestamp_nanos);

int      durak_frame_pacer_init(void *libunity_virtbase);
int      durak_frame_pacer_start(void);
void     durak_frame_pacer_stop(void);
void     durak_frame_pacer_pulse(void);
uint64_t durak_frame_pacer_get_counter(void);
void     durak_frame_pacer_set_handler_for_test(fn_unity_on_vsync handler,
                                                volatile uint64_t *counter,
                                                volatile uint64_t *ts_cur,
                                                volatile uint64_t *ts_prev);

#endif /* DURAK_FRAME_PACER_H */
