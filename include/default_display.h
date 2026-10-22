#pragma once
#include <switch.h>
/* Borrow the Default display opened by libnx before main. The caller must not
 * close it. No guessed ID and no second OpenDisplay on the same VI session. */
int durak_default_display_snapshot(ViDisplay *out);
