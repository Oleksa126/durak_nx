/* error.c -- error handler
 *
 * Copyright (C) 2021 fgsfds, Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#ifdef __SWITCH__
#include <switch.h>
#endif

#include "util.h"
#include "error.h"
#ifdef __SWITCH__
#include "boot_screen.h"
#endif

void fatal_error(const char *fmt, ...) {
  char msg[1024];
  va_list list;
  va_start(list, fmt);
  vsnprintf(msg, sizeof(msg), fmt, list);
  va_end(list);

  durak_log_printf("\n[FATAL ERROR] %s\n", msg);
  durak_log_flush_critical();

#ifdef __SWITCH__
  boot_screen_shutdown();
  PadState pad;
  padConfigureInput(1, HidNpadStyleSet_NpadStandard);
  padInitializeDefault(&pad);

  consoleInit(NULL);
  printf("\x1b[1;31m\n\n[FATAL ERROR]\n%s\x1b[0m\n", msg);
  printf("\n\nPress A to exit.\n");
  consoleUpdate(NULL);

  while (appletMainLoop()) {
    padUpdate(&pad);
    const u64 keys = padGetButtonsDown(&pad);
    if (keys & HidNpadButton_A) break;
  }

  consoleExit(NULL);
#else
  fprintf(stderr, "\n[FATAL ERROR] %s\n", msg);
#endif

  durak_log_close();
  exit(1);
}
