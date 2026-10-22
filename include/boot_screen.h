#ifndef DURAK_BOOT_SCREEN_H
#define DURAK_BOOT_SCREEN_H
#include <stdint.h>
void boot_screen_begin(uint64_t tick);
void boot_screen_report(void);
void boot_screen_disconnect(void);
void boot_screen_shutdown(void);
int boot_screen_waiting(void);
int boot_screen_framebuffer_active(void);
int boot_screen_blocks_default_window(void);
int boot_screen_independent(void);
void boot_screen_menu_ready(void);
/* Called only on the current EGL rendering thread. */
int boot_screen_draw(int width, int height);
void boot_screen_presented(void);
void boot_screen_context_destroyed(void *context);
#endif
