/* unity_input_hook.h -- Fail-closed Switch touchscreen & pointer hooks for Durak 25.0
 *
 * Target: Android ARM64 ru.appscraft.durak v25.0 (Unity 6 / IL2CPP)
 * libil2cpp.so Build-ID: d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0
 */
#ifndef UNITY_INPUT_HOOK_H
#define UNITY_INPUT_HOOK_H

#include <stdint.h>
#include "so_util.h"

/* Durak 25.0 libil2cpp.so verified RVAs (Build-ID d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0) */
#define DURAK_RVA_get_touchCount      0x184408c
#define DURAK_RVA_GetTouch            0x1843998
#define DURAK_RVA_get_mousePosition   0x1843bb4
#define DURAK_RVA_GetMouseButton      0x18438e4
#define DURAK_RVA_GetMouseButtonDown  0x1843920
#define DURAK_RVA_GetMouseButtonUp    0x184395c
#define DURAK_RVA_get_touchSupported  0x1844020
#define DURAK_RVA_get_mousePresent    0x1843fb4

/* Install fail-closed input hooks into libil2cpp.so text */
int nx_install_input_hooks(uintptr_t il2cpp_base);
/* Resolve exported reflection APIs; dispatch Plus from a Unity input callback. */
int nx_input_menu_init(so_module *module);
void nx_input_menu_request(void);

/* Push touch state (Unity screen coordinates, bottom-left origin) */
void nx_input_hook_update(int active, float ux, float uy, float raw_x, float raw_y);

/* Query current hook state (for diagnostic tests) */
int   nx_input_hook_get_count(void);
int   nx_input_hook_get_btn(void);
int   nx_input_hook_get_btn_down(void);
int   nx_input_hook_get_btn_up(void);
int   nx_input_hook_get_phase(void);
void  nx_input_hook_get_pos(float *x, float *y);

#endif /* UNITY_INPUT_HOOK_H */
