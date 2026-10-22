#pragma once
#include <switch.h>
/* Main-thread startup only, before guest threads. A distinct VI producer keeps
 * the loading framebuffer independent of Unity's default EGL window. */
NWindow *loading_layer_begin(void);
void loading_layer_end(void);
void loading_layer_report(void);
