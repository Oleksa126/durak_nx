#pragma once
#include <stdint.h>
#include <math.h>
#define LOADING_WIDTH 1280
#define LOADING_HEIGHT 720
#define LOADING_LOGO_SIZE 400
#define LOADING_LOGO_X 440
#define LOADING_LOGO_Y 160
#define LOADING_CENTER_X 640
#define LOADING_CENTER_Y 360
#define LOADING_FRAME_MS 50
#define LOADING_PERIOD_MS 2000
/* gtasa_nx draw_main: cosine pulse, two seconds, scale 1.00 -> 1.08 -> 1.00.
 * Quantized to the CPU refresh cadence so both display paths share a phase. */
static inline unsigned durak_loading_phase(uint64_t ms) {
  return (unsigned)(ms / LOADING_FRAME_MS % (LOADING_PERIOD_MS / LOADING_FRAME_MS));
}
static inline float durak_loading_scale(unsigned phase) {
  return 1.0f + 0.04f * (1.0f - cosf(phase *
      (6.28318530718f / (LOADING_PERIOD_MS / LOADING_FRAME_MS))));
}
