# Loading activity

Updated 2026-10-06 at the user's request: match the central cover pulse in
gtasa_nx/source/settings_menu.c (draw_main), without its launcher/options UI.
The original game art is 400x400, centered on a plain dark (10,10,15) background.
No Loading text, dots, line, countdown, extra screen or progress percentage.
Cosine scaling follows the reference: 1.00 -> 1.08 -> 1.00 over two seconds.
The formula and layout live in include/loading_style.h, which the asset builder
also reads. The original source logo is unchanged.

The libnx worker refreshes the scaled picture every 50 ms in its own VI layer,
including while Unity starts EGL or blocks its main thread. Details and source
evidence: independent_loading.md.
It copies the base image and resamples only the expanded logo rectangle; padded
framebuffer stride is preserved. The framebuffer mutex prevents a present after
disconnection. Shutdown joins the worker before freeing the artwork.
Unity renders behind this opaque layer into its original default window. There
is no additional EGL context or surface. MainMenu readiness and two successful
Unity presents remove the layer. The original frame-driven EGL path remains
only as a same-image fallback if VI manager/layer or thread creation fails, with
the actual setup stage/Result logged; fallback animation can still pause.

Native mocks verify the pulse endpoints and transformed pixels, expansion edges,
constant background, padded row stride, disconnection and worker cleanup,
including failed thread creation and start. A real pthread test verifies updates
while the main thread makes no presents. Target compilation validates the GLES
API calls; shader execution and the visual transition still require Switch testing.
The runtime reports animation thread Result codes on failure and logs successful start.

Copy the updated `build/switch/` to the SD root, merging folders. Confirm that
the logo pulses independently until the menu appears, with no new black
screen or second loader, and that MainMenu still appears normally. The accepted
v0.1.0 tag remains unchanged; this update is a subsequent commit.
