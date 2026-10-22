# One image until the main menu

Current 2026-10-06: the CPU worker owns a separate VI layer that stays visible
while Unity renders behind it. It no longer disconnects at EGL acquisition.
See independent_loading.md. The CPU-to-EGL image handoff described below is
retained only as a fallback when independent-layer setup fails.

## Log 22 correction

Hardware rejected the initial implementation: custom image, original Unity
splash, then black. CPU framebuffer queued at 32 ms and disconnected at 3606 ms;
active MainMenu was detected at 14252 ms. No early menu dismissal occurred.
The overlay's two EGL size queries called raw eglQuerySurface instead of the
existing Switch Mesa wrapper. That wrapper documents Mesa's zero-sized window
queries; boot_screen_draw immediately returns without drawing on a 0×0 extent.
The old “First EGL loading present” marker incorrectly counted raw swaps even
when no loading draw happened, so it could not establish overlay presentation.

The corrected implementation shares nx_egl_query_surface between Unity and
both overlay paths, preserving valid dimensions and applying the existing
screen_width/height fallback for zero dimensions. eglGetProcAddress also routes
registered EGL names through the same shim table, so dynamically acquired
MakeCurrent cannot bypass the early loading present. GLES resolution stays
unchanged. Loading presents count only when overlay drawing was attempted and
the swap succeeded. First overlay context/viewport/program/texture is logged;
shader errors and missing current context remain explicit.
Native regression tests simulate Mesa 0×0, valid extents, unrelated query errors,
and dynamic EGL lookup. The visible fix still needs a Switch run.

User requested the black periods before and after the Unity splash covered by
one loading screen. The current style (2026-10-06) follows gtasa_nx: supplied
jester artwork centered on a flat (10,10,15) background, cosine scale pulse
1.00 -> 1.08 -> 1.00 over two seconds. No loading text, line or dots remain.
Layout and pulse timing are shared in include/loading_style.h. No runtime font
or additional SD file is needed. Details: loading_activity.md.

`scripts/build_loading_art.py` converts assets/loading_logo.png into the shared
RGBA image in data/loading_screen.bin (zlib). The same decoded bytes are scaled
into the early libnx framebuffer and uploaded once into each Unity EGL context.
Rebuild with Pillow: python scripts/build_loading_art.py assets/loading_logo.png
data/loading_screen.bin tools/cache/loading-logo-preview.png. Optional
--animation-preview tools/cache/loading-logo-preview.gif creates an animated
layout preview. Build does not regenerate the image automatically.

Queue the early framebuffer at the start of main, before socket setup and ELF
loading. Defer NWindow geometry updates while its buffers remain registered.
Disconnect only immediately before the actual EGL window-surface creation, then
apply the exact pending Unity dimensions. No extra EGL context or swapchain.
Present the shared image immediately on the first successful window MakeCurrent;
overlay it before each Unity window swap so splash and bootstrap black clears
remain covered. Guard against pbuffer/auxiliary surfaces. Context teardown drops
only that context's loading resource record.

Readiness: on existing managed Input callbacks, use verified exported IL2CPP
reflection APIs to find active `MainMenu` (original level3 root). Do not call Unity
scene APIs from HID or GL threads. Clear the cover only after readiness and two
successful window swaps. No startup timeout, guessed framebuffer colors, new
managed offsets, executable patches, or database changes.

The GL overlay saves/restores draw framebuffer and its default draw-buffer
selection, viewport, program, VAO, color mask, active texture, unit-0 texture and
sampler, unpack buffer/row state, eight enable flags, and transform-feedback pause
state. Use GLES3 immutable RGBA texture storage and matching shader interfaces.
CPU lifecycle and state transitions are mutex/atomic protected. Fatal console
and process shutdown release the CPU display ownership before console rendering.

Diagnostics: `[LOADING] Early image` retains actual decode/Framebuffer Results;
framebuffer disconnect, first EGL present, active MainMenu, and menu handoff
include milliseconds from main. Shader compiler/linker failures and texture
allocation GL codes are logged. There is no claim of reducing initialization
time. Display work before main and the CPU-to-EGL surface handoff still require
hardware timing; accepted swaps do not prove compositor scanout.

Host tests cover padded framebuffer stride, failed creation/linearization/decode
cleanup, idempotent disconnect/shutdown, waiting across 200 pre-menu presents,
and readiness-gated release. Decoder and libnx calls are mocked; actual artwork
is independently decoded and visually inspected. GLES state restoration and
continuous visible presentation require Switch validation.

Libnx ownership reference: [NWindow/default initialization](https://github.com/switchbrew/libnx/blob/master/nx/source/display/default_window.c).
Deploy only durak_nx.nro to `/switch/durak_nx/durak_nx.nro`. Existing modified
data.unity3d remains in place. Gate: launch in handheld/docked mode, see one image
and centered pulsing artwork without text, then a complete interactive main menu; confirm
audio, cursor, Single Game and Plus still work. If a gap persists, the LOADING
timestamps distinguish pre-main, framebuffer/EGL handoff and menu release.
