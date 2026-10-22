# Independent loading layer — 2026-10-06

Hardware/user rejected the frame-driven pulse: it animates early, then freezes
while nativeRender takes seconds. Changing an EGL uniform on Unity swaps cannot
produce animation during intervals with no swaps. No further startup speed or
forwarder work is included in this change.

## Current correction: log (27), keep the proven default-window image — 2026-10-07

25c4f0a still shows black on hardware. Both visibility commands return zero,
layer 506/producer 1 is created, 139 CPU frames are queued with maximum gap
65 ms, menu arrives at 7890 ms. This disproves visibility requests alone as a
sufficient fix. The compositor/ownership/opacity cause remains unconfirmed.

A confirmed regression in the host is that layer initialization success bypasses
all three default-window presentation paths: early CPU framebuffer, first EGL
MakeCurrent and the actual GL draw at subsequent Unity swaps. Thus a layer that
queues successfully but is not displayed leaves the proven window empty. Remove
that coupling. Queue the same logo on the default window first; retain its CPU
buffer until EGL acquisition. The private worker uses a distinct NWindow and
continues after only the default CPU buffer is closed. If private framebuffer
setup fails, move the existing default framebuffer ownership into the worker
instead of discarding the already queued picture. At every startup default-window
present the existing GLES renderer draws the same art/pulse regardless of private
layer success. No additional artwork, text, stock splash or guest patch is added.

Graphics operations use their own mutex. Driver compilation/uploads/drawing do
not hold the CPU worker lock. Shutdown closes both CPU buffers, joins the worker,
then locks the graphics mutex before freeing the immutable shared image. EGL
context cleanup uses that graphics mutex too. No CPU/EGL producer is shared
concurrently: the default CPU connection is released before Mesa's window setup.

For the private layer, align creation ownership with the linked libtesla Renderer
reference: manager-owned ARUID 0, rather than an extra application-owned layer
created outside AM. Explicitly request alpha 1 using system command 2209 (f32
at byte 0, zero padding at 4, owned u64 ID at 8). Read back the applied Z using
system command 2204 (u64 ID input, s64 output), require a positive requested Z and
exact readback match. Only the owned layer changes; no applet focus, display-wide
visibility/alpha, global content state or HOME setting changes. This configuration
is a source-backed candidate for fixing independent scanout; hardware log (27)
does not prove the ownership or alpha cause. Exact Results and requested/read-back
values remain file-only, including failure cleanup. Default-window presentation
does not depend on this candidate working.

Regression coverage includes default and private framebuffer creation/linear
failures separately, transferring fallback ownership without duplicate close,
default CPU close before EGL while the real pthread worker advances, and menu
release. A second native target compiles the actual GLES boot_screen.c drawing
body against the pinned SDK EGL/GLES headers and a host driver boundary. It
requires a real draw when independent=1, validates texture upload/layout/uniforms,
blocks glDrawArrays for 250 ms and requires the CPU worker to advance meanwhile.
Layer tests check manager ownership, alpha wire bytes, Z readback mismatch, and
all 15 setup failure paths. Visible smooth scanout still needs Switch validation.

The sections below document earlier attempts; the current correction supersedes
their suppression of default-window CPU/EGL drawing when independent=1.

## Hardware correction: log (25)

Build 3df3fe8 did not create the independent layer. Its report is
stage=viOpenDefaultDisplay Result=0x1272, independent=0. The early framebuffer
disconnects at 1629 ms and the frame-driven EGL fallback runs until the 7971 ms
menu handoff. The animation thread started successfully; there are no independent
pulse heartbeats. This is a layer-initialization failure, not evidence that the
independent worker stopped rendering.

libnx already opens Default in __nx_win_init before main. The loader incorrectly
called OpenDisplay again on that same global VI session. Capture the first
successful SDK viOpenDisplay output using GNU --wrap=viOpenDisplay, and borrow
its exact ID/name instead. No second display open, guessed display ID, separate
VI service replacement, or close of the SDK-owned display. Layer/window resources
remain separately owned and released as before. Capture preserves real Result
and errno and does no logging/service calls/allocation before main. Failed or
non-Default opens cannot publish a snapshot.

Regression gates: a second Default open is modeled returning the observed
0x1272; the layer factory must never call it or close the borrowed display.
Native capture tests cover real errors, dynamic nonzero ID and owner isolation.
A linked ARM64 ELF test verifies __nx_win_init calls __wrap_viOpenDisplay and
that the wrapper calls the original viOpenDisplay. Hardware layer creation and
continuous scanout still require validation after this correction.

## Hardware correction: log (26), missing visible logo

03f5ceb successfully creates a distinct layer (display 480, owned layer 482,
producer 1 versus default producer 0). Both framebuffer calls and thread startup
succeed. Four heartbeats and the final count show 146 queued CPU frames, maximum
gap 97 ms, until the menu at 8314 ms. The user reports a black screen throughout.
This rules out the earlier creation failure and a seconds-long worker stall;
successful queueing does not prove that the compositor displays this layer.

The factory did not issue either per-layer visibility command. Unlike the
SDK default layer, this additional managed layer is created directly through VI,
outside AM's CreateManagedDisplayLayer path. It must not assume the default
window's visibility state. Explicitly request visibility on the owned layer only:
manager command 6002 and system command 2207. These are separate service entry
points. Both real Results are required before publishing the private window;
failure releases it and retains the existing same-image fallback. No display-wide
content visibility, other layer, global alpha, applet focus or HOME state is changed.

The [SwIPC interface reconstruction](https://reswitched.github.io/SwIPC/ifaces.html#nn::visrv::sf::IManagerDisplayService)
specifies the on-wire inputs as (b8, u64) for both calls: boolean at byte 0,
zero padding 1..7, owned ID at byte 8, total 16 bytes. Static assertions and
native byte-level tests cover this layout and service/command pairing. The
regression model begins with a created but hidden layer and refuses to publish
its window unless both requests succeed. Both visibility failures retain their
real Result and stage and exercise complete cleanup. A file-only report retains
the two Results and visibility_enabled after startup, including partial failure.

Missing explicit visibility is a confirmed code omission; its sufficiency to
correct hardware scanout is still a hardware gate. Host mocks cannot establish
visible output, and no claim of continuous visible animation is made from them.
Verification: the new regression rejects the pre-fix factory at window publication
because visibility was never enabled. Updated factory passes, including both
visibility error injections. Pinned NRO/native build, 13 Python ELF tests, 10
SQLite tests and all 29 package files pass; the game asset bundle is unchanged.

The host creates its own managed VI layer, distinct IGraphicBufferProducer
and NWindow before starting guest threads. The existing CPU framebuffer worker
keeps this layer above the game's default EGL window at 20 Hz. Unity acquires
its original default window normally; it does not share loader buffer slots,
context, texture or rendering ownership. CPU FastLoad is still restored at EGL
acquisition. No new guest ABI, RVA or instruction patch is involved.

The loading buffer stays active across EGL acquisition. The same original logo
pulse/background is opaque and covers all Unity startup frames. The existing
packaged m_ShowUnitySplashScreen=false is verified during packaging; no new
loading canvas is added and no initialization controller is disabled. Removing
the private layer reveals the already rendered menu, after active MainMenu
detection and two successful default-window presents. Pbuffer/auxiliary swaps
do not count. First MakeCurrent no longer emits an extra loader swap in this
mode. Shutdown/fatal cleanup forces release, joins the worker, then frees art.

Layer setup uses libnx 4.12.0 public APIs and one proven VI manager IPC command:
AddToLayerStack (6000), 16-byte request with stack u32 at 0, padding zero at 4,
owned layer ID u64 at 8. Static assertions and native wire tests cover the ABI.
Only Default and LCD stacks are changed, and only for the new owned layer.
Default VI logical size 1920x1080 with FitToLayer scales the 1280x720 framebuffer
in handheld/docked modes. The initial default producer is explicitly rejected
as a loading target. The libnx global layer override is restored immediately
after opening the owned ID, before any guest threads exist.

Evidence:

- [Pinned libnx viCreateLayer/managed layer lifecycle](https://raw.githubusercontent.com/switchbrew/libnx/v4.12.0/nx/source/services/vi.c).
- [Pinned default NWindow initialization](https://raw.githubusercontent.com/switchbrew/libnx/v4.12.0/nx/source/display/default_window.c).
- [libtesla VI stack request and renderer lifecycle](https://raw.githubusercontent.com/WerWolv/libtesla/master/include/tesla.hpp), helper viAddToLayerStack and Renderer::init.
- [VI display services, logical display size and command definitions](https://switchbrew.org/wiki/Display_services).

Failure at any layer setup stage preserves its Result and stage for the report
after logger initialization, releases partial resources, and retains the same
artwork through the existing CPU/EGL fallback. Thread startup failure likewise
releases the private framebuffer at EGL acquisition. The independent path needs
the VI manager session; a fallback does not claim continuous animation.

File-only evidence: [LOADING LAYER] stage=ready Result=0, distinct owned/default
producer IDs, [LOADING] independent=1 default_window_blocked=0, periodic pulse
heartbeats, and CPU frame count/max queue gap when the layer is removed. These
describe successful submissions; compositor scanout still requires hardware.

Validation includes all 13 current layer-stage failures, manager unavailability, missing snapshot, producer
alias rejection, restored override/idempotent cleanup, native pixel and padding
checks, and a real pthread test: 300 ms with no main/Unity presents while loader
frames advance, then readiness/two presents stop updates and shutdown joins the
worker before freeing memory. Existing build/target/input/SQLite gates remain.

Status: NEEDS_HARDWARE_TEST. Verify continuous pulse through Unity initialization,
one visible screen, correct menu reveal, and HOME/resume and docked/handheld
behavior. Manager availability and VI layer visibility/order are new hardware
boundaries; native mocks cannot establish them.
