# Early host loading screen

Historical: the current implementation is documented in continuous_loading.md.
It keeps one shared image across CPU/EGL rendering instead of the separate
publisher splash and bootstrap canvases described below.

**Retired after hardware feedback:** the user observed three sequential loaders.
The host framebuffer implementation is removed and bootstrap loading canvases
are no longer added by the asset builder. The original Unity splash is retained
as the sole loading presentation. Text below records the earlier implementation.

Log 21 confirms the logger optimization: constructors/JNI complete at 2832 ms
(log 20: 8358 ms), first nativeRender return at 4154 ms (log 20: 9941 ms).
These measure from main, not from title selection, and cannot prove visible logo.

New path: after logger initialization, before ELF load, queue one software
libnx framebuffer (1280x720 RGBA, double buffering). Brown backdrop, original
Unity splash sprite `globalgamemanagers.assets #1258 appscraft_new`, and static
LOADING... text. No fake progress percentage, animation thread, SDL video or
host EGL context. `scripts/extract_boot_logo.py` reproduces the embedded 5777-byte
zlib asset; decoded sprite is 314x60 RGBA, displayed at 2x scale without changing
its aspect ratio. No new SD file is needed.

The framebuffer is closed before guest NWindow geometry changes and guarded
again immediately before eglCreateWindowSurface. Close is serialized by a
mutex and idempotent. Fatal console also closes the framebuffer first.
Failed framebuffer create/linearization logs the real Result and falls back
to the normal startup path; linearization failure closes allocated resources.
Unity retains its own EGL context, config and singleton surface behavior.

New log markers (`BOOT DISPLAY`, elapsed from main):

- Host loading frame queued.
- Host framebuffer closed before Unity window acquisition.
- First Unity eglSwapBuffers accepted (only after EGL_TRUE, once across threads).

Queued/accepted means submitted successfully; neither proves compositor scanout
or that Unity's buffer contains its logo. Time before main remains outside the
measurement. A gap during framebuffer disconnect -> Unity surface startup may
still occur and requires hardware validation; no seamless handoff claim is made.

Host mock tests exercise create failure, linearization cleanup, padded row
stride without overwrite, single queue and idempotent close, and one-time first
Unity present logging. They render the actual embedded sprite into a PPM for
visual inspection. NRO build and existing native/Python tests must also pass.

Deploy only `/switch/durak_nx/durak_nx.nro`; keep existing asset bundle.
Hardware gate: early loading image visible, then Unity logo/menu with correct
geometry in handheld/docked modes, audio and input working; check markers in log.
