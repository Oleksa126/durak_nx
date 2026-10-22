# Startup cleanup — 2026-10-02

User reports text diagnostics during launch and a blue screen after the logo.

Confirmed overhead: main initialized a libnx console, repeatedly presented its
frames during constructors/JNI, then waited 50 ms to exit the console before
Unity took NWindow. The logger also fflush/fsynced every message, including
thousands of ordinary asset/JNI/SQLite messages. Log 19 has no stage timestamps,
so it cannot establish total load time or a measured speedup.

Changes:

- Startup never initializes/presents a text console. Main messages go to the
  diagnostic file. Fatal errors still initialize their own visible error screen.
  The 50 ms display handoff pause is removed. Loader validation, constructors,
  JNI lifecycle, asset scan, EGL and frame pacing remain.
- Logger uses a 16 KiB buffer. Ordinary messages synchronize at most once per
  250 ms while messages arrive; explicit durak_log_flush checkpoints still call
  fflush/fsync immediately, including before critical guest calls. Normal close
  also synchronizes. An uncheckpointed tail can be lost on abrupt power loss;
  errors remain tracked and exposed, including delayed buffered write failures.
- Add boot-relative times for modules loaded, constructors/JNI complete, and
  first nativeRender return. A render return does not prove the menu is visible.
- Asset script additionally changes only Camera #5 in level0 from default blue
  RGB (0.1921569, 0.3019608, 0.4745098) to black. level0 contains DatabaseImporter;
  log 19 probes this scene around line 1671, then level1 and level3. This removes
  the blue background during import, preserving scene/import logic and logo.
  Its connection to the user's observed blue screen needs visual confirmation.

Output bundle includes prior hiding of main-menu extras; 17 intentional changed
objects, 22564 unchanged serialized payloads, streamed resources byte-identical.
SHA256: `b5dba0905243f13745dc32ca04c8fde1dd543e7440c18d2a4e05c2cd156af29f`.

Native logger tests verify a 2000-record burst, errors with /dev/full, and a
deterministic syscall-count test: 1000 ordinary records perform zero fsync calls;
250 ms interval, explicit checkpoint and close each synchronize. Build uses the
pinned toolchain and existing native/12 Python loader checks.

Install both root durak_nx.nro at `/switch/durak_nx/durak_nx.nro` and generated
`.single-game-startup/assets/bin/Data/data.unity3d` at
`/switch/durak_nx/game/assets/bin/Data/data.unity3d` (path proven by log 19).
Preserve the original bundle as backup. This NRO retains Single Game unlock.
User saves/databases and original .so files remain untouched.

Status: NEEDS_HARDWARE_TEST. Verify silent startup, background transition, actual
time to menu, Single Game selection/start, and check new BOOT TIME log lines.
# Constructor log sync optimization (2026-10-02)

Hardware log 20: modules loaded at 2326 ms, constructors/JNI complete at
8358 ms, first nativeRender returned at 9941 ms. This log predates the successful
heap-only audio fix; the user's current startup estimate is approximately 10 s.
These markers measure from main, not launch selection, and do not prove a visible logo.

528 constructors each had BEGIN and END followed by durable fflush/fsync:
1056 explicit syncs, bypassing the existing 250 ms logging interval. Removed
only these two per-constructor flush calls. All records remain, along with
module entry/exit, DT_INIT, JNI and error checkpoints. Abrupt crashes may lose
the latest buffered constructor records; interval syncs occur on subsequent
log writes, not on an independent timer. A constructor hang/crash can therefore
leave a last BEGIN buffered. No constructors are skipped or reordered.

Added constructor and JNI stage markers plus cumulative logger sync count/time
(`BOOT LOG IO`). Counters include periodic and explicit sync attempts, exclude
final close, and measure fflush/fsync elapsed monotonic time. A marker's own
flush is reflected in the next snapshot. The native logger test injects 5 ms
per fsync and checks the observed count and elapsed time.

This change targets actual waiting time. An early host loading screen is not
part of this diff; until Unity renders, the display can still be black. Measure
the next hardware log and time to visible logo before changing the graphics
handoff. SHA-256/Build-ID, relocation, ABI and audio behavior are unchanged.
