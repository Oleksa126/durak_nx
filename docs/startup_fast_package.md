# Combined startup optimization — 2026-10-06

User requested one combined build after baseline ea81d2d (18.577009 s from main
to handoff). No new loader design or online functionality is included.

- Full original module SHA256/Build-ID verification remains mandatory. Switch
  hashing uses libnx hardware SHA256 (ARM crypto); portable one-shot hashing
  processes full blocks directly. Runtime empty/abc self-tests with unaligned
  buffers/guards fail closed before module loading. Native vectors test padding
  boundaries and large inputs; the Switch call is covered by the runtime
  self-test because libnx is available only in the target build.
- CPU FastLoad requested at main startup, real Result logged. Normal mode is
  restored on the existing framebuffer-disconnect path before EGL window use,
  and on shutdown/fatal cleanup. FastLoad throttles GPU, so it is not retained
  during Unity rendering/gameplay. An unavailable request retains normal mode.
- Startup checkpoint flushes now fflush without fsync; periodic durable sync
  every 1000 ms instead of 250 ms. At handoff, normal policy returns and the
  summary is synced. Fatal errors, fail-stop traps and watchdog reports force
  immediate durable sync. Sudden process/device loss can lose up to the latest
  interval of diagnostics. Game database fsync/journal policy is unchanged.
  Update 2026-10-07: runtime checkpoints now also coalesce log syncs at 1000 ms;
  see single_play_latency.md. Fatal/watchdog/close durability is retained.
- Disable m_ShowUnitySplashScreen (globalgamemanagers/1, byte 100), so the
  existing shared host loader covers initialization without a hidden splash
  timer. Exact object hash and typetree roundtrip verified; preserve unknown
  four-byte tail, images and every other PlayerSettings byte.
- Disable existing SimpleSQLManager.overwriteIfExists only for level1/53,
  L10n, serialized byte 60. Original flag=true caused File.Delete/re-copy each
  startup, proven in both logs and SimpleSQL_Runtime Initialize token 06000101.
  Field sequence, instance flag +0x48, File.Exists/Delete/WriteAllBytes metadata
  and conditional branches are verified in scripts/verify_startup_fast.py.
  False retains an existing localization DB and copies the bundled DB if
  missing. Metrics and dictionary manager flags are unchanged. No DB files,
  schemas, statistics, language choices or saves are modified by packaging.
  This targets the pinned 25.0 database; a future game-data revision needs a
  migration/version check, rather than retaining incompatible local data.

Bundle validation compares every serialized object/resource after repacking:
two additional objects, each with one byte changed; no additions. Existing menu
changes retained. Tests cover SHA vectors, logger batching/critical sync/normal
restoration, loading failure cleanup and existing cache/SQLite/input gates.
Actual total speedup requires one Switch run of the complete package.

Hardware acceptance: all module identities verified, SHA self-test=0, FastLoad
and normal restore Results, no visible extra Unity splash/black gap, no startup
l10n deletion/reimport when its valid DB exists, correct English menu, gameplay,
sound/input and a BOOT PROFILE summary. Status: NEEDS_HARDWARE_TEST.
