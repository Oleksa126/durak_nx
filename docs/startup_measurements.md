# Startup measurement baseline — 2026-10-06

Diagnostics only: CPU mode, Unity splash, artwork, timers, database schemas,
gameplay and I/O behavior are unchanged. Runtime measurements are written only
to the existing durak_nx.log file; new diagnostics check that this file is open
and never fall back to screen output. No per-read or per-SQL-step log lines.

`[BOOT PROFILE]` uses monotonic nanoseconds internally and integer microseconds
in the file. The origin is the first profiling call in main. Existing LOADING
markers describe submitted frames, active MainMenu detection and accepted
presents; they do not prove compositor scanout or completed UI initialization.

Phases measure bootstrap, per-module file reading/allocation, SHA256/Build-ID,
whole ELF load, import binding/patches, executable finalization/cache flush,
Unity initJni/recreate-graphics/resume and existing startup checkpoints.
Whole-load and checkpoint durations include nested operations/diagnostics.
They must not be added to their constituent phases.

Counters measure nativeRender calls; 1 MB asset cache fills (including seek and
physical reads, excluding cache-hit copies/lock waiting); wrapped SQLite opens,
prepare and step; the local inventory helper; commit-on-close; guest fsync plus
its SD commit. No SQL/errno/Result return values are modified. SQLite totals
cover these wrappers, not an exact interval for the managed DatabaseImporter.
Other reads, unwrapped SQLite calls and other commit sites are not attributed
to these counters. This is attribution coverage, not a whole-process CPU trace.

The main loop freezes counters when it observes the existing loader handoff and
prints one summary plus logger sync counts/time. First/last offsets, call counts,
inclusive wall time, maximum call time and bytes are retained. Nested categories
and different threads overlap; totals cannot be summed into startup wall time.
Calls still in flight at the snapshot are excluded. After the snapshot the
clock/counter collection is disabled. An exit-before-menu summary is labeled.

Heap initialization before main is measured separately with libnx ticks. The
interval from heap exit to the main startup tick is also recorded. Time before
heap entry (Homebrew Menu/title takeover, NRO load and earlier libnx setup)
remains unmeasured. None of these clocks can detect the user's icon click.

## Switch procedure

Install the packaged NRO, retain current assets and saves. Use the same launch
mode for each run. Make three separate launches, exiting the app each time;
copy durak_nx.log after each launch because the next launch overwrites it.
Wait until the menu is visible, then exit normally so the file is closed.
For click-to-menu wall time, record video from pressing the icon to seeing the
menu; note whether launch was from Homebrew Menu or a forwarder. Include a first
launch after reboot to distinguish first-run/cache effects. Do not clear saves.

Native tests validate clock units, errno preservation despite an errno-changing
clock mock, concurrent counting, invalid/disabled samples, one file-only summary
and disabling collection after handoff. Hardware baseline still required.
