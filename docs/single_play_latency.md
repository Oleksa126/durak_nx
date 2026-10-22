# Single Play transition latency — 2026-10-07

## Accepted result and diagnostic cleanup — 2026-10-10

User accepts the result measured in hardware log (5) and requests removing
temporary logs and committing the current implementation. Freeze this measured
result; do not claim further acceleration or completion of the remaining
database migration from a release build alone.

Remove the temporary post-menu profiler, per-call SQL/I/O/wait/shader timing,
per-frame archive/catalog snapshots and success-only catalog/cleanup messages.
Retain the original startup profiler, patch fingerprints and fail-closed checks,
reference readback errors, SQLite/I/O errors, watchdog and critical flushes.
Remove periodic render/EGL/pacer/touch and Choreographer/vsync inspection traces;
EGL swap failure still logs without consuming the guest's EGL error. Android
VERBOSE/DEBUG/INFO (priorities 2–4) are omitted; unknown/default priorities and
WARN/ERROR/FATAL remain. Archive counters remain only in native regression
builds and are not collected on Switch.

The resident archive, 19 compiled original catalogs/localization tables,
wide GC handles, direct reference setter contract, progress fallbacks and
instruction-only offline cleanup are retained. Native tests still validate
every row/column, independent lists, reference pointers, roots and cache reads.
No save data or game journal/fsync behavior changes. The quiet build needs a
normal launch smoke test; accepted timing evidence belongs to log (5), not
to an unmeasured new binary. Full modes/languages/reload and normally completed
game return were not established by that log.

The quiet build passed the full pinned NRO/native/Python/real-SQLite/package
gate before committing, including catalog roots/reference setters and every
cleanup fingerprint. A final build will embed the resulting clean commit ID.

## Offline cleanup hardware log (5) — 2026-10-10

`durak_nx (5).log` identifies the new build `2026-10-10T11:23:18Z`
(5228969-dirty) and includes the `[OFFLINE CLEANUP]` marker. It reaches
frame 1800 with nativeRender/EGL returning successfully; no recorded fatal
exception, abort or static-data reference error. This is coverage of the logged
session, not a guarantee about untested modes or reload persistence.

| Context | Frame | Render ms | Previous log (4) ms |
|---|---:|---:|---:|
| First Single Play, Tab 1 | 92 | 320.872 | 310.205 |
| MainMenu return | 424 | 614.106 | 680.437 |
| Automatic selector, Tab 1 | 432 | 276.891 | 269.556 |
| ProfileWindowNew context | 597 | 339.818 | 342.494 |

`CHECK PREMIUM` and `SceneOpeningNumber` occur zero times in the entire log.
The menu-return frame now has two native SQLite steps / 5.188 ms, including
the retained starter_bonus read; its previous 60.558-ms scene-counter UPDATE
is absent. The observed menu reduction is 66.331 ms, consistent with removing
that write, but these single sessions are not a controlled benchmark. Selector
and profile timings show no further meaningful improvement from this cleanup.
The measured menu-render start to automatic-selector-render end is 1023.861 ms
(previous 1090.799 ms), including the interval between frames, not click-to-visible.

The automatic-return flag is True after gameplay/home input. This run does not
prove a normally completed game/result flow. Correction to earlier interpretation:
MainMenu's old `isEnded`/`isStarted` messages belong to the companion-offer time
checks in updateUserBlock, not the game's completion state. They must not be
used as proof of a finished game in log (4) or other sessions.

Every reported slow frame retains the 32,272,398-byte archive with zero native
archive fills/bytes or evictions. First/automatic selectors use 8/6 SQLite steps
taking 6.770/8.114 ms; the profile uses eight steps / 4.903 ms. Catalog/text hits
remain present. The remaining roughly 277–340-ms window work is not localized
by this native-only instrumentation; database, archive I/O and logger figures
do not explain the whole interval. Do not attribute it to Instantiate, layout,
TextMeshPro, animation or a particular managed method without narrower timing.

Separate slow contexts remain: game initialization frame 227 is 1048.101 ms
(single_stats UPDATE 54.835 ms plus worker shader activity); a later 39-row
UI context at frame 1241 is 397.468 ms with no recorded SQLite step, main reads
1.873 ms and compiled rows 0.420 ms. The window's identity is not explicitly
marked there. Subsequent frames 1317/1368/1404/1516/1701 take 152–168 ms and
include Variables UPDATE calls lasting 54–59 ms. Bound key/value data is absent
from the SQL sample, so this log does not justify disabling those saves.
All counts/timings are inclusive and overlapping; worker spans are not additive
main-thread stall attribution. Original registerUser/gameStartStats network
requests, ADS COUNTERS messages and missing ProfileWindowNew script warnings
remain; the cleanup has not removed every legacy/online path.

Evidence-only update: no production edit or rebuild. Additional cleanup is
confirmed on hardware, while visible acceptance, completed-game return,
both languages/all modes, reload persistence and attribution of the residual
managed/engine cost remain open.

## Continue offline cleanup — 2026-10-10

User requests further cleanup after hardware log (4). The measured
SceneOpeningNumber UPDATE on MainMenu return took 60.558 ms; this is one
observed cost, not an explanation of the full 680.437-ms scene transition.
No rollback of the compiled catalogs, reference setter/GC fixes or archive cache.

The existing instruction-only cleanup table now also removes:

- MainMenu.updateUserBlock's premium_end/date/log block at 0xd6efe0, branching
  to 0xd6f0c0 after initializing the retained G.O pointer in x22. Its later
  time-dependent purchased_companions offer scan at 0xd6f640 branches to the
  original hide-offer path 0xd6f858. Profile ribbon/level, keys, online count,
  currency and all three cup counts/images refresh through the original code.
  Only the removed offer tail reads the skipped date/time locals.
- Existing scene-counter row updates: 0xd8f718 branches to the balanced
  epilogue 0xd8f8a8. Selection of the actual scene row is retained, and the
  original missing-row initializer still creates first_run/date records.
  ShowDailyReward's metadata-resolved predicate at 0xd90e04 selects first_run;
  bypassing the whole SceneLoadingCounter method would break this dependency
  on a fresh save. DailyRewards records, calendar checks and claims remain.
- Automatic SceneLoader.ShowSpecialOffer (0xd8f8c8), advertising-ID reporting
  MainMenu.GetADID (0xd6d57c), OnNoAdsPurchase (0xd6cf1c), ShowAlternatePayment
  (0xd6dac0), buttonPremium (0xd6e280), buyPremium(bool) (0xd7032c), and the
  PremiumWindowController/PremiumWindow purchase entries (0xd72ecc/0xd88680).
  Every entry returns void; a leaf RET ignores instance/arguments/MethodInfo
  without modifying SP, LR or callee-saved registers. GetADID's original path
  posts the advertising ID and marks its own sent flag, not game progress.

`scripts/verify_offline_cleanup.py` is now a packaging gate. Assembly-CSharp
method tokens/RIDs resolve through ELF relocations to the entry RVAs; original
four-word fingerprints cover all 14 cleanup sites. Independent registration
discovery resolves field offsets, literal keys and generic method arguments
(SceneOpeningNumber/purchased_companions), validates void/bool/int/string ABI
kinds, branch targets and both balanced epilogues. Native patch tests reject
a mismatch at every cleanup site atomically and reject every post-map context
corruption. No new managed/native callback or executable trampoline is added.

The boot-only `[OFFLINE CLEANUP]` marker and existing per-render SQL/I/O/static
catalog profiling write solely to durak_nx.log. New hardware acceptance: test
startup, direct/automatic selector, profile, tabs/modes and reload persistence;
check that existing scene rows no longer emit SceneOpeningNumber UPDATE and
MainMenu no longer prints CHECK PREMIUM. A first visit to a previously unseen
scene may still run the original compatibility initializer. This retains
progress-dependent legacy storage; full removal of all non-progress database
initialization/read paths has not been claimed. New speed/visible correctness
requires a new Switch log; the prior hardware timings belong to the prior build.

Verification: pinned full NRO/native/Python/real-SQLite/package gates passed;
all three intentionally incorrect branch destinations are rejected by the new
target verifier, and diff whitespace checks pass with repository CRLF handling.
Build identity `5228969-dirty`, `2026-10-10T11:23:18Z`; root and packaged NRO
SHA256 `81ce478616deb87a2b243e50917731ac10c22f2c252ca6cc40ab4e59b9889ff9`.
Status: NEEDS_HARDWARE_TEST for additional latency improvement and UI behavior.

## First/automatic selector and profile: hardware log (4) — 2026-10-10

`durak_nx (4).log` runs the same corrected build `2026-10-10T08:23:53Z`.
It exercises first Single Play, game start/return with autoShowSingleSelect=True,
profile, tabs 1/3 and blocks (other game ID 2) with another home return. No fatal
exception or reference readback error is recorded through frame 2340.

| Event | Frame | Current render ms | Earlier diagnostic baseline ms |
|---|---:|---:|---:|
| First selector, Tab 1 | 754 | 310.205 | 1829 (frame 112) |
| Automatic selector after game-to-home | 1120 | 269.556 | 1224 (frame 1359, Tab 2) |
| ProfileWindowNew context | 1241 | 342.494 | 1961 (frame 247) |
| Later selector after blocks/home, tabs 1/3 | 2134 | 243.509 | no identical baseline |

These are synchronous nativeRender wall intervals, not click-to-visible or
controlled multi-run benchmarks. The automatic-return flag is True before
frame 1111, MainMenu reports isEnded=True, then Show Tab 1 precedes frame 1120.
This directly exercises the automatic selector path missing from log (3).
The comparison return tabs differ; first selector tabs and profile contexts
match. Actual visible response and full mode correctness require user acceptance.

First selector handles 24/24 catalog rows and 21/21 texts from code. Automatic
selector handles 21/21 texts, 3/8 table attempts from code and the five remaining
table attempts through original progress paths. Its native SQLite steps are
6 calls / 5.231 ms, versus 66.7 ms in the earlier return baseline. Profile handles
13/13 texts, 3/3 rows and 4/7 table attempts from code; recorded remaining queries
read actual cups_array/solitaire_progress. All slow frames still have zero archive
native fills/bytes and zero evictions. Metrics are inclusive/overlapping and are
not a partition of render time.

Scene/menu work remains separate: returning MainMenu frame 1111 takes 680.437 ms,
with a real SceneOpeningNumber UPDATE taking 60.558 ms. From the measured start
of frame 1111 to the end of selector frame 1120 is 1090.799 ms, including the
inter-frame interval; this is not timing from the user's button press. Later
blocks/home return frame 2128 takes 752.105 ms. Game initialization frame 922
takes 845.543 ms. Do not label these as the mode-selector or profile stall.

The original multi-second selector/profile stalls are substantially reduced on
the exercised hardware paths, and both previously reported startup crashes are
absent in this run. This does not claim that every remaining scene/UI cost or all
non-progress SQL/premium reads have been removed. Missing ProfileWindowNew script
warnings remain visible, as in earlier logs. Full modes, both languages, reload
persistence and visible-response acceptance remain outstanding. Evidence-only
update: no runtime modifications or rebuild.

## Corrected catalog build: hardware log (3) — 2026-10-10

User's `durak_nx (3).log` identifies build `2026-10-10T08:23:53Z`. It reaches
MainMenu (7324 ms), opens Single Play, starts perevodnoy (ID 2, two players),
continues through game turn 13 and frame 4140, and ends after a Plus-menu input
with successful nativeRender/EGL return. There is no recorded fatal exception,
reference readback mismatch or recurrence of either reported startup abort in
this run. This confirms the exercised startup/list/gameplay paths only.

| Context | Frame | Render ms | Main SQLite steps / ms | Compiled table / row / text hits |
|---|---:|---:|---:|---:|
| First Single Play, Show Tab 1 | 172 | 320.843 | 8 / 7.530 | 3 / 24 / 21 |
| Selection/options context, perevodnoy ID 2 | 351 | 169.891 | none recorded | 0 / 0 / 1 |
| Game initialization, player/deck/game-start messages | 433 | 885.470 | 8 / 156.900 | 4 / 39 / 0 |

Frame 172 has 8 table attempts (3 compiled, 5 original fallbacks), 24/24 row
hits and 21/21 text hits. Callback main times are separately 182, 218 and 117 us;
these are inclusive measurements, not additive render partitions. Main file
reads take 1.814 ms and the main condition wait 11.877 ms. Archive fills/native
bytes remain zero; 3,997,486 archive bytes are served from retained memory.

The earlier first selector at frame 112 in `durak_nx.log` also opens Tab 1:
1829 ms / 1713 native SQLite steps. The archive-only build in log (1) takes
841 ms / 1713 steps, but opens Tab 2. Thus the new observed first-opening stall
is substantially lower and the thousands of SQLite row steps are removed;
these are separate runs, not exact click-to-visible or repeated statistical
benchmarks. Remaining 320-ms engine work has not been attributed to UI/TMP,
resource decoding or animation by this log.

All eleven current DictTypes tables are materialized from code during startup.
The exercised localization/catalog readbacks and progress fallbacks work. This
does not verify every mode, both languages, restart persistence or all modals.
There is no ProfileWindowNew opening and no autoShowSingleSelect=True/game-end
return sequence in this run. Frame 433 is game initialization, not the mode
selector or profile modal. Automatic reopening after a completed game remains
an outstanding hardware acceptance case.

Legacy dict/l10n startup initialization and the MainMenu `CHECK PREMIUM` message
remain visible; full removal of non-progress SQL initialization and scattered
premium checks has not been completed. Evidence-only follow-up: no new runtime
change or NRO rebuild. The two known startup regressions are absent on the
exercised path; the broader UI latency/cleanup gate remains open.

## Follow-up crash: direct reference setter contract — 2026-10-10

Report `01791620508_05f5d338a7a28000.log` moves past GCHandle::Free and faults
at executable-segment offset 0x398770 / libil2cpp RVA 0xeb4770:
`ldrb` is not involved here; the instruction is `ldr w9,[x9,#0x104]` in the
shared list indexer, with X9=0xe0000. Its caller is RVA 0xdd6ac4 (LR 0xdd6ac8)
in the original consumer of GetTableData. The supposed array pointer is stack
memory (`X8=0x79099880`) instead of the array allocated by the callback.

Target export `il2cpp_field_set_value` at 0xbeb52c branches to 0xc40b1c.
It passes W3=0 to SetValueRaw, i.e. **dereference=false**. STRING (14) and
SZARRAY (29) dispatch through the actual type jump table to 0xc4050c; the
false branch forwards the supplied X2 itself to the write barrier/store.
Our code wrongly passed `&array` / `&str`, putting stack-variable addresses
into the list's _items and row string fields. The previous native mock copied
through every reference argument and therefore reproduced our wrong assumption.

Pass the managed object itself (or NULL) for reference fields; retain addresses
of value bytes for scalar fields. All three reference-writing paths are fixed.
After each write, read the field back through the exported API while construction
roots are still held; a mismatch logs and returns to the original method before
exposing the result. The mock now follows the verified target contract and only
accepts registered managed allocations for references. Reintroducing &array or
&str independently fails that regression with SIGABRT; fixed code passes all
rows/columns, both languages, independent results and >4-GiB GC handles.

Packaging verifies the setter export, zero dereference flag, STRING/SZARRAY
jump-table targets and final direct pointer store. No migration/premium/archive
work is rolled back. Hardware startup/modal/persistence validation remains
required; this report does not establish successful operation of the new build.

## Startup crash: pointer-sized GC handle ABI fix — 2026-10-10

User supplies Atmosphere reports `01791619719_05f5d338a7a28000.log` and
`01791619731_05f5d338a7a28000.log` and explicitly requires fixing rather than
reverting the catalog migration. Both reports have the same normalized stack:

- Guest executable-segment offset `0xc9c04` is libil2cpp RVA `0xbe5c04`
  (segment page RVA `0xb1c000`), the `ldrb w8,[x22,#0x20]` in GCHandle::Free.
- X1 points to the exported `il2cpp_gchandle_free` (RVA `0xbeb638`).
- Native LR `durak_nx+0x2554c` follows that API call in durak_static_table;
  the calling instruction loads its handle into **W0**, truncating it.
- X0 is `0xf2718028` / `0x36718028`; X22 is the corresponding masked block
  `0xf2718000` / `0x36718000`. The abort access is the block plus 0x20.
  Caller `durak_nx+0x2b020` is durak_static_table_guard. ASLR changes absolute
  addresses between runs but not this fault/call path.

The exported target API is not the historical 32-bit GC-handle ABI. New returns
the slot in X0 (`csel x0,x9,x21,lo` at 0xbe595c), and GetTarget/Free mask the
full X0 to a block pointer before dereferencing it. The host incorrectly used
uint32_t in API signatures, local roots and cached translation handles. Earlier
tests returned only small indices and failed to detect this ABI mismatch.

Use one `DurakGcHandle = uintptr_t` type, assert its eight-byte ARM64 size and
preserve it through every API argument/return, temporary and translation cache.
The native regression now returns opaque handles with high bits `0xd00000000`
and verifies those bits at every GetTarget/Free, covering construction, cached
texts and both languages. Deliberately restoring just the 32-bit list-root local
makes it fail at root_index with SIGABRT; the fixed source passes. Packaging
also verifies target export branches, X0 return and the full-width block-mask/
dereference instructions. No catalog, premium, archive or persistence change
is reverted, and no exception is suppressed.

This fixes the statically identified truncation demonstrated by both reports.
The fixed build still requires Switch startup/menu/modal/progress validation;
successful native tests do not establish absence of other runtime issues.

## Compiled catalogs and premium cleanup — 2026-10-10

User explicitly authorizes moving non-progress data into code and removing
premium checks. The key lookup at LocalizationManager.GetText(string), token
0x0600043e / RVA 0xd5f3dc, allocates a closure, queries GetTableData<Generic>
on a dictionary miss, searches the returned list and reflects the selected
language property. In log (1), profile-context frame 308 executes 3078 native
SQLite steps while its render takes 1081 ms; native steps themselves total
51.5 ms. This proves repeated reads, not the entire managed elapsed share.

`scripts/generate_static_catalog.py` extracts **only the original packaged**
dict/l10n TextAssets, in memory, and emits `include/static_catalog_data.h`:
19 current catalog tables, 1298 rows. Historical SQL tables with no current
managed catalog type are excluded. Original IDs, ordering, strings, numeric
types, sprites and scene names are retained. Per user authorization, only the
companions price/ispremium/specialofferid columns are set to zero. This does not
invent progress or change the player's selected companion.

Three managed entry boundaries use these compiled records:

- GetText(string): direct key/language lookup and GC-rooted immutable strings,
  bypassing SQL row mapping and language-property reflection.
- DataManager.GetTableData<T> shared reference body: original List<T> and row
  classes populated through exported GC-aware IL2CPP field APIs. Each call gets
  independent lists/rows, so sorting/clearing/editing cannot contaminate later
  results. Construction uses temporary pinned GC handles; constants are native.
- DataManager.GetRowData<T>(int) shared reference body: original row class and
  fields from compiled descriptors; progress types follow the original body.

The generator resolves Assembly-CSharp methods through metadata and codegen
relocations, MethodRef usage through method specs, and the shared generic bodies
through the metadata/generic-method registration tables and known callers.
All row constructors are verified as side-effect-free tail calls to the base
Object constructor. No MethodInfo layout is accessed by native callbacks:
inflated return types/classes/fields are obtained through the exported API.

The entry patch checks eight original ARM64 words at each boundary and all
premium cleanup contexts before writing anything; missing exports also reject
before mutation. Post-map verification checks the exact code and destinations.
The three assembled guards preserve x0/x1/x2 and LR, accept the x0/x1 aggregate
result, and on fallback execute exactly the displaced stack prologue before
tail-entering the original function at +16. There are no dynamic trampolines,
relocated PC-relative instructions or new executable allocations. Null inputs,
unknown/missing keys/rows, unsupported languages/types or incompatible shapes
retain the original managed path and its error behavior; exceptions are not
caught or converted to successful empty lists.

SinglePlayerSelect.OnEnable skips the marketing counter read/write before both
original redraw calls, then skips the premium-date/banner block and enters the
original active-tab selection. DRAFT.ShowPremimBannerWnd returns immediately
for all premium marketing banners. Existing mode, tab, difficulty and statistics
updates remain. This is not a blanket patch of every scattered premium field
read in the application.

The original progress/selection/inventory/PlayerPrefs persistence remains live.
Existing databases are not deleted, rewritten or migrated on SD. Legacy startup
database initialization and original fallback paths still exist; this release
does **not** claim physical removal of every non-progress database/table or
replacement of every possible raw SQL call. No synthetic SQLite statements,
parallel database backend, journal/fsync change or suppressed error is added.

Log-only `[STATIC DATA]` counters distinguish attempted/handled table, row and
text calls per slow frame; `compiled_table`, `compiled_row`, `compiled_text`
measure the native callback spans. These overlap with enclosing render and each
other and exclude the original body after a fallback. They still do not time
all Instantiate/TMP/layout/resource work or actual click-to-visible time.

Verification: real original data regeneration must match the generated header;
native tests check every row/column, both languages, cached rooted strings,
independent lists/rows after consumer mutation,
errno, missing/progress fallback, allocation failure, pre-write rejection on
fingerprint/missing API and post-map rejection. Assembled guard checks verify
argument restoration, actual displaced guest instructions and continuations.
Full pinned build/native/13 Python/10 real-SQLite/asset/package gates passed.
Status: NEEDS_HARDWARE_TEST. Next acceptance: first/repeated Single Play and
profile, every mode/tab, both languages, game return and persistence; compare
Generic/catalog SQLite work, handled counters and render intervals in the log.

## Archive retention hardware follow-up — 2026-10-10

User's `durak_nx (1).log` identifies build `2026-10-10T06:49:28Z`, matching
the delivered NRO SHA256
`EFFE92399CB5C5CDA7295D6E0044D8E6806FD60852E6131318A5C0719F962262`.
The archive is retained at 32,272,398 bytes. Every reported slow frame has
zero archive native fills/bytes and zero evictions; archive requests are served
from retained content. This confirms the I/O change on Switch.

| Event | Previous frame / render ms | Current frame / render ms | Current archive served bytes |
|---|---:|---:|---:|
| First Single Play selector | 112 / 1829 | 106 / 841 | 3,997,486 |
| Profile-window context | 247 / 1961 | 308 / 1081 | 6,520,303 |
| Automatic selector after game | 1359 / 1224 | 866 / 320 | 3,997,486 |

These are render intervals, **not click-to-visible timings**. First/return tabs
differ between runs (previous: 1/2; current: 2/1), so this is observational
evidence of reduced stalls, not an identical-workload percentage benchmark.
ProfileWindowNew warnings occur before frame 308; they identify context, not
the cause. Frame 726 takes 1189 ms during game initialization (player/deck/game
start messages), and must not be labelled a modal opening.

The remaining profile-context frame 308 spends 51.5 ms in 3078 main-thread
SQLite steps, 3.3 ms in prepare, and 5.3 ms in measured main file reads. There
are no reported shader or condition/mutex waits in that frame. These inclusive
metrics overlap; their absence/short durations do not measure managed mapping,
resource decoding, Instantiate, UI layout, TMP or every engine wait. Thus most
of its 1081 ms still lacks attribution. The first selector likewise has 129.8 ms
of native SQLite steps and 11.8 ms of main file reads within its 841 ms interval.
Do not infer a managed localization or UI cause solely from query counts.

Return-to-menu frame 858 takes 673 ms separately from selector frame 866.
Selector frame 866 contains 60.8 ms of SQLite step work, including a real
Variables UPDATE; saves and their syncs remain unchanged. Hardware-visible
opening time and list/selection correctness still require user confirmation.
Archive I/O removal is confirmed; the overall modal latency gate remains open.
This follow-up changes evidence only; the delivered runtime/NRO is unchanged.

## Hardware log follow-up and archive retention — 2026-10-10

User's `durak_nx.log`, build timestamp `2026-10-10T06:32:04Z`, confirms the new
measurement windows. NativeRender frame 112 takes 1829 ms; frame 247 takes
1961 ms; returning to the selector at frame 1359 takes 1224 ms.

| Frame | Render ms | Main asset-fill ms | All-thread asset-fill ms | Native asset-fill bytes | Main SQLite step ms |
|---|---:|---:|---:|---:|---:|
| 112 | 1829 | 588.5 | 904.1 | 72,351,744 (69 MiB) | 129.8 |
| 247 | 1961 | 376.4 | 828.7 | 65,011,712 (62 MiB) | 45.4 |
| 512 (repeated selector) | 239 | 0 | 0 | 0 | 62.8 |
| 1359 (selector after game) | 1224 | 594.6 | 915.5 | 72,351,744 (69 MiB) | 66.7 |

These inclusive/all-thread durations are **not a partition** and must not be
added. This establishes expensive resource I/O; it does not attribute all render
time to it. Frame 1352 separately spends 555.9 ms on a real Variables UPDATE amid
worker asset reads, so save work remains measurable and unchanged.

The runtime attaches `assets/bin/Data/data.unity3d` at size 32,272,398 bytes
(30.8 MiB). It exceeds the former 4-MiB whole-file limit, leaving only one
1-MiB forward window per fd. Backward/distant seeks refill that window; independent
opens cannot share or retain it. The log repeatedly reads more asset bytes than
the entire archive's size, with the slow read caller `libunity.so+0xef68a0`.
Per-file native byte attribution was not in that diagnostic build, so the precise
archive share still needs confirmation; no full root-cause claim is made.

Reuse the existing whole-file cache for exactly the read-only packaged
`/assets/bin/Data/data.unity3d` suffix (including the `/game/assets/` layout), up
to 32 MiB. Its separate 32-MiB budget cannot consume the existing small-asset
16-MiB budget. Keys retain full path and actual size; independent handles retain
independent logical cursors. Pinned content is never evicted; oversized archives,
slot pressure or allocation failure retain the original window/native fallback.
Errors and positive short reads retain the existing behavior. Mutable databases,
journals and saves are never attached by the production caller.

This adds at most 32 MiB of retained RAM. It introduces no managed hooks, resource
substitution, UI skipping, save batching, fsync/journal change or animation patch.
`[ARCHIVE CACHE] retain` confirms allocation/path/budget; slow frames report
native fills/bytes, served bytes, reopen reuse, evictions and resident size.
Served bytes include the just-filled request, so they are not a pure hit count.

Native regression uses a real archive larger than 4 MiB: 69 scattered reads
across six MiB, reopen/independent/concurrent cursors, negative and short reads,
dup synchronization and two pinned 32-MiB aliases. The previous implementation
fails its zero-additional-read assertion; the new implementation passes.

Required Switch acceptance: repeat the same first/repeated modal and game-return
sequence; confirm correct lists/modes and inspect native archive bytes alongside
render time. Hardware acceleration is not yet verified. Status:
NEEDS_HARDWARE_TEST. Remaining unmeasured Unity/managed work and real save latency
must be handled from the next log if still dominant.

## Modal diagnostic build — 2026-10-10

User reports delays in multiple modals and requests a log build. Keep the existing
game behavior and use the existing native wrappers; no new IL2CPP instruction
patches, managed trampolines, loader changes, database modifications or timing
shortcuts. Hardware log (29) already disproves logger sync/sidecar probes as the
dominant explanation for the Single Play 1810/1219 ms frames.

After menu handoff, each nativeRender has an in-memory measurement window. Frames
taking at least 100 ms emit `[MODAL PROFILE]`: SQLite prepare/step/open, inventory,
asset cache fills, file reads/writes, mmap, metadata checks, save sync/commit,
mutex/condition/semaphore waits, and shader compile/link where the native import
wrappers are used. Main-thread calls/time are separate from all-thread counts.
The latter include the main thread. These are inclusive wall spans: SQLite steps
can contain file reads, fsync and waits; render contains everything. Do not add
these rows or subtract their all-thread totals from render time. Calls crossing
the window or still running at its end are excluded.

`[MODAL CALL]` buffers up to 16 longest completed calls >=1 ms per slow frame:
category, main/worker, monotonic timestamp, duration, caller module/RVA and bounded
SQL text where available. Data is copied before statements can be finalized;
errno, SQLite return values and existing error diagnostics are preserved. All
reporting occurs after nativeRender, only in durak_nx.log. The existing latency
marker takes its logger snapshot before this new report, preserving comparison.

Coverage limits: this does not directly time OnEnable, Instantiate, TMP layout,
managed SQL mapping/reflection, GC, coroutine delays or actual modal visibility.
Unmeasured main-thread work must not be labelled SQLite just because a query is
nearby. Graphics calls bypassing the import wrappers and cross-frame worker work
also need follow-up if measured categories do not explain the slow frame. This
build localizes native categories first; it does not claim an acceleration.

Switch test: replace only `/switch/durak_nx/durak_nx.nro`; retain existing assets
and databases. Open several affected modals one at a time, close them, reopen
each, then test returning from a game to Single Play. Return the complete
`/switch/durak_nx/durak_nx.log` and identify which windows felt slow. Compare first
vs repeated opening and main vs worker SQL/I/O/wait/shader durations before making
a targeted fix. Status: NEEDS_HARDWARE_TEST.

Verification: extended native measurement tests cover frozen startup stats,
main/worker distinction, concurrency, errno, bounded details, and rejection of
cross-window calls. Existing read EOF/error tests retain the real read behavior.
Full pinned NRO/native/Python/SQLite/package gate is required for delivery.

## Hardware follow-up: log (28)

5050012 does not produce a noticeable selector speedup. First opening stalls
nativeRender frame 86 for 1820 ms, with one logger sync totaling 16 ms. The
return-to-menu sequence includes frame 1151 at 782 ms (5 ms logger sync) and
selector reopening at frame 1158 at 1220 ms (zero logger syncs). There is no
slow-EGL-present marker. Logger syncs are therefore not the dominant remaining
explanation. The log visibly repeats dozens of journal/WAL absence checks,
particularly l10n.bytes after the selector's Show Tab 1. These prove repeated
filesystem work, not its exact share of the stall; the next build measures that.

Apply a frame-scoped cache of observed ENOENT for exactly metrics.bytes,
l10n.bytes and dict.bytes journal/WAL/SHM siblings. Each post-startup nativeRender
starts with empty absence state and ends by discarding it. Positive metadata,
base databases, arbitrary files, EIO/EACCES and all probes outside that scope
remain live. The cache performs no write, schema change, PRAGMA or SQLite stub.

Namespace mutations through the host wrappers are bracketed before/after the
actual operation: writable open/openat/__open_2 and fopen; unlink/unlinkat/remove;
rename (both source and destination), mkdir and rmdir. The real mutation clears
the exact affected entry or ancestor, including case aliases on FAT. Ambiguous
relative/dot/device aliases clear all entries. Hits/publication are disabled
while a mutation is in flight; an epoch check prevents an earlier miss from
publishing stale absence after a concurrent writer. Failed mutations also
invalidate. Entries do not survive a frame or process restart. This targets the
per-title, in-process VFS paths, not a cross-process database cache.

SQLite sidecar stats also stop attempting the generic asset basename fallback:
an absent fully resolved journal must not be replaced by an unrelated same-name
file in the working directory. Other asset fallback behavior stays in place.
The initial real errno and native Result are retained with each cached absence;
log lines explicitly distinguish cached observations from fresh calls. No live
native Result is fabricated/set by a hit, and SQLite return/extended codes are
unchanged. Existing metadata-recovery fallback on real EIO remains active.

Slow-frame records now include real sidecar probe count/time and avoided-probe
count, inclusive across threads. A real-file native regression checks 2000
repeated probes with no further native calls; initial/out-of-frame failures;
live existing file size; create/unlink/rename and parent/relative/case alias
invalidation; mutation-in-progress and stale-miss publication races; three
reader threads; preserved errno/native Result and no EIO/EACCES caching.

This is a targeted reduction of the filesystem repetition observed in the log.
The full 1.82/1.22-second stall has not been attributed to this work alone and
hardware reduction remains unverified. Serialized UI lists and managed methods
are unchanged; selector showTab/list refresh call graph was inspected, not patched.

## Earlier logger change

User confirms both delays concern the Single Play mode selector: its direct
opening from MainMenu and reopening after a finished game returns home.
Latest attached log (27) ends around startup/frame 60; it contains no measured
click-to-selector or end-game-to-selector interval. No numerical improvement
or full root-cause claim can be made from that log.

Confirmed host overhead: durak_boot_measure_finish disables startup batching at
menu handoff. Previously, every subsequent durak_log_flush called fflush+fsync
under the global logger mutex. Render/SwapBuffers checkpoints and Input/Plus
diagnostics call this function. The periodic vprintf sync also shortened from
1000 to 250 ms. Bursts therefore forced SD durability on the calling game thread
and could block other logging threads. This is independent of the selector's
managed logic and can affect both transition paths; its exact hardware contribution
is unmeasured. Original selector OnEnable still calls redrawGameList and other
list refreshes (metadata/disassembly scripts/analyze_single_game.py); no managed
method, resource, animation or database query is stubbed or skipped here.

Routine log flush now publishes all buffered bytes with fflush and coalesces
durable fsyncs at 1000 ms in runtime as during startup. Fatal/fail-stop/watchdog
durak_log_flush_critical and final log close remain immediately durable.
The __assert2 diagnostic now explicitly uses the critical flush before aborting.
Errors from fflush/fsync remain reported. Game SQLite journal/fsync, saves and
schema logic do not change. A sudden process/device loss may lose the latest
interval of diagnostic durability; this policy does not weaken saved game data.

File-only [UI LATENCY] lines report post-startup nativeRender calls >=100 ms,
including logger-sync counter/time deltas. These logger totals include concurrent
threads and are not a strict partition of the frame duration. Slow default-window
eglSwapBuffers >=100 ms is reported separately. NativeRender excludes later async
GPU work, so the two spans must not be added. These markers help distinguish
synchronous engine work from graphics presentation stalls; they do not measure a
timer-based UI animation or the exact instant the modal first becomes visible.

Native regression simulates boot batching, disables it as the real menu handoff
does, then emits 1000 runtime message/flush pairs. It requires zero extra per-call
fsyncs, continued file publication, interval sync, immediate critical sync, propagated
sync failure and durable close. Existing /dev/full and startup measurement tests
retain their gates. Runtime transition improvement needs Switch confirmation.
