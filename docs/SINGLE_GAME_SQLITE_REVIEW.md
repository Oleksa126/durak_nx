# Single Game: SQLite initialization fix, 2026-10-02

Scope: incremental changes over the existing Gemini worktree. Review-only patch
is `docs/single_game_fix.patch`; no commits or user DB modifications.

## Evidence

- Input: `C:/Users/oleks/AppData/Local/Temp/durak_nx (17).log`.
- Serialized `level1`: DataManager 46 and SimpleSQLManager 47 share GameObject 2.
  Their saved fields select namespace `MetricsTypes` and TextAsset `metrics`.
  Metadata places `single_stats` in namespace `MetricsTypes`. Thus its database
  is `/switch/durak_nx/metrics.bytes`, mapped to
  `sdmc:/switch/durak_nx/metrics.bytes`, not `data.db`.
- Original metrics asset is a 24576-byte SQLite DB; its sqlite_master has no
  single_stats table. The game owns schema migration and table creation.
- Target code registration (resolved from relocations, not donor addresses):
  Assembly-CSharp module `0x1b0d0e0`, pointers `0x1c3b158`, 2865 methods;
  SimpleSQL_Runtime module `0x1bb7778`, pointers `0x1d6c330`, 304 methods.
  DataManager.Awake `0xd4733c` invokes InitializeDatabaseInfo `0xd474a8`,
  DetectTables `0xd476e8`, UpdateDatabaseVariables `0xd47af0`, then
  UpdateDatabaseStructure `0xd48178`. That function calls CreateTable
  `0xd49fa8` at `0xd48688` / `0xd488fc`; it also calls SimpleSQLManager.Execute
  `0x1210a7c` at `0xd48668`. No table schema is injected by the wrapper.
- Log line 1871: metrics open succeeds with Android flags `0xa0042`
  (RDWR|CREAT|NOFOLLOW|CLOEXEC). Access mode/CREAT are translated to newlib
  RDWR|CREAT. There is no read-only retry in the log. Later stat of the open
  file returns EIO; ReadOnly follows at 1895 and again at 2102. Similar failure
  occurs for l10n and dict. No SQLite journal open is attempted at that point.
- libnx fsdev_stat gets file size by opening another read handle:
  https://github.com/switchbrew/libnx/blob/master/nx/source/runtime/devices/fs_dev.c
  (fsdev_stat). This conflicts with the live writer on Horizon. Target SQLite's
  stat dispatch relocation is `0x1c4790`; file-control code at `0x43230` calls
  stat at `0x43248`, treats failure as moved (`0x43250`), and otherwise compares
  inode at `0x43424..0x43434`. This explains a writable DB becoming unwritable
  before journal creation. The exact extended SQLite error was not logged by
  build 17; the new diagnostics must confirm it on hardware.

Reproduce asset/metadata evidence with `python scripts/inspect_single_game_assets.py`
(requires UnityPy, pyelftools, capstone). Analysis reads the bundle and deserializes
the original metrics DB into memory only.

## Changes and checks

- On sdmc stat EIO, obtain size/type from the real directory entry without
  another file handle. Missing entries remain ENOENT; failed FS queries remain
  errors. Log original errno/native Result and recovery result.
- Preserve open/stat/pwrite/fsync errno across logging, seeking and commit;
  expose failed commits. SQLite open/prepare_v2/step diagnostics forward the
  original return value and capture filename, SQL, errno, extended code/message.
- Fault-injection test covers valid entry, unrelated entry, root parent, missing
  file, directory open/read failures, path translation failure and handle closure.
  `python3 -m unittest tests.test_single_game_stat` passed in devkitA64 container.
- Pinned `scripts/build_nro.ps1` build passed; native target/loader checks and
  12 Python loader checks passed. Existing unrelated compiler warnings remain.

## Remaining gate: NEEDS_HARDWARE_TEST (updated after log 18 below)

Install the rebuilt root durak_nx.nro at `/switch/durak_nx/durak_nx.nro`; keep all
existing databases. Launch, open Single Game and choose a mode. New log should
show successful schema CREATE (SQLite step 101), journal creation with writable
host flags, and no ReadOnly/no-such-table errors. Extended codes remain visible
if initialization still fails. No hardware success is claimed.

If the list remains empty after schema creation, use the fresh click log to
localize the surviving NullReferenceException. Static entry path is
SinglePlayerSelect.OnEnable `0xd7ae44` -> redrawGameList `0xd79430` (call at
`0xd7af78`). Build 17 has several unqualified NRE messages, so none can yet be
assigned to a particular dereference after this fix. Do not replace them with
blanket stubs. Completion requires modes visible and one selectable on Switch.

## Hardware log 18: schema creation still fails

The first fix passed its actual boundary: stat now recovers from native Result
`0xe02`, and metrics journal opens successfully (log 1895/1897), with Android
`0xa0042` translated to host `0x202` (RDWR|CREAT). ReadOnly is absent.
However log 1912 reports `_db_info` CREATE failure: primary 10, extended 266,
errno 5. This is SQLITE_IOERR_READ, not a completed schema initialization.
All three DBs fail similarly. Later metrics query `SELECT * FROM single_stats`
still fails with code 1. NRE localization is therefore still downstream of a
failed DB initialization, not evidence that the schema fix completed.

Target SQLite unixRead at `0x420d0` calls lseek64 at `0x42148`, then the imported
read at `0x42170`. A negative read produces `0x10a` (266) at `0x4223c`; a short
read produces `0x20a` (522) and zero-fills at `0x42220..0x42234`.
This establishes the failing native boundary. The log does not identify the
read fd/offset; it cannot alone prove that the failure was an EOF probe.

There is a verified API mismatch to correct: Atmosphere IFile::DryRead rejects
offset > file_size, while POSIX read past EOF returns zero. Source:
https://github.com/Atmosphere-NX/Atmosphere/blob/master/libraries/libstratosphere/include/stratosphere/fs/fsa/fs_ifile.hpp
(DryRead). libnx forwards FsFileRead failures as errno/-1. SQLite journal
probes can read a future sector header past the current file size.

The follow-up changes only read_fake: after EIO, obtain actual position and
fstat size; return EOF only for a regular file with position strictly past its
end. Preserve errors for in-range reads, unknown position/size, and other
errno values. Log original native Result, errno, fd, position, size, count,
and caller; keep all SQLite errors visible. No DB/journal schema is fabricated.

Fault-injected read tests cover beyond-EOF, exact EOF, crossing EOF, valid data,
partial transfer followed by EIO, EBADF, failed fstat/seek, and in-range EIO.
Both read/stat tests passed in the devkitA64 container. The new hardware log
must show `[io] read past EOF` to confirm this cause on the device, followed
by successful CREATE steps (101). An `[io] read FAILED` line supplies the
missing native evidence if another cause remains. The new incremental patch
is `docs/single_game_log18_fix.patch`; log 18 does not satisfy the UI criterion.

## Hardware log 19: PASS, 2026-10-02

User confirms the game works. Log `C:/Users/oleks/AppData/Local/Temp/durak_nx (19).log`
confirms the cause: journal read at offset 4096, size 3608, count 8 returns native
Result 0x177a02 and errno 5 (line 1919); the shim converts the verified beyond-EOF
case to EOF. `_db_info` CREATE succeeds with rc=101 (line 1928), and the game
creates `single_stats` with rc=101 (line 2252). Across 8064 log lines there are
zero SQLiteException, NullReferenceException, or `[io] read FAILED` messages.
The final log records attack phase, cards on table and deck sorting, providing
gameplay evidence alongside the user confirmation. Single Game gate is passed;
the earlier pending statuses above are retained as historical evidence.
