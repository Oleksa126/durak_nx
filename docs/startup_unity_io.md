# Unity startup I/O optimization — 2026-10-06

Scope: the remaining nativeRender startup interval only. Hardware log (24),
commit 5d1b04b, records 8.860697 s in nine nativeRender calls and 10.150068 s
from main to menu handoff. Forwarder/launch behavior and CPU/GPU modes unchanged.

Confirmed avoidable work:

- Each managed sqlite3_step re-resolves step/db_handle/sql using linear ELF
  symbol searches before the measured native SQLite interval. There are 2386
  steps before menu. Cache 13 explicitly named SQLite exports, including those
  used by the inventory helper. Successful addresses are published atomically;
  first lookup is serialized, missing exports retry and unknown names delegate.
  The module stays loaded at a stable address for the lifetime of the guest.
  Wrappers retain function signatures, return codes, errno and diagnostic data.
- open_fake previously attached only assets >=4 MiB. The 192224-byte
  sharedassets1.resource has ten opens in log (24); default resources (3750740
  bytes) also bypassed the cache. All positive-size read-only regular assets
  now attach. Files <=4 MiB use shared process-local contents keyed by absolute
  resolved path and size, with independent descriptor cursors. Eight content
  entries, a 16 MiB content budget and eviction only of unreferenced entries;
  fallback retains the existing eight 1 MiB descriptor windows. Fill is lazy.
  Large assets retain the old window implementation. Closed fd numbers are
  detached; they cannot alias a different path's retained data.
  Before native dup(), synchronize the logical offset and release that fd's
  adapter, so both native handles retain their required shared cursor. Failed
  synchronization returns the original error and leaves the adapter intact.
- Cache successful regular-file stat metadata only under the immutable asset
  paths. Saves, SQLite files, journals, directories and failures stay live.
  Neither ENOENT nor storage errors are cached; a missing file can appear later.
  The existing EIO directory-entry recovery for writable databases is retained.
  The cache is bounded to 128 paths and assumes packaged assets remain unchanged
  during this process, as does the existing immutable read-ahead implementation.

File-only startup evidence now includes per-frame nativeRender spans (first 20
calls while startup profiling is active), sqlite_export_miss, host_stat and
asset_reopen_reuse. The reuse byte count describes available retained contents,
not an exact count of saved physical bytes. All spans overlap and must not be
added into a startup total. Successful asset metadata hits bypass host_stat.

Native tests cover concurrent export initialization/hits, retry and errno;
metadata errors, creation after ENOENT, live mutable files/directories and hits;
small-file independent/concurrent cursors, reopen reuse, path/fd identity,
short reads, errors, dup shared cursors and budget pressure without evicting pinned content. Existing
large-file cache, loading, SQLite inventory and target verification gates remain.
Actual startup speedup and gameplay acceptance require Switch validation.
