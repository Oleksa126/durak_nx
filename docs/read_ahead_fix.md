# Read-ahead activation — 2026-10-06

Hardware baseline: durak_nx 1.log, build 422c06d. Main-to-loader-handoff
19.331510 s; asset_cache_fill calls=0 despite opening the 32 MB asset bundle
and 7 MB metadata. The old static slots were BSS-zero, while attachment searched
for fd<0. No descriptor was initially free; descriptor 0 could falsely match.

The corrected implementation explicitly initializes all eight slots to -1.
The existing 1 MB windows remain bounded to 8 MB and reused after close.
Capacity/allocation failure falls back to ordinary I/O. Only immutable asset
paths under assets/game-assets and canonical IL2CPP metadata are eligible;
databases, saves and other root files cannot be attached.

Enabling the previously unused reader also requires correcting latent behavior:
lookup/read/seek/detach use the same lock; errors before any bytes return -1;
partial reads preserve progress and real errno/Result; negative, invalid and
overflowing seeks leave the cursor unchanged; seeking beyond EOF reads zero
without an invalid Horizon read. Positive short native reads are usable windows.
Duplicate attachment does not reset the cursor. Reused descriptors start fresh.

Sequential read, fortified read, lseek/lseek64 share the virtual position.
pread/fortified pread and file-map copies use a positional adapter under the
same lock, retaining the sequential cursor. Ordinary FILE streams still use
their native stdio buffering; they are not attached. Both close wrappers detach.
No instruction patches, CPU boost, splash, SQL schema or importer changes.

Native tests exercise actual temporary files, syscall-count reduction, window
boundaries, positional reads, EOF, invalid/overflow seeks, short reads, injected
I/O errors (including partial progress), concurrent read/pread, slot capacity
fallback and descriptor reuse. Error logger deliberately changes errno to test
preservation. Existing startup timing stays enabled and writes only to the log.

Hardware gate: run the updated NRO with unchanged assets/saves and provide its
log. Check ASSET CACHE attach active=1, nonzero asset_cache_fill, MainMenu handoff,
and gameplay/audio/input. Speedup is not established by native tests. The old
19.33 s run also reimported l10n.bytes; comparisons must distinguish that work.
