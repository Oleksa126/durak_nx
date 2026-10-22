# Case sensitivity probe cleanup

Log (22) shows an empty CASESENSITIVETEST GUID file opened with guest flags
0xc2, then unlink failing with errno 5 while its descriptor is still open.
Metadata/relocations identify System.IO.PathInternal.GetIsCaseSensitive
(token 0x06002d90, RVA 0x10acc80). Its FileStream constructor at 0x10acd94
receives FileOptions.DeleteOnClose (0x04000000 at 0x10acd8c), after combining
Path.GetTempPath with a GUID name and before testing its lowercase spelling.

The shim retains the original unlink failure and logs errno plus libnx Result.
Only writable created, empty regular files immediately inside GAME_HOME with
the exact CASESENSITIVETEST + 32 hexadecimal characters name are tracked.
EIO/EBUSY failures schedule retry after successful close/fclose of the last
tracked handle. Cleanup checks type and size again; failures remain logged.
Existing empty probes are enumerated before Unity startup; the directory is
closed before deletion. SD changes are committed. No database, catalog,
synthetic platform file or nonempty probe is removed.

Native fault injection covers EIO, EBUSY, EACCES, failed close, multiple handles,
errno preservation despite a logger that changes errno, strict names, outside
roots, nonempty files, directories, symlinks and idempotent startup cleanup.

Status: NEEDS_HARDWARE_TEST. Copy the updated NRO, launch twice on Switch and
check CASE PROBE logs for actual cleanup rc=0 and no new leftover probes.
If deletion still fails, retain its errno/Result and investigate that evidence.
