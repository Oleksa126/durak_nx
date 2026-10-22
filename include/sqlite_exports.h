#pragma once
/* SQLite is loaded once and remains registered for the lifetime of the guest.
 * Cache only successful lookups from that module; unknown names pass through. */
void *durak_sqlite_export(const char *name, void *(*resolve)(const char *));
