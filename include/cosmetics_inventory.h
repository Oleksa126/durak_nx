#pragma once

/* Called before a managed SELECT, on the same SQLite connection/thread.
 * Only existing MetricsTypes inventory tables are eligible. */
int durak_inventory_before_query(void *db, const char *sql, int length,
                                void *(*resolve)(const char *));
