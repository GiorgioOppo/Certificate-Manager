#ifndef CERTIFICATI_MONITOR_H
#define CERTIFICATI_MONITOR_H

#include "remote.h"
#include "store.h"

int monitor_save(Store *store, int64_t id, int64_t certificate_id,
                  const char *target, int interval_seconds, int enabled,
                  int64_t now, int64_t *saved_id, char *err, size_t errlen);
int monitor_request(Store *store, int64_t id, int64_t now,
                     char *err, size_t errlen);
int monitor_remove(Store *store, int64_t id, char *err, size_t errlen);

/* Poll once per server iteration. No network operation runs in this process.
 * A single worker is active; SQLite lease tokens also coordinate other servers.
 * Call shutdown before closing the Store used by monitor_tick. */
int monitor_tick(Store *store, int64_t now, char *err, size_t errlen);
void monitor_shutdown(void);

/* Apply a synchronous result transactionally; stale revisions are ignored.
 * Intended for tests or a caller already owning the monitor's scheduling lease. */
int monitor_record_result(Store *store, int64_t monitor_id, int64_t revision,
                           int64_t now, const RemoteResult *result,
                           int local_error, const char *local_message,
                           char *err, size_t errlen);

#endif
