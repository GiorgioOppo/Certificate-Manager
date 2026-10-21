#ifndef CERTIFICATI_INCIDENT_H
#define CERTIFICATI_INCIDENT_H
#include "store.h"

/* Called by the schema migration, not lazily from network callbacks. */
const char *incident_schema(void);
char *incident_api(Store *, const char *method, const char *path,
    const unsigned char *body, size_t bodylen, size_t *length, int *status,
    char *err, size_t errlen);
/* Record observations only within monitor_result's revision-guarded savepoint. */
int incident_record(Store *, int64_t monitor_id, int64_t now,
    const char *status, const char *previous_status, const char *expected,
    const char *observed, const char *previous_fingerprint, const char *message,
    char *err, size_t errlen);
/* Maintenance expiration requests a new revision and immediate observation. */
int incident_tick(Store *, int64_t now, char *err, size_t errlen);
#endif
