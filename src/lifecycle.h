#ifndef CERTIFICATI_LIFECYCLE_H
#define CERTIFICATI_LIFECYCLE_H

#include "store.h"
#include <stdio.h>

int lifecycle_is_candidate(Store *store, int64_t old_certificate_id,
    int64_t new_certificate_id, int *matches, char *err, size_t errlen);
int lifecycle_state_append(Store *store, FILE *out, char *err, size_t errlen);
int lifecycle_set_plan(Store *store, int64_t job_id, int64_t old_certificate_id,
    const char *status, int64_t requested_at, int64_t planned_renewal_at,
    int64_t planned_install_at, const char *responsible, const char *notes,
    int64_t *saved_id, char *err, size_t errlen);
int lifecycle_link_existing(Store *store, int64_t old_certificate_id,
    int64_t new_certificate_id, int64_t *job_id, int *queued,
    char *err, size_t errlen);
/* monitor_id=0 requests a fresh check for all endpoints in this renewal. */
int lifecycle_request_install(Store *store, int64_t job_id, int64_t monitor_id,
    char *err, size_t errlen);
int lifecycle_finish(Store *store, int64_t job_id, char *err, size_t errlen);
/* Explicit retirement is separate from verified installation and needs a note. */
int lifecycle_retire(Store *store, int64_t job_id, char *err, size_t errlen);

/* These hooks run within the monitor result's revision-guarded transaction. */
int lifecycle_fingerprint_approved(Store *store, int64_t monitor_id,
    const char *fingerprint, int64_t now, int *approved,
    char *err, size_t errlen);
int lifecycle_record_monitor(Store *store, int64_t monitor_id, int64_t now,
    const char *fingerprint, int verified, char *err, size_t errlen);
#endif
