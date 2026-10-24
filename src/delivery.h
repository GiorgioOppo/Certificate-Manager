#ifndef CERTIFICATI_DELIVERY_H
#define CERTIFICATI_DELIVERY_H

#include "store.h"
#include "smtp_settings.h"

/* Queue functions participate in the caller's transaction. Subject/body are
 * rendered once from the alert/audience template and stored as snapshots.
 * Baseline recipients stay enabled; additional template copies are opt-in. */
int delivery_queue_expiry(Store *store, int64_t certificate_id, int threshold,
                          int64_t now, char *err, size_t n);
int delivery_queue_certificate(Store *store, int64_t certificate_id,
                               const char *pem_bundle, int64_t now,
                               int *queued, char *err, size_t n);
int delivery_queue_monitor_event(Store *store, int64_t event_id, int64_t now,
                                  int *queued, char *err, size_t n);

/* Missing policy rows use 45,30,15,2,0. The most urgent reached threshold is
 * returned, or -1 when no reminder is due / the policy is paused. */
int reminder_policy_due(Store *store, int64_t certificate_id, int64_t not_after,
                         int64_t now, int *threshold, char *err, size_t n);
/* Escalation is measured from the first recorded reminder, and is deduplicated
 * per certificate and destination. Both helpers use the caller's transaction. */
int reminder_policy_check_escalation(Store *store, int64_t certificate_id,
                                     int64_t now, int *queued, char *err, size_t n);

/* Call outside a transaction. No SMTP configuration means no delivery. */
int delivery_process(Store *store, int64_t now, int *sent, char *err, size_t n);
int delivery_is_configured(Store *store);

/* Connect, negotiate verified TLS and authenticate, without sending a message. */
int delivery_test_connection(const SmtpSettings *settings, char *err, size_t n);

/* Caller owns the returned RFC 5322 / MIME message. Does not send anything. */
char *delivery_message(Store *store, int64_t outbox_id, size_t *length,
                       char *err, size_t n);

#endif
