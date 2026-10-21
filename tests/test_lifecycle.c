#include "app.h"
#include "lifecycle.h"
#include "monitor.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static char error[1024];
static int64_t scalar(Store *s, const char *sql) {
    sqlite3_stmt *q = NULL;
    assert(sqlite3_prepare_v2(s->db, sql, -1, &q, NULL) == SQLITE_OK);
    assert(sqlite3_step(q) == SQLITE_ROW);
    int64_t value = sqlite3_column_int64(q, 0);
    sqlite3_finalize(q);
    return value;
}

static int64_t add_certificate(Store *s, const char *fingerprint, int days, int64_t now) {
    Certificate cert = {0};
    cert.fingerprint = (char *)fingerprint;
    cert.common_name = "localhost"; cert.subject = "CN=localhost"; cert.issuer = "CN=Test CA";
    cert.serial = "01"; cert.sans = "DNS:localhost";
    cert.key_algorithm = "RSA"; cert.key_bits = 2048; cert.signature_algorithm = "sha256WithRSAEncryption";
    cert.not_before = now - 60; cert.not_after = now + (int64_t)days * 86400;
    int inserted = 0; int64_t id = 0;
    assert(store_add(s, &cert, "lifecycle test", now, &id, &inserted, error, sizeof error));
    assert(inserted);
    return id;
}

int main(void) {
    Store store = {0};
    assert(store_open(&store, ":memory:", error, sizeof error));
    int64_t now = (int64_t)time(NULL);
    const char *old_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char *new_fingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    int64_t old_id = add_certificate(&store, old_fingerprint, 10, now);
    int64_t new_id = add_certificate(&store, new_fingerprint, 100, now);
    int64_t monitor_id = 0;
    assert(monitor_save(&store, 0, old_id, "https://localhost:443", 900, 1, now,
                        &monitor_id, error, sizeof error));
    int64_t job_id = 0; int queued = 0;
    assert(lifecycle_link_existing(&store, old_id, new_id, &job_id, &queued, error, sizeof error));
    assert(job_id && !queued);
    /* Saving an old pre-signing form must not revoke an approved replacement. */
    int64_t saved_job = 0;
    assert(lifecycle_set_plan(&store, job_id, old_id, "requested", now, 0, 0,
                              "Operator", "Plan updated", &saved_job, error, sizeof error));
    assert(saved_job == job_id);
    assert(scalar(&store, "SELECT status='signed' FROM renewal_jobs"));
    assert(!scalar(&store, "SELECT archived FROM certificates WHERE id=1"));
    assert(scalar(&store, "SELECT certificate_id FROM monitors WHERE id=1") == old_id);
    int approved = 0;
    assert(lifecycle_fingerprint_approved(&store, monitor_id, new_fingerprint, now,
                                           &approved, error, sizeof error) && approved);
    assert(!lifecycle_finish(&store, job_id, error, sizeof error));
    int64_t previous_revision = scalar(&store, "SELECT revision FROM monitors WHERE id=1");
    assert(lifecycle_request_install(&store, job_id, monitor_id, error, sizeof error));
    int64_t revision = scalar(&store, "SELECT revision FROM monitors WHERE id=1");
    assert(revision > previous_revision);
    Certificate observed = {0}; observed.fingerprint = (char *)new_fingerprint;
    RemoteResult result = {0};
    result.dns_ok = result.tcp_ok = result.tls_ok = result.verified = 1;
    result.certificates.items = &observed; result.certificates.count = 1;
    /* A worker that began before the explicit request cannot prove installation. */
    assert(monitor_record_result(&store, monitor_id, previous_revision, now, &result,
                                  0, NULL, error, sizeof error));
    assert(scalar(&store, "SELECT last_checked_at IS NULL FROM monitors WHERE id=1"));
    assert(scalar(&store, "SELECT verified_at IS NULL FROM renewal_endpoints"));
    /* Matching an approved fingerprint never bypasses trust/hostname verification. */
    result.verified = 0;
    assert(monitor_record_result(&store, monitor_id, revision, now, &result,
                                  0, NULL, error, sizeof error));
    assert(scalar(&store, "SELECT last_status='verification_error' FROM monitors WHERE id=1"));
    assert(scalar(&store, "SELECT verified_at IS NULL FROM renewal_endpoints"));
    assert(!lifecycle_finish(&store, job_id, error, sizeof error));
    result.verified = 1;
    assert(monitor_record_result(&store, monitor_id, revision, now, &result,
                                  0, NULL, error, sizeof error));
    assert(scalar(&store, "SELECT last_status='ok' FROM monitors WHERE id=1"));
    assert(scalar(&store, "SELECT verified_at IS NOT NULL FROM renewal_endpoints"));
    assert(lifecycle_finish(&store, job_id, error, sizeof error));
    assert(scalar(&store, "SELECT status='verified' FROM renewal_jobs"));
    assert(scalar(&store, "SELECT certificate_id FROM monitors WHERE id=1") == new_id);
    assert(scalar(&store, "SELECT archived FROM certificates WHERE id=1"));
    assert(scalar(&store, "SELECT superseded_by FROM certificates WHERE id=1") == new_id);
    assert(!scalar(&store, "SELECT count(*) FROM pragma_foreign_key_check"));
    store_close(&store);
    puts("Test ciclo rinnovo e revisione monitor: OK");
    return 0;
}
