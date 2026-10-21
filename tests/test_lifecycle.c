#include "app.h"
#include "lifecycle.h"
#include "monitor.h"
#include "operations.h"
#include "workspace.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

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

static void checklist(Store *s, int64_t job, int expected, const char *reason) {
    char *json = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&json, &length);
    int allowed = -1;
    int64_t changes = sqlite3_total_changes64(s->db);
    assert(out && lifecycle_checklist(s, job, out, &allowed, error, sizeof error));
    assert(fclose(out) == 0 && length && allowed == expected);
    assert(sqlite3_total_changes64(s->db) == changes);
    if (reason) assert(strstr(json, reason));
    free(json);
}

static void busy_transaction_rollback(void) {
    char path[] = "/tmp/certificati-lifecycle-busy-XXXXXX";
    int fd = mkstemp(path); assert(fd >= 0); close(fd);
    Store s = {0}; assert(store_open(&s, path, error, sizeof error));
    int64_t now = (int64_t)time(NULL);
    int64_t old = add_certificate(&s, "old-busy", 10, now);
    int64_t next = add_certificate(&s, "new-busy", 100, now);
    int64_t job = 0; int queued = 0;
    assert(lifecycle_link_existing(&s, old, next, &job, &queued, error, sizeof error));
    sqlite3 *reader = NULL; sqlite3_stmt *read = NULL;
    assert(sqlite3_open(path, &reader) == SQLITE_OK);
    assert(sqlite3_prepare_v2(reader, "SELECT * FROM certificates", -1, &read, NULL) == SQLITE_OK);
    assert(sqlite3_step(read) == SQLITE_ROW);
    sqlite3_busy_timeout(s.db, 0);
    int64_t saved = 0;
    assert(!lifecycle_set_plan(&s, job, old, "signed", now, 0, 0,
                               "Busy writer", "Must roll back", &saved, error, sizeof error));
    assert(sqlite3_get_autocommit(s.db));
    assert(!workspace_save_person(&s, 0, "Busy person", "busy@example.test", NULL, 0,
                                  &saved, error, sizeof error));
    assert(sqlite3_get_autocommit(s.db));
    const char *body = "name=Busy&thresholds=45,30,15,2,0&enabled=1&escalation_email=&escalation_name=&escalation_after_days=7";
    size_t length = 0; int status = 0;
    char *json = operations_api(&s, "POST", "/api/operations/templates",
                                (const unsigned char *)body, strlen(body), &length, &status, error, sizeof error);
    assert(!json && sqlite3_get_autocommit(s.db));
    sqlite3_finalize(read); sqlite3_close(reader);
    assert(scalar(&s, "SELECT count(*) FROM directory_people") == 0);
    assert(scalar(&s, "SELECT count(*) FROM policy_templates") == 0);
    assert(scalar(&s, "SELECT notes='' FROM renewal_jobs"));
    /* Nested failures must preserve the caller's unrelated changes. */
    assert(store_exec(&s, "BEGIN; UPDATE certificates SET source='parent transaction'", error, sizeof error));
    assert(!lifecycle_set_plan(&s, 999999, old, "signed", now, 0, 0,
                               "Nobody", "Missing case", &saved, error, sizeof error));
    assert(!sqlite3_get_autocommit(s.db));
    assert(scalar(&s, "SELECT count(*) FROM certificates WHERE source='parent transaction'") == 2);
    assert(store_exec(&s, "ROLLBACK", error, sizeof error));
    store_close(&s); unlink(path);
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
    checklist(&store, job_id, 0, "verification_not_requested");
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
    checklist(&store, job_id, 1, NULL);
    /* The read-only checklist includes services added after the initial snapshot. */
    int64_t late_monitor = 0;
    assert(monitor_save(&store, 0, old_id, "https://localhost:444", 900, 0, now,
                        &late_monitor, error, sizeof error));
    checklist(&store, job_id, 0, "service_paused");
    assert(scalar(&store, "SELECT count(*) FROM renewal_endpoints") == 1);
    assert(!lifecycle_finish(&store, job_id, error, sizeof error));
    assert(monitor_remove(&store, late_monitor, error, sizeof error));
    /* Old requests remain ineligible even if an automatic match is recent. */
    assert(store_exec(&store, "UPDATE renewal_endpoints SET verify_requested_at=verify_requested_at-1800", error, sizeof error));
    checklist(&store, job_id, 0, "request_stale");
    assert(!lifecycle_finish(&store, job_id, error, sizeof error));
    assert(store_exec(&store, "UPDATE renewal_endpoints SET verify_requested_at=verify_requested_at+1800", error, sizeof error));
    /* Duplicate targets on the replacement block both preview and completion. */
    int64_t duplicate = 0;
    assert(monitor_save(&store, 0, new_id, "https://localhost:443", 900, 0, now,
                        &duplicate, error, sizeof error));
    checklist(&store, job_id, 0, "duplicate_targets");
    assert(!lifecycle_finish(&store, job_id, error, sizeof error));
    assert(monitor_remove(&store, duplicate, error, sizeof error));
    checklist(&store, job_id, 1, NULL);
    assert(lifecycle_finish(&store, job_id, error, sizeof error));
    checklist(&store, job_id, 0, "job_closed");
    assert(scalar(&store, "SELECT count(*) FROM renewal_closure_reports WHERE mode='verified'") == 1);
    assert(scalar(&store, "SELECT instr(report_json,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')>0 FROM renewal_closure_reports"));
    assert(scalar(&store, "SELECT status='verified' FROM renewal_jobs"));
    assert(scalar(&store, "SELECT certificate_id FROM monitors WHERE id=1") == new_id);
    assert(scalar(&store, "SELECT archived FROM certificates WHERE id=1"));
    assert(scalar(&store, "SELECT superseded_by FROM certificates WHERE id=1") == new_id);
    assert(!scalar(&store, "SELECT count(*) FROM pragma_foreign_key_check"));
    store_close(&store);
    busy_transaction_rollback();
    puts("Test ciclo rinnovo e revisione monitor: OK");
    return 0;
}
